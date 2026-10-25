"""FastAPI application: four server-rendered pages plus live progress endpoints."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import quote

from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from . import patches, providers, store
from .agents import SURFACES
from .config import APP_NAME, APP_TAGLINE, CLAUDE_MODEL, DATA_DIR, ROOT, RUN_DEPTH_DEFAULT, SCANNER_TIMEOUT
from .runner import DEPTHS, manager
from .fsbrowse import NATIVE_SUPPORTED, list_dir, native_pick
from .scanner import tool_status
from .storage import ensure_data_dir, list_runs, resolve_run_file, run_tree

app = FastAPI(title=APP_NAME, docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(ROOT / "templates"))


def render(request: Request, name: str, active: str, **ctx) -> HTMLResponse:
    base = {"request": request, "active": active, "data_dir": str(DATA_DIR), "model": CLAUDE_MODEL,
            "app_name": APP_NAME, "tagline": APP_TAGLINE}
    return templates.TemplateResponse(request, name, {**base, **ctx})


@app.on_event("startup")
async def _startup() -> None:
    ensure_data_dir()


# ------------------------------------------------------------------ Page 1: configure & launch
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, error: str = "", paths: str = ""):
    return render(
        request, "index.html", "/",
        tools=tool_status(), error=error, paths=paths, running=manager.is_running(),
        run_count=len(list_runs()), timeout_min=SCANNER_TIMEOUT // 60,
        api_key_set=bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")),
        native_picker=NATIVE_SUPPORTED, depths=DEPTHS, depth_default=RUN_DEPTH_DEFAULT, surfaces=SURFACES,
        settings=providers.masked(providers.load()), stages=providers.STAGES,
    )


# ------------------------------------------------------------------ folder pickers (local machine only)
@app.get("/fs/list")
async def fs_list(path: str = "", hidden: int = 0):
    return JSONResponse(list_dir(path or None, show_hidden=bool(hidden)))


@app.post("/fs/native")
async def fs_native():
    # osascript blocks until the user closes the Finder dialog; keep the event loop free meanwhile
    return JSONResponse(await asyncio.to_thread(native_pick))


@app.post("/run")
async def launch(request: Request, paths: str = Form(""), depth: str = Form(RUN_DEPTH_DEFAULT)):
    form = await request.form()
    surfaces = [str(x) for x in form.getlist("surfaces") if str(x) in SURFACES] or None
    models = {st: str(form.get(f"model_{st}") or "") for st in providers.STAGES}
    raw_lines = [ln.strip().strip('"').strip("'") for ln in paths.splitlines()]
    candidates = [ln for ln in raw_lines if ln and not ln.startswith("#")]
    if not candidates:
        return RedirectResponse(f"/?error={quote('Paste at least one repository path.')}", status_code=303)
    resolved: list[Path] = []
    problems: list[str] = []
    seen: set[Path] = set()
    for ln in candidates:
        p = Path(ln).expanduser()
        if not p.is_absolute():
            problems.append(f"{ln}: not an absolute path")
            continue
        p = p.resolve()
        if not p.is_dir():
            problems.append(f"{ln}: directory does not exist")
            continue
        if p in seen:
            continue
        seen.add(p)
        resolved.append(p)
    if problems:
        msg = "Fix these paths and relaunch:\n" + "\n".join(problems)
        return RedirectResponse(f"/?error={quote(msg)}&paths={quote(paths)}", status_code=303)
    try:
        manager.start(resolved, depth=depth, surfaces=surfaces, models=models)
    except RuntimeError as e:
        return RedirectResponse(f"/?error={quote(str(e))}&paths={quote(paths)}", status_code=303)
    return RedirectResponse("/run/status", status_code=303)


# ------------------------------------------------------------------ Page 2: live progress tracker
def _public_state(snap: dict, since: int | None = None) -> dict:
    out = {k: v for k, v in snap.items() if k != "log"}
    if since is not None:
        out["new_log"] = snap["log"][since:]
    return out


@app.get("/run/status", response_class=HTMLResponse)
async def run_status(request: Request):
    snap = manager.snapshot()
    return render(request, "status.html", "/run/status", state=_public_state(snap) if snap else None)


@app.get("/run/state")
async def run_state(since: int = 0):
    snap = manager.snapshot()
    return JSONResponse(_public_state(snap, since) if snap else None)


@app.get("/run/events")
async def run_events(request: Request):
    async def gen():
        sent = 0
        while True:
            if await request.is_disconnected():
                return
            snap = manager.snapshot()
            if snap is None:
                yield "event: end\ndata: {}\n\n"
                return
            for entry in snap["log"][sent:]:
                yield f"event: log\ndata: {json.dumps(entry)}\n\n"
            sent = len(snap["log"])
            yield f"event: state\ndata: {json.dumps(_public_state(snap))}\n\n"
            if snap["status"] in ("done", "failed"):
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(1.0)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ Page 3: history vault
@app.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    return render(request, "history.html", "/history", runs=list_runs())


# ------------------------------------------------------------------ Page 4: report hub
@app.get("/history/{run_id}", response_class=HTMLResponse)
async def report_hub(request: Request, run_id: str):
    tree = run_tree(run_id)
    if tree is None:
        resp = render(request, "history.html", "/history", runs=list_runs(), error="Run not found")
        resp.status_code = 404
        return resp
    return render(request, "report.html", "/history", tree=tree)


@app.get("/history/{run_id}/raw/{rel:path}")
async def raw_file(run_id: str, rel: str):
    target = resolve_run_file(run_id, rel)
    if target is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    media = {"md": "text/markdown", "json": "application/json"}.get(target.suffix.lstrip("."), "text/plain")
    return FileResponse(str(target), media_type=f"{media}; charset=utf-8")


# ------------------------------------------------------------------ findings board (triage)
@app.get("/findings", response_class=HTMLResponse)
async def findings_board(request: Request, run: str = "", project: str = "", status: str = "", surface: str = "",
                         severity: str = "", source: str = "", hide_suppressed: int = 0):
    rows = store.list_findings(run_id=run or None, project=project or None, status=status or None,
                               surface=surface or None, severity=severity or None, source=source or None,
                               include_suppressed=not hide_suppressed)
    filters = {"run": run, "project": project, "status": status, "surface": surface, "severity": severity,
               "source": source, "hide_suppressed": hide_suppressed}
    return render(request, "findings.html", "/findings", rows=rows, stats=store.stats(run or None),
                  facets=store.projects_and_surfaces(), filters=filters, statuses=store.STATUSES,
                  patch_jobs=manager.patch_jobs)


@app.get("/findings/{fp}", response_class=HTMLResponse)
async def finding_detail(request: Request, fp: str, msg: str = "", err: str = ""):
    f = store.get(fp)
    if f is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return render(request, "finding.html", "/findings", f=f, statuses=store.STATUSES,
                  job=manager.patch_jobs.get(fp), msg=msg, err=err)


@app.post("/findings/{fp}/status")
async def finding_status(fp: str, status: str = Form(...), note: str = Form(""), back: str = Form("")):
    try:
        store.set_status(fp, status, note)
    except ValueError as e:
        return RedirectResponse(f"/findings/{fp}?err={quote(str(e))}", status_code=303)
    return RedirectResponse(back or f"/findings/{fp}", status_code=303)


@app.post("/findings/bulk")
async def findings_bulk(request: Request):
    form = await request.form()
    status = str(form.get("status", ""))
    fps = [str(x) for x in form.getlist("fps")]
    back = str(form.get("back") or "/findings")
    if status in store.STATUSES:
        for fp in fps:
            store.set_status(fp, status, "bulk update")
    return RedirectResponse(back, status_code=303)


@app.post("/findings/{fp}/patch")
async def finding_patch(fp: str):
    try:
        manager.start_patch(fp)
    except RuntimeError as e:
        return RedirectResponse(f"/findings/{fp}?err={quote(str(e))}", status_code=303)
    return RedirectResponse(f"/findings/{fp}?msg={quote('Patch agent started')}", status_code=303)


@app.get("/findings/{fp}/patch/status")
async def finding_patch_status(fp: str):
    job = manager.patch_jobs.get(fp)
    f = store.get(fp)
    return JSONResponse({"job": job, "patch": (f or {}).get("patch")})


@app.post("/findings/{fp}/pr")
async def finding_pr(fp: str):
    f = store.get(fp)
    if f is None or not isinstance(f.get("patch"), dict) or not f["patch"].get("commit"):
        return RedirectResponse(f"/findings/{fp}?err={quote('no committed patch to open a PR from')}", status_code=303)
    patch = f["patch"]
    body = (f"## Fianto security fix\n\n**Finding:** {f['title']}  \n**Severity:** {f['severity']}  \n"
            f"**Location:** {f.get('location') or f.get('file')}\n\n{patch.get('summary', '')}\n\n"
            f"**Verification:** {patch.get('verification', '')}\n\n"
            + (f"**Residual risk / follow-ups:** {patch['residual_risk']}\n\n" if patch.get("residual_risk") else "")
            + f"_Fingerprint `{fp}` · generated by Fianto; review before merging._")
    res = await asyncio.to_thread(patches.create_pr, Path(patch["worktree"]), patch["branch"],
                                  f"security: {f['title'][:70]}", body)
    patch["pr"] = res
    store.set_json(fp, "patch", patch, "pr_created" if res.get("ok") else "pr_failed")
    if res.get("ok"):
        return RedirectResponse(f"/findings/{fp}?msg={quote('PR created: ' + res['url'])}", status_code=303)
    return RedirectResponse(f"/findings/{fp}?err={quote(res.get('error', 'PR failed'))}", status_code=303)


# ------------------------------------------------------------------ settings: providers, models, stages
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, msg: str = "", err: str = ""):
    return render(request, "settings.html", "/settings", settings=providers.masked(providers.load()),
                  stages=providers.STAGES, provider_types=providers.PROVIDER_TYPES, msg=msg, err=err)


def _back(msg: str = "", err: str = "") -> RedirectResponse:
    q = f"?msg={quote(msg)}" if msg else (f"?err={quote(err)}" if err else "")
    return RedirectResponse(f"/settings{q}", status_code=303)


@app.post("/settings/providers")
async def settings_add_provider(request: Request):
    form = {k: str(v) for k, v in (await request.form()).items()}
    try:
        p = providers.add_provider(form)
    except ValueError as e:
        return _back(err=str(e))
    return _back(msg=f"Provider '{p['name']}' added. Use Discover to list its models, or add one manually.")


@app.post("/settings/providers/{pid}/key")
async def settings_provider_key(pid: str, api_key: str = Form("")):
    try:
        providers.update_provider_key(pid, api_key)
    except ValueError as e:
        return _back(err=str(e))
    return _back(msg="API key updated")


@app.post("/settings/providers/{pid}/delete")
async def settings_delete_provider(pid: str):
    try:
        providers.delete_provider(pid)
    except ValueError as e:
        return _back(err=str(e))
    return _back(msg="Provider removed")


@app.get("/settings/providers/{pid}/discover")
async def settings_discover(pid: str):
    return JSONResponse(await asyncio.to_thread(providers.discover_models, pid))


@app.post("/settings/models")
async def settings_add_model(request: Request):
    form = await request.form()
    pid = str(form.get("provider", ""))
    ids = [str(x) for x in form.getlist("model_id") if str(x).strip()]
    label = str(form.get("label", ""))
    added = []
    try:
        for mid in ids:
            added.append(providers.add_model(pid, mid, label if len(ids) == 1 else "")["model"])
    except ValueError as e:
        return _back(err=str(e))
    return _back(msg=f"Added {len(added)} model(s): {', '.join(added)}" if added else "", err="" if added else "no model id given")


@app.post("/settings/models/{key}/update")
async def settings_update_model(key: str, request: Request):
    form = await request.form()
    try:
        providers.update_model(key, thinking=str(form.get("thinking", "off")), effort=str(form.get("effort", "")),
                               label=str(form.get("label", "")) or key.split("::", 1)[-1],
                               fallbacks=form.get("fallbacks") == "on", enabled=form.get("enabled") == "on",
                               max_tokens=int(form.get("max_tokens") or 16000))
    except ValueError as e:
        return _back(err=str(e))
    return _back(msg=f"Saved {key.split('::', 1)[-1]}")


@app.post("/settings/models/{key}/delete")
async def settings_delete_model(key: str):
    providers.delete_model(key)
    return _back(msg="Model removed")


@app.post("/settings/models/{key}/test")
async def settings_test_model(key: str):
    return JSONResponse(await asyncio.to_thread(providers.test_model, key))


@app.post("/settings/stages")
async def settings_stages(request: Request):
    form = await request.form()
    providers.set_stages({st: str(form.get(st, "")) for st in providers.STAGES})
    return _back(msg="Stage assignment saved")


@app.get("/health")
async def health():
    return {"ok": True, "running": manager.is_running(), "data_dir": str(DATA_DIR)}
