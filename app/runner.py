"""Sequential run manager: one background thread walks projects 1-by-1 and feeds a live log.

Per project: scanners -> findings store -> surface agents (parallel) -> verifier -> patch agent,
then the Claude summary. Depth is chosen per run (scan | review | verify | patch).
"""
from __future__ import annotations

import copy
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import agents, providers, store
from . import claude_pipeline as ai
from .config import (AGENT_PARALLELISM, MASTER_REPORT, PATCH_MAX_PER_PROJECT, PATCH_MIN_SEVERITY, PROJECT_SUMMARY,
                     RUN_MANIFEST, SCANNER_TIMEOUT, VERIFY_MAX_CANDIDATES)
from .scanner import SEVERITIES, ScanResult, build_commands, detect_stack, run_command
from .storage import new_run_dir, unique_project_name, write_json
from .store import SEVERITY_RANK

DEPTHS = ["scan", "review", "verify", "patch"]


def _tok_in(u: dict) -> str:
    total = u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0)
    return f"{total:,} ({u.get('cache_read_input_tokens', 0):,} cached)"


def _rank(sev: str) -> int:
    return SEVERITY_RANK.get(sev, 9)


class RunManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Optional[dict] = None
        self._thread: Optional[threading.Thread] = None
        self._specs: dict = {}
        self.patch_jobs: dict[str, dict] = {}

    # ----------------------------------------------------------------- public
    def is_running(self) -> bool:
        with self._lock:
            return bool(self._state and self._state["status"] in ("queued", "running"))

    def snapshot(self) -> Optional[dict]:
        with self._lock:
            return copy.deepcopy(self._state)

    def start(self, paths: list[Path], depth: str = "verify", surfaces: Optional[list[str]] = None,
              models: Optional[dict] = None) -> str:
        depth = depth if depth in DEPTHS else "verify"
        specs = providers.stage_specs(models)  # raises if settings are broken, before anything is provisioned
        with self._lock:
            if self._state and self._state["status"] in ("queued", "running"):
                raise RuntimeError("a run is already in progress")
            run_id, run_path = new_run_dir()
            taken: set[str] = set()
            projects = [{
                "name": unique_project_name(p, taken), "path": str(p), "stack": detect_stack(p),
                "surfaces": [s for s in (surfaces or agents.detect_surfaces(p)) if s in agents.SURFACES] or ["infra"],
                "status": "queued", "step": "", "scans": [], "finding_count": None,
                "severity": {s: 0 for s in SEVERITIES}, "summary_status": "", "usage": None,
                "agent_findings": 0, "verdicts": {}, "patched": 0, "store": {},
            } for p in paths]
            self._state = {
                "run_id": run_id, "run_dir": str(run_path), "status": "queued", "depth": depth,
                "started_at": datetime.now().isoformat(timespec="seconds"), "finished_at": None,
                "duration_s": None, "current_index": 0, "total": len(projects), "headline": "Queued",
                "projects": projects, "log": [], "master_status": "", "error": None, "totals": {},
                "triage": {}, "models": {st: sp.label for st, sp in specs.items()},
            }
        self._specs = specs
        self._thread = threading.Thread(target=self._work, args=(run_id, run_path, depth), daemon=True, name=run_id)
        self._thread.start()
        return run_id

    def start_patch(self, fp: str) -> None:
        """Ad-hoc patch job for one finding, launched from the findings board."""
        finding = store.get(fp)
        if finding is None:
            raise RuntimeError("finding not found")
        job = self.patch_jobs.get(fp)
        if job and job["status"] == "running":
            raise RuntimeError("a patch job is already running for this finding")
        self.patch_jobs[fp] = {"status": "running", "started": datetime.now().isoformat(timespec="seconds"), "log": [], "error": None}

        def log(level: str, msg: str) -> None:
            self.patch_jobs[fp]["log"].append({"t": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg})

        def work() -> None:
            project = {"name": finding["project"], "path": finding["project_path"],
                       "surfaces": agents.detect_surfaces(Path(finding["project_path"]))}
            try:
                res = agents.patch_finding(project, finding, log)
                store.set_json(fp, "patch", res, "patched" if res["status"] == "patched" else "patch_no_changes")
                self.patch_jobs[fp]["status"] = "done"
            except (ai.ClaudeUnavailable, RuntimeError) as e:
                store.set_json(fp, "patch", {"status": "failed", "error": str(e)}, "patch_failed")
                self.patch_jobs[fp].update(status="failed", error=str(e))
                log("error", str(e))
            except Exception as e:  # noqa: BLE001
                store.set_json(fp, "patch", {"status": "failed", "error": f"{type(e).__name__}: {e}"}, "patch_failed")
                self.patch_jobs[fp].update(status="failed", error=f"{type(e).__name__}: {e}")
                log("error", traceback.format_exc()[-1500:])

        threading.Thread(target=work, daemon=True, name=f"patch-{fp}").start()

    # ----------------------------------------------------------------- internals
    def _log(self, level: str, msg: str) -> None:
        with self._lock:
            if self._state is not None:
                self._state["log"].append({"t": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg})

    def _set(self, **kv) -> None:
        with self._lock:
            if self._state is not None:
                self._state.update(kv)

    def _set_project(self, i: int, **kv) -> None:
        with self._lock:
            if self._state is not None:
                self._state["projects"][i].update(kv)

    def _persist(self, run_path: Path) -> None:
        snap = self.snapshot()
        if snap is None:
            return
        write_json(run_path / RUN_MANIFEST, {k: v for k, v in snap.items() if k != "log"})

    # ----------------------------------------------------------------- stages
    def _stage_scanners(self, i: int, p: dict, pdir: Path, total: int) -> list[ScanResult]:
        name, ppath = p["name"], Path(p["path"])
        results: list[ScanResult] = []
        for cmd in build_commands(ppath):
            self._set_project(i, step=f"Running {cmd.label}...")
            self._set(headline=f"Scanning project {i + 1} of {total}: {name} -> Running {cmd.label}...")
            self._log("cmd", f"  -> {cmd.label}: {' '.join(cmd.argv)}")
            res = run_command(cmd, pdir, SCANNER_TIMEOUT)
            results.append(res)
            with self._lock:
                self._state["projects"][i]["scans"].append(res.to_manifest())
            level = {"clean": "ok", "findings": "warn", "missing": "skip"}.get(res.status, "error")
            summary = f"{res.finding_count} finding(s)" if res.finding_count is not None else res.message
            self._log(level, f"     {cmd.label}: {res.status} — {summary} [{res.duration_s}s]")
        return results

    def _stage_review(self, i: int, p: dict, run_id: str, rows: list[dict], total: int) -> int:
        name = p["name"]
        self._set_project(i, status="reviewing", step=f"Surface agents: {', '.join(p['surfaces'])}")
        self._set(headline=f"Scanning project {i + 1} of {total}: {name} -> agents reviewing {', '.join(p['surfaces'])}")
        leads = {s: [r for r in rows if r["surface"] == s] for s in p["surfaces"]}
        found = 0
        with ThreadPoolExecutor(max_workers=max(1, AGENT_PARALLELISM)) as ex:
            futs = {ex.submit(agents.review_surface, p, s, leads[s], self._log, self._specs["agent"]): s for s in p["surfaces"]}
            for fut in as_completed(futs):
                s = futs[fut]
                try:
                    res = fut.result()
                except ai.ClaudeUnavailable as e:
                    self._log("error", f"  Agent [{s}] unavailable: {e}")
                    continue
                except Exception as e:  # noqa: BLE001
                    self._log("error", f"  Agent [{s}] crashed: {type(e).__name__}: {e}")
                    continue
                counts = store.upsert(run_id, res["findings"])
                found += len(res["findings"])
                u = res["usage"]
                self._log("ok", f"  Agent [{s}] done: {len(res['findings'])} findings ({counts['new']} new, "
                                f"{counts['suppressed']} suppressed) in {res['turns']} turns, "
                                f"{_tok_in(u)} in / {u['output_tokens']} out")
                if res["text"]:
                    self._log("info", f"  [{s}] {res['text'][:600]}")
        self._set_project(i, agent_findings=found)
        return found

    def _stage_verify(self, i: int, p: dict, run_id: str, total: int) -> dict:
        name = p["name"]
        cands = [f for f in store.list_findings(run_id=run_id, project=name, include_suppressed=False)
                 if f["status"] in ("new", "needs_review") and (f["source"] == "agent" or f["severity"] in ("critical", "high"))]
        cands.sort(key=lambda f: (0 if f["source"] == "agent" else 1, _rank(f["severity"]), -(f.get("confidence") or 0)))
        cands = cands[:VERIFY_MAX_CANDIDATES]
        tally = {"confirmed": 0, "false_positive": 0, "needs_review": 0, "unverdicted": 0}
        if not cands:
            self._log("info", f"  Verifier: nothing to verify in {name}")
            return tally
        self._set_project(i, status="verifying", step=f"Verifying {len(cands)} candidates")
        self._set(headline=f"Scanning project {i + 1} of {total}: {name} -> verifying {len(cands)} candidates")
        try:
            res = agents.verify_project(p, cands, self._log, self._specs["verify"])
        except ai.ClaudeUnavailable as e:
            self._log("error", f"  Verifier unavailable: {e}")
            return tally
        for c in cands:
            v = res["verdicts"].get(c["fingerprint"])
            if not v:
                tally["unverdicted"] += 1
                continue
            store.set_status(c["fingerprint"], v["verdict"], v["reasoning"][:800], actor="verifier")
            store.set_json(c["fingerprint"], "verification", v, "verified")
            fields = {}
            if v.get("severity"):
                fields["severity"] = v["severity"]
            if v.get("exploit_path"):
                fields["exploit_path"] = v["exploit_path"]
            if fields:
                store.update_fields(c["fingerprint"], **fields)
            tally[v["verdict"]] += 1
        u = res["usage"]
        self._log("ok", f"  Verifier done: {tally['confirmed']} confirmed, {tally['false_positive']} false positives, "
                        f"{tally['needs_review']} need review, {tally['unverdicted']} unverdicted "
                        f"({res['turns']} turns, {_tok_in(u)} in / {u['output_tokens']} out)")
        self._set_project(i, verdicts=tally)
        return tally

    def _stage_patch(self, i: int, p: dict, run_id: str, total: int) -> int:
        name = p["name"]
        todo = [f for f in store.list_findings(run_id=run_id, project=name, status="confirmed")
                if _rank(f["severity"]) <= _rank(PATCH_MIN_SEVERITY) and not (f.get("patch") or {}).get("commit")]
        todo.sort(key=lambda f: (_rank(f["severity"]), -(f.get("confidence") or 0)))
        todo = todo[:PATCH_MAX_PER_PROJECT]
        if not todo:
            self._log("info", f"  Patch stage: no confirmed {PATCH_MIN_SEVERITY}+ findings to patch in {name}")
            return 0
        patched = 0
        for n, f in enumerate(todo, 1):
            self._set_project(i, status="patching", step=f"Patching {n}/{len(todo)}: {f['title'][:60]}")
            self._set(headline=f"Scanning project {i + 1} of {total}: {name} -> patching {n}/{len(todo)}")
            try:
                res = agents.patch_finding(p, f, self._log, self._specs["patch"])
                store.set_json(f["fingerprint"], "patch", res, "patched" if res["status"] == "patched" else "patch_no_changes")
                patched += res["status"] == "patched"
            except (ai.ClaudeUnavailable, RuntimeError) as e:
                self._log("error", f"  Patch failed for {f['title'][:60]}: {e}")
                store.set_json(f["fingerprint"], "patch", {"status": "failed", "error": str(e)}, "patch_failed")
        self._set_project(i, patched=patched)
        return patched

    @staticmethod
    def _triage_context(run_id: str, name: str) -> str:
        rows = store.list_findings(run_id=run_id, project=name)
        if not rows:
            return ""
        out = []
        for status in ("confirmed", "needs_review", "new", "false_positive", "accepted_risk", "fixed"):
            group = [r for r in rows if r["status"] == status and (status != "new" or r["source"] == "agent")]
            if not group:
                continue
            out.append(f"### {status} ({len(group)})")
            for r in group[:40]:
                line = f"- [{r['severity'].upper()}] {r['title']} — {r.get('location') or r.get('file')} ({r['tool']}, fp {r['fingerprint']})"
                if r.get("exploit_path"):
                    line += f"\n  exploit path: {str(r['exploit_path'])[:400]}"
                if isinstance(r.get("verification"), dict) and r["verification"].get("reasoning"):
                    line += f"\n  verifier: {r['verification']['reasoning'][:300]}"
                if r.get("patch_hint"):
                    line += f"\n  fix: {str(r['patch_hint'])[:300]}"
                if isinstance(r.get("patch"), dict) and r["patch"].get("commit"):
                    line += f"\n  PATCHED on branch {r['patch']['branch']} (commit {r['patch']['commit']}); files: {r['patch'].get('files_changed', '')}"
                out.append(line)
            if len(group) > 40:
                out.append(f"... {len(group) - 40} more")
        return "\n".join(out)

    # ----------------------------------------------------------------- main loop
    def _work(self, run_id: str, run_path: Path, depth: str) -> None:
        t0 = time.monotonic()
        self._set(status="running", headline="Starting run")
        snap = self.snapshot()
        projects = snap["projects"]
        total = len(projects)
        results_by_project: dict[str, list[ScanResult]] = {}
        summaries: dict[str, str] = {}
        self._log("info", f"Run {run_id} started: {total} project(s), depth={depth}. Output -> {run_path}")
        self._log("info", "Models: " + ", ".join(f"{st}={sp.id} @ {sp.provider['name']}" for st, sp in self._specs.items()))
        try:
            for i, p in enumerate(projects):
                name, ppath = p["name"], Path(p["path"])
                pdir = run_path / name
                pdir.mkdir(parents=True, exist_ok=True)
                self._set(current_index=i, headline=f"Scanning project {i + 1} of {total}: {name}")
                self._set_project(i, status="scanning")
                self._log("info", f"Scanning project {i + 1} of {total}: {name} ({ppath}) "
                                  f"stack={', '.join(p['stack']) or 'unknown'} surfaces={', '.join(p['surfaces'])}")

                results = self._stage_scanners(i, p, pdir, total)
                results_by_project[name] = results
                sev = {s: sum(r.severity.get(s, 0) for r in results) for s in SEVERITIES}
                self._set_project(i, finding_count=sum(r.finding_count or 0 for r in results), severity=sev)

                rows = agents.scanner_rows(p, results)
                counts = store.upsert(run_id, rows)
                self._log("info", f"  Findings store: {counts['new']} new, {counts['seen']} seen before, "
                                  f"{counts['suppressed']} suppressed, {counts['regressed']} regressed")
                self._set_project(i, store=counts)

                if depth in ("review", "verify", "patch"):
                    self._stage_review(i, p, run_id, rows, total)
                if depth in ("verify", "patch"):
                    self._stage_verify(i, p, run_id, total)
                if depth == "patch":
                    self._stage_patch(i, p, run_id, total)

                # Claude summary (project report)
                self._set_project(i, status="triaging", step="Claude is writing PROJECT_SUMMARY.md...")
                self._set(headline=f"Scanning project {i + 1} of {total}: {name} -> writing PROJECT_SUMMARY.md")
                try:
                    md, usage = ai.summarize_project(p, results, self._log, extra=self._triage_context(run_id, name),
                                                     spec=self._specs["report"])
                    self._set_project(i, summary_status="ai", usage=usage)
                    self._log("ok", f"     PROJECT_SUMMARY.md written by {usage['model']} "
                                    f"({usage['input_tokens']} in / {usage['output_tokens']} out)")
                except ai.ClaudeUnavailable as e:
                    md = ai.fallback_project_summary(p, results, str(e))
                    self._set_project(i, summary_status="fallback")
                    self._log("error", f"     Claude unavailable for {name}: {e}. Wrote automated summary instead.")
                (pdir / PROJECT_SUMMARY).write_text(md, encoding="utf-8")
                summaries[name] = md
                self._set_project(i, status="done", step="")
                self._persist(run_path)

            # master aggregator
            self._set(headline=f"Generating {MASTER_REPORT}", master_status="running")
            self._log("info", "All projects processed. Building master report...")
            st = store.stats(run_id)
            triage_md = ("**Triage board for this run** (findings store, deduplicated across runs): "
                         + ", ".join(f"{k}={v}" for k, v in sorted(st["by_status"].items())) + ".")
            try:
                md, usage = ai.master_report(run_id, projects, results_by_project, summaries, self._log, extra=triage_md,
                                             spec=self._specs["report"])
                self._set(master_status="ai")
                self._log("ok", f"{MASTER_REPORT} written by {usage['model']} "
                                f"({usage['input_tokens']} in / {usage['output_tokens']} out)")
            except ai.ClaudeUnavailable as e:
                md = ai.fallback_master_report(run_id, projects, results_by_project, str(e))
                self._set(master_status="fallback")
                self._log("error", f"Claude unavailable for the master report: {e}. Wrote automated report instead.")
            (run_path / MASTER_REPORT).write_text(md, encoding="utf-8")

            totals = {s: sum(sum(r.severity.get(s, 0) for r in rs) for rs in results_by_project.values()) for s in SEVERITIES}
            totals["total"] = sum(totals.values())
            self._set(status="done", headline="Run complete", totals=totals, triage=st["by_status"],
                      finished_at=datetime.now().isoformat(timespec="seconds"), duration_s=round(time.monotonic() - t0, 1))
            self._log("ok", f"Run complete in {round(time.monotonic() - t0, 1)}s. Raw findings: {totals['total']}; "
                            f"triage board: {st['by_status']}.")
        except Exception as e:  # never let one bad project kill the overnight queue silently
            self._set(status="failed", headline="Run failed", error=f"{type(e).__name__}: {e}",
                      finished_at=datetime.now().isoformat(timespec="seconds"), duration_s=round(time.monotonic() - t0, 1))
            self._log("error", f"Run failed: {type(e).__name__}: {e}")
            self._log("error", traceback.format_exc()[-2000:])
        finally:
            self._persist(run_path)


manager = RunManager()
