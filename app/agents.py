"""Fianto agent stages built on the Anthropic SDK tool runner.

  review_surface  - one agent per attack surface with read-only repo tools; submits structured findings
  verify_project  - adversarial verifier that tries to disprove candidate findings against the code
  patch_finding   - patch agent working in an isolated git worktree, then commits the fix
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

import anthropic
from anthropic import beta_tool

from . import patches, providers
from .config import AGENT_MAX_ITERATIONS, PATCH_MAX_ITERATIONS, ROOT, VERIFY_MAX_ITERATIONS
from .claude_pipeline import ClaudeUnavailable
from .repotools import RepoSandbox, read_tools, write_tools
from .scanner import SEVERITIES, ScanResult
from .store import make_fingerprint

Logger = Callable[[str, str], None]
SURFACES = ["web", "mobile", "api", "infra"]
PLAYBOOKS = ROOT / "app" / "playbooks"


# --------------------------------------------------------------------------- surface detection

def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def detect_surfaces(project: Path) -> list[str]:
    """Infra always applies; code surfaces come from the dependency manifests."""
    surfaces: list[str] = []
    pkg = _read_json(project / "package.json")
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    if any(d in deps for d in ("react-native", "expo")) or (project / "app.json").is_file() and "expo" in deps:
        surfaces.append("mobile")
    if any(d in deps for d in ("express", "fastify", "koa", "@nestjs/core", "hapi", "@hapi/hapi", "serverless-http")):
        surfaces.append("api")
    if any(d in deps for d in ("react", "vue", "svelte", "next", "vite", "react-scripts", "@angular/core")) \
            and "mobile" not in surfaces:
        surfaces.append("web")
    req = ""
    for name in ("requirements.txt", "pyproject.toml"):
        if (project / name).is_file():
            try:
                req += (project / name).read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                pass
    if any(k in req for k in ("fastapi", "flask", "django", "starlette", "aiohttp")):
        surfaces.append("api")
    if (project / "Cargo.toml").is_file() or (project / "go.mod").is_file():
        surfaces.append("api")
    if (project / "amplify").is_dir() and "api" not in surfaces:
        surfaces.append("api")  # Lambda handlers under amplify/backend/function
    if not surfaces and (project / "package.json").is_file():
        surfaces.append("api")
    surfaces.append("infra")
    return list(dict.fromkeys(surfaces))


def classify_scanner_surface(tool: str, file: str, project_surfaces: list[str]) -> str:
    f = (file or "").lower()
    if tool in ("npm-audit", "cargo-audit", "pip-audit"):
        return "infra"
    if any(k in f for k in (".github/", "dockerfile", "docker-compose", "cdk/", "terraform", ".tf", "cloudformation",
                            "k8s/", "helm/", ".gitlab-ci", "jenkinsfile", "buildspec")):
        return "infra"
    if tool == "trufflehog":
        return "infra"
    code = [s for s in project_surfaces if s != "infra"]
    if "amplify/backend" in f and "api" in project_surfaces:
        return "api"
    return code[0] if code else "infra"


# --------------------------------------------------------------------------- scanner -> store rows

def scanner_rows(project: dict, results: list[ScanResult]) -> list[dict]:
    rows = []
    for r in results:
        for f in r.findings:
            file = f.location.split(":")[0] if r.tool in ("trufflehog", "semgrep") else {
                "npm-audit": "package.json", "cargo-audit": "Cargo.toml", "pip-audit": "requirements.txt"}.get(r.tool, "")
            m = re.search(r":(\d+)", f.location)
            line = int(m.group(1)) if m else None
            if r.tool == "trufflehog":
                rule = f"secret:{f.fingerprint}"
            elif r.tool == "semgrep":
                rule = f.fingerprint
            else:
                rule = f"dep:{f.package}"
            rows.append({
                "fingerprint": make_fingerprint(project["name"], r.tool, rule, file, f.title),
                "project": project["name"], "project_path": project["path"],
                "surface": classify_scanner_surface(r.tool, file, project.get("surfaces", [])),
                "source": r.tool, "tool": r.tool, "severity": f.severity, "title": f.title,
                "location": f.location, "file": file, "line": line, "rule": rule, "package": f.package,
                "detail": f.detail, "evidence": f.code, "confidence": 0.9 if (r.tool == "trufflehog" and "VERIFIED" in f.title) else 0.5,
            })
    return rows


# --------------------------------------------------------------------------- shared runner

def _short(v: dict) -> str:
    s = json.dumps(v, default=str)
    return s if len(s) <= 90 else s[:87] + "..."


def run_agent(*, spec: providers.ModelSpec, system: str, user: str, tools: list, max_iterations: int,
              log: Logger, label: str) -> dict:
    """Agentic loop on the stage's model: Anthropic tool runner, or OpenAI-compatible function calling."""
    if spec.family == "openai":
        from .openai_compat import OpenAICompatError, run_tools
        try:
            return run_tools(spec, system, user, tools, max_iterations, log, label)
        except OpenAICompatError as e:
            raise ClaudeUnavailable(f"{spec.label}: {e}") from e

    kwargs: dict = spec.anthropic_kwargs()
    kwargs["max_tokens"] = min(int(kwargs.get("max_tokens") or 16000), 16000)  # per turn; non-streaming
    kwargs.update(
        system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}], tools=tools, max_iterations=max_iterations,
        cache_control={"type": "ephemeral"},
    )
    model = spec.id
    usage = {"model": model, "input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0,
             "cache_creation_input_tokens": 0}
    last = None
    turns = 0
    try:
        runner = spec.anthropic_client().beta.messages.tool_runner(**kwargs)
        for message in runner:
            turns += 1
            last = message
            usage["input_tokens"] += message.usage.input_tokens
            usage["output_tokens"] += message.usage.output_tokens
            usage["cache_read_input_tokens"] += getattr(message.usage, "cache_read_input_tokens", 0) or 0
            usage["cache_creation_input_tokens"] += getattr(message.usage, "cache_creation_input_tokens", 0) or 0
            calls = [b for b in message.content if b.type == "tool_use"]
            if calls:
                log("cmd", f"    [{label}] " + "; ".join(f"{b.name}({_short(b.input)})" for b in calls)[:400])
            if message.stop_reason == "refusal":
                details = getattr(message, "stop_details", None)
                raise ClaudeUnavailable(f"model declined ({getattr(details, 'category', '?')}): {getattr(details, 'explanation', '')}")
    except anthropic.AuthenticationError as e:
        raise ClaudeUnavailable(f"{spec.provider['name']}: authentication failed; set the key in Settings or .env") from e
    except anthropic.NotFoundError as e:
        raise ClaudeUnavailable(f"model `{model}` not found at {spec.provider['name']}: {e.message}") from e
    except anthropic.BadRequestError as e:
        raise ClaudeUnavailable(f"bad request for `{model}` (check thinking/fallback toggles in Settings): {e.message}") from e
    except anthropic.RateLimitError as e:
        raise ClaudeUnavailable(f"rate limited after SDK retries: {e.message}") from e
    except anthropic.APIStatusError as e:
        raise ClaudeUnavailable(f"API error {e.status_code}: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise ClaudeUnavailable(f"could not reach {spec.provider['name']}: {e}") from e
    except anthropic.AnthropicError as e:
        raise ClaudeUnavailable(f"Claude client error: {e}") from e
    except TypeError as e:
        if "authentication" in str(e).lower():
            raise ClaudeUnavailable("No Anthropic credentials found; put ANTHROPIC_API_KEY in .env or set the key in Settings") from e
        raise
    text = "".join(b.text for b in (last.content if last else []) if b.type == "text").strip()
    hit_cap = bool(last and any(b.type == "tool_use" for b in last.content))
    if hit_cap:
        log("warn", f"    [{label}] stopped at the {max_iterations}-turn cap; findings submitted so far are kept")
    if last and last.model != model:
        usage["model"] = last.model
        log("warn", f"    [{label}] served by fallback model {last.model}")
    return {"text": text, "usage": usage, "turns": turns, "hit_cap": hit_cap}


def _playbook(surface: str) -> str:
    common = (PLAYBOOKS / "_common.md").read_text(encoding="utf-8")
    specific = (PLAYBOOKS / f"{surface}.md").read_text(encoding="utf-8")
    return common + "\n\n" + specific


def _leads_text(leads: list[dict], cap: int = 50) -> str:
    if not leads:
        return "(no scanner leads for this surface)"
    leads = sorted(leads, key=lambda f: (SEVERITIES.index(f["severity"]) if f["severity"] in SEVERITIES else 9, -float(f.get("confidence") or 0)))
    out = [f"- [{f['severity'].upper()}] {f['title']} — {f.get('location') or f.get('file')} ({f['source']})"
           + (f"\n  {str(f.get('detail'))[:220]}" if f.get("detail") else "") for f in leads[:cap]]
    if len(leads) > cap:
        out.append(f"... {len(leads) - cap} more lower-priority leads omitted")
    return "\n".join(out)


# --------------------------------------------------------------------------- stage 2: surface review

def review_surface(project: dict, surface: str, leads: list[dict], log: Logger,
                   spec: providers.ModelSpec | None = None) -> dict:
    spec = spec or providers.resolve("agent")
    sb = RepoSandbox(Path(project["path"]))
    found: list[dict] = []

    @beta_tool
    def submit_finding(title: str, severity: str, category: str, file: str, line: int, exploit_path: str,
                       evidence: str, patch_hint: str, confidence: float, package: str = "") -> str:
        """Record one confirmed security finding for this repository.

        Args:
            title: One-line description, e.g. "IDOR on GET /orders/:id (no ownership check)".
            severity: One of critical, high, medium, low, info (impact x exploitability, your judgment).
            category: Short kebab-case class such as idor, sqli, xss, ssrf, secret-exposure, auth-bypass, supply-chain, container-root, vulnerable-dependency, misconfig.
            file: Path relative to the repository root where the issue lives.
            line: Line number of the primary evidence (0 if not applicable).
            exploit_path: How an attacker reaches it: input -> code path -> impact, and what access they need.
            evidence: The exact code or config snippet (with file:line) that proves it.
            patch_hint: Concrete fix: what to change, package version to upgrade to, config to set.
            confidence: 0.0-1.0 that this is real and exploitable.
            package: Vulnerable dependency name, if this is a dependency finding.
        """
        sev = severity.lower().strip()
        if sev not in SEVERITIES:
            return f"ERROR: severity must be one of {SEVERITIES}"
        try:
            sb._resolve(file)
        except ValueError:
            return "ERROR: file must be a path inside the repository"
        exists = (sb.root / file).exists()
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
        rule = f"{category.lower().strip()}:{slug}"
        found.append({
            "fingerprint": make_fingerprint(project["name"], "agent", rule, file, title),
            "project": project["name"], "project_path": project["path"], "surface": surface,
            "source": "agent", "tool": f"agent:{surface}", "severity": sev, "title": title.strip(),
            "location": f"{file}:{line}" if line else file, "file": file, "line": line or None,
            "rule": rule, "package": package, "detail": exploit_path, "evidence": evidence,
            "exploit_path": exploit_path, "patch_hint": patch_hint,
            "confidence": max(0.0, min(1.0, float(confidence))),
        })
        log("ok", f"    [{surface}] finding #{len(found)} [{sev}] {title[:90]}" + ("" if exists else " (file not found!)"))
        return f"recorded finding #{len(found)}" + ("" if exists else " — warning: that file does not exist in the checkout")

    user = (f"Repository: **{project['name']}** at `{project['path']}`\n"
            f"Detected surfaces for this repo: {', '.join(project.get('surfaces', []))}. You own the **{surface}** surface.\n"
            f"Stack markers: {', '.join(project.get('stack') or []) or 'unknown'}\n\n"
            f"## Scanner leads for this surface\n{_leads_text(leads)}\n\n"
            "Start by orienting in the tree, then investigate. Submit findings with submit_finding as you confirm them, "
            "and finish with a short summary.")
    log("info", f"  Agent [{surface}] reviewing {project['name']} with {len(leads)} leads ({spec.id})")
    res = run_agent(spec=spec, system=_playbook(surface), user=user, tools=read_tools(sb) + [submit_finding],
                    max_iterations=AGENT_MAX_ITERATIONS, log=log, label=surface)
    res["findings"] = found
    return res


# --------------------------------------------------------------------------- stage 3: adversarial verification

VERIFY_SYSTEM = """You are the adversarial verifier in Fianto, an internal security review. Other reviewers and scanners produced candidate
findings for a repository the team owns. Your job is to try to DISPROVE each one against the actual code using
read_file, list_dir, grep and git_log, and then give a verdict with submit_verdict:

- confirmed: you traced attacker-controlled input to the vulnerable sink (or saw the secret/config) and the
  impact is real. State the precise exploit path and set the severity you believe is right.
- false_positive: the code is not reachable, input is not attacker-controlled, the package is dev-only or the
  vulnerable function is never called, the value is a placeholder/test fixture, or a mitigating control exists.
  Explain exactly what you saw.
- needs_review: cannot be settled from static code alone (needs runtime, credentials, infra context). Say what
  a human must check.

Be rigorous and economical: ~2-6 tool calls per candidate, more only for critical ones. For vulnerable-dependency
candidates, check whether the package is in dependencies vs devDependencies and whether it is imported on a
request path. Submit a verdict for EVERY candidate fingerprint, then reply with a two-sentence summary."""


def verify_project(project: dict, candidates: list[dict], log: Logger,
                   spec: providers.ModelSpec | None = None) -> dict:
    spec = spec or providers.resolve("verify")
    sb = RepoSandbox(Path(project["path"]))
    verdicts: dict[str, dict] = {}
    valid = {c["fingerprint"] for c in candidates}

    @beta_tool
    def submit_verdict(fingerprint: str, verdict: str, reasoning: str, severity: str = "", exploit_path: str = "") -> str:
        """Record the verdict for one candidate finding.

        Args:
            fingerprint: The candidate's fingerprint exactly as listed.
            verdict: One of confirmed, false_positive, needs_review.
            reasoning: What you checked in the code and why it leads to this verdict (cite file:line).
            severity: Your corrected severity (critical/high/medium/low/info) when confirmed; empty to keep.
            exploit_path: For confirmed findings, the precise attacker path; empty otherwise.
        """
        if fingerprint not in valid:
            return "ERROR: unknown fingerprint; use one from the candidate list"
        v = verdict.lower().strip()
        if v not in ("confirmed", "false_positive", "needs_review"):
            return "ERROR: verdict must be confirmed, false_positive or needs_review"
        sev = severity.lower().strip()
        verdicts[fingerprint] = {"verdict": v, "reasoning": reasoning, "severity": sev if sev in SEVERITIES else "",
                                 "exploit_path": exploit_path, "model": spec.id}
        log({"confirmed": "warn", "false_positive": "skip", "needs_review": "info"}[v],
            f"    [verify] {v}: {next(c['title'] for c in candidates if c['fingerprint'] == fingerprint)[:80]}")
        return f"recorded ({len(verdicts)}/{len(valid)})"

    lines = []
    for c in candidates:
        lines.append(f"### {c['fingerprint']} — [{c['severity'].upper()}] {c['title']}\n"
                     f"- source: {c['source']} ({c.get('surface')}), confidence {c.get('confidence')}\n"
                     f"- location: {c.get('location') or c.get('file')}\n"
                     + (f"- claimed exploit path: {c['exploit_path'][:600]}\n" if c.get("exploit_path") else "")
                     + (f"- evidence: {str(c['evidence'])[:500]}\n" if c.get("evidence") else "")
                     + (f"- detail: {str(c['detail'])[:400]}\n" if c.get("detail") and c.get("detail") != c.get("exploit_path") else ""))
    user = (f"Repository: **{project['name']}** at `{project['path']}` (surfaces: {', '.join(project.get('surfaces', []))})\n\n"
            f"## {len(candidates)} candidate findings\n\n" + "\n".join(lines) +
            "\n\nVerify each one against the code and submit a verdict for every fingerprint.")
    log("info", f"  Verifier checking {len(candidates)} candidates in {project['name']} ({spec.id})")
    res = run_agent(spec=spec, system=VERIFY_SYSTEM, user=user, tools=read_tools(sb) + [submit_verdict],
                    max_iterations=VERIFY_MAX_ITERATIONS, log=log, label="verify")
    res["verdicts"] = verdicts
    return res


# --------------------------------------------------------------------------- stage 4: patch

PATCH_SYSTEM = """You are a senior engineer fixing one confirmed security finding in an isolated git worktree of a
repository the team owns. Tools: read_file, list_dir, grep, git_log, replace_in_file, write_file, run_check, git_diff.

Rules
- Make the smallest correct fix. No refactors, no formatting churn, no unrelated changes.
- Prefer replace_in_file with exact snippets. Read the surrounding code first so the edit is correct and idiomatic.
- For dependency fixes edit the manifest (and lockfile only via run_check "npm install <pkg>@<ver> --package-lock-only"
  or equivalent) rather than hand-editing lockfiles.
- Verify with the narrowest useful check (a targeted test, "npx tsc --noEmit", a linter, "semgrep --config=auto <file>").
  Full test suites are fine if they run in under a few minutes. Do not spend turns fighting unrelated failures.
- Never commit secrets, never print secret values, never weaken existing security checks.
- Finish by calling submit_patch with a summary suitable for a pull request description, then reply briefly."""


def patch_finding(project: dict, finding: dict, log: Logger, spec: providers.ModelSpec | None = None) -> dict:
    spec = spec or providers.resolve("patch")
    fp = finding["fingerprint"]
    wt, branch = patches.prepare_worktree(Path(project["path"]), project["name"], fp)
    sb = RepoSandbox(wt, writable=True)
    submitted: dict = {}

    @beta_tool
    def submit_patch(summary: str, files_changed: str, verification: str, residual_risk: str = "") -> str:
        """Record the finished patch.

        Args:
            summary: PR-ready description of the vulnerability and the fix (3-8 sentences, markdown ok).
            files_changed: Comma-separated list of files you changed.
            verification: Which checks you ran and their results.
            residual_risk: Anything the reviewer must still do (rotate a key, deploy config, follow-up refactor).
        """
        submitted.update({"summary": summary, "files_changed": files_changed, "verification": verification,
                          "residual_risk": residual_risk})
        return "recorded"

    user = (f"Repository worktree: `{wt}` (branch {branch}), project **{project['name']}**\n\n"
            f"## Finding to fix\n- Title: {finding['title']}\n- Severity: {finding['severity']}\n"
            f"- Location: {finding.get('location') or finding.get('file')}\n"
            f"- Exploit path: {finding.get('exploit_path') or finding.get('detail')}\n"
            f"- Evidence: {str(finding.get('evidence'))[:1200]}\n- Suggested fix: {finding.get('patch_hint') or '(none given)'}\n"
            + (f"- Verifier notes: {finding['verification'].get('reasoning', '')[:800]}\n" if isinstance(finding.get("verification"), dict) else "")
            + "\nImplement the fix, verify it, call submit_patch, and reply briefly.")
    log("info", f"  Patch agent fixing [{finding['severity']}] {finding['title'][:80]} in {branch} ({spec.id})")
    res = run_agent(spec=spec, system=PATCH_SYSTEM, user=user,
                    tools=read_tools(sb) + write_tools(sb) + [submit_patch],
                    max_iterations=PATCH_MAX_ITERATIONS, log=log, label="patch")
    diff = sb.git_diff()
    committed, info = patches.commit_worktree(wt, f"security: {finding['title'][:70]}\n\nFianto finding {fp}")
    status = "patched" if committed else "no_changes"
    if committed:
        log("ok", f"    committed {info} on {branch} ({len(diff.splitlines())} diff lines)")
    else:
        log("warn", f"    patch agent made no committable changes: {info}")
    return {"status": status, "branch": branch, "worktree": str(wt), "commit": info if committed else "",
            "diff": diff[:200000], "stat": patches.diff_stat(wt) if committed else "",
            "summary": submitted.get("summary") or res["text"], "files_changed": submitted.get("files_changed", ""),
            "verification": submitted.get("verification", ""), "residual_risk": submitted.get("residual_risk", ""),
            "checks": sb.checks, "usage": res["usage"], "turns": res["turns"], "pr": None}
