"""Claude triage & patch pipeline.

Step 1: one call per project -> PROJECT_SUMMARY.md (triaged list + copy-pasteable patches).
Step 2: one final call over all summaries -> the master report.

Every call is streamed (long outputs), uses adaptive thinking, and opts into the
server-side refusal fallback so a safety-classifier decline on scanner evidence is
retried on a fallback model inside the same request.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable

import anthropic

from . import providers
from .config import CLAUDE_MAX_INPUT_CHARS, MASTER_REPORT
from .scanner import SEVERITIES, ScanResult, digest_project

Logger = Callable[[str, str], None]


class ClaudeUnavailable(Exception):
    """Raised when the AI step cannot produce a report; the run continues with a fallback."""


SYSTEM_TRIAGE = """You are a senior application security engineer running Fianto, an internal security review.
You receive the normalized output of automated scanners (TruffleHog, Semgrep, npm audit, cargo audit, pip-audit)
for ONE repository that the team owns and is authorized to test and fix.

Write a Markdown document that will be saved verbatim as PROJECT_SUMMARY.md. Output only the Markdown, no preamble.
Structure:
1. `# <project> — Security Triage` with a 3-5 sentence executive overview and a severity count line.
2. `## Triaged Vulnerability List` — a table: ID | Severity | Tool | Location | Issue | Confidence.
   Re-rank severities using your own judgment (exploitability, exposure, whether a secret is verified live).
   Mark likely false positives explicitly and explain why in one clause.
3. `## Patches` — for each real finding (highest severity first), a subsection with a complete, copy-pasteable fix:
   unified diffs or full replacement snippets in fenced code blocks with the language tag, exact package upgrade
   commands (e.g. `npm install pkg@x.y.z`, `pip install 'pkg>=x.y'`, `cargo update -p pkg`), and one line on how to verify.
4. `## Secrets Rotation` — if any credential was found: which secret, where, rotation steps, and the git history purge
   command. Never print the secret itself; use the redacted form.
5. `## Deferred / Noise` — findings you judged low value, with the reason.
Be concrete and terse. Prefer the smallest correct patch. If a scanner was missing or errored, say so in the overview
and name the install command so the team can rerun it."""

SYSTEM_MASTER = """You are the lead security architect closing out a multi-repository Fianto security review.
You receive (a) a count grid and cross-repo correlations computed directly from scanner output, and
(b) the per-project triage summaries already written by a security engineer.

Write a Markdown document that will be saved verbatim as the master report file. Output only the Markdown.
Structure:
1. `# Fianto Master Report — <run id>` with a crisp executive summary (risk posture in 5-8 sentences).
2. `## Total Vulnerability Count Grid` — reproduce the provided grid (projects x severity, with totals) exactly;
   add a one-line reading of it. Do not invent numbers.
3. `## Cross-Repo Leak Correlations` — same secrets shared across repos (by fingerprint), shared vulnerable
   dependencies, and the same insecure pattern (Semgrep rule) recurring across repos. Explain the blast radius.
4. `## Executive Roadmap` — ordered patch plan: P0 (today), P1 (this week), P2 (this month). Each item names the
   repo(s), the fix, the owner type, and the effort (S/M/L). Put verified live secrets and remotely exploitable
   issues first.
5. `## Rerun Checklist` — scanners that were missing or failed per project, with install/fix commands.
Be decisive and specific; this is read by engineering leadership and the on-call team."""


def _call(system: str, user: str, log: Logger, spec: "providers.ModelSpec | None" = None) -> tuple[str, dict]:
    """One system+user completion on the stage's configured model (Anthropic family or OpenAI-compatible)."""
    spec = spec or providers.resolve("report")
    if spec.family == "openai":
        from .openai_compat import OpenAICompatError, chat
        try:
            res = chat(spec, system, user)
        except OpenAICompatError as e:
            raise ClaudeUnavailable(f"{spec.label}: {e}") from e
        if res.get("finish_reason") == "length":
            log("warn", f"{spec.label} hit its max_tokens; report may be truncated.")
        return res["text"], res["usage"]

    kwargs: dict = spec.anthropic_kwargs()
    kwargs.update(system=system, messages=[{"role": "user", "content": user}])
    try:
        with spec.anthropic_client().beta.messages.stream(**kwargs) as stream:
            msg = stream.get_final_message()
    except anthropic.AuthenticationError as e:
        raise ClaudeUnavailable(
            f"{spec.provider['name']}: authentication failed. Set the API key in Settings or ANTHROPIC_API_KEY in .env."
        ) from e
    except anthropic.NotFoundError as e:
        raise ClaudeUnavailable(f"Model `{spec.id}` not found at {spec.provider['name']}: {e.message}") from e
    except anthropic.BadRequestError as e:
        raise ClaudeUnavailable(f"Bad request for `{spec.id}` (check thinking/fallback toggles in Settings): {e.message}") from e
    except anthropic.RateLimitError as e:
        raise ClaudeUnavailable(f"Rate limited after SDK retries: {e.message}") from e
    except anthropic.APIStatusError as e:
        raise ClaudeUnavailable(f"API error {e.status_code}: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise ClaudeUnavailable(f"Could not reach {spec.provider['name']}: {e}") from e
    except anthropic.AnthropicError as e:
        raise ClaudeUnavailable(f"Claude client error: {e}") from e
    except TypeError as e:  # SDK raises a bare TypeError when no credential source resolves
        if "authentication" in str(e).lower():
            raise ClaudeUnavailable(
                "No Anthropic credentials found. Put ANTHROPIC_API_KEY=sk-ant-... in the .env file (or set the key "
                "on the provider in Settings) and restart the server."
            ) from e
        raise

    if msg.stop_reason == "refusal":
        details = getattr(msg, "stop_details", None)
        why = f" ({details.category}: {details.explanation})" if details else ""
        raise ClaudeUnavailable(f"{spec.id} declined to produce this report{why}.")

    text = "".join(b.text for b in msg.content if b.type == "text").strip()
    if msg.stop_reason == "max_tokens":
        log("warn", f"{spec.id} hit max_tokens={kwargs['max_tokens']}; report may be truncated at the end.")
        text += "\n\n> **Note:** output reached the token limit and may be truncated.\n"
    served_by = getattr(msg, "model", spec.id)
    usage = {"model": served_by, "input_tokens": msg.usage.input_tokens, "output_tokens": msg.usage.output_tokens}
    if served_by != spec.id:
        log("warn", f"Request was served by fallback model {served_by}.")
    return text, usage


# --------------------------------------------------------------------------- step 1

def summarize_project(project: dict, results: list[ScanResult], log: Logger, extra: str = "",
                      spec: "providers.ModelSpec | None" = None) -> tuple[str, dict]:
    spec = spec or providers.resolve("report")
    digest = digest_project(results, max(60000, CLAUDE_MAX_INPUT_CHARS - len(extra)))
    user = (
        f"Project: **{project['name']}**\nLocal path: `{project['path']}`\n"
        f"Detected stack: {', '.join(project.get('stack') or []) or 'unknown'}\n\n"
        + (f"## Agent review and verification results (authoritative; prefer these over raw scanner labels)\n\n{extra}\n\n" if extra else "")
        + f"## Scanner evidence\n\n{digest}\n\n"
        "Produce PROJECT_SUMMARY.md now."
    )
    log("info", f"Report model {spec.id}: triaging {project['name']} "
                f"({sum(len(r.findings) for r in results)} raw findings, {len(user):,} chars of evidence)")
    return _call(SYSTEM_TRIAGE, user, log, spec)


def fallback_project_summary(project: dict, results: list[ScanResult], reason: str) -> str:
    """Deterministic summary written when Claude is unavailable so the report hub is never empty."""
    lines = [f"# {project['name']} — Security Triage (automated, no AI)", "",
             f"> **AI triage unavailable:** {reason}", "",
             f"Local path: `{project['path']}`  ", f"Stack: {', '.join(project.get('stack') or []) or 'unknown'}", "",
             "## Scanner status", "", "| Tool | Status | Findings | Note |", "|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.label} | {r.status} | {r.finding_count if r.finding_count is not None else '-'} | {r.message} |")
    lines += ["", "## Findings (raw, ordered by severity)", ""]
    any_f = False
    for r in results:
        for f in sorted(r.findings, key=lambda x: SEVERITIES.index(x.severity) if x.severity in SEVERITIES else 9):
            any_f = True
            lines.append(f"- **[{f.severity.upper()}]** {f.title} — `{f.location}`" + (f"  \n  {f.detail}" if f.detail else ""))
    if not any_f:
        lines.append("_No findings parsed from the scanners that ran._")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- step 2

def count_grid(projects: list[dict], results_by_project: dict[str, list[ScanResult]]) -> str:
    header = "| Project | " + " | ".join(s.title() for s in SEVERITIES) + " | Total |"
    sep = "|---|" + "---:|" * (len(SEVERITIES) + 1)
    rows = [header, sep]
    col_tot = {s: 0 for s in SEVERITIES}
    for p in projects:
        counts = {s: 0 for s in SEVERITIES}
        for r in results_by_project.get(p["name"], []):
            for s in SEVERITIES:
                counts[s] += r.severity.get(s, 0)
        for s in SEVERITIES:
            col_tot[s] += counts[s]
        rows.append(f"| {p['name']} | " + " | ".join(str(counts[s]) for s in SEVERITIES) + f" | {sum(counts.values())} |")
    rows.append("| **All projects** | " + " | ".join(f"**{col_tot[s]}**" for s in SEVERITIES) + f" | **{sum(col_tot.values())}** |")
    return "\n".join(rows)


def correlations(results_by_project: dict[str, list[ScanResult]]) -> str:
    secrets: dict[str, dict] = defaultdict(lambda: {"projects": set(), "title": "", "locations": []})
    deps: dict[str, set] = defaultdict(set)
    rules: dict[str, set] = defaultdict(set)
    for proj, results in results_by_project.items():
        for r in results:
            for f in r.findings:
                if r.tool == "trufflehog" and f.fingerprint:
                    s = secrets[f.fingerprint]
                    s["projects"].add(proj)
                    s["title"] = f.title
                    s["locations"].append(f"{proj}:{f.location}")
                elif f.package:
                    deps[f.package].add(proj)
                elif r.tool == "semgrep" and f.fingerprint:
                    rules[f.fingerprint].add(proj)
    out = ["### Secrets appearing in more than one repository"]
    shared = [(fp, s) for fp, s in secrets.items() if len(s["projects"]) > 1]
    out += [f"- fingerprint `{fp}` — {s['title']} — in {', '.join(sorted(s['projects']))} ({'; '.join(s['locations'][:6])})"
            for fp, s in shared] or ["- none"]
    out.append("\n### Vulnerable dependencies shared across repositories")
    shared_deps = sorted((d, p) for d, p in deps.items() if len(p) > 1)
    out += [f"- `{d}` — {', '.join(sorted(p))}" for d, p in shared_deps] or ["- none"]
    out.append("\n### Semgrep rules firing in more than one repository")
    shared_rules = sorted((r, p) for r, p in rules.items() if len(p) > 1)
    out += [f"- `{r}` — {', '.join(sorted(p))}" for r, p in shared_rules] or ["- none"]
    return "\n".join(out)


def master_report(run_id: str, projects: list[dict], results_by_project: dict[str, list[ScanResult]],
                  summaries: dict[str, str], log: Logger, extra: str = "",
                  spec: "providers.ModelSpec | None" = None) -> tuple[str, dict]:
    spec = spec or providers.resolve("report")
    grid = count_grid(projects, results_by_project)
    if extra:
        grid += "\n\n" + extra
    corr = correlations(results_by_project)
    budget = CLAUDE_MAX_INPUT_CHARS - len(grid) - len(corr) - 4000
    per = max(4000, budget // max(1, len(summaries)))
    parts = []
    for name, md in summaries.items():
        body = md if len(md) <= per else md[:per] + f"\n\n... (summary truncated for the aggregator; full text in {name}/PROJECT_SUMMARY.md)\n"
        parts.append(f"<<<PROJECT_SUMMARY {name}>>>\n{body}\n<<<END {name}>>>")
    user = (f"Run id: {run_id}\nProjects: {', '.join(p['name'] for p in projects)}\n\n"
            f"## Count grid (computed from raw scanner output)\n\n{grid}\n\n"
            f"## Cross-repo correlations (computed)\n\n{corr}\n\n"
            f"## Per-project summaries\n\n" + "\n\n".join(parts) + "\n\nProduce the master report now.")
    log("info", f"Report model {spec.id}: aggregating {len(summaries)} summaries into the master report")
    return _call(SYSTEM_MASTER, user, log, spec)


def fallback_master_report(run_id: str, projects: list[dict], results_by_project: dict[str, list[ScanResult]],
                           reason: str) -> str:
    lines = [f"# Fianto Master Report — {run_id} (automated, no AI)", "",
             f"> **AI aggregation unavailable:** {reason}", "",
             "## Total Vulnerability Count Grid", "", count_grid(projects, results_by_project), "",
             "## Cross-Repo Leak Correlations", "", correlations(results_by_project), "",
             "## Rerun Checklist", ""]
    for p in projects:
        for r in results_by_project.get(p["name"], []):
            if r.status in ("missing", "error", "timeout"):
                lines.append(f"- {p['name']}: {r.label} — {r.status}: {r.message}")
    if lines[-1] == "":
        lines.append("- all scanners ran")
    return "\n".join(lines) + "\n"
