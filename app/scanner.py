"""Auto-detect project stacks, run security CLIs, normalize their output.

Every scanner is run through `run_command`, which never raises on a non-zero exit code.
Security scanners exit >0 when they find issues, so status is derived from parsing
stdout rather than from the exit code.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]

TOOLS = [
    {"name": "trufflehog", "binary": "trufflehog", "required": True,
     "purpose": "Secrets & leaked credentials (every project)", "install": "brew install trufflehog"},
    {"name": "semgrep", "binary": "semgrep", "required": True,
     "purpose": "SAST logic bugs, --config=auto (every project)", "install": "brew install semgrep"},
    {"name": "npm audit", "binary": "npm", "required": False,
     "purpose": "Node.js dependency CVEs (when package.json exists)", "install": "install Node.js"},
    {"name": "cargo audit", "binary": "cargo-audit", "required": False,
     "purpose": "Rust dependency CVEs (when Cargo.toml exists)", "install": "cargo install cargo-audit"},
    {"name": "pip-audit", "binary": "pip-audit", "required": False,
     "purpose": "Python dependency CVEs (when requirements.txt exists)", "install": "pipx install pip-audit"},
]


def tool_status() -> list[dict]:
    out = []
    for t in TOOLS:
        path = shutil.which(t["binary"])
        out.append({**t, "installed": path is not None, "path": path or ""})
    return out


def detect_stack(project: Path) -> list[str]:
    tags = []
    if (project / "package.json").is_file():
        tags.append("node")
    if (project / "Cargo.toml").is_file():
        tags.append("rust")
    if (project / "requirements.txt").is_file():
        tags.append("python")
    if (project / ".git").exists():
        tags.append("git")
    return tags


@dataclass
class ScanCommand:
    tool: str
    label: str
    argv: list[str]
    cwd: Optional[str]
    output_file: str
    binary: str


@dataclass
class Finding:
    severity: str
    title: str
    location: str
    detail: str = ""
    package: str = ""      # vulnerable dependency name (dep scanners)
    fingerprint: str = ""  # stable key for cross-repo correlation (secrets / rule ids)
    code: str = ""


@dataclass
class ScanResult:
    tool: str
    label: str
    command: str
    status: str = "pending"  # clean | findings | error | missing | timeout
    exit_code: Optional[int] = None
    finding_count: Optional[int] = None
    severity: dict = field(default_factory=dict)
    output_file: Optional[str] = None
    stderr_file: Optional[str] = None
    duration_s: float = 0.0
    message: str = ""
    findings: list[Finding] = field(default_factory=list)

    def to_manifest(self) -> dict:
        d = asdict(self)
        d.pop("findings", None)
        return d


def build_commands(project: Path) -> list[ScanCommand]:
    cmds: list[ScanCommand] = []
    if (project / ".git").exists():
        th = ["trufflehog", "git", f"file://{project}", "--json"]
    else:  # not a git repo: fall back to filesystem mode so secrets are still scanned
        th = ["trufflehog", "filesystem", str(project), "--json"]
    cmds.append(ScanCommand("trufflehog", "TruffleHog (secrets)", th, None, "trufflehog.json", "trufflehog"))
    cmds.append(ScanCommand("semgrep", "Semgrep (SAST)",
                            ["semgrep", "scan", "--config=auto", "--json", str(project)],
                            None, "semgrep.json", "semgrep"))
    if (project / "package.json").is_file():
        cmds.append(ScanCommand("npm-audit", "npm audit (Node deps)", ["npm", "audit", "--json"],
                                str(project), "npm_audit.json", "npm"))
    if (project / "Cargo.toml").is_file():
        cmds.append(ScanCommand("cargo-audit", "cargo audit (Rust deps)", ["cargo", "audit", "--json"],
                                str(project), "cargo_audit.json", "cargo-audit"))
    if (project / "requirements.txt").is_file():
        cmds.append(ScanCommand("pip-audit", "pip-audit (Python deps)",
                                ["pip-audit", "-r", "requirements.txt", "--json"],
                                str(project), "pip_audit.json", "pip-audit"))
    return cmds


def run_command(cmd: ScanCommand, out_dir: Path, timeout: int) -> ScanResult:
    res = ScanResult(tool=cmd.tool, label=cmd.label, command=" ".join(shlex.quote(a) for a in cmd.argv))
    if shutil.which(cmd.binary) is None or shutil.which(cmd.argv[0]) is None:
        res.status = "missing"
        res.message = f"{cmd.binary} is not installed; skipped"
        return res

    env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0", "CI": "1"}
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd.argv, cwd=cmd.cwd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        res.status = "timeout"
        res.duration_s = round(time.monotonic() - start, 1)
        res.message = f"timed out after {timeout}s"
        partial = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        if partial:
            (out_dir / cmd.output_file).write_text(partial, encoding="utf-8")
            res.output_file = cmd.output_file
        return res
    except OSError as e:
        res.status = "error"
        res.message = f"could not start process: {e}"
        return res

    res.duration_s = round(time.monotonic() - start, 1)
    res.exit_code = proc.returncode
    (out_dir / cmd.output_file).write_text(proc.stdout, encoding="utf-8")
    res.output_file = cmd.output_file
    if proc.stderr.strip():
        stderr_name = f"{cmd.tool}.stderr.log"
        (out_dir / stderr_name).write_text(proc.stderr, encoding="utf-8")
        res.stderr_file = stderr_name

    findings = parse_output(cmd.tool, proc.stdout)
    if findings is None:
        res.status = "error"
        tail = proc.stderr.strip().splitlines()[-3:] if proc.stderr.strip() else []
        res.message = f"exit code {proc.returncode}; stdout was not parseable JSON. " + " | ".join(tail)
        return res

    res.findings = findings
    res.finding_count = len(findings)
    res.severity = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    res.status = "findings" if findings else "clean"
    if proc.returncode not in (0, 1):
        res.message = f"exit code {proc.returncode} (output still parsed)"
    return res


# --------------------------------------------------------------------------- parsers

def parse_output(tool: str, stdout: str) -> Optional[list[Finding]]:
    try:
        if tool == "trufflehog":
            return _parse_trufflehog(stdout)
        if tool == "semgrep":
            return _parse_semgrep(stdout)
        if tool == "npm-audit":
            return _parse_npm(stdout)
        if tool == "cargo-audit":
            return _parse_cargo(stdout)
        if tool == "pip-audit":
            return _parse_pip_audit(stdout)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    return None


def _json_or_none(stdout: str):
    text = stdout.strip()
    if not text:
        return None
    # some tools print a banner before the JSON document
    for start in (text.find("{"), text.find("[")):
        if start >= 0:
            try:
                return json.loads(text[start:])
            except ValueError:
                continue
    return None


def _redact(raw: str, tool_redacted: str) -> str:
    """Never trust the scanner's own redaction: show at most a 4-char prefix of the secret."""
    src = raw or tool_redacted or ""
    if not src:
        return "***"
    return src[:4] + "*" * min(max(len(src) - 4, 4), 12) + f" ({len(src)} chars)"


def _parse_trufflehog(stdout: str) -> Optional[list[Finding]]:
    findings: list[Finding] = []
    saw_json = False
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        saw_json = True
        if "DetectorName" not in obj:
            continue  # log line, not a result
        meta = (obj.get("SourceMetadata") or {}).get("Data") or {}
        src = meta.get("Git") or meta.get("Filesystem") or next(iter(meta.values()), {}) or {}
        location = f"{src.get('file', '?')}:{src.get('line', '?')}"
        if src.get("commit"):
            location += f" @ {str(src['commit'])[:10]}"
        raw = obj.get("Raw") or ""
        fp = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16] if raw else ""
        verified = bool(obj.get("Verified"))
        findings.append(Finding(
            severity="critical" if verified else "high",
            title=f"{obj.get('DetectorName')} credential ({'VERIFIED live' if verified else 'unverified'})",
            location=location,
            detail=f"redacted={_redact(raw, obj.get('Redacted') or '')}; fingerprint={fp}",
            fingerprint=fp,
        ))
    if not saw_json and stdout.strip():
        return None  # output present but not NDJSON -> treat as scanner error
    return findings


_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _parse_semgrep(stdout: str) -> Optional[list[Finding]]:
    doc = _json_or_none(stdout)
    if not isinstance(doc, dict) or "results" not in doc:
        return None
    findings = []
    for r in doc.get("results", []):
        extra = r.get("extra") or {}
        md = extra.get("metadata") or {}
        cwe = md.get("cwe")
        cwe = ", ".join(cwe) if isinstance(cwe, list) else (cwe or "")
        findings.append(Finding(
            severity=_SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), "medium"),
            title=str(r.get("check_id", "semgrep rule")),
            location=f"{r.get('path', '?')}:{(r.get('start') or {}).get('line', '?')}",
            detail=(str(extra.get("message", "")).strip()[:600] + (f" [{cwe}]" if cwe else "")),
            fingerprint=str(r.get("check_id", "")),
            code=str(extra.get("lines", ""))[:400],
        ))
    return findings


_NPM_SEV = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "info"}


def _parse_npm(stdout: str) -> Optional[list[Finding]]:
    doc = _json_or_none(stdout)
    if not isinstance(doc, dict):
        return None
    findings = []
    if "vulnerabilities" in doc:  # npm >= 7
        for name, v in (doc.get("vulnerabilities") or {}).items():
            titles = [x.get("title") for x in v.get("via", []) if isinstance(x, dict) and x.get("title")]
            urls = [x.get("url") for x in v.get("via", []) if isinstance(x, dict) and x.get("url")]
            fix = v.get("fixAvailable")
            if isinstance(fix, dict):
                fix_txt = f"fix: upgrade {fix.get('name')} to {fix.get('version')}" + (
                    " (semver-major)" if fix.get("isSemVerMajor") else "")
            else:
                fix_txt = "fix available via npm audit fix" if fix else "no automatic fix"
            findings.append(Finding(
                severity=_NPM_SEV.get(str(v.get("severity", "")).lower(), "medium"),
                title="; ".join(titles) or f"vulnerable dependency {name}",
                location=f"{name}@{v.get('range', '?')}" + (" (direct)" if v.get("isDirect") else " (transitive)"),
                detail=f"{fix_txt}. {' '.join(urls[:3])}".strip(),
                package=name,
                fingerprint=f"npm:{name}",
            ))
        return findings
    if "advisories" in doc:  # npm 6
        for adv in (doc.get("advisories") or {}).values():
            findings.append(Finding(
                severity=_NPM_SEV.get(str(adv.get("severity", "")).lower(), "medium"),
                title=adv.get("title", "advisory"),
                location=f"{adv.get('module_name')}@{adv.get('vulnerable_versions', '?')}",
                detail=f"patched: {adv.get('patched_versions', '?')}. {adv.get('url', '')}",
                package=adv.get("module_name", ""),
                fingerprint=f"npm:{adv.get('module_name', '')}",
            ))
        return findings
    if doc.get("error"):
        return None
    return []


def _parse_cargo(stdout: str) -> Optional[list[Finding]]:
    doc = _json_or_none(stdout)
    if not isinstance(doc, dict) or "vulnerabilities" not in doc:
        return None
    findings = []
    for v in (doc.get("vulnerabilities") or {}).get("list", []):
        adv = v.get("advisory") or {}
        pkg = v.get("package") or {}
        patched = ", ".join((v.get("versions") or {}).get("patched", [])) or "none listed"
        findings.append(Finding(
            severity="high",
            title=f"{adv.get('id', 'RUSTSEC')}: {adv.get('title', '')}",
            location=f"{pkg.get('name')}@{pkg.get('version')}",
            detail=f"patched versions: {patched}. {adv.get('url', '')}",
            package=str(pkg.get("name", "")),
            fingerprint=f"cargo:{pkg.get('name', '')}",
        ))
    for kind, items in ((doc.get("warnings") or {}).items()):
        for w in items or []:
            pkg = w.get("package") or {}
            adv = w.get("advisory") or {}
            findings.append(Finding(
                severity="info",
                title=f"{kind}: {adv.get('title') or pkg.get('name')}",
                location=f"{pkg.get('name')}@{pkg.get('version')}",
                detail=adv.get("url", ""),
                package=str(pkg.get("name", "")),
                fingerprint=f"cargo:{pkg.get('name', '')}",
            ))
    return findings


def _parse_pip_audit(stdout: str) -> Optional[list[Finding]]:
    doc = _json_or_none(stdout)
    if isinstance(doc, dict):
        deps = doc.get("dependencies")
    elif isinstance(doc, list):
        deps = doc
    else:
        return None
    if deps is None:
        return None
    findings = []
    for d in deps:
        for v in d.get("vulns", []) or []:
            fixes = ", ".join(v.get("fix_versions", []) or []) or "no fix version listed"
            aliases = ", ".join(v.get("aliases", []) or [])
            findings.append(Finding(
                severity="medium",  # pip-audit reports no severity; treat as medium until triaged
                title=f"{v.get('id', 'PYSEC')}{f' ({aliases})' if aliases else ''}",
                location=f"{d.get('name')}=={d.get('version')}",
                detail=f"fix versions: {fixes}. {str(v.get('description', ''))[:400]}",
                package=str(d.get("name", "")),
                fingerprint=f"pip:{d.get('name', '')}",
            ))
    return findings


# --------------------------------------------------------------------------- digests for Claude

def digest_scan(res: ScanResult, max_items: int) -> str:
    """Compact, model-readable evidence for one scanner result."""
    head = f"### {res.label}\n- command: `{res.command}`\n- status: {res.status}"
    if res.exit_code is not None:
        head += f" (exit code {res.exit_code})"
    if res.message:
        head += f"\n- note: {res.message}"
    if res.status in ("missing", "error", "timeout"):
        return head + "\n"
    head += f"\n- findings: {res.finding_count}  " + ", ".join(f"{k}={v}" for k, v in res.severity.items() if v)
    lines = [head]
    ordered = sorted(res.findings, key=lambda f: SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 9)
    for i, f in enumerate(ordered[:max_items], 1):
        entry = f"{i}. [{f.severity.upper()}] {f.title} — {f.location}"
        if f.detail:
            entry += f"\n   {f.detail}"
        if f.code:
            entry += "\n   ```\n   " + f.code.strip().replace("\n", "\n   ") + "\n   ```"
        lines.append(entry)
    omitted = len(ordered) - max_items
    if omitted > 0:
        lines.append(f"... {omitted} lower-severity findings omitted from this digest (all are in the raw JSON).")
    return "\n".join(lines) + "\n"


def digest_project(results: list[ScanResult], max_chars: int) -> str:
    """Digest all scanners for a project, shrinking the per-tool item cap until it fits max_chars."""
    cap = 200
    while True:
        text = "\n".join(digest_scan(r, cap) for r in results)
        if len(text) <= max_chars or cap <= 10:
            return text
        cap = max(10, cap // 2)
