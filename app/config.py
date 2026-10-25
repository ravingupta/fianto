"""Central configuration. Everything is overridable through environment variables."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP_NAME = os.environ.get("APP_NAME", "Fianto")
APP_TAGLINE = "Scanners, review agents, adversarial verification and patches for every repo you point it at."


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from .env into os.environ without overriding real env vars."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if key and value and key not in os.environ:
            os.environ[key] = value


_load_dotenv(ROOT / ".env")

# All run data lives under one central directory (data/run_YYYYMMDD_HHMMSS/...).
DATA_DIR = Path(os.environ.get("SCANNER_DATA_DIR", ROOT / "data")).expanduser().resolve()

# Default Claude model for every stage; the Settings page overrides these per stage after first start.
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-opus-5-5")
CLAUDE_EFFORT = os.environ.get("CLAUDE_EFFORT", "high")
CLAUDE_MAX_TOKENS = int(os.environ.get("CLAUDE_MAX_TOKENS", "64000"))
# Server-side refusal fallback: "default" (on) or "off".
CLAUDE_FALLBACKS = os.environ.get("CLAUDE_FALLBACKS", "default")
# Upper bound on the characters of scanner evidence sent per Claude call.
CLAUDE_MAX_INPUT_CHARS = int(os.environ.get("CLAUDE_MAX_INPUT_CHARS", "350000"))

# Agentic stages ------------------------------------------------------------------
# RUN_DEPTH: scan (scanners + reports) | review (+ surface agents) | verify (+ adversarial verifier)
#            | patch (+ auto-patch confirmed findings in git worktrees)
RUN_DEPTH_DEFAULT = os.environ.get("RUN_DEPTH", "verify")
CLAUDE_AGENT_MODEL = os.environ.get("CLAUDE_AGENT_MODEL", CLAUDE_MODEL)
CLAUDE_VERIFY_MODEL = os.environ.get("CLAUDE_VERIFY_MODEL", CLAUDE_MODEL)
CLAUDE_PATCH_MODEL = os.environ.get("CLAUDE_PATCH_MODEL", CLAUDE_MODEL)
AGENT_MAX_ITERATIONS = int(os.environ.get("AGENT_MAX_ITERATIONS", "45"))
VERIFY_MAX_ITERATIONS = int(os.environ.get("VERIFY_MAX_ITERATIONS", "35"))
PATCH_MAX_ITERATIONS = int(os.environ.get("PATCH_MAX_ITERATIONS", "40"))
AGENT_PARALLELISM = int(os.environ.get("AGENT_PARALLELISM", "4"))
VERIFY_MAX_CANDIDATES = int(os.environ.get("VERIFY_MAX_CANDIDATES", "25"))
PATCH_MAX_PER_PROJECT = int(os.environ.get("PATCH_MAX_PER_PROJECT", "3"))
PATCH_MIN_SEVERITY = os.environ.get("PATCH_MIN_SEVERITY", "high")
WORKTREES_DIR = DATA_DIR / "worktrees"

# Per-scanner wall clock timeout in seconds (semgrep on a large monorepo can be slow).
SCANNER_TIMEOUT = int(os.environ.get("SCANNER_TIMEOUT_SECONDS", "1800"))

MASTER_REPORT = "MASTER_REPORT.md"
LEGACY_MASTER_REPORTS = ("MASTER_GAMEDAY_REPORT.md",)  # runs created before the rename
PROJECT_SUMMARY = "PROJECT_SUMMARY.md"
RUN_MANIFEST = "run_manifest.json"
