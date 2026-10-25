"""Confined repository tools handed to the agents.

Every path is resolved inside the sandbox root; anything that escapes is refused. Read-only tools
are used by the review and verification agents; write/run tools only by the patch agent, which
operates in a dedicated git worktree so the user's checkout is never touched.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from anthropic import beta_tool

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", ".expo",
             "coverage", ".turbo", "target", ".cache", "ios/Pods", "android/.gradle", ".fianto_results"}
MAX_TOOL_OUTPUT = 24000
ALLOWED_CHECK_CMDS = {"npm", "npx", "yarn", "pnpm", "node", "pytest", "python", "python3", "semgrep",
                      "cargo", "go", "tsc", "eslint", "ruff", "mypy", "make", "trufflehog", "pip-audit"}


def _clip(text: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


class RepoSandbox:
    def __init__(self, root: Path, writable: bool = False):
        self.root = Path(root).resolve()
        self.writable = writable
        self.writes: list[str] = []
        self.checks: list[dict] = []

    # --------------------------------------------------------------- helpers
    def _resolve(self, rel: str) -> Path:
        p = (self.root / (rel or ".")).resolve()
        try:
            p.relative_to(self.root)
        except ValueError:
            raise ValueError(f"path escapes the repository: {rel}")
        return p

    def _skip(self, p: Path) -> bool:
        return any(part in SKIP_DIRS for part in p.relative_to(self.root).parts)

    # --------------------------------------------------------------- read-only
    def read_file(self, path: str, start_line: int = 1, end_line: int = 0) -> str:
        p = self._resolve(path)
        if not p.is_file():
            return f"ERROR: {path} is not a file"
        if p.stat().st_size > 2_000_000:
            return f"ERROR: {path} is larger than 2 MB; read a line range instead"
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, start_line)
        end = len(lines) if end_line <= 0 else min(end_line, len(lines))
        if end - start > 400:
            end = start + 400
        body = "\n".join(f"{i:5d}| {lines[i - 1]}" for i in range(start, end + 1))
        more = f"\n... ({len(lines) - end} more lines; call again with start_line={end + 1})" if end < len(lines) else ""
        return _clip(f"{path} (lines {start}-{end} of {len(lines)})\n{body}{more}")

    def list_dir(self, path: str = ".", depth: int = 2) -> str:
        base = self._resolve(path)
        if not base.is_dir():
            return f"ERROR: {path} is not a directory"
        out, count = [], 0
        for dirpath, dirnames, filenames in os.walk(base):
            d = Path(dirpath)
            rel_depth = len(d.relative_to(base).parts)
            dirnames[:] = sorted(x for x in dirnames if x not in SKIP_DIRS and not x.startswith("."))
            if rel_depth >= depth:
                dirnames[:] = []
            indent = "  " * rel_depth
            out.append(f"{indent}{d.relative_to(self.root) if d != self.root else '.'}/")
            for f in sorted(filenames)[:60]:
                out.append(f"{indent}  {f}")
                count += 1
            if count > 800:
                out.append("... (listing truncated)")
                break
        return _clip("\n".join(out))

    def grep(self, pattern: str, path: str = ".", glob: str = "", max_results: int = 60) -> str:
        base = self._resolve(path)
        rg = shutil.which("rg")
        if rg:
            cmd = [rg, "-n", "--no-heading", "--color=never", "-m", "50", "--max-columns", "300",
                   "-e", pattern, str(base)]
            for d in SKIP_DIRS:
                cmd += ["-g", f"!{d}"]
            if glob:
                cmd += ["-g", glob]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                return "ERROR: grep timed out"
            lines = proc.stdout.splitlines()
            if proc.returncode == 2 and not lines:
                return f"ERROR: {proc.stderr.strip()[:300]}"
        else:
            try:
                rx = re.compile(pattern)
            except re.error as e:
                return f"ERROR: bad regex: {e}"
            lines = []
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS]
                for fn in filenames:
                    fp = Path(dirpath) / fn
                    if glob and not fp.match(glob):
                        continue
                    try:
                        for i, line in enumerate(fp.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                            if rx.search(line):
                                lines.append(f"{fp}:{i}:{line[:300]}")
                    except OSError:
                        continue
                    if len(lines) > max_results * 3:
                        break
        rel = [ln.replace(str(self.root) + "/", "") for ln in lines[:max_results]]
        extra = f"\n... {len(lines) - max_results} more matches (narrow the pattern or path)" if len(lines) > max_results else ""
        return _clip("\n".join(rel) + extra) if rel else "no matches"

    def git_log(self, path: str = ".", n: int = 15) -> str:
        p = self._resolve(path)
        try:
            proc = subprocess.run(["git", "log", f"-{min(n, 50)}", "--date=short", "--format=%h %ad %an: %s", "--",
                                   str(p.relative_to(self.root))], cwd=self.root, capture_output=True, text=True, timeout=30)
        except (subprocess.TimeoutExpired, OSError) as e:
            return f"ERROR: {e}"
        return _clip(proc.stdout or proc.stderr or "(no history)")

    # --------------------------------------------------------------- write / run (patch agent only)
    def write_file(self, path: str, content: str) -> str:
        if not self.writable:
            return "ERROR: this sandbox is read-only"
        p = self._resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self.writes.append(str(p.relative_to(self.root)))
        return f"wrote {path} ({len(content)} chars)"

    def replace_in_file(self, path: str, old: str, new: str) -> str:
        if not self.writable:
            return "ERROR: this sandbox is read-only"
        p = self._resolve(path)
        if not p.is_file():
            return f"ERROR: {path} is not a file"
        text = p.read_text(encoding="utf-8", errors="replace")
        n = text.count(old)
        if n == 0:
            return "ERROR: old text not found (it must match exactly, including whitespace)"
        if n > 1:
            return f"ERROR: old text occurs {n} times; include more context to make it unique"
        p.write_text(text.replace(old, new, 1), encoding="utf-8")
        self.writes.append(str(p.relative_to(self.root)))
        return f"replaced 1 occurrence in {path}"

    def run_check(self, command: str, timeout: int = 300) -> str:
        if not self.writable:
            return "ERROR: this sandbox is read-only"
        try:
            argv = shlex.split(command)
        except ValueError as e:
            return f"ERROR: {e}"
        if not argv or Path(argv[0]).name not in ALLOWED_CHECK_CMDS:
            return f"ERROR: command not allowed. Allowed: {', '.join(sorted(ALLOWED_CHECK_CMDS))}"
        if any(tok in ("&&", "||", ";", "|", ">", "<", "`", "$(") for tok in argv):
            return "ERROR: shell operators are not allowed"
        env = {**os.environ, "CI": "1", "NO_COLOR": "1", "FORCE_COLOR": "0"}
        try:
            proc = subprocess.run(argv, cwd=self.root, capture_output=True, text=True, timeout=timeout, env=env,
                                  stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            self.checks.append({"command": command, "exit_code": None, "output": "timed out"})
            return f"ERROR: timed out after {timeout}s"
        except OSError as e:
            return f"ERROR: {e}"
        out = (proc.stdout + ("\n--- stderr ---\n" + proc.stderr if proc.stderr.strip() else "")).strip()
        self.checks.append({"command": command, "exit_code": proc.returncode, "output": out[-4000:]})
        return _clip(f"exit code {proc.returncode}\n{out}", 12000)

    def git_diff(self) -> str:
        try:
            subprocess.run(["git", "add", "-A"], cwd=self.root, capture_output=True, timeout=30)
            proc = subprocess.run(["git", "diff", "--cached", "--no-color"], cwd=self.root, capture_output=True,
                                  text=True, timeout=30)
            return proc.stdout
        except (subprocess.TimeoutExpired, OSError) as e:
            return f"ERROR: {e}"


def read_tools(sb: RepoSandbox) -> list:
    """Read-only @beta_tool closures bound to a sandbox."""

    @beta_tool
    def read_file(path: str, start_line: int = 1, end_line: int = 0) -> str:
        """Read a file from the repository with line numbers (max 400 lines per call).

        Args:
            path: Path relative to the repository root.
            start_line: First line to read (1-based).
            end_line: Last line to read; 0 means to the end (capped at 400 lines).
        """
        try:
            return sb.read_file(path, start_line, end_line)
        except ValueError as e:
            return f"ERROR: {e}"

    @beta_tool
    def list_dir(path: str = ".", depth: int = 2) -> str:
        """List directories and files under a path (node_modules, .git etc. are skipped).

        Args:
            path: Directory relative to the repository root.
            depth: How many levels deep to list (1-4).
        """
        try:
            return sb.list_dir(path, max(1, min(depth, 4)))
        except ValueError as e:
            return f"ERROR: {e}"

    @beta_tool
    def grep(pattern: str, path: str = ".", glob: str = "", max_results: int = 60) -> str:
        """Search file contents with a regular expression; returns file:line:text matches.

        Args:
            pattern: Regular expression (ripgrep syntax).
            path: Directory or file to search, relative to the repository root.
            glob: Optional filename glob filter such as "*.ts" or "**/routes/*.js".
            max_results: Maximum matches to return (default 60).
        """
        try:
            return sb.grep(pattern, path, glob, max(1, min(max_results, 200)))
        except ValueError as e:
            return f"ERROR: {e}"

    @beta_tool
    def git_log(path: str = ".", n: int = 15) -> str:
        """Show recent git commits touching a path.

        Args:
            path: File or directory relative to the repository root.
            n: Number of commits (max 50).
        """
        try:
            return sb.git_log(path, n)
        except ValueError as e:
            return f"ERROR: {e}"

    return [read_file, list_dir, grep, git_log]


def write_tools(sb: RepoSandbox) -> list:
    """Mutating tools for the patch agent (sandbox must be a git worktree)."""

    @beta_tool
    def write_file(path: str, content: str) -> str:
        """Create or overwrite a file in the working tree.

        Args:
            path: Path relative to the repository root.
            content: Full file contents.
        """
        try:
            return sb.write_file(path, content)
        except ValueError as e:
            return f"ERROR: {e}"

    @beta_tool
    def replace_in_file(path: str, old: str, new: str) -> str:
        """Replace one exact, unique text snippet in a file with new text (preferred over write_file for edits).

        Args:
            path: Path relative to the repository root.
            old: Exact existing text to replace; must occur exactly once.
            new: Replacement text.
        """
        try:
            return sb.replace_in_file(path, old, new)
        except ValueError as e:
            return f"ERROR: {e}"

    @beta_tool
    def run_check(command: str) -> str:
        """Run a verification command in the working tree (tests, linters, type checks, semgrep, npm audit).

        Only these programs are allowed: npm, npx, yarn, pnpm, node, pytest, python, semgrep, cargo, go, tsc,
        eslint, ruff, mypy, make, trufflehog, pip-audit. No shell operators. 5 minute timeout.

        Args:
            command: The command line, e.g. "npm test" or "npx tsc --noEmit".
        """
        return sb.run_check(command)

    @beta_tool
    def git_diff() -> str:
        """Show the full diff of every change made so far in the working tree."""
        return _clip(sb.git_diff() or "(no changes yet)")

    return [write_file, replace_in_file, run_check, git_diff]
