"""Git worktree isolation for the patch agent, plus PR creation via the gh CLI."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .config import WORKTREES_DIR


def _git(args: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def repo_root(path: Path) -> Path | None:
    try:
        proc = _git(["rev-parse", "--show-toplevel"], path)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return Path(proc.stdout.strip()) if proc.returncode == 0 and proc.stdout.strip() else None


def branch_name(fp: str) -> str:
    return f"fianto/{fp[:8]}"


def prepare_worktree(project_path: Path, project_name: str, fp: str) -> tuple[Path, str]:
    """Create (or recreate) data/worktrees/<project>/<fp8> on branch fianto/<fp8> from the repo's HEAD."""
    root = repo_root(project_path)
    if root is None:
        raise RuntimeError("patching needs a git repository (no .git found); commit the project first")
    branch = branch_name(fp)
    wt = WORKTREES_DIR / project_name / fp[:8]
    if wt.exists():
        _git(["worktree", "remove", "--force", str(wt)], root)
        shutil.rmtree(wt, ignore_errors=True)
    _git(["worktree", "prune"], root)
    wt.parent.mkdir(parents=True, exist_ok=True)
    proc = _git(["worktree", "add", "-B", branch, str(wt), "HEAD"], root)
    if proc.returncode != 0:
        raise RuntimeError(f"git worktree add failed: {proc.stderr.strip()[:400]}")
    # node_modules are not in git; link them so tests/type checks can run in the worktree
    for nm in ("node_modules",):
        src = project_path / nm
        if src.is_dir() and not (wt / nm).exists():
            try:
                (wt / nm).symlink_to(src, target_is_directory=True)
            except OSError:
                pass
    return wt, branch


def commit_worktree(wt: Path, message: str) -> tuple[bool, str]:
    _git(["add", "-A"], wt)
    status = _git(["status", "--porcelain"], wt).stdout.strip()
    if not status:
        return False, "no changes to commit"
    proc = _git(["-c", "user.name=Fianto", "-c", "user.email=fianto@localhost",
                 "commit", "-q", "-m", message], wt)
    if proc.returncode != 0:
        return False, proc.stderr.strip()[:400]
    return True, _git(["rev-parse", "--short", "HEAD"], wt).stdout.strip()


def diff_stat(wt: Path) -> str:
    return _git(["show", "--stat", "--format=", "HEAD"], wt).stdout.strip()


def create_pr(wt: Path, branch: str, title: str, body: str) -> dict:
    """Push the worktree branch and open a PR with gh. Only ever called from an explicit user action."""
    if shutil.which("gh") is None:
        return {"ok": False, "error": "gh CLI is not installed"}
    push = _git(["push", "-u", "origin", branch, "--force-with-lease"], wt, timeout=300)
    if push.returncode != 0:
        return {"ok": False, "error": f"git push failed: {push.stderr.strip()[-600:]}"}
    try:
        proc = subprocess.run(["gh", "pr", "create", "--head", branch, "--title", title, "--body", body],
                              cwd=wt, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "error": f"gh failed: {e}"}
    if proc.returncode != 0:
        err = proc.stderr.strip()
        if "already exists" in err:
            view = subprocess.run(["gh", "pr", "view", branch, "--json", "url", "-q", ".url"], cwd=wt,
                                  capture_output=True, text=True, timeout=60)
            if view.returncode == 0 and view.stdout.strip():
                return {"ok": True, "url": view.stdout.strip(), "note": "PR already existed; branch updated"}
        return {"ok": False, "error": err[-600:] or proc.stdout[-600:]}
    return {"ok": True, "url": proc.stdout.strip().splitlines()[-1]}
