"""Folder picking for the Configure page.

Two paths to a list of absolute directories:
  * `list_dir`  - JSON directory listing for the in-page multi-select browser (any OS).
  * `native_pick` - macOS Finder "choose folder" dialog with multiple selection (osascript).
"""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

_native_lock = threading.Lock()

REPO_MARKERS = {
    "git": ".git", "node": "package.json", "rust": "Cargo.toml", "python": "requirements.txt",
    "pyproject": "pyproject.toml", "go": "go.mod",
}


def shortcuts() -> list[dict]:
    home = Path.home()
    cands = [home, home / "Documents", home / "Desktop", home / "Developer", home / "code", home / "src",
             home / "Projects", home / "projects", home / "repos", home / "workspace", home / "GitHub", Path("/")]
    out, seen = [], set()
    for c in cands:
        if c.is_dir() and c not in seen:
            seen.add(c)
            out.append({"name": "~" if c == home else (c.name or "/"), "path": str(c)})
    return out


def _markers(p: Path) -> list[str]:
    found = []
    for tag, marker in REPO_MARKERS.items():
        try:
            if (p / marker).exists():
                found.append(tag)
        except OSError:
            pass
    return found


def list_dir(path: Optional[str], show_hidden: bool = False) -> dict:
    base = Path(path).expanduser() if path else Path.home()
    try:
        base = base.resolve()
    except OSError:
        base = Path.home()
    if not base.is_dir():
        return {"error": f"{base} is not a directory", "path": str(base), "parent": str(base.parent),
                "entries": [], "shortcuts": shortcuts()}
    entries = []
    try:
        children = sorted(base.iterdir(), key=lambda p: p.name.lower())
    except PermissionError:
        return {"error": f"permission denied: {base}", "path": str(base), "parent": str(base.parent),
                "entries": [], "shortcuts": shortcuts()}
    for child in children:
        if not show_hidden and child.name.startswith("."):
            continue
        try:
            if not child.is_dir() or child.is_symlink() and not child.resolve().is_dir():
                continue
        except OSError:
            continue
        m = _markers(child)
        entries.append({"name": child.name, "path": str(child), "markers": m, "is_repo": bool(m)})
    return {"path": str(base), "parent": str(base.parent) if base.parent != base else None,
            "entries": entries, "shortcuts": shortcuts(),
            "this_is_repo": bool(_markers(base))}


NATIVE_SUPPORTED = sys.platform == "darwin"

_APPLESCRIPT = '''
set chosen to choose folder with prompt "Select repositories to scan (⌘-click for multiple)" with multiple selections allowed
set out to {}
repeat with f in chosen
    set end of out to POSIX path of f
end repeat
set AppleScript's text item delimiters to linefeed
return out as text
'''


def native_pick(timeout: int = 600) -> dict:
    """Open the macOS Finder folder chooser; returns {"paths": [...]} or {"error": ...}."""
    if not NATIVE_SUPPORTED:
        return {"error": "native folder picker is only available on macOS", "paths": []}
    if not _native_lock.acquire(blocking=False):
        return {"error": "a folder dialog is already open", "paths": []}
    try:
        proc = subprocess.run(["osascript", "-e", _APPLESCRIPT], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "folder dialog timed out", "paths": []}
    except OSError as e:
        return {"error": f"could not launch osascript: {e}", "paths": []}
    finally:
        _native_lock.release()
    if proc.returncode != 0:
        if "canceled" in proc.stderr.lower():
            return {"paths": [], "cancelled": True}
        return {"error": proc.stderr.strip() or "folder dialog failed", "paths": []}
    paths = [ln.rstrip("/") or "/" for ln in proc.stdout.splitlines() if ln.strip()]
    return {"paths": paths}
