"""Date-isolated file storage under data/run_YYYYMMDD_HHMMSS/<project>/."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .config import DATA_DIR, LEGACY_MASTER_REPORTS, MASTER_REPORT, PROJECT_SUMMARY, RUN_MANIFEST

RUN_ID_RE = re.compile(r"^run_\d{8}_\d{6}$")
RAW_SUFFIXES = {".json", ".log", ".md", ".txt"}


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def new_run_dir(now: Optional[datetime] = None) -> tuple[str, Path]:
    """Provision data/run_YYYYMMDD_HHMMSS/ for a new trigger instance."""
    ensure_data_dir()
    now = now or datetime.now()
    run_id = now.strftime("run_%Y%m%d_%H%M%S")
    path = DATA_DIR / run_id
    path.mkdir(parents=True, exist_ok=False)
    return run_id, path


def unique_project_name(project_path: Path, taken: set[str]) -> str:
    """Folder-safe, unique project name derived from the directory basename."""
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", project_path.name).strip("-.") or "project"
    name, i = base, 2
    while name in taken or name.upper().startswith("MASTER_"):
        name = f"{base}-{i}"
        i += 1
    taken.add(name)
    return name


def master_file(run_path: Path) -> Optional[str]:
    """Name of the master report in a run folder: the current name, or a legacy one for older runs."""
    for name in (MASTER_REPORT, *LEGACY_MASTER_REPORTS):
        if (run_path / name).is_file():
            return name
    return None


def run_dir(run_id: str) -> Optional[Path]:
    if not RUN_ID_RE.match(run_id):
        return None
    path = DATA_DIR / run_id
    return path if path.is_dir() else None


def parse_run_time(run_id: str) -> datetime:
    return datetime.strptime(run_id, "run_%Y%m%d_%H%M%S")


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_runs() -> list[dict]:
    """All historical runs on disk, newest first."""
    ensure_data_dir()
    runs = []
    for d in DATA_DIR.iterdir():
        if not (d.is_dir() and RUN_ID_RE.match(d.name)):
            continue
        manifest = read_json(d / RUN_MANIFEST) or {}
        projects = sorted(p.name for p in d.iterdir() if p.is_dir())
        runs.append(
            {
                "run_id": d.name,
                "time": parse_run_time(d.name),
                "label": parse_run_time(d.name).strftime("%b %d, %Y - %I:%M %p"),
                "projects": projects,
                "has_master": master_file(d) is not None,
                "status": manifest.get("status", "unknown"),
                "totals": manifest.get("totals", {}),
                "duration_s": manifest.get("duration_s"),
            }
        )
    runs.sort(key=lambda r: r["time"], reverse=True)
    return runs


def run_tree(run_id: str) -> Optional[dict]:
    """Sidebar tree for the report hub: master report first, then each project."""
    d = run_dir(run_id)
    if d is None:
        return None
    manifest = read_json(d / RUN_MANIFEST) or {}
    by_name = {p.get("name"): p for p in manifest.get("projects", [])}
    projects = []
    for p in sorted(x for x in d.iterdir() if x.is_dir()):
        raw = sorted(
            f.name for f in p.iterdir() if f.is_file() and f.suffix in RAW_SUFFIXES and f.name != PROJECT_SUMMARY
        )
        meta = by_name.get(p.name, {})
        projects.append(
            {
                "name": p.name,
                "path": meta.get("path", ""),
                "has_summary": (p / PROJECT_SUMMARY).is_file(),
                "summary_file": f"{p.name}/{PROJECT_SUMMARY}",
                "raw_files": [f"{p.name}/{r}" for r in raw],
                "finding_count": meta.get("finding_count"),
                "summary_status": meta.get("summary_status", ""),
            }
        )
    return {
        "run_id": run_id,
        "label": parse_run_time(run_id).strftime("%b %d, %Y - %I:%M %p"),
        "has_master": master_file(d) is not None,
        "master_file": master_file(d) or MASTER_REPORT,
        "projects": projects,
        "status": manifest.get("status", "unknown"),
    }


def resolve_run_file(run_id: str, rel: str) -> Optional[Path]:
    """Resolve a file inside a run directory, refusing anything that escapes it."""
    d = run_dir(run_id)
    if d is None or not rel or rel.startswith(("/", "\\")):
        return None
    target = (d / rel).resolve()
    try:
        target.relative_to(d.resolve())
    except ValueError:
        return None
    if not target.is_file() or target.suffix not in RAW_SUFFIXES:
        return None
    return target
