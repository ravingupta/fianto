"""Persistent findings store (SQLite): one row per fingerprint, deduplicated across runs.

Status lifecycle: new -> needs_review -> confirmed -> fixed, or false_positive / accepted_risk
(both act as suppressions: a finding that reappears in a later run keeps that status).
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from .config import DATA_DIR

STATUSES = ["new", "needs_review", "confirmed", "false_positive", "accepted_risk", "fixed"]
SUPPRESSED = {"false_positive", "accepted_risk"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  project TEXT NOT NULL, project_path TEXT DEFAULT '',
  surface TEXT DEFAULT '', source TEXT NOT NULL, tool TEXT DEFAULT '',
  severity TEXT DEFAULT 'medium', title TEXT NOT NULL, location TEXT DEFAULT '',
  file TEXT DEFAULT '', line INTEGER, rule TEXT DEFAULT '', package TEXT DEFAULT '',
  detail TEXT DEFAULT '', evidence TEXT DEFAULT '', exploit_path TEXT DEFAULT '',
  patch_hint TEXT DEFAULT '', confidence REAL DEFAULT 0.5,
  status TEXT DEFAULT 'new', note TEXT DEFAULT '',
  verification TEXT DEFAULT '', patch TEXT DEFAULT '',
  first_run TEXT, last_run TEXT, run_count INTEGER DEFAULT 1,
  created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(last_run);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT, ts TEXT, event TEXT, detail TEXT
);
"""


def _db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATA_DIR / "findings.db", timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _norm_file(file: str) -> str:
    return re.sub(r"^\./", "", (file or "").strip()).lower()


def make_fingerprint(project: str, source: str, rule: str, file: str, title: str = "") -> str:
    """Stable identity: same project + source + rule + file (line numbers excluded) => same finding."""
    key = "|".join([project, source, (rule or "").lower().strip(), _norm_file(file),
                    "" if rule else re.sub(r"\W+", " ", (title or "").lower()).strip()[:80]])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _row_to_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("verification", "patch"):
        try:
            d[k] = json.loads(d[k]) if d[k] else None
        except ValueError:
            d[k] = None
    return d


def upsert(run_id: str, items: Iterable[dict]) -> dict:
    """Insert or refresh findings for a run. Returns counts {new, seen, suppressed, regressed}."""
    counts = {"new": 0, "seen": 0, "suppressed": 0, "regressed": 0}
    now = _now()
    with _lock, _db() as conn:
        for it in items:
            fp = it["fingerprint"]
            row = conn.execute("SELECT status, run_count FROM findings WHERE fingerprint=?", (fp,)).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO findings (fingerprint, project, project_path, surface, source, tool, severity, title,
                       location, file, line, rule, package, detail, evidence, exploit_path, patch_hint, confidence,
                       status, first_run, last_run, run_count, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
                    (fp, it["project"], it.get("project_path", ""), it.get("surface", ""), it["source"],
                     it.get("tool", ""), it.get("severity", "medium"), it["title"], it.get("location", ""),
                     it.get("file", ""), it.get("line"), it.get("rule", ""), it.get("package", ""),
                     it.get("detail", ""), it.get("evidence", ""), it.get("exploit_path", ""),
                     it.get("patch_hint", ""), float(it.get("confidence", 0.5)), it.get("status", "new"),
                     run_id, run_id, now, now))
                conn.execute("INSERT INTO history VALUES (NULL,?,?,?,?)", (fp, now, "discovered", run_id))
                counts["new"] += 1
            else:
                status = row["status"]
                if status == "fixed":
                    status = "new"
                    conn.execute("INSERT INTO history VALUES (NULL,?,?,?,?)", (fp, now, "regressed", run_id))
                    counts["regressed"] += 1
                elif status in SUPPRESSED:
                    counts["suppressed"] += 1
                else:
                    counts["seen"] += 1
                conn.execute(
                    """UPDATE findings SET severity=?, title=?, location=?, line=?, detail=?, evidence=?,
                       exploit_path=CASE WHEN ?='' THEN exploit_path ELSE ? END,
                       patch_hint=CASE WHEN ?='' THEN patch_hint ELSE ? END,
                       confidence=?, status=?, last_run=?, run_count=run_count+1, updated_at=? WHERE fingerprint=?""",
                    (it.get("severity", "medium"), it["title"], it.get("location", ""), it.get("line"),
                     it.get("detail", ""), it.get("evidence", ""), it.get("exploit_path", ""), it.get("exploit_path", ""),
                     it.get("patch_hint", ""), it.get("patch_hint", ""), float(it.get("confidence", 0.5)),
                     status, run_id, now, fp))
    return counts


def list_findings(run_id: Optional[str] = None, project: Optional[str] = None, status: Optional[str] = None,
                  surface: Optional[str] = None, severity: Optional[str] = None, source: Optional[str] = None,
                  include_suppressed: bool = True, limit: int = 2000) -> list[dict]:
    q, args = "SELECT * FROM findings WHERE 1=1", []
    for col, val in (("last_run", run_id), ("project", project), ("status", status),
                     ("surface", surface), ("severity", severity), ("source", source)):
        if val:
            q += f" AND {col}=?"
            args.append(val)
    if not include_suppressed:
        q += " AND status NOT IN ('false_positive','accepted_risk')"
    q += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, confidence DESC, project LIMIT ?"
    args.append(limit)
    with _lock, _db() as conn:
        return [_row_to_dict(r) for r in conn.execute(q, args).fetchall()]


def get(fp: str) -> Optional[dict]:
    with _lock, _db() as conn:
        r = conn.execute("SELECT * FROM findings WHERE fingerprint=?", (fp,)).fetchone()
        if r is None:
            return None
        d = _row_to_dict(r)
        d["history"] = [dict(h) for h in conn.execute(
            "SELECT ts, event, detail FROM history WHERE fingerprint=? ORDER BY id DESC LIMIT 50", (fp,))]
        return d


def set_status(fp: str, status: str, note: str = "", actor: str = "user") -> None:
    if status not in STATUSES:
        raise ValueError(f"unknown status {status}")
    with _lock, _db() as conn:
        conn.execute("UPDATE findings SET status=?, note=CASE WHEN ?='' THEN note ELSE ? END, updated_at=? WHERE fingerprint=?",
                     (status, note, note, _now(), fp))
        conn.execute("INSERT INTO history VALUES (NULL,?,?,?,?)", (fp, _now(), f"status:{status}", f"{actor}: {note}"[:500]))


def set_json(fp: str, column: str, value: Any, event: str) -> None:
    assert column in ("verification", "patch")
    with _lock, _db() as conn:
        conn.execute(f"UPDATE findings SET {column}=?, updated_at=? WHERE fingerprint=?",
                     (json.dumps(value, default=str), _now(), fp))
        conn.execute("INSERT INTO history VALUES (NULL,?,?,?,?)", (fp, _now(), event, str(value.get("summary", ""))[:500] if isinstance(value, dict) else ""))


def update_fields(fp: str, **fields) -> None:
    allowed = {"severity", "exploit_path", "confidence", "surface", "patch_hint", "detail"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    with _lock, _db() as conn:
        conn.execute("UPDATE findings SET " + ", ".join(f"{k}=?" for k in sets) + ", updated_at=? WHERE fingerprint=?",
                     (*sets.values(), _now(), fp))


def stats(run_id: Optional[str] = None) -> dict:
    where, args = ("WHERE last_run=?", [run_id]) if run_id else ("", [])
    with _lock, _db() as conn:
        by_status = {r[0]: r[1] for r in conn.execute(f"SELECT status, COUNT(*) FROM findings {where} GROUP BY status", args)}
        by_sev = {r[0]: r[1] for r in conn.execute(
            f"SELECT severity, COUNT(*) FROM findings {where} {'AND' if where else 'WHERE'} status NOT IN ('false_positive','accepted_risk','fixed') GROUP BY severity", args)}
        by_project = {r[0]: r[1] for r in conn.execute(f"SELECT project, COUNT(*) FROM findings {where} GROUP BY project", args)}
        total = conn.execute(f"SELECT COUNT(*) FROM findings {where}", args).fetchone()[0]
    return {"total": total, "by_status": by_status, "by_severity": by_sev, "by_project": by_project}


def projects_and_surfaces() -> dict:
    with _lock, _db() as conn:
        return {
            "projects": [r[0] for r in conn.execute("SELECT DISTINCT project FROM findings ORDER BY project")],
            "surfaces": [r[0] for r in conn.execute("SELECT DISTINCT surface FROM findings WHERE surface<>'' ORDER BY surface")],
            "runs": [r[0] for r in conn.execute("SELECT DISTINCT last_run FROM findings ORDER BY last_run DESC")],
        }
