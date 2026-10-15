from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "accesscheck.sqlite3"


def database_path() -> Path:
    return Path(os.environ.get("ACCESSCHECK_DB_PATH", str(DEFAULT_DB_PATH)))


def connect() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextmanager
def managed_connection():
    connection = connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize() -> None:
    with managed_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
              id TEXT PRIMARY KEY,
              url TEXT NOT NULL,
              domain TEXT NOT NULL,
              title TEXT NOT NULL,
              page_title TEXT NOT NULL,
              page_url TEXT NOT NULL,
              status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
              created_at TEXT NOT NULL,
              duration_ms INTEGER NOT NULL,
              violation_count INTEGER NOT NULL,
              critical_count INTEGER NOT NULL,
              serious_count INTEGER NOT NULL,
              moderate_count INTEGER NOT NULL,
              minor_count INTEGER NOT NULL,
              pass_count INTEGER NOT NULL,
              incomplete_count INTEGER NOT NULL,
              findings_json TEXT NOT NULL,
              error TEXT
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at DESC)"
        )


def save_scan(scan: dict[str, Any]) -> None:
    with managed_connection() as connection:
        connection.execute(
            """
            INSERT INTO scans (
              id, url, domain, title, page_title, page_url, status, created_at,
              duration_ms, violation_count, critical_count, serious_count,
              moderate_count, minor_count, pass_count, incomplete_count,
              findings_json, error
            ) VALUES (
              :id, :url, :domain, :title, :page_title, :page_url, :status, :created_at,
              :duration_ms, :violation_count, :critical_count, :serious_count,
              :moderate_count, :minor_count, :pass_count, :incomplete_count,
              :findings_json, :error
            )
            """,
            {
                **scan,
                "findings_json": json.dumps(scan["findings"], separators=(",", ":")),
            },
        )


def _summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "url": row["url"],
        "domain": row["domain"],
        "title": row["title"],
        "status": row["status"],
        "created_at": row["created_at"],
        "duration_ms": row["duration_ms"],
        "violation_count": row["violation_count"],
        "critical_count": row["critical_count"],
        "serious_count": row["serious_count"],
        "moderate_count": row["moderate_count"],
        "minor_count": row["minor_count"],
    }


def list_scans(limit: int) -> list[dict[str, Any]]:
    with managed_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_summary(row) for row in rows]


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with managed_connection() as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        **_summary(row),
        "page_title": row["page_title"],
        "page_url": row["page_url"],
        "findings": json.loads(row["findings_json"]),
        "pass_count": row["pass_count"],
        "incomplete_count": row["incomplete_count"],
        "error": row["error"],
    }


def dashboard() -> dict[str, Any]:
    with managed_connection() as connection:
        totals = connection.execute(
            """
            SELECT COUNT(*) AS total_scans,
                   COALESCE(SUM(violation_count), 0) AS total_violations,
                   COALESCE(SUM(critical_count), 0) AS critical,
                   COALESCE(SUM(serious_count), 0) AS serious,
                   COALESCE(SUM(moderate_count), 0) AS moderate,
                   COALESCE(SUM(minor_count), 0) AS minor
            FROM scans
            WHERE status = 'completed'
            """
        ).fetchone()
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, rowid DESC LIMIT 6"
        ).fetchall()
    return {
        "total_scans": totals["total_scans"],
        "total_violations": totals["total_violations"],
        "severity_counts": {
            "critical": totals["critical"],
            "serious": totals["serious"],
            "moderate": totals["moderate"],
            "minor": totals["minor"],
        },
        "recent_scans": [_summary(row) for row in rows],
    }
