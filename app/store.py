"""
store.py - SQLite storage for DiffShield holds, audits, and reports.

Zero ORM. Clean, human-inspectable SQLite tables:
- holds: active and historic PR quarantine holds
- audits: append-only action log (diffshield / GitHub user logins)
- reports: canonical analysis payloads indexed by head SHA
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger("diffshield.store")


@dataclass
class HoldRow:
    id: int
    repo: str
    pr_number: int
    installation: int
    head_sha: str
    decision: str
    score: int
    band: str
    reason: str
    created_at: str
    release_at: str
    released_at: Optional[str]
    released_by: Optional[str]
    release_kind: Optional[str]  # auto | override | release | closed | auto-extended
    comment_id: Optional[int]
    check_run_id: Optional[int]


class Store:
    """Manages SQLite tables for holds, audit log, and analysis reports."""

    def __init__(self, db_path: str = "diffshield.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Holds table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS holds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    installation INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    band TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    release_at TEXT NOT NULL,
                    released_at TEXT,
                    released_by TEXT,
                    release_kind TEXT,
                    comment_id INTEGER,
                    check_run_id INTEGER,
                    UNIQUE(repo, pr_number, head_sha)
                );
            """)

            # 2. Audits table (append-only)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    at TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
            """)

            # 3. Reports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    repo TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(repo, pr_number, head_sha)
                );
            """)
            conn.commit()

    def record_audit(self, repo: str, pr_number: int, actor: str, action: str, detail: str) -> None:
        """Append an audit record."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO audits (at, repo, pr_number, actor, action, detail) VALUES (?, ?, ?, ?, ?, ?)",
                (now, repo, pr_number, actor, action, detail)
            )
            conn.commit()

    def upsert_hold(
        self,
        repo: str,
        pr_number: int,
        installation: int,
        head_sha: str,
        decision: str,
        score: int,
        band: str,
        reason: str,
        hold_hours: int = 12,
        comment_id: Optional[int] = None,
        check_run_id: Optional[int] = None
    ) -> HoldRow:
        """
        Insert or update a quarantine hold row keyed on (repo, pr_number, head_sha).
        Guarantees webhook idempotency.
        """
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        created_at = now_dt.isoformat()
        release_at = (now_dt + datetime.timedelta(hours=hold_hours)).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO holds (
                    repo, pr_number, installation, head_sha, decision, score, band,
                    reason, created_at, release_at, comment_id, check_run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repo, pr_number, head_sha) DO UPDATE SET
                    decision=excluded.decision,
                    score=excluded.score,
                    band=excluded.band,
                    reason=excluded.reason,
                    comment_id=COALESCE(excluded.comment_id, holds.comment_id),
                    check_run_id=COALESCE(excluded.check_run_id, holds.check_run_id)
                RETURNING *;
                """,
                (repo, pr_number, installation, head_sha, decision, score, band,
                 reason, created_at, release_at, comment_id, check_run_id)
            )
            row = cursor.fetchone()
            conn.commit()
            return HoldRow(**dict(row))

    def get_open_hold(self, repo: str, pr_number: int) -> Optional[HoldRow]:
        """Fetch current unreleased quarantine hold for a PR."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM holds WHERE repo = ? AND pr_number = ? AND released_at IS NULL ORDER BY id DESC LIMIT 1",
                (repo, pr_number)
            )
            row = cursor.fetchone()
            return HoldRow(**dict(row)) if row else None

    def get_due_holds(self, current_time: Optional[datetime.datetime] = None) -> List[HoldRow]:
        """Fetch all unreleased holds whose release_at timestamp has passed."""
        now = (current_time or datetime.datetime.now(datetime.timezone.utc)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM holds WHERE released_at IS NULL AND release_at <= ? ORDER BY id ASC",
                (now,)
            )
            rows = cursor.fetchall()
            return [HoldRow(**dict(r)) for r in rows]

    def release_hold(self, hold_id: int, actor: str, kind: str) -> None:
        """Mark a hold as released (auto | override | release | closed)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE holds SET released_at = ?, released_by = ?, release_kind = ? WHERE id = ?",
                (now, actor, kind, hold_id)
            )
            conn.commit()

    def extend_hold(self, hold_id: int, additional_hours: int = 12) -> None:
        """Extend an expiring hold when re-analysis indicates code is still vulnerable."""
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        new_release_at = (now_dt + datetime.timedelta(hours=additional_hours)).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE holds SET release_at = ?, release_kind = 'auto-extended' WHERE id = ?",
                (new_release_at, hold_id)
            )
            conn.commit()

    def upsert_report(self, repo: str, pr_number: int, head_sha: str, decision: str, score: int, payload: Dict[str, Any]) -> None:
        """Store canonical analysis report JSON."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload_str = json.dumps(payload)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO reports (repo, pr_number, head_sha, created_at, decision, score, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repo, pr_number, head_sha) DO UPDATE SET
                    decision=excluded.decision,
                    score=excluded.score,
                    payload=excluded.payload;
                """,
                (repo, pr_number, head_sha, now, decision, score, payload_str)
            )
            conn.commit()

    def get_report(self, repo: str, pr_number: int) -> Optional[Dict[str, Any]]:
        """Retrieve most recent analysis report for PR."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT payload FROM reports WHERE repo = ? AND pr_number = ? ORDER BY created_at DESC LIMIT 1",
                (repo, pr_number)
            )
            row = cursor.fetchone()
            return json.loads(row["payload"]) if row else None

    def get_audits(self, repo: str, pr_number: int) -> List[Dict[str, Any]]:
        """Retrieve audit log history for PR."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audits WHERE repo = ? AND pr_number = ? ORDER BY id ASC",
                (repo, pr_number)
            )
            return [dict(r) for r in cursor.fetchall()]

    def list_holds(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent holds for dashboard."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM holds ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            return [dict(r) for r in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics for API & dashboard."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            total_holds = cursor.execute("SELECT COUNT(*) FROM holds").fetchone()[0]
            active_holds = cursor.execute("SELECT COUNT(*) FROM holds WHERE released_at IS NULL").fetchone()[0]
            released_holds = cursor.execute("SELECT COUNT(*) FROM holds WHERE released_at IS NOT NULL").fetchone()[0]
            total_audits = cursor.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
            total_reports = cursor.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            return {
                "total_holds": total_holds,
                "active_holds": active_holds,
                "released_holds": released_holds,
                "total_audits": total_audits,
                "total_reports": total_reports
            }

