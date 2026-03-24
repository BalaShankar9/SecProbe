"""
Scan State Persistence — SQLite-backed scan resume and coverage tracking.

This solves a critical enterprise problem: real pentests take HOURS.
If a scan crashes, gets rate-limited, or times out, you don't start
from scratch — you RESUME.

Features:
    - Persist scan progress to SQLite
    - Resume interrupted scans (pick up where you left off)
    - Track per-URL, per-scanner coverage (what's been tested)
    - Incremental scanning — only test NEW endpoints on re-scan
    - Finding deduplication across scan runs
    - Scan session history and statistics

Architecture:
    ScanState creates/opens a .secprobe.db file in the working directory.
    All operations are thread-safe (SQLite with WAL mode).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secprobe.core.logger import get_logger

log = get_logger("state")


@dataclass
class ScanSession:
    """A scan session record."""
    session_id: str
    target: str
    started_at: float
    finished_at: Optional[float] = None
    status: str = "running"     # running, completed, interrupted, failed
    config_json: str = ""
    findings_count: int = 0
    urls_scanned: int = 0
    scanners_run: int = 0


@dataclass
class CoverageRecord:
    """Tracks what scanner has been run against what URL."""
    url: str
    scanner: str
    status: str             # pending, running, completed, skipped, error
    started_at: float = 0
    finished_at: float = 0
    findings_count: int = 0


class ScanState:
    """
    SQLite-backed scan state for resume and coverage tracking.

    Usage:
        state = ScanState("target.com")

        # Start a scan session
        session_id = state.start_session("https://target.com", config_dict)

        # Check what needs to be scanned
        if not state.is_scanned("https://target.com/login", "sqli"):
            # Run the scan
            state.mark_running("https://target.com/login", "sqli")
            findings = sqli_scanner.scan(...)
            state.mark_completed("https://target.com/login", "sqli", len(findings))

        # Save findings
        for finding in findings:
            state.save_finding(finding)

        # If interrupted, resume later:
        pending = state.get_pending_scans()
        # Returns list of (url, scanner) pairs that weren't completed

        state.finish_session()
    """

    def __init__(self, target: str, db_dir: str = "."):
        safe_name = hashlib.md5(target.encode()).hexdigest()[:12]
        self._db_path = Path(db_dir) / f".secprobe_{safe_name}.db"
        self._lock = threading.Lock()
        self._session_id = ""
        self._target = target

        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    status TEXT DEFAULT 'running',
                    config_json TEXT DEFAULT '',
                    findings_count INTEGER DEFAULT 0,
                    urls_scanned INTEGER DEFAULT 0,
                    scanners_run INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS coverage (
                    url TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    started_at REAL DEFAULT 0,
                    finished_at REAL DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    PRIMARY KEY (url, scanner, session_id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_hash TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    url TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    evidence TEXT DEFAULT '',
                    found_at REAL NOT NULL,
                    raw_json TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS urls (
                    url TEXT PRIMARY KEY,
                    discovered_at REAL NOT NULL,
                    source TEXT DEFAULT '',
                    session_id TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_coverage_status
                    ON coverage(status);
                CREATE INDEX IF NOT EXISTS idx_coverage_session
                    ON coverage(session_id);
                CREATE INDEX IF NOT EXISTS idx_findings_scanner
                    ON findings(scanner);
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON findings(severity);
            """)
        log.info("ScanState DB ready: %s", self._db_path)

    def _connect(self) -> sqlite3.Connection:
        """Get a connection with WAL mode for concurrency."""
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    # ─── Session Management ──────────────────────────────────────────

    def start_session(self, target: str, config: Optional[dict] = None) -> str:
        """Start a new scan session. Returns session ID."""
        import secrets
        self._session_id = secrets.token_hex(8)
        self._target = target

        config_json = json.dumps(config) if config else ""

        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, target, started_at, config_json) "
                "VALUES (?, ?, ?, ?)",
                (self._session_id, target, time.time(), config_json),
            )
        log.info("Scan session started: %s for %s", self._session_id, target)
        return self._session_id

    def resume_session(self) -> Optional[str]:
        """
        Resume the last interrupted session for this target.
        Returns session_id if found, None otherwise.
        """
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT session_id, status FROM sessions WHERE target = ? "
                "ORDER BY started_at DESC LIMIT 1",
                (self._target,),
            ).fetchone()

        if row and row["status"] in ("running", "interrupted"):
            self._session_id = row["session_id"]
            # Mark as running again
            with self._lock, self._connect() as conn:
                conn.execute(
                    "UPDATE sessions SET status = 'running' WHERE session_id = ?",
                    (self._session_id,),
                )
            log.info("Resumed session: %s", self._session_id)
            return self._session_id

        return None

    def finish_session(self, status: str = "completed"):
        """Mark the current session as finished."""
        if not self._session_id:
            return

        with self._lock, self._connect() as conn:
            # Compute stats
            stats = conn.execute(
                "SELECT COUNT(DISTINCT url) as urls, COUNT(DISTINCT scanner) as scanners "
                "FROM coverage WHERE session_id = ? AND status = 'completed'",
                (self._session_id,),
            ).fetchone()

            findings = conn.execute(
                "SELECT COUNT(*) as cnt FROM findings WHERE session_id = ?",
                (self._session_id,),
            ).fetchone()

            conn.execute(
                "UPDATE sessions SET finished_at = ?, status = ?, "
                "urls_scanned = ?, scanners_run = ?, findings_count = ? "
                "WHERE session_id = ?",
                (time.time(), status,
                 stats["urls"] if stats else 0,
                 stats["scanners"] if stats else 0,
                 findings["cnt"] if findings else 0,
                 self._session_id),
            )

        log.info("Session %s finished: %s", self._session_id, status)

    # ─── Coverage Tracking ───────────────────────────────────────────

    def is_scanned(self, url: str, scanner: str) -> bool:
        """Check if a URL has already been scanned by a specific scanner (any session)."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM coverage WHERE url = ? AND scanner = ? "
                "AND status = 'completed' ORDER BY finished_at DESC LIMIT 1",
                (url, scanner),
            ).fetchone()
        return row is not None

    def mark_pending(self, url: str, scanner: str):
        """Mark a URL+scanner pair as pending."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO coverage (url, scanner, session_id, status) "
                "VALUES (?, ?, ?, 'pending')",
                (url, scanner, self._session_id),
            )

    def mark_running(self, url: str, scanner: str):
        """Mark a scan as currently running."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO coverage "
                "(url, scanner, session_id, status, started_at) "
                "VALUES (?, ?, ?, 'running', ?)",
                (url, scanner, self._session_id, time.time()),
            )

    def mark_completed(self, url: str, scanner: str, findings_count: int = 0):
        """Mark a scan as completed."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE coverage SET status = 'completed', finished_at = ?, "
                "findings_count = ? WHERE url = ? AND scanner = ? AND session_id = ?",
                (time.time(), findings_count, url, scanner, self._session_id),
            )

    def mark_error(self, url: str, scanner: str):
        """Mark a scan as failed with error."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE coverage SET status = 'error', finished_at = ? "
                "WHERE url = ? AND scanner = ? AND session_id = ?",
                (time.time(), url, scanner, self._session_id),
            )

    def get_pending_scans(self) -> list[tuple[str, str]]:
        """Get all URL+scanner pairs that haven't been completed."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT url, scanner FROM coverage WHERE session_id = ? "
                "AND status IN ('pending', 'running')",
                (self._session_id,),
            ).fetchall()
        return [(r["url"], r["scanner"]) for r in rows]

    def get_coverage_stats(self) -> dict:
        """Get coverage statistics for the current session."""
        with self._lock, self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM coverage WHERE session_id = ?",
                (self._session_id,),
            ).fetchone()

            completed = conn.execute(
                "SELECT COUNT(*) as cnt FROM coverage "
                "WHERE session_id = ? AND status = 'completed'",
                (self._session_id,),
            ).fetchone()

            errors = conn.execute(
                "SELECT COUNT(*) as cnt FROM coverage "
                "WHERE session_id = ? AND status = 'error'",
                (self._session_id,),
            ).fetchone()

        return {
            "total": total["cnt"] if total else 0,
            "completed": completed["cnt"] if completed else 0,
            "errors": errors["cnt"] if errors else 0,
            "pending": (total["cnt"] if total else 0) - (completed["cnt"] if completed else 0) - (errors["cnt"] if errors else 0),
        }

    # ─── URL Tracking ────────────────────────────────────────────────

    def add_url(self, url: str, source: str = "crawl"):
        """Record a discovered URL."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO urls (url, discovered_at, source, session_id) "
                "VALUES (?, ?, ?, ?)",
                (url, time.time(), source, self._session_id),
            )

    def get_new_urls(self, since_session: str = "") -> list[str]:
        """Get URLs discovered since a given session (for incremental scanning)."""
        with self._lock, self._connect() as conn:
            if since_session:
                session_row = conn.execute(
                    "SELECT started_at FROM sessions WHERE session_id = ?",
                    (since_session,),
                ).fetchone()
                if session_row:
                    rows = conn.execute(
                        "SELECT url FROM urls WHERE discovered_at > ?",
                        (session_row["started_at"],),
                    ).fetchall()
                    return [r["url"] for r in rows]
            rows = conn.execute("SELECT url FROM urls").fetchall()
            return [r["url"] for r in rows]

    def get_unscanned_urls(self, scanner: str) -> list[str]:
        """Get URLs that haven't been tested by a specific scanner."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT u.url FROM urls u "
                "LEFT JOIN coverage c ON u.url = c.url AND c.scanner = ? AND c.status = 'completed' "
                "WHERE c.url IS NULL",
                (scanner,),
            ).fetchall()
        return [r["url"] for r in rows]

    # ─── Finding Storage ─────────────────────────────────────────────

    def save_finding(self, finding: dict) -> bool:
        """
        Save a finding. Deduplicates by content hash.
        Returns True if this is a new finding, False if duplicate.
        """
        # Hash the finding for dedup
        hash_input = f"{finding.get('scanner','')}-{finding.get('url','')}-{finding.get('title','')}"
        finding_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        with self._lock, self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO findings "
                    "(finding_hash, session_id, scanner, url, severity, title, "
                    "description, evidence, found_at, raw_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        finding_hash,
                        self._session_id,
                        finding.get("scanner", ""),
                        finding.get("url", ""),
                        finding.get("severity", "info"),
                        finding.get("title", ""),
                        finding.get("description", ""),
                        finding.get("evidence", ""),
                        time.time(),
                        json.dumps(finding),
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False  # Duplicate

    def get_findings(self, scanner: str = "", severity: str = "") -> list[dict]:
        """Get saved findings, optionally filtered."""
        query = "SELECT raw_json FROM findings WHERE session_id = ?"
        params: list = [self._session_id]

        if scanner:
            query += " AND scanner = ?"
            params.append(scanner)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY found_at DESC"

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [json.loads(r["raw_json"]) for r in rows]

    def get_all_findings(self) -> list[dict]:
        """Get all findings across all sessions (for comparison)."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT raw_json FROM findings ORDER BY found_at DESC"
            ).fetchall()
        return [json.loads(r["raw_json"]) for r in rows]

    # ─── History & Reporting ─────────────────────────────────────────

    def get_session_history(self) -> list[dict]:
        """Get all previous scan sessions."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_summary(self) -> dict:
        """Get a summary of the current scan session."""
        stats = self.get_coverage_stats()

        with self._lock, self._connect() as conn:
            findings_by_sev = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings "
                "WHERE session_id = ? GROUP BY severity",
                (self._session_id,),
            ).fetchall()

            scanners = conn.execute(
                "SELECT DISTINCT scanner FROM coverage WHERE session_id = ?",
                (self._session_id,),
            ).fetchall()

        return {
            "session_id": self._session_id,
            "target": self._target,
            "coverage": stats,
            "findings_by_severity": {r["severity"]: r["cnt"] for r in findings_by_sev},
            "scanners": [r["scanner"] for r in scanners],
        }

    @property
    def db_path(self) -> str:
        return str(self._db_path)

    @property
    def session_id(self) -> str:
        return self._session_id
