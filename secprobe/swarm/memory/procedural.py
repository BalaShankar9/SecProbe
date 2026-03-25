"""
L4: Procedural Memory — Successful attack sequences for replay.

Procedural memory stores "how-to" knowledge — ordered sequences of
actions that successfully found or exploited vulnerabilities.  When the
swarm encounters a similar target, it can replay proven procedures
instead of exploring from scratch.

Example procedure: "WordPress SQLi via search parameter"
    1. Detect WordPress via wp-content in HTML
    2. Confirm version < 6.0 via readme.html
    3. Send ``' OR 1=1--`` to ``/?s=`` parameter
    4. Confirm via MySQL error pattern in response
    5. Extract data via UNION SELECT
    Applicability: {cms: wordpress, version_lt: 6.0}
    Success rate: 78% across 23 attempts

Storage: SQLite database at ~/.secprobe/memory/procedural/procedural.db
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("secprobe.memory.procedural")

_DEFAULT_STORAGE = Path.home() / ".secprobe" / "memory" / "procedural"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS procedures (
    procedure_id   TEXT PRIMARY KEY,
    vuln_type      TEXT NOT NULL,
    technology     TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    steps          TEXT NOT NULL DEFAULT '[]',
    prerequisites  TEXT NOT NULL DEFAULT '[]',
    success_count  INTEGER NOT NULL DEFAULT 0,
    failure_count  INTEGER NOT NULL DEFAULT 0,
    avg_duration   REAL NOT NULL DEFAULT 0.0,
    created_at     TEXT NOT NULL,
    last_used      TEXT NOT NULL,
    metadata       TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_proc_vuln ON procedures(vuln_type);
CREATE INDEX IF NOT EXISTS idx_proc_tech ON procedures(technology);
CREATE INDEX IF NOT EXISTS idx_proc_success
    ON procedures(success_count DESC);
"""


@dataclass
class AttackStep:
    """A single step in an attack procedure."""

    action: str = ""            # e.g. "inject_payload", "bypass_waf", "escalate"
    target_url: str = ""
    parameter: str = ""
    payload: str = ""
    response_indicator: str = ""  # regex or string that signals success
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "action": self.action,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "payload": self.payload,
            "response_indicator": self.response_indicator,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> AttackStep:
        return cls(
            action=d.get("action", ""),
            target_url=d.get("target_url", ""),
            parameter=d.get("parameter", ""),
            payload=d.get("payload", ""),
            response_indicator=d.get("response_indicator", ""),
            notes=d.get("notes", ""),
        )


@dataclass
class AttackProcedure:
    """A complete, replayable attack procedure."""

    procedure_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    vuln_type: str = ""
    technology: str = ""
    name: str = ""
    description: str = ""
    steps: list[AttackStep] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0
    avg_duration: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)

    @property
    def attempt_count(self) -> int:
        return self.success_count + self.failure_count

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    @property
    def is_proven(self) -> bool:
        """A procedure is proven when it has at least 3 attempts and >= 60% success."""
        return self.attempt_count >= 3 and self.success_rate >= 0.6

    def to_row(self) -> tuple:
        return (
            self.procedure_id,
            self.vuln_type,
            self.technology,
            self.name,
            self.description,
            json.dumps([s.to_dict() for s in self.steps]),
            json.dumps(self.prerequisites),
            self.success_count,
            self.failure_count,
            self.avg_duration,
            self.created_at.isoformat() if isinstance(self.created_at, datetime) else str(self.created_at),
            self.last_used.isoformat() if isinstance(self.last_used, datetime) else str(self.last_used),
            json.dumps(self.metadata, default=str),
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> AttackProcedure:
        steps_raw = json.loads(row["steps"])
        return cls(
            procedure_id=row["procedure_id"],
            vuln_type=row["vuln_type"],
            technology=row["technology"],
            name=row["name"],
            description=row["description"],
            steps=[AttackStep.from_dict(s) for s in steps_raw],
            prerequisites=json.loads(row["prerequisites"]),
            success_count=row["success_count"],
            failure_count=row["failure_count"],
            avg_duration=row["avg_duration"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_used=datetime.fromisoformat(row["last_used"]),
            metadata=json.loads(row["metadata"]),
        )


class ProceduralMemory:
    """
    Stores and retrieves proven attack procedures, backed by SQLite.

    Usage::

        mem = ProceduralMemory()

        # Record a successful procedure
        proc = AttackProcedure(
            vuln_type="sqli", technology="mysql",
            name="Error-based SQLi via search",
            steps=[
                AttackStep(action="inject", parameter="q",
                           payload="' OR 1=1--",
                           response_indicator="SQL syntax"),
            ],
            prerequisites=["detected_mysql"],
        )
        mem.record_procedure(proc)

        # Find procedures for a new scan
        procs = mem.find_procedure("sqli", tech="mysql")
        for p in procs:
            print(f"{p.name}: {p.success_rate:.0%} over {p.attempt_count} attempts")

        # Replay
        procedure = mem.replay_procedure(procs[0].procedure_id)

        # Update after replay
        mem.update_success(procedure.procedure_id, success=True, duration=2.4)
    """

    def __init__(self, storage_path: Optional[Path] = None):
        self._storage_path = Path(storage_path) if storage_path else _DEFAULT_STORAGE
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._db_path = self._storage_path / "procedural.db"
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()
        logger.debug("Procedural memory database initialised at %s", self._db_path)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Record / update
    # ------------------------------------------------------------------

    def record_procedure(self, procedure: AttackProcedure) -> str:
        """
        Store a successful attack procedure.

        If a procedure with the same ``procedure_id`` already exists it is
        replaced.

        Returns:
            The ``procedure_id``.
        """
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO procedures
                   (procedure_id, vuln_type, technology, name, description,
                    steps, prerequisites, success_count, failure_count,
                    avg_duration, created_at, last_used, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                procedure.to_row(),
            )
            conn.commit()
            logger.info(
                "Recorded procedure %s (%s / %s): %d steps",
                procedure.procedure_id,
                procedure.vuln_type,
                procedure.technology,
                len(procedure.steps),
            )
            return procedure.procedure_id
        except sqlite3.Error:
            logger.exception("Failed to record procedure %s", procedure.procedure_id)
            raise

    def update_success(
        self, procedure_id: str, success: bool, duration: float = 0.0
    ) -> bool:
        """
        Track whether a procedure replay succeeded or failed.

        Updates success/failure counters and running average duration.
        Returns ``True`` if the procedure existed.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        # Read current state
        row = conn.execute(
            "SELECT success_count, failure_count, avg_duration "
            "FROM procedures WHERE procedure_id = ?",
            (procedure_id,),
        ).fetchone()

        if row is None:
            return False

        new_success = row["success_count"] + (1 if success else 0)
        new_failure = row["failure_count"] + (0 if success else 1)
        total = new_success + new_failure

        # Update running average duration
        if duration > 0 and total > 0:
            new_avg = (row["avg_duration"] * (total - 1) + duration) / total
        else:
            new_avg = row["avg_duration"]

        conn.execute(
            """UPDATE procedures
               SET success_count = ?, failure_count = ?,
                   avg_duration = ?, last_used = ?
               WHERE procedure_id = ?""",
            (new_success, new_failure, new_avg, now, procedure_id),
        )
        conn.commit()
        logger.debug(
            "Updated procedure %s: success=%s, rate=%.0f%%",
            procedure_id, success,
            (new_success / total * 100) if total else 0,
        )
        return True

    def delete_procedure(self, procedure_id: str) -> bool:
        """Delete a procedure.  Returns ``True`` if it existed."""
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM procedures WHERE procedure_id = ?", (procedure_id,)
        )
        conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Query / recall
    # ------------------------------------------------------------------

    def _fetch_procedures(self, query: str, params: tuple = ()) -> list[AttackProcedure]:
        conn = self._get_conn()
        cursor = conn.execute(query, params)
        return [AttackProcedure.from_row(row) for row in cursor.fetchall()]

    def find_procedure(
        self, vuln_type: str, tech: str | None = None
    ) -> list[AttackProcedure]:
        """
        Find known procedures for a vuln type, optionally filtered by
        technology.  Results are sorted by ``success_count`` descending.
        """
        if tech:
            return self._fetch_procedures(
                """SELECT * FROM procedures
                   WHERE vuln_type = ? AND technology = ?
                   ORDER BY success_count DESC""",
                (vuln_type, tech),
            )
        return self._fetch_procedures(
            "SELECT * FROM procedures WHERE vuln_type = ? ORDER BY success_count DESC",
            (vuln_type,),
        )

    def replay_procedure(self, procedure_id: str) -> Optional[AttackProcedure]:
        """
        Get full procedure for replay.  Returns ``None`` if not found.
        """
        procs = self._fetch_procedures(
            "SELECT * FROM procedures WHERE procedure_id = ?", (procedure_id,)
        )
        return procs[0] if procs else None

    def find_by_technology(self, tech: str) -> list[AttackProcedure]:
        """Get all procedures targeting a specific technology."""
        return self._fetch_procedures(
            "SELECT * FROM procedures WHERE technology = ? ORDER BY success_count DESC",
            (tech,),
        )

    def find_proven(self, min_success_rate: float = 0.6, min_attempts: int = 3) -> list[AttackProcedure]:
        """
        Get all procedures that meet the "proven" threshold.
        """
        return self._fetch_procedures(
            """SELECT * FROM procedures
               WHERE (success_count + failure_count) >= ?
                 AND CAST(success_count AS REAL) /
                     MAX(success_count + failure_count, 1) >= ?
               ORDER BY success_count DESC""",
            (min_attempts, min_success_rate),
        )

    def find_with_prerequisite(self, prerequisite: str) -> list[AttackProcedure]:
        """Find procedures that list a specific prerequisite."""
        return self._fetch_procedures(
            "SELECT * FROM procedures WHERE prerequisites LIKE ? ORDER BY success_count DESC",
            (f"%{prerequisite}%",),
        )

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def count(self) -> int:
        """Total stored procedures."""
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM procedures").fetchone()[0]

    def prune_ineffective(
        self, max_failure_rate: float = 0.8, min_attempts: int = 5
    ) -> int:
        """
        Remove procedures that consistently fail.  Returns count removed.

        A procedure is pruned when it has at least *min_attempts* and a
        failure rate exceeding *max_failure_rate*.
        """
        conn = self._get_conn()
        cursor = conn.execute(
            """DELETE FROM procedures
               WHERE (success_count + failure_count) >= ?
                 AND CAST(failure_count AS REAL) /
                     MAX(success_count + failure_count, 1) >= ?""",
            (min_attempts, max_failure_rate),
        )
        conn.commit()
        removed = cursor.rowcount
        if removed:
            logger.info("Pruned %d ineffective procedures", removed)
        return removed
