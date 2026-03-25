"""
L2: Episodic Memory — Complete scan history and outcomes.

Episodic memory records everything that happened during each scan session:
targets, findings, agent actions, timing, and attack surface discoveries.
This is the "autobiography" of the scanner — it remembers what happened,
when, and what the outcome was.

Data flows here from L1 (WorkingMemory) at scan completion. Over time,
patterns extracted from episodes promote to L3 (SemanticMemory).

Storage: SQLite database at ~/.secprobe/memory/episodic/episodes.db
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("secprobe.memory.episodic")

_DEFAULT_STORAGE = Path.home() / ".secprobe" / "memory" / "episodic"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS episodes (
    scan_id          TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'recon',
    duration_seconds REAL NOT NULL DEFAULT 0.0,
    findings         TEXT NOT NULL DEFAULT '[]',
    agent_actions    TEXT NOT NULL DEFAULT '[]',
    attack_surface   TEXT NOT NULL DEFAULT '{}',
    success_rate     REAL NOT NULL DEFAULT 0.0,
    metadata         TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_episodes_target    ON episodes(target);
CREATE INDEX IF NOT EXISTS idx_episodes_timestamp ON episodes(timestamp);
CREATE INDEX IF NOT EXISTS idx_episodes_mode      ON episodes(mode);
"""


@dataclass
class ScanEpisode:
    """A single recorded scan session."""

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    mode: str = "recon"  # recon / audit / redteam
    duration_seconds: float = 0.0
    findings: list[dict] = field(default_factory=list)
    agent_actions: list[dict] = field(default_factory=list)
    attack_surface: dict = field(default_factory=dict)
    success_rate: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_row(self) -> tuple:
        """Serialize to a database row tuple."""
        return (
            self.scan_id,
            self.target,
            self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            self.mode,
            self.duration_seconds,
            json.dumps(self.findings, default=str),
            json.dumps(self.agent_actions, default=str),
            json.dumps(self.attack_surface, default=str),
            self.success_rate,
            json.dumps(self.metadata, default=str),
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ScanEpisode:
        """Deserialize from a database row."""
        ts_raw = row["timestamp"]
        try:
            ts = datetime.fromisoformat(ts_raw)
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)

        return cls(
            scan_id=row["scan_id"],
            target=row["target"],
            timestamp=ts,
            mode=row["mode"],
            duration_seconds=row["duration_seconds"],
            findings=json.loads(row["findings"]),
            agent_actions=json.loads(row["agent_actions"]),
            attack_surface=json.loads(row["attack_surface"]),
            success_rate=row["success_rate"],
            metadata=json.loads(row["metadata"]),
        )


class EpisodicMemory:
    """
    Persistent scan history backed by SQLite.

    Stores complete scan episodes including findings, agent actions, and
    attack surface data.  Supports querying by target, technology, mode,
    and recency.

    Usage::

        mem = EpisodicMemory()
        episode = ScanEpisode(target="example.com", mode="audit",
                              findings=[{"type": "sqli", "url": "/search"}])
        scan_id = mem.record_episode(episode)

        # Recall past scans against the same target
        history = mem.recall_by_target("example.com")

        # Summarise a target's full history
        summary = mem.get_target_history("example.com")
    """

    def __init__(self, storage_path: Optional[Path] = None):
        self._storage_path = Path(storage_path) if storage_path else _DEFAULT_STORAGE
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._db_path = self._storage_path / "episodes.db"
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return (and lazily create) a SQLite connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _init_db(self) -> None:
        """Create tables and indexes if they don't exist."""
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()
        logger.debug("Episodic memory database initialised at %s", self._db_path)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Core write operations
    # ------------------------------------------------------------------

    def record_episode(self, episode: ScanEpisode) -> str:
        """
        Store a complete scan episode.

        If an episode with the same ``scan_id`` already exists it is
        replaced (upsert behaviour).

        Returns:
            The ``scan_id`` of the recorded episode.
        """
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO episodes
                   (scan_id, target, timestamp, mode, duration_seconds,
                    findings, agent_actions, attack_surface, success_rate, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                episode.to_row(),
            )
            conn.commit()
            logger.info(
                "Recorded episode %s for target %s (%s mode, %.1fs, %d findings)",
                episode.scan_id,
                episode.target,
                episode.mode,
                episode.duration_seconds,
                len(episode.findings),
            )
            return episode.scan_id
        except sqlite3.Error:
            logger.exception("Failed to record episode %s", episode.scan_id)
            raise

    def delete_episode(self, scan_id: str) -> bool:
        """Delete a single episode.  Returns ``True`` if it existed."""
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM episodes WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0

    def purge_before(self, before: datetime) -> int:
        """Delete episodes older than *before*.  Returns count deleted."""
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM episodes WHERE timestamp < ?",
            (before.isoformat(),),
        )
        conn.commit()
        removed = cursor.rowcount
        if removed:
            logger.info("Purged %d episodes older than %s", removed, before.isoformat())
        return removed

    # ------------------------------------------------------------------
    # Recall / query operations
    # ------------------------------------------------------------------

    def _fetch_episodes(self, query: str, params: tuple = ()) -> list[ScanEpisode]:
        """Run *query* and return deserialized episodes."""
        conn = self._get_conn()
        cursor = conn.execute(query, params)
        return [ScanEpisode.from_row(row) for row in cursor.fetchall()]

    def recall_by_target(self, target: str) -> list[ScanEpisode]:
        """Get all episodes for a target domain, most recent first."""
        return self._fetch_episodes(
            "SELECT * FROM episodes WHERE target = ? ORDER BY timestamp DESC",
            (target,),
        )

    def recall_by_technology(self, tech: str) -> list[ScanEpisode]:
        """
        Find episodes where the given technology was detected in the
        attack surface.  Uses JSON substring matching.
        """
        return self._fetch_episodes(
            "SELECT * FROM episodes WHERE attack_surface LIKE ? ORDER BY timestamp DESC",
            (f"%{tech}%",),
        )

    def recall_by_mode(self, mode: str) -> list[ScanEpisode]:
        """Get all episodes that used a specific scan mode."""
        return self._fetch_episodes(
            "SELECT * FROM episodes WHERE mode = ? ORDER BY timestamp DESC",
            (mode,),
        )

    def recall_recent(self, limit: int = 10) -> list[ScanEpisode]:
        """Get the most recent episodes."""
        return self._fetch_episodes(
            "SELECT * FROM episodes ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    def get_episode(self, scan_id: str) -> Optional[ScanEpisode]:
        """Retrieve a single episode by ``scan_id``."""
        episodes = self._fetch_episodes(
            "SELECT * FROM episodes WHERE scan_id = ?", (scan_id,)
        )
        return episodes[0] if episodes else None

    # ------------------------------------------------------------------
    # Aggregate / analytics
    # ------------------------------------------------------------------

    def get_target_history(self, target: str) -> dict[str, Any]:
        """
        Summary statistics for a target across all recorded episodes.

        Returns a dict with keys: ``target``, ``first_seen``, ``last_seen``,
        ``scan_count``, ``total_findings``, ``unique_vuln_types``,
        ``finding_trend``, ``modes_used``.
        """
        episodes = self.recall_by_target(target)
        if not episodes:
            return {
                "target": target,
                "first_seen": None,
                "last_seen": None,
                "scan_count": 0,
                "total_findings": 0,
                "unique_vuln_types": [],
                "finding_trend": [],
                "modes_used": [],
            }

        vuln_types: set[str] = set()
        modes: set[str] = set()
        trend: list[dict] = []
        total_findings = 0

        for ep in episodes:
            total_findings += len(ep.findings)
            modes.add(ep.mode)
            for finding in ep.findings:
                vtype = finding.get("vuln_type") or finding.get("type", "unknown")
                vuln_types.add(vtype)
            trend.append(
                {
                    "scan_id": ep.scan_id,
                    "timestamp": ep.timestamp.isoformat(),
                    "finding_count": len(ep.findings),
                    "success_rate": ep.success_rate,
                }
            )

        return {
            "target": target,
            "first_seen": episodes[-1].timestamp.isoformat(),
            "last_seen": episodes[0].timestamp.isoformat(),
            "scan_count": len(episodes),
            "total_findings": total_findings,
            "unique_vuln_types": sorted(vuln_types),
            "finding_trend": trend,
            "modes_used": sorted(modes),
        }

    def count(self) -> int:
        """Total number of recorded episodes."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT COUNT(*) FROM episodes")
        return cursor.fetchone()[0]

    def diff(self, scan_id_a: str, scan_id_b: str) -> dict[str, Any]:
        """
        Compare two scan episodes for regression detection.

        Returns a dict describing new, resolved, and persistent findings
        between the two scans.
        """
        ep_a = self.get_episode(scan_id_a)
        ep_b = self.get_episode(scan_id_b)
        if not ep_a or not ep_b:
            return {"error": "One or both episodes not found"}

        def _finding_key(f: dict) -> str:
            return f"{f.get('vuln_type', f.get('type', ''))}:{f.get('url', '')}:{f.get('param', '')}"

        keys_a = {_finding_key(f) for f in ep_a.findings}
        keys_b = {_finding_key(f) for f in ep_b.findings}

        return {
            "scan_a": scan_id_a,
            "scan_b": scan_id_b,
            "new_findings": sorted(keys_b - keys_a),
            "resolved_findings": sorted(keys_a - keys_b),
            "persistent_findings": sorted(keys_a & keys_b),
            "finding_count_a": len(ep_a.findings),
            "finding_count_b": len(ep_b.findings),
            "success_rate_a": ep_a.success_rate,
            "success_rate_b": ep_b.success_rate,
        }
