"""
L3: Semantic Memory — Learned patterns across multiple scans.

Semantic memory stores generalizable knowledge extracted from episodic
memories.  It tracks two kinds of learned data:

1. **Technology-vulnerability correlations** — statistical relationships
   between tech stacks and vulnerability types (e.g. "WordPress 6.2 has
   SQLi 73% of the time").

2. **Payload effectiveness** — which payloads work best against which
   technologies and WAFs.

These correlations guide intelligent scan planning: when the swarm sees
a tech stack, semantic memory tells it which vulnerabilities to try first
and which payloads to lead with.

Storage: SQLite database at ~/.secprobe/memory/semantic/semantic.db
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("secprobe.memory.semantic")

_DEFAULT_STORAGE = Path.home() / ".secprobe" / "memory" / "semantic"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tech_vuln_correlations (
    technology    TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    hit_count     INTEGER NOT NULL DEFAULT 0,
    miss_count    INTEGER NOT NULL DEFAULT 0,
    confidence    REAL NOT NULL DEFAULT 0.0,
    last_updated  TEXT NOT NULL,
    PRIMARY KEY (technology, vuln_type)
);

CREATE INDEX IF NOT EXISTS idx_tvc_tech
    ON tech_vuln_correlations(technology);
CREATE INDEX IF NOT EXISTS idx_tvc_vuln
    ON tech_vuln_correlations(vuln_type);
CREATE INDEX IF NOT EXISTS idx_tvc_confidence
    ON tech_vuln_correlations(confidence DESC);

CREATE TABLE IF NOT EXISTS payload_effectiveness (
    payload_hash    TEXT NOT NULL,
    payload_preview TEXT NOT NULL DEFAULT '',
    vuln_type       TEXT NOT NULL,
    technology      TEXT NOT NULL DEFAULT '',
    success_count   INTEGER NOT NULL DEFAULT 0,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    last_updated    TEXT NOT NULL,
    PRIMARY KEY (payload_hash, vuln_type, technology)
);

CREATE INDEX IF NOT EXISTS idx_pe_vuln
    ON payload_effectiveness(vuln_type);
CREATE INDEX IF NOT EXISTS idx_pe_tech
    ON payload_effectiveness(technology);
"""


@dataclass
class TechVulnCorrelation:
    """Statistical correlation between a technology and a vulnerability type."""

    technology: str
    vuln_type: str
    hit_count: int = 0
    miss_count: int = 0
    confidence: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def sample_count(self) -> int:
        return self.hit_count + self.miss_count

    @property
    def frequency(self) -> float:
        """How often this tech has this vuln (0.0-1.0)."""
        total = self.hit_count + self.miss_count
        if total == 0:
            return 0.0
        return self.hit_count / total


@dataclass
class PayloadEffectiveness:
    """Track record for a specific payload."""

    payload_hash: str
    payload_preview: str = ""
    vuln_type: str = ""
    technology: str = ""
    success_count: int = 0
    failure_count: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def effectiveness(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    @property
    def total_uses(self) -> int:
        return self.success_count + self.failure_count


class SemanticMemory:
    """
    Cross-scan pattern learning engine backed by SQLite.

    Learns two things over time:

    * Which vulnerabilities are likely given a tech stack (Bayesian
      update on every observation).
    * Which payloads are most effective for a given vuln type and
      technology.

    Usage::

        mem = SemanticMemory()

        # Observe that WordPress had SQLi
        mem.learn_correlation("wordpress/6.2", "sqli", found=True)

        # Later — plan a scan for a WordPress target
        likely = mem.get_likely_vulns(["wordpress/6.2", "nginx"])
        for c in likely:
            print(f"{c.vuln_type}: freq={c.frequency:.0%} conf={c.confidence:.0%}")

        # Track payload success
        mem.learn_payload("' OR 1=1--", "sqli", success=True, tech="mysql")
        best = mem.get_best_payloads("sqli", tech="mysql")
    """

    # Beta prior parameters for Bayesian confidence estimation.
    # A weak prior (alpha=1, beta=1) gives a uniform distribution,
    # meaning new correlations start uncertain and converge quickly.
    _PRIOR_ALPHA = 1.0
    _PRIOR_BETA = 1.0

    def __init__(self, storage_path: Optional[Path] = None):
        self._storage_path = Path(storage_path) if storage_path else _DEFAULT_STORAGE
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._db_path = self._storage_path / "semantic.db"
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
        logger.debug("Semantic memory database initialised at %s", self._db_path)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Bayesian helpers
    # ------------------------------------------------------------------

    @classmethod
    def _beta_confidence(cls, hits: int, misses: int) -> float:
        """
        Bayesian confidence using a Beta distribution.

        Returns the *mean* of Beta(alpha + hits, beta + misses) scaled so
        that low sample counts produce low confidence.  The scaling factor
        is ``1 - 1/sqrt(n+1)`` which approaches 1 as *n* grows.
        """
        alpha = cls._PRIOR_ALPHA + hits
        beta = cls._PRIOR_BETA + misses
        mean = alpha / (alpha + beta)
        n = hits + misses
        # Scale down when sample size is small
        scale = 1.0 - 1.0 / math.sqrt(n + 1)
        return mean * scale

    # ------------------------------------------------------------------
    # Tech-vuln correlations
    # ------------------------------------------------------------------

    def learn_correlation(self, tech: str, vuln_type: str, found: bool) -> None:
        """
        Update the frequency estimate for *(tech, vuln_type)* based on a
        single observation.

        Args:
            tech: Technology identifier (e.g. ``"wordpress/6.2"``).
            vuln_type: Vulnerability class (e.g. ``"sqli"``).
            found: ``True`` if the vuln was present, ``False`` if tested
                   and absent.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        # Upsert — increment hit or miss count
        hit_inc = 1 if found else 0
        miss_inc = 0 if found else 1

        conn.execute(
            """INSERT INTO tech_vuln_correlations
                   (technology, vuln_type, hit_count, miss_count, confidence, last_updated)
               VALUES (?, ?, ?, ?, 0.0, ?)
               ON CONFLICT(technology, vuln_type) DO UPDATE SET
                   hit_count    = hit_count + ?,
                   miss_count   = miss_count + ?,
                   last_updated = ?""",
            (tech, vuln_type, hit_inc, miss_inc, now, hit_inc, miss_inc, now),
        )

        # Re-read counts to compute updated confidence
        row = conn.execute(
            "SELECT hit_count, miss_count FROM tech_vuln_correlations "
            "WHERE technology = ? AND vuln_type = ?",
            (tech, vuln_type),
        ).fetchone()

        if row:
            conf = self._beta_confidence(row["hit_count"], row["miss_count"])
            conn.execute(
                "UPDATE tech_vuln_correlations SET confidence = ? "
                "WHERE technology = ? AND vuln_type = ?",
                (conf, tech, vuln_type),
            )

        conn.commit()
        logger.debug(
            "Learned correlation: %s -> %s (found=%s)", tech, vuln_type, found
        )

    def get_likely_vulns(self, tech_stack: list[str]) -> list[TechVulnCorrelation]:
        """
        Given a tech stack, return vulnerability types sorted by
        ``frequency * confidence`` (descending).

        The result aggregates across all technologies in *tech_stack*,
        keeping the highest score per vuln type.
        """
        if not tech_stack:
            return []

        conn = self._get_conn()
        placeholders = ",".join("?" for _ in tech_stack)
        cursor = conn.execute(
            f"""SELECT technology, vuln_type, hit_count, miss_count,
                       confidence, last_updated
                FROM tech_vuln_correlations
                WHERE technology IN ({placeholders})
                ORDER BY confidence DESC""",
            tuple(tech_stack),
        )

        # Deduplicate: keep the highest-scoring entry per vuln_type
        best: dict[str, TechVulnCorrelation] = {}
        for row in cursor.fetchall():
            c = TechVulnCorrelation(
                technology=row["technology"],
                vuln_type=row["vuln_type"],
                hit_count=row["hit_count"],
                miss_count=row["miss_count"],
                confidence=row["confidence"],
                last_updated=datetime.fromisoformat(row["last_updated"]),
            )
            score = c.frequency * c.confidence
            existing = best.get(c.vuln_type)
            if existing is None or score > existing.frequency * existing.confidence:
                best[c.vuln_type] = c

        result = list(best.values())
        result.sort(key=lambda c: c.frequency * c.confidence, reverse=True)
        return result

    def get_correlations_for_tech(self, tech: str) -> list[TechVulnCorrelation]:
        """Return all known correlations for a single technology."""
        conn = self._get_conn()
        cursor = conn.execute(
            """SELECT technology, vuln_type, hit_count, miss_count,
                      confidence, last_updated
               FROM tech_vuln_correlations
               WHERE technology = ?
               ORDER BY confidence DESC""",
            (tech,),
        )
        return [
            TechVulnCorrelation(
                technology=row["technology"],
                vuln_type=row["vuln_type"],
                hit_count=row["hit_count"],
                miss_count=row["miss_count"],
                confidence=row["confidence"],
                last_updated=datetime.fromisoformat(row["last_updated"]),
            )
            for row in cursor.fetchall()
        ]

    # ------------------------------------------------------------------
    # Payload effectiveness
    # ------------------------------------------------------------------

    @staticmethod
    def _payload_hash(payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    def learn_payload(
        self, payload: str, vuln_type: str, success: bool, tech: str = ""
    ) -> None:
        """
        Track a payload's effectiveness against a vuln type / tech combo.

        Args:
            payload: The literal payload string.
            vuln_type: Vulnerability class (e.g. ``"sqli"``).
            success: Whether the payload triggered a positive result.
            tech: Technology it was tested against (optional).
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        p_hash = self._payload_hash(payload)
        preview = payload[:50]
        succ_inc = 1 if success else 0
        fail_inc = 0 if success else 1

        conn.execute(
            """INSERT INTO payload_effectiveness
                   (payload_hash, payload_preview, vuln_type, technology,
                    success_count, failure_count, last_updated)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(payload_hash, vuln_type, technology) DO UPDATE SET
                   success_count = success_count + ?,
                   failure_count = failure_count + ?,
                   last_updated  = ?""",
            (p_hash, preview, vuln_type, tech, succ_inc, fail_inc, now,
             succ_inc, fail_inc, now),
        )
        conn.commit()
        logger.debug(
            "Learned payload effectiveness: %s... -> %s (success=%s, tech=%s)",
            preview[:20], vuln_type, success, tech,
        )

    def get_best_payloads(
        self, vuln_type: str, tech: str | None = None, limit: int = 20
    ) -> list[PayloadEffectiveness]:
        """
        Get the most effective payloads for a vuln type, optionally
        filtered by technology.  Results are sorted by effectiveness
        (descending).
        """
        conn = self._get_conn()

        if tech:
            cursor = conn.execute(
                """SELECT payload_hash, payload_preview, vuln_type, technology,
                          success_count, failure_count, last_updated
                   FROM payload_effectiveness
                   WHERE vuln_type = ? AND technology = ?
                   ORDER BY CAST(success_count AS REAL) / MAX(success_count + failure_count, 1) DESC
                   LIMIT ?""",
                (vuln_type, tech, limit),
            )
        else:
            cursor = conn.execute(
                """SELECT payload_hash, payload_preview, vuln_type, technology,
                          success_count, failure_count, last_updated
                   FROM payload_effectiveness
                   WHERE vuln_type = ?
                   ORDER BY CAST(success_count AS REAL) / MAX(success_count + failure_count, 1) DESC
                   LIMIT ?""",
                (vuln_type, limit),
            )

        return [
            PayloadEffectiveness(
                payload_hash=row["payload_hash"],
                payload_preview=row["payload_preview"],
                vuln_type=row["vuln_type"],
                technology=row["technology"],
                success_count=row["success_count"],
                failure_count=row["failure_count"],
                last_updated=datetime.fromisoformat(row["last_updated"]),
            )
            for row in cursor.fetchall()
        ]

    # ------------------------------------------------------------------
    # Attack priority (composite helper)
    # ------------------------------------------------------------------

    def get_attack_priority(
        self, tech_stack: list[str]
    ) -> list[tuple[str, float]]:
        """
        Ranked list of ``(vuln_type, probability)`` for intelligent scan
        planning.  Probability is ``frequency * confidence`` for the best
        matching technology in the stack.
        """
        correlations = self.get_likely_vulns(tech_stack)
        return [
            (c.vuln_type, round(c.frequency * c.confidence, 4))
            for c in correlations
        ]

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def correlation_count(self) -> int:
        """Number of stored tech-vuln correlations."""
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM tech_vuln_correlations").fetchone()[0]

    def payload_count(self) -> int:
        """Number of stored payload records."""
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM payload_effectiveness").fetchone()[0]

    def prune_low_confidence(self, min_confidence: float = 0.1, min_samples: int = 2) -> int:
        """
        Remove correlations with low confidence *and* low sample count.
        Returns the number of rows removed.
        """
        conn = self._get_conn()
        cursor = conn.execute(
            """DELETE FROM tech_vuln_correlations
               WHERE confidence < ? AND (hit_count + miss_count) < ?""",
            (min_confidence, min_samples),
        )
        conn.commit()
        return cursor.rowcount
