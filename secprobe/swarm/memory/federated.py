"""
L5: Federated Memory — Community intelligence (opt-in, anonymized).

The most powerful memory tier. When enabled, SecProbe can learn from
the collective experience of all users:
    - "This payload bypassed Cloudflare for 47 users this week"
    - "WordPress 6.4 has a new SQLi pattern in REST API"
    - "AWS WAF v2 blocks X-Forwarded-For spoofing since March"

Privacy model:
    - ALL data is anonymized before sharing (no target URLs, IPs, or org info)
    - Only patterns are shared: (technology, vulnerability_type, success_rate)
    - Users opt-in explicitly with --federated flag
    - Local-only mode is the default

This module defines the data structures and local aggregation logic.
The actual network sync is a separate service (not included here).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FederatedInsight:
    """An anonymized insight from the community."""
    id: str
    category: str                   # "waf_bypass", "tech_vuln", "payload_success", etc.
    conditions: dict[str, Any] = field(default_factory=dict)
    insight: str = ""               # What was learned
    confidence: float = 0.0         # Community confidence (0.0-1.0)
    contributors: int = 0           # How many unique users contributed
    first_reported: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    payload_hash: str = ""          # SHA256 of payload (not the payload itself)
    success_rate: float = 0.0
    sample_size: int = 0


@dataclass
class LocalContribution:
    """Data we're willing to share (anonymized)."""
    technology: str = ""            # e.g., "wordpress", "nginx"
    technology_version: str = ""    # e.g., "6.4", "1.25"
    vulnerability_type: str = ""    # e.g., "sqli", "xss"
    waf_detected: str = ""          # e.g., "cloudflare", "aws_waf"
    payload_hash: str = ""          # SHA256 hash of successful payload
    success: bool = False
    evasion_technique: str = ""     # e.g., "double_url_encode", "unicode_normalization"
    timestamp: float = field(default_factory=time.time)

    @staticmethod
    def hash_payload(payload: str) -> str:
        """Hash a payload for privacy-preserving sharing."""
        return hashlib.sha256(payload.encode()).hexdigest()


class FederatedMemory:
    """
    Community intelligence layer — opt-in, privacy-first.

    Usage:
        mem = FederatedMemory(enabled=True)
        mem.load()

        # Query community intelligence
        insights = mem.query(conditions={"waf": "cloudflare", "vuln_type": "sqli"})
        for i in insights:
            print(f"{i.insight} ({i.confidence:.0%} confidence, {i.contributors} users)")

        # Contribute anonymized data
        mem.contribute(LocalContribution(
            technology="wordpress",
            technology_version="6.4",
            vulnerability_type="sqli",
            waf_detected="cloudflare",
            payload_hash=LocalContribution.hash_payload("' OR 1=1--"),
            success=True,
            evasion_technique="double_url_encode",
        ))

        mem.persist()
    """

    def __init__(self, enabled: bool = False, storage_dir: str = ""):
        self.enabled = enabled
        if not storage_dir:
            storage_dir = os.path.join(os.path.expanduser("~"), ".secprobe", "memory", "federated")
        self._storage_dir = storage_dir
        self._insights: dict[str, FederatedInsight] = {}
        self._contributions: list[LocalContribution] = []
        self._pending_sync: list[LocalContribution] = []

    def query(self, *, category: str = "",
              conditions: dict[str, Any] | None = None,
              min_confidence: float = 0.5,
              min_contributors: int = 2) -> list[FederatedInsight]:
        """Query community insights."""
        if not self.enabled:
            return []

        results = list(self._insights.values())

        if category:
            results = [i for i in results if i.category == category]

        if min_confidence > 0:
            results = [i for i in results if i.confidence >= min_confidence]

        if min_contributors > 0:
            results = [i for i in results if i.contributors >= min_contributors]

        if conditions:
            matched = []
            for insight in results:
                overlap = any(
                    k in insight.conditions and insight.conditions[k] == v
                    for k, v in conditions.items()
                )
                if overlap:
                    matched.append(insight)
            results = matched

        results.sort(key=lambda i: (i.confidence, i.contributors), reverse=True)
        return results

    def contribute(self, contribution: LocalContribution):
        """Add an anonymized contribution for future sync."""
        if not self.enabled:
            return
        self._contributions.append(contribution)
        self._pending_sync.append(contribution)

        # Also update local insights based on our own contributions
        self._update_local_insight(contribution)

    def _update_local_insight(self, contrib: LocalContribution):
        """Update local insight database from our own contribution."""
        key = f"{contrib.technology}:{contrib.vulnerability_type}:{contrib.waf_detected}"
        insight_id = hashlib.sha256(key.encode()).hexdigest()[:16]

        existing = self._insights.get(insight_id)
        if existing:
            existing.sample_size += 1
            if contrib.success:
                existing.success_rate = (
                    (existing.success_rate * (existing.sample_size - 1) + 1.0)
                    / existing.sample_size
                )
            else:
                existing.success_rate = (
                    (existing.success_rate * (existing.sample_size - 1) + 0.0)
                    / existing.sample_size
                )
            existing.last_updated = time.time()
        else:
            self._insights[insight_id] = FederatedInsight(
                id=insight_id,
                category="local_observation",
                conditions={
                    "technology": contrib.technology,
                    "vulnerability_type": contrib.vulnerability_type,
                    "waf": contrib.waf_detected,
                },
                insight=f"{contrib.vulnerability_type} on {contrib.technology} "
                        f"{'succeeded' if contrib.success else 'failed'}"
                        f"{' (WAF: ' + contrib.waf_detected + ')' if contrib.waf_detected else ''}",
                confidence=1.0 if contrib.success else 0.0,
                contributors=1,
                success_rate=1.0 if contrib.success else 0.0,
                sample_size=1,
                payload_hash=contrib.payload_hash,
            )

    def get_pending_sync(self) -> list[dict]:
        """Get contributions ready for network sync (anonymized dicts)."""
        pending = [
            {
                "technology": c.technology,
                "technology_version": c.technology_version,
                "vulnerability_type": c.vulnerability_type,
                "waf_detected": c.waf_detected,
                "payload_hash": c.payload_hash,
                "success": c.success,
                "evasion_technique": c.evasion_technique,
            }
            for c in self._pending_sync
        ]
        self._pending_sync.clear()
        return pending

    def ingest_remote(self, insights: list[dict]):
        """Ingest insights received from the federated network."""
        for item in insights:
            insight = FederatedInsight(
                id=item.get("id", ""),
                category=item.get("category", "community"),
                conditions=item.get("conditions", {}),
                insight=item.get("insight", ""),
                confidence=item.get("confidence", 0.5),
                contributors=item.get("contributors", 1),
                success_rate=item.get("success_rate", 0.0),
                sample_size=item.get("sample_size", 1),
                payload_hash=item.get("payload_hash", ""),
            )
            self._insights[insight.id] = insight

    @property
    def count(self) -> int:
        return len(self._insights)

    @property
    def contribution_count(self) -> int:
        return len(self._contributions)

    def persist(self) -> str:
        """Save insights and contributions to disk."""
        os.makedirs(self._storage_dir, exist_ok=True)
        path = os.path.join(self._storage_dir, "federated.json")
        data = {
            "insights": [
                {
                    "id": i.id, "category": i.category,
                    "conditions": i.conditions, "insight": i.insight,
                    "confidence": i.confidence, "contributors": i.contributors,
                    "first_reported": i.first_reported, "last_updated": i.last_updated,
                    "success_rate": i.success_rate, "sample_size": i.sample_size,
                    "payload_hash": i.payload_hash,
                }
                for i in self._insights.values()
            ],
            "contributions": [
                {
                    "technology": c.technology,
                    "technology_version": c.technology_version,
                    "vulnerability_type": c.vulnerability_type,
                    "waf_detected": c.waf_detected,
                    "payload_hash": c.payload_hash,
                    "success": c.success,
                    "evasion_technique": c.evasion_technique,
                    "timestamp": c.timestamp,
                }
                for c in self._contributions
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def load(self) -> int:
        """Load from disk. Returns count of insights loaded."""
        path = os.path.join(self._storage_dir, "federated.json")
        if not os.path.exists(path):
            return 0
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("insights", []):
            self._insights[item["id"]] = FederatedInsight(
                id=item["id"], category=item.get("category", ""),
                conditions=item.get("conditions", {}),
                insight=item.get("insight", ""),
                confidence=item.get("confidence", 0.5),
                contributors=item.get("contributors", 1),
                first_reported=item.get("first_reported", 0),
                last_updated=item.get("last_updated", 0),
                success_rate=item.get("success_rate", 0.0),
                sample_size=item.get("sample_size", 1),
                payload_hash=item.get("payload_hash", ""),
            )
        return len(self._insights)
