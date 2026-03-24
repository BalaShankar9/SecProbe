"""
L3: Semantic Memory — Learned patterns across multiple scans.

Semantic memory stores generalizable knowledge:
    - "WordPress sites running PHP < 8.0 frequently have SQLi in wp-admin"
    - "Cloudflare WAF blocks payloads with '<script>' but not '\\x3cscript\\x3e'"
    - "API endpoints returning 405 for DELETE often lack auth on PUT"

This is built by analyzing episodic memories (L2) across scans.
Patterns that appear repeatedly get promoted to semantic knowledge,
which guides future scan planning and agent prioritization.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SemanticPattern:
    """A learned pattern from cross-scan analysis."""
    id: str
    description: str
    category: str                  # "tech_correlation", "waf_bypass", "attack_sequence", etc.
    conditions: dict[str, Any] = field(default_factory=dict)  # When this pattern applies
    predictions: dict[str, Any] = field(default_factory=dict)  # What it predicts
    confidence: float = 0.0        # 0.0-1.0 — how reliable this pattern is
    evidence_count: int = 0        # How many scans confirmed this
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    false_positive_rate: float = 0.0  # Rate of predictions that were wrong
    tags: tuple[str, ...] = ()

    def reinforce(self, success: bool):
        """Update confidence based on new evidence."""
        self.evidence_count += 1
        self.last_seen = time.time()
        if success:
            # Bayesian-style update: confidence converges toward observed rate
            self.confidence = (
                (self.confidence * (self.evidence_count - 1) + 1.0)
                / self.evidence_count
            )
        else:
            self.confidence = (
                (self.confidence * (self.evidence_count - 1) + 0.0)
                / self.evidence_count
            )
            self.false_positive_rate = (
                (self.false_positive_rate * (self.evidence_count - 1) + 1.0)
                / self.evidence_count
            )

    @property
    def is_reliable(self) -> bool:
        """A pattern is reliable if high confidence and enough evidence."""
        return self.confidence >= 0.7 and self.evidence_count >= 3


class SemanticMemory:
    """
    Cross-scan pattern learning engine.

    Usage:
        mem = SemanticMemory(storage_dir="~/.secprobe/memory/semantic")
        mem.load()

        # Learn a new pattern
        mem.learn(SemanticPattern(
            id="wp-sqli-correlation",
            description="WordPress < 6.0 with SQLi in search parameter",
            category="tech_correlation",
            conditions={"cms": "wordpress", "version_lt": "6.0"},
            predictions={"likely_vuln": "sqli", "likely_param": "s"},
            confidence=0.85,
            evidence_count=12,
        ))

        # Query during scan planning
        patterns = mem.query(conditions={"cms": "wordpress"})
        for p in patterns:
            print(f"Predict {p.predictions} with {p.confidence:.0%} confidence")

        mem.persist()
    """

    def __init__(self, storage_dir: str = ""):
        if not storage_dir:
            storage_dir = os.path.join(os.path.expanduser("~"), ".secprobe", "memory", "semantic")
        self._storage_dir = storage_dir
        self._patterns: dict[str, SemanticPattern] = {}
        self._by_category: dict[str, list[str]] = {}

    def learn(self, pattern: SemanticPattern):
        """Add or update a semantic pattern."""
        existing = self._patterns.get(pattern.id)
        if existing:
            # Merge — reinforce existing pattern
            existing.reinforce(True)
            existing.predictions.update(pattern.predictions)
        else:
            self._patterns[pattern.id] = pattern
            self._by_category.setdefault(pattern.category, []).append(pattern.id)

    def reinforce(self, pattern_id: str, success: bool):
        """Reinforce or weaken a pattern based on new evidence."""
        pattern = self._patterns.get(pattern_id)
        if pattern:
            pattern.reinforce(success)

    def query(self, *, category: str = "",
              conditions: dict[str, Any] | None = None,
              min_confidence: float = 0.5,
              tag: str = "") -> list[SemanticPattern]:
        """Query patterns matching given criteria."""
        results = list(self._patterns.values())

        if category:
            ids = self._by_category.get(category, [])
            results = [p for p in results if p.id in ids]

        if min_confidence > 0:
            results = [p for p in results if p.confidence >= min_confidence]

        if tag:
            results = [p for p in results if tag in p.tags]

        if conditions:
            matched = []
            for pattern in results:
                # Check if pattern conditions overlap with query conditions
                overlap = any(
                    k in pattern.conditions and pattern.conditions[k] == v
                    for k, v in conditions.items()
                )
                if overlap:
                    matched.append(pattern)
            results = matched

        # Sort by confidence descending
        results.sort(key=lambda p: p.confidence, reverse=True)
        return results

    def get(self, pattern_id: str) -> SemanticPattern | None:
        return self._patterns.get(pattern_id)

    def prune(self, min_confidence: float = 0.3, min_evidence: int = 2) -> int:
        """Remove unreliable patterns. Returns count removed."""
        to_remove = [
            pid for pid, p in self._patterns.items()
            if p.confidence < min_confidence or p.evidence_count < min_evidence
        ]
        for pid in to_remove:
            del self._patterns[pid]
        return len(to_remove)

    @property
    def count(self) -> int:
        return len(self._patterns)

    def persist(self) -> str:
        """Save all patterns to disk."""
        os.makedirs(self._storage_dir, exist_ok=True)
        path = os.path.join(self._storage_dir, "patterns.json")
        data = [
            {
                "id": p.id,
                "description": p.description,
                "category": p.category,
                "conditions": p.conditions,
                "predictions": p.predictions,
                "confidence": p.confidence,
                "evidence_count": p.evidence_count,
                "first_seen": p.first_seen,
                "last_seen": p.last_seen,
                "false_positive_rate": p.false_positive_rate,
                "tags": list(p.tags),
            }
            for p in self._patterns.values()
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def load(self) -> int:
        """Load patterns from disk. Returns count loaded."""
        path = os.path.join(self._storage_dir, "patterns.json")
        if not os.path.exists(path):
            return 0
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            pattern = SemanticPattern(
                id=item["id"],
                description=item["description"],
                category=item["category"],
                conditions=item.get("conditions", {}),
                predictions=item.get("predictions", {}),
                confidence=item.get("confidence", 0.5),
                evidence_count=item.get("evidence_count", 1),
                first_seen=item.get("first_seen", 0),
                last_seen=item.get("last_seen", 0),
                false_positive_rate=item.get("false_positive_rate", 0.0),
                tags=tuple(item.get("tags", ())),
            )
            self._patterns[pattern.id] = pattern
            self._by_category.setdefault(pattern.category, []).append(pattern.id)
        return len(data)
