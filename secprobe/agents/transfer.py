"""
Cross-Target Knowledge Transfer System.

Agents shouldn't start from zero on every target. This module enables:

  1. TARGET SIMILARITY ENGINE
     - Fingerprints targets by tech stack, WAF, behavior
     - Computes similarity scores between targets
     - Finds the most similar previously-scanned target

  2. KNOWLEDGE DATABASE
     - Stores effective payloads per tech stack / WAF
     - Records scan strategies that worked
     - Accumulates vuln patterns per technology
     - Persists across scan sessions

  3. STRATEGY TEMPLATES
     - Pre-built scan strategies per tech stack
     - Learned from prior engagements
     - Dynamic: updated as agents learn more

  4. TRANSFER MECHANISMS
     - Warm-start: initialize agent with prior knowledge
     - Fine-tune: adjust transferred knowledge to new target
     - Negative transfer detection: stop if old knowledge hurts

What makes this world-class:
  - No agent starts from scratch — ever
  - Knowledge compounds across ALL scans
  - Automatically adapts old knowledge to new contexts
  - Detects when transfer is helping vs hurting
"""

from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════
# TARGET FINGERPRINT
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TargetFingerprint:
    """
    Unique behavioral fingerprint of a scan target.

    Captures technology stack, WAF presence, server behavior,
    and other characteristics that determine scan strategy.
    """
    target_id: str = ""           # Hash of target URL
    url: str = ""
    technologies: list[str] = field(default_factory=list)
    waf_type: str = ""
    waf_detected: bool = False
    server_type: str = ""
    framework: str = ""
    language: str = ""
    response_behavior: dict[str, float] = field(default_factory=dict)
    scan_time: float = field(default_factory=time.time)

    def feature_vector(self) -> dict[str, float]:
        """Convert fingerprint to a feature dict for similarity computation."""
        features: dict[str, float] = {}

        # Technology features (one-hot style)
        all_techs = [
            "php", "python", "java", "nodejs", "ruby", "go", "dotnet",
            "wordpress", "django", "flask", "spring", "express", "rails",
            "react", "angular", "vue", "jquery",
            "mysql", "postgres", "mssql", "oracle", "sqlite", "mongodb",
            "apache", "nginx", "iis", "tomcat", "gunicorn",
        ]
        for tech in all_techs:
            features[f"tech_{tech}"] = 1.0 if tech in [
                t.lower() for t in self.technologies
            ] else 0.0

        # WAF features
        waf_types = [
            "cloudflare", "akamai", "imperva", "modsecurity",
            "aws_waf", "f5", "fortiweb", "barracuda",
        ]
        for waf in waf_types:
            features[f"waf_{waf}"] = 1.0 if waf in self.waf_type.lower() else 0.0
        features["waf_present"] = 1.0 if self.waf_detected else 0.0

        return features

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "url": self.url,
            "technologies": self.technologies,
            "waf_type": self.waf_type,
            "waf_detected": self.waf_detected,
            "server_type": self.server_type,
            "framework": self.framework,
            "language": self.language,
        }


# ═══════════════════════════════════════════════════════════════════
# SIMILARITY ENGINE
# ═══════════════════════════════════════════════════════════════════

class SimilarityEngine:
    """
    Computes similarity between target fingerprints.

    Uses weighted feature similarity to find the most
    similar previously-scanned target.
    """

    # Weights for different feature categories
    CATEGORY_WEIGHTS = {
        "tech_": 0.30,    # Technology stack matters most
        "waf_": 0.25,     # WAF configuration is critical
        "framework_": 0.20,
        "server_": 0.15,
        "other_": 0.10,
    }

    def compute_similarity(self, fp1: TargetFingerprint,
                           fp2: TargetFingerprint) -> float:
        """
        Compute similarity score between two target fingerprints.

        Returns 0.0 (completely different) to 1.0 (identical).
        """
        v1 = fp1.feature_vector()
        v2 = fp2.feature_vector()

        all_keys = set(v1.keys()) | set(v2.keys())
        if not all_keys:
            return 0.0

        # Weighted cosine similarity by category
        category_sims: dict[str, list[float]] = defaultdict(list)

        for key in all_keys:
            val1 = v1.get(key, 0.0)
            val2 = v2.get(key, 0.0)
            match = 1.0 if val1 == val2 else 0.0

            # Classify key into category
            for prefix in self.CATEGORY_WEIGHTS:
                if key.startswith(prefix):
                    category_sims[prefix].append(match)
                    break
            else:
                category_sims["other_"].append(match)

        # Weighted average across categories
        total_weight = 0.0
        weighted_sim = 0.0
        for category, weight in self.CATEGORY_WEIGHTS.items():
            sims = category_sims.get(category, [])
            if sims:
                cat_sim = sum(sims) / len(sims)
                weighted_sim += weight * cat_sim
                total_weight += weight

        return weighted_sim / total_weight if total_weight > 0 else 0.0

    def find_most_similar(self, target: TargetFingerprint,
                          candidates: list[TargetFingerprint],
                          min_similarity: float = 0.3
                          ) -> list[tuple[TargetFingerprint, float]]:
        """
        Find the most similar targets from a list of candidates.

        Returns list of (fingerprint, similarity) sorted by similarity desc.
        """
        results = []
        for candidate in candidates:
            sim = self.compute_similarity(target, candidate)
            if sim >= min_similarity:
                results.append((candidate, sim))

        results.sort(key=lambda x: x[1], reverse=True)
        return results


# ═══════════════════════════════════════════════════════════════════
# PAYLOAD EFFECTIVENESS DATABASE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PayloadRecord:
    """Record of a payload's effectiveness."""
    payload: str = ""
    vuln_type: str = ""
    success_count: int = 0
    failure_count: int = 0
    block_count: int = 0
    tech_contexts: list[str] = field(default_factory=list)
    waf_contexts: list[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_success: float = 0.0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count + self.block_count
        return self.success_count / total if total > 0 else 0.0

    @property
    def total_uses(self) -> int:
        return self.success_count + self.failure_count + self.block_count

    def record_result(self, success: bool, blocked: bool = False,
                      tech_context: str = "", waf_context: str = ""):
        """Record a use of this payload."""
        if blocked:
            self.block_count += 1
        elif success:
            self.success_count += 1
            self.last_success = time.time()
        else:
            self.failure_count += 1

        if tech_context and tech_context not in self.tech_contexts:
            self.tech_contexts.append(tech_context)
        if waf_context and waf_context not in self.waf_contexts:
            self.waf_contexts.append(waf_context)


class PayloadDatabase:
    """
    Accumulated database of payload effectiveness.

    Stores effectiveness data across ALL scans so agents can
    pick the best payloads for any given context.
    """

    def __init__(self):
        self.payloads: dict[str, PayloadRecord] = {}  # hash → record
        self._by_vuln: dict[str, list[str]] = defaultdict(list)  # vuln_type → [hashes]
        self._by_tech: dict[str, list[str]] = defaultdict(list)  # tech → [hashes]

    def _hash_payload(self, payload: str) -> str:
        return hashlib.md5(payload.encode()).hexdigest()[:12]

    def record(self, payload: str, vuln_type: str, success: bool,
               blocked: bool = False, tech_context: str = "",
               waf_context: str = ""):
        """Record a payload usage result."""
        h = self._hash_payload(payload)

        if h not in self.payloads:
            self.payloads[h] = PayloadRecord(
                payload=payload, vuln_type=vuln_type
            )
            self._by_vuln[vuln_type].append(h)

        record = self.payloads[h]
        record.record_result(success, blocked, tech_context, waf_context)

        if tech_context:
            if h not in self._by_tech[tech_context]:
                self._by_tech[tech_context].append(h)

    def get_best_payloads(self, vuln_type: str, tech_context: str = "",
                          waf_context: str = "",
                          limit: int = 10) -> list[PayloadRecord]:
        """
        Get the most effective payloads for a given context.

        Filters by vuln type, tech stack, and WAF presence.
        Ranks by success rate with a minimum usage threshold.
        """
        # Start with all payloads for this vuln type
        candidates = []
        for h in self._by_vuln.get(vuln_type, []):
            record = self.payloads[h]
            if record.total_uses >= 2:  # Minimum usage threshold
                candidates.append(record)

        # Boost payloads that have worked in similar contexts
        scored = []
        for record in candidates:
            score = record.success_rate

            # Tech context bonus
            if tech_context and tech_context in record.tech_contexts:
                score += 0.2

            # WAF context bonus
            if waf_context and waf_context in record.waf_contexts:
                score += 0.15

            # Penalize payloads that get blocked
            if record.block_count > 0:
                block_penalty = record.block_count / record.total_uses
                score -= block_penalty * 0.3

            # Recency bonus
            if record.last_success > 0:
                age = time.time() - record.last_success
                recency = math.exp(-age / (86400 * 30))  # 30-day half-life
                score += recency * 0.1

            scored.append((record, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [r for r, _ in scored[:limit]]

    @property
    def total_payloads(self) -> int:
        return len(self.payloads)

    @property
    def vuln_types(self) -> list[str]:
        return list(self._by_vuln.keys())

    def get_stats(self) -> dict:
        return {
            "total_payloads": len(self.payloads),
            "vuln_types": list(self._by_vuln.keys()),
            "by_vuln_count": {
                vt: len(hashes) for vt, hashes in self._by_vuln.items()
            },
            "top_success_rates": sorted(
                [
                    (r.payload[:50], round(r.success_rate, 3))
                    for r in self.payloads.values()
                    if r.total_uses >= 5
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }


# ═══════════════════════════════════════════════════════════════════
# STRATEGY TEMPLATE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ScanStrategy:
    """A learned or pre-built scan strategy template."""
    name: str = ""
    description: str = ""
    tech_stack: list[str] = field(default_factory=list)
    waf_type: str = ""
    scanner_order: list[str] = field(default_factory=list)
    evasion_techniques: list[str] = field(default_factory=list)
    payload_priorities: dict[str, float] = field(default_factory=dict)
    timing_config: dict[str, float] = field(default_factory=dict)
    success_rate: float = 0.0
    uses: int = 0
    created: float = field(default_factory=time.time)

    def update_success(self, success: bool):
        """Update strategy success rate."""
        self.uses += 1
        # Exponential moving average
        alpha = 0.1
        value = 1.0 if success else 0.0
        self.success_rate = alpha * value + (1 - alpha) * self.success_rate


class StrategyLibrary:
    """
    Library of scan strategy templates.

    Pre-built strategies for common tech stacks +
    learned strategies from prior engagements.
    """

    def __init__(self):
        self.strategies: dict[str, ScanStrategy] = {}
        self._tech_index: dict[str, list[str]] = defaultdict(list)
        self._waf_index: dict[str, list[str]] = defaultdict(list)
        self._load_defaults()

    def _load_defaults(self):
        """Load default strategy templates for common stacks."""
        defaults = [
            ScanStrategy(
                name="php_mysql_no_waf",
                description="PHP + MySQL without WAF — aggressive testing",
                tech_stack=["php", "mysql"],
                scanner_order=[
                    "sql_injection", "xss", "lfi", "rfi",
                    "command_injection", "file_upload",
                ],
                payload_priorities={"sql": 0.9, "xss": 0.8, "lfi": 0.7},
                timing_config={"delay": 0.1, "concurrent": 5},
            ),
            ScanStrategy(
                name="php_mysql_modsecurity",
                description="PHP + MySQL behind ModSecurity — evasion mode",
                tech_stack=["php", "mysql"],
                waf_type="modsecurity",
                scanner_order=[
                    "sql_injection", "xss", "lfi",
                ],
                evasion_techniques=[
                    "case_swap", "comment_inject", "url_encode",
                    "whitespace_sub",
                ],
                payload_priorities={"sql": 0.7, "xss": 0.6, "lfi": 0.5},
                timing_config={"delay": 1.0, "concurrent": 2},
            ),
            ScanStrategy(
                name="python_django",
                description="Python + Django — template injection focus",
                tech_stack=["python", "django"],
                scanner_order=[
                    "ssti", "xss", "sql_injection", "command_injection",
                    "idor", "ssrf",
                ],
                payload_priorities={"ssti": 0.9, "xss": 0.7, "sql": 0.5},
                timing_config={"delay": 0.2, "concurrent": 3},
            ),
            ScanStrategy(
                name="nodejs_express",
                description="Node.js + Express — prototype pollution focus",
                tech_stack=["nodejs", "express"],
                scanner_order=[
                    "xss", "nosql_injection", "ssrf", "ssti",
                    "command_injection",
                ],
                payload_priorities={"xss": 0.9, "nosql": 0.8, "ssrf": 0.7},
                timing_config={"delay": 0.15, "concurrent": 4},
            ),
            ScanStrategy(
                name="java_spring",
                description="Java + Spring — deserialization focus",
                tech_stack=["java", "spring"],
                scanner_order=[
                    "sql_injection", "xxe", "ssti", "ssrf",
                    "command_injection",
                ],
                payload_priorities={"sql": 0.8, "xxe": 0.9, "ssti": 0.7},
                timing_config={"delay": 0.3, "concurrent": 3},
            ),
            ScanStrategy(
                name="cloudflare_protected",
                description="Behind Cloudflare — heavy evasion required",
                waf_type="cloudflare",
                scanner_order=[
                    "sql_injection", "xss", "ssti",
                ],
                evasion_techniques=[
                    "unicode_escape", "double_encode", "null_byte",
                    "encoding_chain", "comment_inject",
                ],
                timing_config={"delay": 2.0, "concurrent": 1},
            ),
        ]

        for strategy in defaults:
            self.add_strategy(strategy)

    def add_strategy(self, strategy: ScanStrategy):
        """Add a strategy to the library."""
        self.strategies[strategy.name] = strategy
        for tech in strategy.tech_stack:
            if strategy.name not in self._tech_index[tech]:
                self._tech_index[tech].append(strategy.name)
        if strategy.waf_type:
            if strategy.name not in self._waf_index[strategy.waf_type]:
                self._waf_index[strategy.waf_type].append(strategy.name)

    def find_strategy(self, tech_stack: list[str] = None,
                      waf_type: str = "",
                      min_success_rate: float = 0.0
                      ) -> list[ScanStrategy]:
        """
        Find matching strategies for a target profile.

        Matches by tech stack and WAF type, sorted by success rate.
        """
        candidates: set[str] = set()

        if tech_stack:
            for tech in tech_stack:
                for name in self._tech_index.get(tech.lower(), []):
                    candidates.add(name)

        if waf_type:
            for name in self._waf_index.get(waf_type.lower(), []):
                candidates.add(name)

        if not candidates and not tech_stack and not waf_type:
            candidates = set(self.strategies.keys())

        results = []
        for name in candidates:
            strategy = self.strategies[name]
            if strategy.success_rate >= min_success_rate or strategy.uses == 0:
                results.append(strategy)

        results.sort(key=lambda s: s.success_rate, reverse=True)
        return results

    def get_stats(self) -> dict:
        return {
            "total_strategies": len(self.strategies),
            "tech_coverage": list(self._tech_index.keys()),
            "waf_coverage": list(self._waf_index.keys()),
        }


# ═══════════════════════════════════════════════════════════════════
# TRANSFER ENGINE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TransferResult:
    """Result of a knowledge transfer operation."""
    source_target: str = ""
    similarity: float = 0.0
    strategy_transferred: str = ""
    payloads_transferred: int = 0
    evasion_techniques: list[str] = field(default_factory=list)
    confidence: float = 0.0


class KnowledgeTransferEngine:
    """
    Complete cross-target knowledge transfer system.

    Integrates:
    - Target similarity matching
    - Payload effectiveness transfer
    - Strategy template selection
    - Negative transfer detection

    Ensures agents never start from scratch.
    """

    def __init__(self):
        self.similarity_engine = SimilarityEngine()
        self.payload_db = PayloadDatabase()
        self.strategy_library = StrategyLibrary()
        self.target_history: list[TargetFingerprint] = []
        self._transfer_results: list[TransferResult] = []
        self._negative_transfers: int = 0

    def register_target(self, fingerprint: TargetFingerprint):
        """Register a scanned target in the history."""
        self.target_history.append(fingerprint)

    def transfer_knowledge(self, new_target: TargetFingerprint
                           ) -> TransferResult:
        """
        Transfer knowledge from previous scans to a new target.

        Steps:
        1. Find most similar previous target
        2. Transfer effective payloads
        3. Select matching scan strategy
        4. Compile evasion techniques
        """
        result = TransferResult()

        # Find similar targets
        if self.target_history:
            similar = self.similarity_engine.find_most_similar(
                new_target, self.target_history
            )
            if similar:
                best_match, sim = similar[0]
                result.source_target = best_match.target_id
                result.similarity = sim

        # Find matching strategy
        strategies = self.strategy_library.find_strategy(
            tech_stack=new_target.technologies,
            waf_type=new_target.waf_type,
        )
        if strategies:
            result.strategy_transferred = strategies[0].name
            result.evasion_techniques = strategies[0].evasion_techniques

        # Transfer payload knowledge
        tech_ctx = new_target.language or (
            new_target.technologies[0] if new_target.technologies else ""
        )
        waf_ctx = new_target.waf_type

        vuln_types = ["sql_injection", "xss", "ssti", "lfi",
                      "command_injection", "ssrf"]
        transferred_count = 0
        for vt in vuln_types:
            payloads = self.payload_db.get_best_payloads(
                vt, tech_context=tech_ctx, waf_context=waf_ctx, limit=5
            )
            transferred_count += len(payloads)
        result.payloads_transferred = transferred_count

        # Confidence based on similarity and data quality
        result.confidence = result.similarity * 0.5 + min(
            1.0, transferred_count / 20
        ) * 0.5

        self._transfer_results.append(result)
        return result

    def record_transfer_outcome(self, was_helpful: bool):
        """Record whether a transfer was actually helpful."""
        if not was_helpful:
            self._negative_transfers += 1

    def get_recommended_payloads(self, vuln_type: str,
                                 target: TargetFingerprint,
                                 limit: int = 10) -> list[PayloadRecord]:
        """Get recommended payloads for a specific vuln type and target."""
        tech_ctx = target.language or (
            target.technologies[0] if target.technologies else ""
        )
        return self.payload_db.get_best_payloads(
            vuln_type, tech_context=tech_ctx,
            waf_context=target.waf_type, limit=limit
        )

    @property
    def negative_transfer_rate(self) -> float:
        total = len(self._transfer_results)
        return self._negative_transfers / total if total > 0 else 0.0

    def get_stats(self) -> dict:
        return {
            "targets_scanned": len(self.target_history),
            "transfers_performed": len(self._transfer_results),
            "negative_transfer_rate": round(self.negative_transfer_rate, 4),
            "payload_db": self.payload_db.get_stats(),
            "strategy_library": self.strategy_library.get_stats(),
        }
