"""
Vulnerability DNA — genetic fingerprinting for vulnerabilities.

Each vulnerability gets a DNA string encoding its characteristics.
Similar DNA = similar vulnerability = likely related root cause.
"""

from __future__ import annotations
import hashlib
from dataclasses import dataclass


@dataclass
class VulnDNA:
    dna_hash: str       # SHA256-based fingerprint
    category: str       # sqli, xss, etc.
    location_type: str  # parameter, header, cookie, body, path
    tech_context: str   # Framework/language context
    severity: str
    response_pattern: str  # How it manifests (error, timing, reflection, etc.)

    def similarity(self, other: VulnDNA) -> float:
        """Calculate similarity score (0.0-1.0) between two vulnerabilities."""
        score = 0.0
        if self.category == other.category: score += 0.3
        if self.location_type == other.location_type: score += 0.2
        if self.tech_context == other.tech_context: score += 0.2
        if self.response_pattern == other.response_pattern: score += 0.2
        if self.severity == other.severity: score += 0.1
        return score


class VulnDNAEngine:
    """Generate and analyze vulnerability DNA fingerprints."""

    def fingerprint(self, finding) -> VulnDNA:
        """Generate DNA for a finding."""
        category = (getattr(finding, 'category', '') or '').lower()
        url = getattr(finding, 'url', '') or ''
        evidence = getattr(finding, 'evidence', '') or ''
        severity = str(getattr(finding, 'severity', ''))

        location_type = self._detect_location_type(url, evidence)
        tech_context = self._detect_tech_context(evidence)
        response_pattern = self._detect_response_pattern(evidence)

        dna_string = f"{category}:{location_type}:{tech_context}:{response_pattern}"
        dna_hash = hashlib.sha256(dna_string.encode()).hexdigest()[:16]

        return VulnDNA(
            dna_hash=dna_hash,
            category=category,
            location_type=location_type,
            tech_context=tech_context,
            severity=severity,
            response_pattern=response_pattern,
        )

    def find_siblings(self, target_dna: VulnDNA, all_dna: list[VulnDNA],
                       threshold: float = 0.7) -> list[tuple[VulnDNA, float]]:
        """Find vulnerabilities with similar DNA."""
        siblings = []
        for dna in all_dna:
            if dna.dna_hash == target_dna.dna_hash:
                continue
            sim = target_dna.similarity(dna)
            if sim >= threshold:
                siblings.append((dna, sim))
        return sorted(siblings, key=lambda x: x[1], reverse=True)

    def cluster_findings(self, findings: list) -> dict[str, list[VulnDNA]]:
        """Group findings by DNA similarity (same root cause)."""
        dnas = [self.fingerprint(f) for f in findings]
        clusters: dict[str, list[VulnDNA]] = {}
        assigned = set()

        for i, dna in enumerate(dnas):
            if i in assigned:
                continue
            cluster_key = dna.dna_hash
            clusters[cluster_key] = [dna]
            assigned.add(i)

            for j, other in enumerate(dnas):
                if j in assigned:
                    continue
                if dna.similarity(other) >= 0.7:
                    clusters[cluster_key].append(other)
                    assigned.add(j)

        return clusters

    @staticmethod
    def _detect_location_type(url: str, evidence: str) -> str:
        if "header" in evidence.lower(): return "header"
        if "cookie" in evidence.lower(): return "cookie"
        if "json" in evidence.lower() or "body" in evidence.lower(): return "body"
        if "?" in url: return "parameter"
        return "path"

    @staticmethod
    def _detect_tech_context(evidence: str) -> str:
        e = evidence.lower()
        if "mysql" in e or "mariadb" in e: return "mysql"
        if "postgresql" in e or "postgres" in e: return "postgresql"
        if "sqlite" in e: return "sqlite"
        if "express" in e or "node" in e: return "nodejs"
        if "django" in e or "python" in e: return "python"
        if "php" in e or "laravel" in e: return "php"
        return "unknown"

    @staticmethod
    def _detect_response_pattern(evidence: str) -> str:
        e = evidence.lower()
        if "error" in e or "syntax" in e: return "error_based"
        if "time" in e or "sleep" in e or "delay" in e: return "time_based"
        if "reflect" in e: return "reflection"
        if "union" in e: return "union_based"
        if "boolean" in e or "true" in e and "false" in e: return "boolean_based"
        return "unknown"
