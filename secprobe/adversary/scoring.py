"""
Universal Security Score (0-100) with industry benchmarking.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class SecurityScore:
    total: float  # 0-100
    vulnerability_score: float  # 0-40
    configuration_score: float  # 0-20
    architecture_score: float  # 0-20
    resilience_score: float  # 0-20
    grade: str  # A+ through F
    percentile: float = 0.0  # vs industry benchmark


class SecurityScorer:
    """Calculate universal security score from scan results."""

    def score(self, findings: list, headers_present: list[str] = None,
              tls_grade: str = "", has_rate_limiting: bool = False,
              has_waf: bool = False) -> SecurityScore:
        vuln = self._score_vulnerabilities(findings)
        config = self._score_configuration(headers_present or [])
        arch = self._score_architecture(findings)
        resilience = self._score_resilience(has_rate_limiting, has_waf)

        total = vuln + config + arch + resilience
        total = max(0.0, min(100.0, total))

        return SecurityScore(
            total=round(total, 1),
            vulnerability_score=round(vuln, 1),
            configuration_score=round(config, 1),
            architecture_score=round(arch, 1),
            resilience_score=round(resilience, 1),
            grade=self._grade(total),
        )

    def _score_vulnerabilities(self, findings: list) -> float:
        score = 40.0
        for f in findings:
            sev = str(getattr(f, 'severity', '')).upper()
            if 'CRITICAL' in sev:
                score -= 15
            elif 'HIGH' in sev:
                score -= 8
            elif 'MEDIUM' in sev:
                score -= 3
            elif 'LOW' in sev:
                score -= 1
        return max(0.0, score)

    def _score_configuration(self, headers: list[str]) -> float:
        score = 0.0
        important_headers = {
            "strict-transport-security": 4,
            "content-security-policy": 4,
            "x-content-type-options": 2,
            "x-frame-options": 2,
            "referrer-policy": 2,
            "permissions-policy": 2,
            "x-xss-protection": 1,
            "x-permitted-cross-domain-policies": 1,
        }
        headers_lower = [h.lower() for h in headers]
        for header, points in important_headers.items():
            if header in headers_lower:
                score += points
        return min(20.0, score)

    def _score_architecture(self, findings: list) -> float:
        score = 20.0
        # Deduct for common architectural issues
        categories = [str(getattr(f, 'category', '')).lower() for f in findings]
        if any('idor' in c or 'bola' in c for c in categories):
            score -= 5  # Missing authorization
        if any('cors' in c for c in categories):
            score -= 3  # CORS misconfiguration
        if any('info' in c and 'disclosure' in c for c in categories):
            score -= 2  # Information leakage
        return max(0.0, score)

    def _score_resilience(self, has_rate_limiting: bool, has_waf: bool) -> float:
        score = 0.0
        if has_rate_limiting:
            score += 10
        if has_waf:
            score += 10
        return min(20.0, score)

    @staticmethod
    def _grade(score: float) -> str:
        if score >= 95: return "A+"
        if score >= 90: return "A"
        if score >= 85: return "A-"
        if score >= 80: return "B+"
        if score >= 75: return "B"
        if score >= 70: return "B-"
        if score >= 65: return "C+"
        if score >= 60: return "C"
        if score >= 55: return "C-"
        if score >= 50: return "D"
        return "F"
