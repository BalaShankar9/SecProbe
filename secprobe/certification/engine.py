"""
SecProbe Certification Engine — 5-tier security certification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json


class CertLevel(Enum):
    BRONZE = "bronze"      # Pass recon + config checks
    SILVER = "silver"      # No critical/high vulns
    GOLD = "gold"          # No vulns above LOW
    PLATINUM = "platinum"  # Pass full redteam, no exploitable chains
    DIAMOND = "diamond"    # 90-day continuous monitoring, zero regressions


@dataclass
class Certification:
    cert_id: str
    target: str
    level: CertLevel
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = None  # 90 days from issue
    scan_id: str = ""
    findings_summary: dict = field(default_factory=dict)
    risk_score: float = 0.0
    grade: str = ""
    attestation_hash: str = ""  # SHA256 of certification data


class CertificationEngine:
    """Evaluate scan results and issue certifications."""

    def evaluate(self, findings: list, risk_score: float, grade: str,
                 mode: str = "audit") -> CertLevel | None:
        """
        Determine certification level based on scan results.

        Returns None if target doesn't qualify for any level.
        """
        severity_counts = {}
        for f in findings:
            sev = str(getattr(f, 'severity', 'INFO')).upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        critical = severity_counts.get('CRITICAL', 0)
        high = severity_counts.get('HIGH', 0)
        medium = severity_counts.get('MEDIUM', 0)
        low = severity_counts.get('LOW', 0)

        # Diamond requires continuous monitoring (not evaluable from single scan)
        # Platinum requires redteam mode with no exploitable chains
        if mode == "redteam" and critical == 0 and high == 0 and medium == 0 and low == 0:
            return CertLevel.PLATINUM
        # Gold: no vulns above LOW
        if critical == 0 and high == 0 and medium == 0:
            return CertLevel.GOLD
        # Silver: no critical or high
        if critical == 0 and high == 0:
            return CertLevel.SILVER
        # Bronze: basic hygiene (risk score > 40)
        if risk_score >= 40:
            return CertLevel.BRONZE

        return None  # Doesn't qualify

    def issue_certification(self, target: str, level: CertLevel,
                            scan_id: str = "", findings_summary: dict = None,
                            risk_score: float = 0.0, grade: str = "") -> Certification:
        """Issue a certification."""
        from datetime import timedelta

        cert = Certification(
            cert_id=hashlib.sha256(f"{target}:{level.value}:{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            target=target,
            level=level,
            scan_id=scan_id,
            findings_summary=findings_summary or {},
            risk_score=risk_score,
            grade=grade,
        )
        cert.expires_at = cert.issued_at + timedelta(days=90)
        cert.attestation_hash = self._compute_attestation(cert)
        return cert

    def verify_certification(self, cert: Certification) -> bool:
        """Verify a certification's attestation hash."""
        return cert.attestation_hash == self._compute_attestation(cert)

    @staticmethod
    def _compute_attestation(cert: Certification) -> str:
        data = json.dumps({
            "cert_id": cert.cert_id,
            "target": cert.target,
            "level": cert.level.value,
            "issued_at": cert.issued_at.isoformat(),
            "risk_score": cert.risk_score,
            "grade": cert.grade,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()
