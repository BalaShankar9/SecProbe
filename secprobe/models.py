"""
Data models for scan results and findings.

v5.0.0 — Added CVSS 3.1 scoring, OWASP/CWE/PCI-DSS/NIST compliance fields.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    """Represents a single security finding with enterprise compliance data."""

    title: str
    severity: str
    description: str
    recommendation: str = ""
    evidence: str = ""
    scanner: str = ""
    category: str = ""
    url: str = ""
    cwe: str = ""

    # ── CVSS 3.1 Scoring ─────────────────────────────────────────
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cvss_severity: str = ""

    # ── Compliance Mappings ───────────────────────────────────────
    owasp_category: str = ""      # e.g. "A03:2021 - Injection"
    pci_dss: list[str] = field(default_factory=list)  # e.g. ["6.5.1", "6.2.4"]
    nist: list[str] = field(default_factory=list)      # e.g. ["SI-10", "SI-15"]

    @property
    def details(self) -> str:
        """Alias for description — used by attack chain analyzer."""
        return self.description

    @property
    def remediation(self) -> str:
        """Alias for recommendation — used by template engine."""
        return self.recommendation

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "scanner": self.scanner,
            "category": self.category,
            "url": self.url,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cvss_severity": self.cvss_severity,
            "owasp_category": self.owasp_category,
            "pci_dss": self.pci_dss,
            "nist": self.nist,
        }


@dataclass
class ScanResult:
    """Aggregated results from a scanner module."""

    scanner_name: str
    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    findings: list[Finding] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def finding_count(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "raw_data": self.raw_data,
            "error": self.error,
        }
