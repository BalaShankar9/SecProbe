"""
Bug bounty triage — automatically verify and prioritize incoming reports.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class TriageVerdict(Enum):
    CONFIRMED = "confirmed"      # Vulnerability is real and reproducible
    PARTIAL = "partial"          # Exists but impact differs from report
    DUPLICATE = "duplicate"      # Already known from SecProbe scan
    INVALID = "invalid"          # Cannot reproduce
    NEEDS_REVIEW = "needs_review"  # Requires human review


@dataclass
class BountyReport:
    report_id: str
    target_url: str
    vuln_type: str
    description: str
    payload: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    reporter: str = ""
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TriageResult:
    report_id: str
    verdict: TriageVerdict
    confidence: float = 0.0  # 0-1
    matching_findings: list[str] = field(default_factory=list)  # Matching finding titles
    auto_severity: str = ""
    notes: str = ""


class BountyTriageEngine:
    """Automatically verify and triage bug bounty reports."""

    def triage(self, report: BountyReport, existing_findings: list) -> TriageResult:
        """
        Auto-triage a bug bounty report against existing scan findings.
        """
        result = TriageResult(report_id=report.report_id, verdict=TriageVerdict.NEEDS_REVIEW)

        # Check for duplicates against existing findings
        matching = self._find_matching_findings(report, existing_findings)
        if matching:
            result.matching_findings = [getattr(f, 'title', '') for f in matching]
            result.verdict = TriageVerdict.DUPLICATE
            result.confidence = 0.9
            result.notes = f"Matches {len(matching)} existing finding(s)"
            result.auto_severity = str(getattr(matching[0], 'severity', ''))
            return result

        # Validate the report has enough info
        if not report.target_url or not report.vuln_type:
            result.verdict = TriageVerdict.INVALID
            result.confidence = 0.7
            result.notes = "Missing target URL or vulnerability type"
            return result

        # If we have a payload, we could theoretically re-test
        # For now, mark as needs_review with classification
        result.verdict = TriageVerdict.NEEDS_REVIEW
        result.confidence = 0.5
        result.auto_severity = self._estimate_severity(report.vuln_type)
        result.notes = f"Vuln type: {report.vuln_type}, has payload: {bool(report.payload)}"
        return result

    def _find_matching_findings(self, report: BountyReport, findings: list) -> list:
        """Find existing findings that match this report."""
        matches = []
        report_url = report.target_url.lower()
        report_type = report.vuln_type.lower()

        for f in findings:
            f_url = (getattr(f, 'url', '') or '').lower()
            f_cat = (getattr(f, 'category', '') or '').lower()
            f_title = (getattr(f, 'title', '') or '').lower()

            # URL and category match
            url_match = f_url and (f_url in report_url or report_url in f_url)
            type_match = (report_type in f_cat or report_type in f_title or
                         f_cat in report_type)

            if url_match and type_match:
                matches.append(f)
            elif type_match and not report_url:
                matches.append(f)

        return matches

    @staticmethod
    def _estimate_severity(vuln_type: str) -> str:
        critical = {"sqli", "cmdi", "rce", "deserialization", "ssrf"}
        high = {"xss", "auth", "idor", "lfi", "xxe", "ssti"}
        medium = {"csrf", "cors", "redirect", "jwt", "nosql"}
        low = {"headers", "cookies", "info"}

        vt = vuln_type.lower()
        if any(c in vt for c in critical):
            return "CRITICAL"
        if any(h in vt for h in high):
            return "HIGH"
        if any(m in vt for m in medium):
            return "MEDIUM"
        return "LOW"
