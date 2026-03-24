"""
Finding Deduplicator — intelligent cross-scanner deduplication.

Groups similar findings, merges duplicates, and provides a unified
view without noise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional

from secprobe.models import Finding


@dataclass
class FindingGroup:
    """A group of related/duplicate findings."""
    primary: Finding
    duplicates: list[Finding] = field(default_factory=list)
    scanners: set[str] = field(default_factory=set)

    @property
    def count(self) -> int:
        return 1 + len(self.duplicates)

    @property
    def highest_severity(self) -> str:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        all_findings = [self.primary] + self.duplicates
        return min(all_findings, key=lambda f: order.get(f.severity, 5)).severity


class FindingDeduplicator:
    """Deduplicates findings across scanners using similarity analysis."""

    def __init__(self, similarity_threshold: float = 0.75):
        self.threshold = similarity_threshold

    def deduplicate(self, findings: list[Finding]) -> list[FindingGroup]:
        """Group similar findings together.
        
        Returns:
            List of FindingGroup objects, sorted by severity
        """
        if not findings:
            return []

        groups: list[FindingGroup] = []

        for finding in findings:
            merged = False
            for group in groups:
                if self._is_similar(finding, group.primary):
                    group.duplicates.append(finding)
                    group.scanners.add(finding.scanner)
                    merged = True
                    break

            if not merged:
                groups.append(FindingGroup(
                    primary=finding,
                    scanners={finding.scanner},
                ))

        # Sort by severity
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        groups.sort(key=lambda g: sev_order.get(g.highest_severity, 5))
        return groups

    def _is_similar(self, a: Finding, b: Finding) -> bool:
        """Determine if two findings are similar enough to be grouped."""
        # Same scanner, same title → definitely duplicate
        if a.scanner == b.scanner and a.title == b.title:
            return True

        # Different scanners but very similar titles
        title_sim = SequenceMatcher(None, a.title.lower(), b.title.lower()).ratio()
        if title_sim >= self.threshold:
            return True

        # Same URL and same vulnerability class
        if a.url == b.url and self._same_vuln_class(a, b):
            return True

        return False

    @staticmethod
    def _same_vuln_class(a: Finding, b: Finding) -> bool:
        """Check if two findings belong to the same vulnerability class."""
        classes = {
            "injection": {"sqli", "xss"},
            "crypto": {"ssl"},
            "config": {"header", "cookie", "cors"},
            "recon": {"port", "dns", "tech", "directory"},
        }
        a_class = None
        b_class = None
        for cls, scanners in classes.items():
            if a.scanner.lower() in scanners:
                a_class = cls
            if b.scanner.lower() in scanners:
                b_class = cls

        return a_class is not None and a_class == b_class

    def get_stats(self, groups: list[FindingGroup]) -> dict:
        """Get deduplication statistics."""
        total_findings = sum(g.count for g in groups)
        unique_findings = len(groups)
        duplicates_removed = total_findings - unique_findings

        return {
            "total_findings": total_findings,
            "unique_findings": unique_findings,
            "duplicates_removed": duplicates_removed,
            "dedup_ratio": round(duplicates_removed / max(total_findings, 1) * 100, 1),
            "cross_scanner_groups": sum(1 for g in groups if len(g.scanners) > 1),
        }
