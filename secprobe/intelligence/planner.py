"""
Intelligent scan planning — uses memory to optimize scan order.
"""

from __future__ import annotations

import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ScanPlanner:
    """Uses learned patterns to plan optimal scan strategy."""

    def __init__(self, storage_path: Optional[Path] = None):
        from secprobe.intelligence.learning import ScanLearner
        self._learner = ScanLearner(storage_path)

    def plan_scan(self, target: str, tech_stack: list[str],
                   available_scanners: list[str]) -> list[str]:
        """
        Reorder scanners based on learned patterns.

        Scanners for more likely vulns run first.
        """
        priorities = self._learner.get_scan_priorities(tech_stack)

        if not priorities:
            return available_scanners  # No data, use default order

        # Build priority map
        priority_map = {vuln: score for vuln, score in priorities}

        # Map scanner names to vuln types
        scanner_vuln_map = {
            "sqli_scanner": "sqli", "xss_scanner": "xss",
            "ssti_scanner": "ssti", "cmdi_scanner": "cmdi",
            "lfi_scanner": "lfi", "ssrf_scanner": "ssrf",
            "nosql_scanner": "nosql", "cors_scanner": "cors",
            "csrf_scanner": "csrf", "jwt_scanner": "jwt",
            "xxe_scanner": "xxe", "redirect_scanner": "redirect",
            "header_scanner": "headers", "cookie_scanner": "cookies",
            "idor_scanner": "idor",
        }

        def sort_key(scanner_name: str) -> float:
            vuln = scanner_vuln_map.get(scanner_name, "")
            return -priority_map.get(vuln, 0.0)  # Higher priority = lower sort key

        sorted_scanners = sorted(available_scanners, key=sort_key)

        logger.info("Scan plan for %s: %s (based on %d learned patterns)",
                    target, [s[:15] for s in sorted_scanners[:5]], len(priorities))

        return sorted_scanners

    def get_recommended_divisions(self, tech_stack: list[str]) -> list[int]:
        """Recommend which swarm divisions to deploy based on tech stack."""
        priorities = self._learner.get_scan_priorities(tech_stack)

        vuln_to_division = {
            "sqli": [2], "xss": [2, 6], "ssti": [2], "cmdi": [2],
            "lfi": [12], "ssrf": [8], "nosql": [2], "cors": [1],
            "csrf": [3], "jwt": [3, 7], "xxe": [12], "redirect": [2],
            "idor": [4], "auth": [3], "headers": [1],
        }

        divisions = set([1, 18, 19, 20])  # Always include recon, compliance, intel, meta

        for vuln, score in priorities:
            if score > 0.3:  # Only include if probability > 30%
                for div in vuln_to_division.get(vuln, []):
                    divisions.add(div)

        return sorted(divisions)

    def close(self):
        self._learner.close()
