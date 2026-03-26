"""
Post-scan learning — feeds scan results into memory tiers.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from secprobe.swarm.memory.semantic import SemanticMemory
from secprobe.swarm.memory.episodic import EpisodicMemory, ScanEpisode
from secprobe.swarm.memory.procedural import ProceduralMemory

logger = logging.getLogger(__name__)

_DEFAULT_MEMORY_PATH = Path.home() / ".secprobe" / "memory"


class ScanLearner:
    """Learns from completed scans to improve future scans."""

    def __init__(self, storage_path: Optional[Path] = None):
        self._path = storage_path or _DEFAULT_MEMORY_PATH
        self._semantic = SemanticMemory(storage_path=self._path)
        self._episodic = EpisodicMemory(storage_path=self._path)

    def learn_from_scan(self, target: str, tech_stack: list[str],
                         findings: list, scan_duration: float = 0.0,
                         mode: str = "audit") -> dict:
        """
        Learn from a completed scan.

        - Records episodic memory (scan history)
        - Updates semantic correlations (tech -> vuln patterns)
        - Tracks payload effectiveness

        Returns dict with learning stats.
        """
        stats = {"correlations_updated": 0, "episode_recorded": False}

        # 1. Record episodic memory
        try:
            episode = ScanEpisode(
                target=target,
                mode=mode,
                duration_seconds=scan_duration,
                findings=[self._serialize_finding(f) for f in findings],
                attack_surface={"tech_stack": tech_stack},
            )
            self._episodic.record_episode(episode)
            stats["episode_recorded"] = True
        except Exception:
            logger.warning("Failed to record episode", exc_info=True)

        # 2. Learn tech-vuln correlations
        vuln_types_found = set()
        for finding in findings:
            category = getattr(finding, 'category', '') or ''
            vuln_type = self._normalize_vuln_type(category)
            if vuln_type:
                vuln_types_found.add(vuln_type)

        # For each tech in stack, record which vulns were found
        scanner_types = {"sqli", "xss", "ssti", "cmdi", "lfi", "ssrf", "nosql",
                         "cors", "csrf", "idor", "jwt", "xxe", "redirect"}
        for tech in tech_stack:
            for vuln_type in scanner_types:
                found = vuln_type in vuln_types_found
                try:
                    self._semantic.learn_correlation(tech, vuln_type, found)
                    stats["correlations_updated"] += 1
                except Exception:
                    pass

        # 3. Learn payload effectiveness from evidence
        for finding in findings:
            evidence = getattr(finding, 'evidence', '') or ''
            category = getattr(finding, 'category', '') or ''
            vuln_type = self._normalize_vuln_type(category)
            if vuln_type and 'Payload:' in evidence:
                payload = evidence.split('Payload:')[1].strip().split('\n')[0]
                for tech in tech_stack:
                    try:
                        self._semantic.learn_payload(payload, vuln_type, True, tech)
                    except Exception:
                        pass

        logger.info("Learned from scan of %s: %d correlations, %d vuln types",
                    target, stats["correlations_updated"], len(vuln_types_found))
        return stats

    def get_scan_priorities(self, tech_stack: list[str]) -> list[tuple[str, float]]:
        """Get prioritized vuln types based on learned patterns."""
        try:
            return self._semantic.get_attack_priority(tech_stack)
        except Exception:
            return []

    def get_target_history(self, target: str) -> dict:
        """Get scan history for a target."""
        try:
            return self._episodic.get_target_history(target)
        except Exception:
            return {}

    def close(self):
        """Close memory connections."""
        self._semantic.close()
        self._episodic.close()

    @staticmethod
    def _normalize_vuln_type(category: str) -> str:
        category = category.lower().strip()
        mapping = {
            "sql injection": "sqli", "sqli": "sqli", "sql": "sqli",
            "cross-site scripting": "xss", "xss": "xss",
            "server-side template injection": "ssti", "ssti": "ssti",
            "command injection": "cmdi", "cmdi": "cmdi",
            "local file inclusion": "lfi", "lfi": "lfi",
            "server-side request forgery": "ssrf", "ssrf": "ssrf",
            "nosql injection": "nosql", "nosql": "nosql",
            "cors": "cors", "cross-origin": "cors",
            "csrf": "csrf", "cross-site request forgery": "csrf",
            "idor": "idor", "insecure direct object": "idor",
            "jwt": "jwt", "json web token": "jwt",
            "xxe": "xxe", "xml external entity": "xxe",
            "open redirect": "redirect", "redirect": "redirect",
            "header": "headers", "headers": "headers",
            "cookie": "cookies", "cookies": "cookies",
        }
        return mapping.get(category, category.split()[0] if category else "")

    @staticmethod
    def _serialize_finding(finding) -> dict:
        return {
            "title": getattr(finding, 'title', ''),
            "severity": str(getattr(finding, 'severity', '')),
            "category": getattr(finding, 'category', ''),
            "url": getattr(finding, 'url', ''),
            "cwe": getattr(finding, 'cwe', ''),
        }
