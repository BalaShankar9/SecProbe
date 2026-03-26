"""
Records successful attack sequences as replayable procedures.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from secprobe.swarm.memory.procedural import (
    ProceduralMemory, AttackProcedure, AttackStep
)

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path.home() / ".secprobe" / "memory"


class ProcedureRecorder:
    """Records and replays attack procedures."""

    def __init__(self, storage_path: Optional[Path] = None):
        self._memory = ProceduralMemory(storage_path=storage_path or _DEFAULT_PATH)

    def record_from_findings(self, findings: list, tech_stack: list[str]) -> int:
        """
        Extract attack procedures from scan findings.

        Each finding with evidence containing payloads becomes a procedure step.
        Multi-finding chains on the same endpoint become multi-step procedures.

        Returns count of procedures recorded.
        """
        count = 0
        # Group findings by URL
        by_url: dict[str, list] = {}
        for f in findings:
            url = getattr(f, 'url', '') or ''
            if url:
                by_url.setdefault(url, []).append(f)

        for url, url_findings in by_url.items():
            for finding in url_findings:
                category = getattr(finding, 'category', '') or ''
                evidence = getattr(finding, 'evidence', '') or ''
                title = getattr(finding, 'title', '') or ''

                if not category:
                    continue

                # Extract payload from evidence
                payload = ""
                if "Payload:" in evidence:
                    payload = evidence.split("Payload:")[1].strip().split("\n")[0]
                elif "payload" in evidence.lower():
                    lines = evidence.split("\n")
                    for line in lines:
                        if "payload" in line.lower():
                            payload = line.split(":", 1)[-1].strip() if ":" in line else line
                            break

                # Extract parameter
                param = ""
                if "parameter" in title.lower():
                    # "SQL Injection in parameter 'q'" -> q
                    m = re.search(r"parameter\s+['\"]?(\w+)", title, re.IGNORECASE)
                    if m:
                        param = m.group(1)

                # Build procedure
                tech = tech_stack[0] if tech_stack else "unknown"
                step = AttackStep(
                    action="inject_payload",
                    target_url=url,
                    parameter=param,
                    payload=payload,
                    response_indicator=title,
                )
                procedure = AttackProcedure(
                    vuln_type=self._normalize_category(category),
                    technology=tech,
                    name=f"{title} on {url}",
                    steps=[step],
                    success_count=1,
                )
                try:
                    self._memory.record_procedure(procedure)
                    count += 1
                except Exception:
                    logger.debug("Failed to record procedure", exc_info=True)

        logger.info("Recorded %d procedures from %d findings", count, len(findings))
        return count

    def find_known_procedures(self, vuln_type: str, tech: str = "") -> list[AttackProcedure]:
        """Find known procedures for a vuln type and tech."""
        try:
            return self._memory.find_procedure(vuln_type, tech=tech or None)
        except Exception:
            return []

    def get_quick_wins(self, tech_stack: list[str]) -> list[AttackProcedure]:
        """Get high-success-rate procedures for this tech stack."""
        results = []
        common_vulns = ["sqli", "xss", "ssti", "lfi", "ssrf", "idor"]
        for tech in tech_stack:
            for vuln in common_vulns:
                procs = self.find_known_procedures(vuln, tech)
                results.extend(procs)
        # Sort by success count descending
        results.sort(key=lambda p: p.success_count, reverse=True)
        return results[:20]  # Top 20

    def close(self):
        self._memory.close()

    @staticmethod
    def _normalize_category(category: str) -> str:
        mapping = {
            "sql injection": "sqli", "sqli": "sqli",
            "cross-site scripting": "xss", "xss": "xss",
            "ssti": "ssti", "cmdi": "cmdi", "lfi": "lfi",
            "ssrf": "ssrf", "nosql": "nosql", "cors": "cors",
            "csrf": "csrf", "idor": "idor", "jwt": "jwt",
            "xxe": "xxe", "redirect": "redirect",
        }
        return mapping.get(category.lower().strip(), category.lower().split()[0] if category else "")
