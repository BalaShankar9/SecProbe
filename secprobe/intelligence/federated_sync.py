"""
Federated intelligence sync — anonymized pattern sharing via Supabase.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class FederatedSync:
    """Sync intelligence with the federated community network."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._supabase_url = os.getenv("SECPROBE_SUPABASE_URL", "")
        self._supabase_key = os.getenv("SECPROBE_SUPABASE_KEY", "")
        self._memory = None

    def _get_memory(self):
        if self._memory is None:
            from secprobe.swarm.memory.federated import FederatedMemory
            self._memory = FederatedMemory(
                supabase_url=self._supabase_url,
                supabase_key=self._supabase_key,
                enabled=self.enabled and bool(self._supabase_url),
            )
        return self._memory

    def contribute_findings(self, findings: list, tech_stack: list[str],
                             waf_name: str = "") -> int:
        """
        Anonymize and contribute findings to community intelligence.

        PRIVACY: Only shares vuln_type, technology, payload_hash, effectiveness.
        NEVER shares: target URLs, IPs, credentials, raw payloads.
        """
        if not self.enabled:
            return 0

        memory = self._get_memory()
        count = 0

        for finding in findings:
            try:
                from secprobe.swarm.memory.federated import FederatedPattern

                category = getattr(finding, 'category', '') or ''
                evidence = getattr(finding, 'evidence', '') or ''

                # Hash the payload (never send raw)
                payload_hash = ""
                if "Payload:" in evidence:
                    payload = evidence.split("Payload:")[1].strip().split("\n")[0]
                    payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]

                tech = tech_stack[0] if tech_stack else ""

                pattern = FederatedPattern(
                    vuln_type=category.lower(),
                    technology=tech,
                    payload_hash=payload_hash,
                    effectiveness=1.0,  # Found = effective
                    waf_bypasses=[waf_name] if waf_name else [],
                )

                asyncio.run(memory.contribute_pattern(pattern))
                count += 1
            except Exception:
                logger.debug("Failed to contribute pattern", exc_info=True)

        logger.info("Contributed %d anonymized patterns to community", count)
        return count

    def query_intel(self, vuln_type: str, tech: str = "") -> list[dict]:
        """Query community intelligence for patterns."""
        if not self.enabled:
            return []

        try:
            memory = self._get_memory()
            patterns = asyncio.run(memory.query_patterns(vuln_type, tech))
            return [{"vuln_type": p.vuln_type, "technology": p.technology,
                     "effectiveness": p.effectiveness, "contributors": p.contributor_count}
                    for p in patterns]
        except Exception:
            return []

    def query_waf_intel(self, waf_name: str) -> list[dict]:
        """Query community WAF bypass intelligence."""
        if not self.enabled:
            return []

        try:
            memory = self._get_memory()
            return asyncio.run(memory.query_waf_bypasses(waf_name))
        except Exception:
            return []

    def get_trending(self) -> list[dict]:
        """Get trending vulnerabilities from community."""
        if not self.enabled:
            return []

        try:
            memory = self._get_memory()
            return asyncio.run(memory.get_trending_vulns())
        except Exception:
            return []

    async def close(self):
        if self._memory:
            await self._memory.close()
