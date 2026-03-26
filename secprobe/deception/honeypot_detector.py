"""
Honeypot Detection — identify if targets are honeypots/deception systems.

Checks for telltale signs:
- Too many open ports (real servers don't have 100+ ports open)
- Known honeypot signatures (Cowrie, Kippo, HoneyDB)
- Intentionally vulnerable services
- Fake data patterns
"""

from __future__ import annotations
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class HoneypotIndicator:
    indicator: str
    confidence: float  # 0.0-1.0
    description: str


class HoneypotDetector:
    """Detect if a target is a honeypot or deception system."""

    # Known honeypot signatures
    SIGNATURES = {
        "cowrie": [
            "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",  # Cowrie default
        ],
        "kippo": [
            "SSH-2.0-OpenSSH_5.1p1 Debian-5",  # Kippo default
        ],
        "glastopf": [
            "Blog Comments",  # Glastopf default page
        ],
        "honeyd": [
            "Microsoft-IIS/5.0",  # Common honeyd impersonation
        ],
    }

    def analyze(self, target_info: dict) -> list[HoneypotIndicator]:
        """Analyze target for honeypot indicators."""
        indicators = []

        # Check for too many open ports
        open_ports = target_info.get("open_ports", [])
        if len(open_ports) > 50:
            indicators.append(HoneypotIndicator(
                indicator="excessive_ports",
                confidence=0.7,
                description=f"{len(open_ports)} open ports detected — real servers rarely have this many",
            ))

        # Check for known honeypot banners
        banners = target_info.get("service_banners", {})
        for port, banner in banners.items():
            for honey_type, sigs in self.SIGNATURES.items():
                for sig in sigs:
                    if sig in banner:
                        indicators.append(HoneypotIndicator(
                            indicator=f"{honey_type}_signature",
                            confidence=0.9,
                            description=f"Known {honey_type} honeypot signature detected on port {port}",
                        ))

        # Check for intentionally vulnerable responses
        responses = target_info.get("responses", {})
        vuln_count = sum(1 for r in responses.values()
                        if isinstance(r, dict) and r.get("status") == 200
                        and any(p in str(r.get("body", ""))
                               for p in ["root:x:0:0", "admin:admin", "SELECT * FROM"]))
        if vuln_count >= 3:
            indicators.append(HoneypotIndicator(
                indicator="too_vulnerable",
                confidence=0.6,
                description=f"Target returns obviously vulnerable content on {vuln_count} endpoints — possible honeypot",
            ))

        # Check for fake/generated data patterns
        data_responses = target_info.get("data_responses", [])
        if self._detect_fake_data(data_responses):
            indicators.append(HoneypotIndicator(
                indicator="fake_data",
                confidence=0.5,
                description="Response data appears auto-generated — possible honeypot with fake data",
            ))

        return indicators

    def is_likely_honeypot(self, indicators: list[HoneypotIndicator]) -> tuple[bool, float]:
        """Determine if target is likely a honeypot based on indicators."""
        if not indicators:
            return False, 0.0
        avg_confidence = sum(i.confidence for i in indicators) / len(indicators)
        is_honeypot = avg_confidence > 0.6 and len(indicators) >= 2
        return is_honeypot, avg_confidence

    @staticmethod
    def _detect_fake_data(responses: list) -> bool:
        """Detect auto-generated/fake data patterns."""
        if not responses:
            return False
        # Check for sequential IDs, lorem ipsum, etc.
        for resp in responses:
            text = str(resp).lower()
            if "lorem ipsum" in text or "john doe" in text:
                return True
            if "example.com" in text and "test@example.com" in text:
                return True
        return False
