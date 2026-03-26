"""
Agent-to-Scanner Bridge.

Maps AgentSpec metadata to real scanner execution. Each of the 600 agents
is a specialized configuration of one of the 48 real scanners.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from secprobe.config import ScanConfig
from secprobe.models import Finding, ScanResult
from secprobe.core.crawler import AttackSurface
from secprobe.core.http_client import HTTPClient

logger = logging.getLogger(__name__)

# Map agent attack_types to scanner module names
ATTACK_TYPE_TO_SCANNER = {
    # SQLi variants
    "sqli": "sqli_scanner",
    "sqli-error": "sqli_scanner",
    "sqli-union": "sqli_scanner",
    "sqli-blind": "sqli_scanner",
    "sqli-time": "sqli_scanner",
    "sqli-boolean": "sqli_scanner",
    "sqli-oob": "sqli_scanner",
    "sqli-stacked": "sqli_scanner",
    "sqli-second-order": "sqli_scanner",
    # XSS variants
    "xss": "xss_scanner",
    "xss-reflected": "xss_scanner",
    "xss-stored": "xss_scanner",
    "xss-dom": "domxss_scanner",
    "xss-mutation": "xss_scanner",
    # Other injection
    "ssti": "ssti_scanner",
    "cmdi": "cmdi_scanner",
    "lfi": "lfi_scanner",
    "xxe": "xxe_scanner",
    "nosql": "nosql_scanner",
    "ldap": "ldap_scanner",
    "xpath": "xpath_scanner",
    "crlf": "crlf_scanner",
    "hpp": "hpp_scanner",
    # API/Protocol
    "api": "api_scanner",
    "graphql": "graphql_scanner",
    "websocket": "websocket_scanner",
    "oauth": "oauth_scanner",
    # Auth/Session
    "jwt": "jwt_scanner",
    "csrf": "csrf_scanner",
    "auth": "header_scanner",
    "session": "cookie_scanner",
    # Access control
    "idor": "idor_scanner",
    "bola": "idor_scanner",
    # Infrastructure
    "ssrf": "ssrf_scanner",
    "cors": "cors_scanner",
    "redirect": "redirect_scanner",
    "upload": "upload_scanner",
    "deserialization": "deserialization_scanner",
    "smuggling": "smuggling_scanner",
    "hostheader": "hostheader_scanner",
    "race": "race_scanner",
    # Recon
    "port-scan": "port_scanner",
    "ssl": "ssl_scanner",
    "headers": "header_scanner",
    "cookies": "cookie_scanner",
    "dns": "dns_scanner",
    "tech": "tech_scanner",
    "directory": "directory_scanner",
    # Advanced
    "prototype": "prototype_scanner",
    "cloud": "cloud_scanner",
    "cve": "cve_scanner",
    "takeover": "takeover_scanner",
    "email": "email_scanner",
    "bizlogic": "bizlogic_scanner",
    "waf": "waf_scanner",
    "js-analysis": "js_scanner",
    "cache-poison": "cache_poisoning_scanner",
    "fuzzing": "fuzzer_scanner",
    "passive": "passive_scanner",
}


@dataclass
class AgentRunResult:
    """Result of running an agent via the bridge."""
    agent_id: str
    agent_name: str
    division: int
    scanner_used: str
    findings: list[Finding] = field(default_factory=list)
    endpoints_tested: int = 0
    requests_made: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None


class AgentScannerBridge:
    """Bridge between AgentSpec metadata and real scanner execution."""

    def __init__(self, http_client: HTTPClient, attack_surface: Optional[AttackSurface] = None):
        self.http_client = http_client
        self.attack_surface = attack_surface or AttackSurface()
        self._scanner_cache: dict[str, type] = {}
        self._payload_cache: dict[str, list[str]] = {}

    def run_agent(self, agent_spec, target: str, mode: str = "audit",
                  timeout: float = 30.0) -> AgentRunResult:
        """
        Execute an agent's scan logic via the appropriate scanner.

        Args:
            agent_spec: AgentSpec object with attack_types, payloads, detection_patterns
            target: Target URL
            mode: Operational mode (recon/audit/redteam)
            timeout: Request timeout in seconds

        Returns:
            AgentRunResult with findings
        """
        start = time.time()

        result = AgentRunResult(
            agent_id=agent_spec.id,
            agent_name=agent_spec.name,
            division=agent_spec.division,
            scanner_used="",
        )

        # Determine which scanner to use
        scanner_name = self._resolve_scanner(agent_spec)
        if not scanner_name:
            result.error = f"No scanner mapped for attack types: {agent_spec.attack_types}"
            result.duration_seconds = time.time() - start
            return result

        result.scanner_used = scanner_name

        # Load and configure scanner
        try:
            scanner_class = self._load_scanner(scanner_name)
            if scanner_class is None:
                result.error = f"Scanner module not found: {scanner_name}"
                result.duration_seconds = time.time() - start
                return result

            # Build config for this agent
            config = ScanConfig(target=target, timeout=int(timeout))

            # Build context with attack surface
            from secprobe.core.context import ScanContext
            context = ScanContext(
                http_client=self.http_client,
                attack_surface=self.attack_surface,
            )

            # Instantiate and run scanner
            scanner = scanner_class(config, context)
            scan_result = scanner.run()

            result.findings = scan_result.findings
            result.endpoints_tested = len(self.attack_surface.endpoints)

        except Exception as e:
            result.error = str(e)
            logger.warning("Agent %s failed: %s", agent_spec.id, e, exc_info=True)

        result.duration_seconds = time.time() - start
        return result

    def run_agents_for_division(self, division_agents: list, target: str,
                                mode: str = "audit", max_agents: int = 10) -> list[AgentRunResult]:
        """Run multiple agents from a division, deduplicating by scanner."""
        results = []
        scanners_run: set[str] = set()

        for spec in division_agents[:max_agents]:
            scanner_name = self._resolve_scanner(spec)
            if scanner_name and scanner_name not in scanners_run:
                scanners_run.add(scanner_name)
                result = self.run_agent(spec, target, mode)
                results.append(result)
                logger.info(
                    "Agent %s (%s): %d findings in %.1fs",
                    spec.id, scanner_name, len(result.findings), result.duration_seconds
                )

        return results

    def _resolve_scanner(self, agent_spec) -> Optional[str]:
        """Map agent's attack_types to a scanner module name."""
        for attack_type in agent_spec.attack_types:
            normalized = attack_type.lower().replace(" ", "-").replace("_", "-")
            if normalized in ATTACK_TYPE_TO_SCANNER:
                return ATTACK_TYPE_TO_SCANNER[normalized]
            # Try prefix matching
            for key, scanner in ATTACK_TYPE_TO_SCANNER.items():
                if normalized.startswith(key) or key.startswith(normalized):
                    return scanner
        return None

    def _load_scanner(self, scanner_name: str):
        """Dynamically load a scanner class by module name."""
        if scanner_name in self._scanner_cache:
            return self._scanner_cache[scanner_name]

        try:
            module = __import__(f"secprobe.scanners.{scanner_name}", fromlist=[""])
            # Find the scanner class (convention: class name ends with Scanner)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type)
                    and attr_name.endswith("Scanner")
                    and attr_name != "BaseScanner"
                    and attr_name != "SmartScanner"):
                    self._scanner_cache[scanner_name] = attr
                    return attr
        except ImportError:
            logger.debug("Scanner module not found: %s", scanner_name)
        except Exception:
            logger.warning("Failed to load scanner: %s", scanner_name, exc_info=True)

        return None

    def get_scanner_for_agent(self, agent_spec) -> Optional[str]:
        """Get the scanner name for an agent (for inspection/debugging)."""
        return self._resolve_scanner(agent_spec)

    def get_coverage_report(self, agents: list) -> dict:
        """Report which scanners would be used for a set of agents."""
        coverage: dict[str, list[str]] = {}
        unmapped: list[str] = []

        for spec in agents:
            scanner = self._resolve_scanner(spec)
            if scanner:
                if scanner not in coverage:
                    coverage[scanner] = []
                coverage[scanner].append(spec.id)
            else:
                unmapped.append(spec.id)

        return {
            "mapped_scanners": len(coverage),
            "total_agents": len(agents),
            "unmapped_agents": len(unmapped),
            "coverage": {k: len(v) for k, v in coverage.items()},
            "unmapped": unmapped[:20],  # First 20 unmapped
        }
