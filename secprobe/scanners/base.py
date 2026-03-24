"""
Base scanner class — all scanner modules inherit from this.

Every scanner receives:
  - ScanConfig: target, timeout, threads, proxy, etc.
  - ScanContext: shared HTTPClient, AuthHandler, WAFDetector, AttackSurface

Scanners access the shared HTTP client via self.http_client, which
has connection pooling, retry logic, rate limiting, proxy, auth,
and WAF evasion already configured.

Injection scanners should use self.detection_engine for baseline-aware
false-positive elimination:
    engine = self._init_detection_engine()
    engine.profile(url, params=...)
    result = engine.test_error_based(url, param, payload, response.text, ...)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from secprobe.config import ScanConfig
from secprobe.models import ScanResult, Finding
from secprobe.utils import print_section, print_status

if TYPE_CHECKING:
    from secprobe.core.context import ScanContext
    from secprobe.core.http_client import HTTPClient
    from secprobe.core.crawler import AttackSurface
    from secprobe.core.detection import DetectionEngine


class BaseScanner(ABC):
    """Abstract base for every scanner module."""

    name: str = "BaseScanner"
    description: str = ""

    def __init__(self, config: ScanConfig, context: Optional[ScanContext] = None):
        self.config = config
        self.context = context
        self.result = ScanResult(scanner_name=self.name, target=config.target)
        self._detection_engine: Optional[DetectionEngine] = None

    # ── Convenience properties for shared services ───────────────
    @property
    def http_client(self) -> Optional[HTTPClient]:
        """Shared HTTP client with pooling, retry, rate limiting, auth."""
        return self.context.http_client if self.context else None

    @property
    def attack_surface(self) -> Optional[AttackSurface]:
        """Crawled URLs, forms, endpoints from the spider phase."""
        return self.context.attack_surface if self.context else None

    @property
    def waf_detected(self) -> Optional[str]:
        """Name of detected WAF, if any."""
        return self.context.waf_name if self.context else None

    @property
    def detection_engine(self) -> Optional[DetectionEngine]:
        """Shared detection engine for baseline-aware analysis."""
        return self._detection_engine

    def _init_detection_engine(self, baseline_samples: int = 5) -> DetectionEngine:
        """
        Initialize the detection engine for this scanner.

        Call at the start of scan() in injection scanners.
        The engine profiles endpoints to establish baselines and
        provides statistically-grounded detection methods.
        """
        from secprobe.core.detection import DetectionEngine, Confidence
        self._detection_engine = DetectionEngine(
            self.http_client,
            baseline_samples=baseline_samples,
            baseline_delay=self.config.rate_limit or 0.3,
            min_confidence=Confidence.FIRM,
        )
        return self._detection_engine

    def run(self) -> ScanResult:
        """Execute the scan with timing and error handling."""
        print_section(f"{self.name} — {self.description}")
        self.result.start_time = datetime.now()
        try:
            self.scan()
        except KeyboardInterrupt:
            print_status("Scan interrupted by user", "warning")
            self.result.error = "Interrupted"
        except Exception as exc:
            self.result.error = str(exc)
            print_status(f"Scanner error: {exc}", "error")
        finally:
            self.result.end_time = datetime.now()
            self._print_summary()
        return self.result

    @abstractmethod
    def scan(self):
        """Override this method to implement the actual scanning logic."""
        ...

    def add_finding(self, title: str, severity: str, description: str,
                    recommendation: str = "", evidence: str = "",
                    category: str = "", url: str = "", cwe: str = ""):
        # ── Auto-enrich with CVSS & compliance data ──────────────
        cvss_score = None
        cvss_vector = ""
        cvss_severity = ""
        owasp_category = ""
        pci_dss: list[str] = []
        nist: list[str] = []

        try:
            from secprobe.core.cvss import get_cvss_for_finding
            cvss_result = get_cvss_for_finding(self.name, severity)
            if cvss_result:
                cvss_score = cvss_result.base_score
                cvss_vector = cvss_result.vector_string
                cvss_severity = cvss_result.base_severity
        except Exception:
            pass

        try:
            from secprobe.core.vulnerability_db import (
                get_scanner_cwes, get_owasp_category, get_pci_requirements
            )
            # SCANNER_CWE_MAP uses full scanner names like "SQL Injection Scanner"
            cwe_entries = get_scanner_cwes(self.name)
            if cwe_entries:
                first_cwe = cwe_entries[0]
                if not cwe:
                    cwe = first_cwe.cwe_id
                owasp_info = get_owasp_category(first_cwe.cwe_id)
                if owasp_info:
                    owasp_category = f"{owasp_info.code} - {owasp_info.name}"
                pci_reqs = get_pci_requirements(first_cwe.cwe_id)
                pci_dss = [r.req_id for r in pci_reqs]
                nist = list(first_cwe.nist)
        except Exception:
            pass

        finding = Finding(
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation,
            evidence=evidence,
            scanner=self.name,
            category=category,
            url=url or self.config.target,
            cwe=cwe,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_severity=cvss_severity,
            owasp_category=owasp_category,
            pci_dss=pci_dss,
            nist=nist,
        )
        self.result.add_finding(finding)

    # ── OOB (Out-of-Band) Helpers ───────────────────────────────

    @property
    def oob_available(self) -> bool:
        """Check if OOB callback server is running and usable."""
        return (self.context is not None
                and self.context.oob_server is not None
                and self.context.oob_server.is_running)

    @property
    def oob_server(self):
        """Shortcut to the OOB callback server."""
        return self.context.oob_server if self.context else None

    def oob_generate_token(self, target_url: str, parameter: str,
                           payload_type: str, payload: str = "",
                           ttl: int = 300) -> str:
        """Generate a unique OOB callback token for this scanner."""
        return self.oob_server.generate_token(
            scanner=self.name,
            target_url=target_url,
            parameter=parameter,
            payload_type=payload_type,
            payload=payload,
            ttl=ttl,
        )

    def oob_get_url(self, token: str) -> str:
        """Get the full HTTP callback URL for a token."""
        return self.oob_server.get_callback_url(token)

    def oob_get_domain(self, token: str) -> str:
        """Get a DNS callback domain for a token."""
        return self.oob_server.get_callback_domain(token)

    def oob_collect_findings(self, wait_seconds: int = 10) -> int:
        """
        Wait for OOB callbacks and create findings for each confirmed hit.

        Returns the number of OOB findings created.
        """
        if not self.oob_available:
            return 0

        import time
        time.sleep(wait_seconds)

        callbacks = self.oob_server.get_callbacks(scanner=self.name)
        count = 0
        seen_tokens = set()
        for cb in callbacks:
            if cb.token in seen_tokens:
                continue
            seen_tokens.add(cb.token)
            count += 1

            from secprobe.config import Severity
            self.add_finding(
                title=f"Blind {cb.payload_type} confirmed via OOB {cb.callback_type.upper()} callback",
                severity=Severity.CRITICAL,
                description=(
                    f"Out-of-band {cb.callback_type} callback received — "
                    f"confirming blind {cb.payload_type}.\n"
                    f"Target: {cb.target_url}\n"
                    f"Parameter: {cb.parameter}\n"
                    f"Callback from: {cb.source_ip}:{cb.source_port}\n"
                    f"Method: {cb.method} {cb.path}"
                ),
                recommendation=self._oob_recommendation(cb.payload_type),
                evidence=(
                    f"Callback type: {cb.callback_type}\n"
                    f"Source IP: {cb.source_ip}\n"
                    f"Timestamp: {cb.timestamp}\n"
                    f"Payload: {cb.payload[:200]}"
                ),
                category=self._oob_category(cb.payload_type),
                url=cb.target_url,
                cwe=self._oob_cwe(cb.payload_type),
            )
            from secprobe.utils import print_finding
            print_finding(
                Severity.CRITICAL,
                f"🔥 OOB {cb.payload_type}: {cb.parameter} at {cb.target_url}"
            )
        return count

    @staticmethod
    def _oob_recommendation(payload_type: str) -> str:
        recs = {
            "sqli_dns_exfil": "Use parameterized queries / prepared statements.",
            "sqli_blind": "Use parameterized queries / prepared statements.",
            "xxe_oob": "Disable DTD processing and external entities in XML parsers.",
            "ssrf_blind": "Validate and whitelist URLs server-side. Block internal IP ranges.",
            "rce_blind": "Never pass user input to shell commands. Use language-native APIs.",
            "ssti_blind": "Sandbox template engines. Never pass raw user input to render().",
            "xss_blind": "Encode output contextually. Use Content-Security-Policy.",
            "lfi_blind": "Validate file path input. Use allow-lists for file access.",
        }
        return recs.get(payload_type, "Investigate and remediate this blind vulnerability.")

    @staticmethod
    def _oob_category(payload_type: str) -> str:
        cats = {
            "sqli_dns_exfil": "SQL Injection",
            "sqli_blind": "SQL Injection",
            "xxe_oob": "XML Injection",
            "ssrf_blind": "Server-Side Request Forgery",
            "rce_blind": "Command Injection",
            "ssti_blind": "Template Injection",
            "xss_blind": "Cross-Site Scripting",
            "lfi_blind": "Path Traversal",
        }
        return cats.get(payload_type, "Blind Injection")

    @staticmethod
    def _oob_cwe(payload_type: str) -> str:
        cwes = {
            "sqli_dns_exfil": "CWE-89",
            "sqli_blind": "CWE-89",
            "xxe_oob": "CWE-611",
            "ssrf_blind": "CWE-918",
            "rce_blind": "CWE-78",
            "ssti_blind": "CWE-1336",
            "xss_blind": "CWE-79",
            "lfi_blind": "CWE-22",
        }
        return cwes.get(payload_type, "CWE-74")

    # ── Header / JSON Injection Helpers ──────────────────────────

    def _inject_into_headers(self, url: str, payload: str,
                             header_names: list[str] | None = None) -> list[dict]:
        """
        Generate requests with payload injected into HTTP headers.

        Returns list of dicts: [{header_name, headers_dict}]
        """
        if header_names is None:
            header_names = [
                "Referer", "User-Agent", "X-Forwarded-For",
                "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
                "Origin", "Accept-Language",
            ]
        results = []
        for header in header_names:
            results.append({
                "header_name": header,
                "headers": {header: payload},
            })
        return results

    def _inject_into_json(self, fields: dict, payload: str) -> list[dict]:
        """
        Generate JSON bodies with payload injected into each field.

        Returns list of dicts: [{field_name, json_body}]
        """
        results = []
        for field_name in fields:
            body = dict(fields)
            body[field_name] = payload
            results.append({
                "field_name": field_name,
                "json_body": body,
            })
        return results

    def _evade_payload(self, payload: str, max_variants: int = 3,
                       vuln_type: str = "generic") -> list[str]:
        """
        Generate WAF evasion variants for a payload.

        Uses the PayloadMutator engine for comprehensive encoding chains,
        with WAF-specific prioritization when a WAF is detected.

        Returns [original_payload] + up to max_variants evasion alternatives.
        All scanners should use this instead of raw payloads when WAF is detected.
        """
        variants = [payload]

        # Determine WAF type from context
        waf_type = None
        if self.config.waf_evasion and self.context and self.context.waf_detector:
            waf_info = getattr(self.context.waf_detector, "detected_waf", None)
            if isinstance(waf_info, str):
                waf_type = waf_info.lower().replace(" ", "_")
            # Also try legacy evade() path
            try:
                legacy = self.context.waf_detector.evade(payload)
                variants.extend(legacy[:max_variants])
            except Exception:
                pass

        # Use PayloadMutator for comprehensive evasion (only when WAF evasion enabled)
        if self.config.waf_evasion:
            try:
                from secprobe.core.payload_mutator import PayloadMutator
                mutator = PayloadMutator()
                mutations = mutator.generate_variants(
                    payload, vuln_type=vuln_type,
                    waf_type=waf_type, max_variants=max_variants,
                )
                for v in mutations:
                    if v not in variants:
                        variants.append(v)
            except Exception:
                pass

        return variants[:max_variants + 1]

    def _print_summary(self):
        counts = self.result.finding_count
        total = sum(counts.values())
        if total == 0 and not self.result.error:
            print_status("No findings detected.", "success")
        else:
            parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if counts[sev]:
                    parts.append(f"{sev}: {counts[sev]}")
            print_status(f"Findings: {' | '.join(parts) or 'None'}  (took {self.result.duration:.1f}s)", "info")
