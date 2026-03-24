"""
SmartScanner — Enhanced scanner base class with wired-in infrastructure.

Extends BaseScanner with:
  1. Built-in FindingVerifier — auto-confirm findings before reporting
  2. HTML Parser integration — DOM-aware analysis, form extraction, reflection mapping
  3. Response Analyzer — content-type aware diffing, anomaly detection, error matching
  4. Safe Mode awareness — respects scan policy, budget, scope
  5. Context-aware payload selection — picks payloads based on reflection context

Scanners that inherit SmartScanner get all of this for free while maintaining
full backward compatibility with BaseScanner's API.

Usage:
    class MyScanner(SmartScanner):
        name = "My Scanner"
        description = "Smart scanner with verification"

        def scan(self):
            # All BaseScanner methods still work
            engine = self._init_detection_engine()

            # NEW: Parse response HTML properly
            doc = self.parse_html(response.text)
            forms = self.extract_forms(response.text, url)

            # NEW: Find where input reflects
            reflections = self.find_reflections(response.text, canary)

            # NEW: Check for error patterns
            errors = self.detect_errors(response.text)

            # NEW: Verify before reporting (eliminates false positives)
            result = self.verify_finding(url, param, payload, vuln_type="sqli_error")
            if result.confirmed:
                self.add_verified_finding(
                    title="SQL Injection",
                    severity="CRITICAL",
                    description="...",
                    confidence=result.confidence,
                    verification_evidence=result.evidence,
                )
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from secprobe.scanners.base import BaseScanner
from secprobe.core.logger import get_logger

if TYPE_CHECKING:
    from secprobe.core.html_parser import (
        HTMLDocument, FormData, ExtractedLink, ScriptInfo,
        ReflectionContext, PageMeta, CommentFinding,
    )
    from secprobe.core.response_analyzer import (
        ResponseModel, AnalysisResult, ErrorMatch, ContentType,
    )
    from secprobe.core.verification import (
        FindingVerifier, VerificationResult, Confidence,
    )
    from secprobe.core.safe_mode import SafeMode

log = get_logger("smart_scanner")


class SmartScanner(BaseScanner):
    """
    Enhanced scanner base with verification, DOM parsing, and response analysis.

    Drop-in replacement for BaseScanner — all existing methods still work.
    New capabilities are opt-in via method calls.
    """

    def __init__(self, config, context=None):
        super().__init__(config, context)
        self._verifier: Optional[FindingVerifier] = None
        self._response_analyzer = None
        self._safe_mode: Optional[SafeMode] = None
        self._diff_engine = None
        self._anomaly_detector = None
        self._dynamic_detector = None

    # ── Lazy initialization (only loaded when used) ─────────────

    @property
    def verifier(self) -> FindingVerifier:
        """Lazy-init finding verifier."""
        if self._verifier is None:
            from secprobe.core.verification import FindingVerifier
            if self.http_client:
                self._verifier = FindingVerifier(self.http_client)
            else:
                raise RuntimeError("FindingVerifier requires http_client (need ScanContext)")
        return self._verifier

    @property
    def response_analyzer(self):
        """Lazy-init response analyzer engine."""
        if self._response_analyzer is None:
            from secprobe.core.response_analyzer import ResponseAnalyzerEngine
            self._response_analyzer = ResponseAnalyzerEngine()
        return self._response_analyzer

    @property
    def safe_mode(self) -> Optional[SafeMode]:
        """Access safe mode from scan session if available."""
        return self._safe_mode

    @safe_mode.setter
    def safe_mode(self, value):
        self._safe_mode = value

    # ═══════════════════════════════════════════════════════════════
    # HTML Parser Integration
    # ═══════════════════════════════════════════════════════════════

    def parse_html(self, html: str) -> HTMLDocument:
        """Parse HTML into a DOM document."""
        from secprobe.core.html_parser import HTMLDocument
        return HTMLDocument.parse(html)

    def extract_forms(self, html: str, base_url: str = "") -> list[FormData]:
        """Extract forms from HTML with proper DOM parsing."""
        from secprobe.core.html_parser import HTMLDocument, FormExtractor
        doc = HTMLDocument.parse(html)
        return FormExtractor.extract(doc, base_url or self.config.target)

    def extract_links(self, html: str, base_url: str = "") -> list[ExtractedLink]:
        """Extract all links from HTML."""
        from secprobe.core.html_parser import HTMLDocument, LinkExtractor
        doc = HTMLDocument.parse(html)
        return LinkExtractor.extract(doc, base_url or self.config.target)

    def analyze_scripts(self, html: str) -> list[ScriptInfo]:
        """Analyze JavaScript in the page for sinks, sources, secrets."""
        from secprobe.core.html_parser import HTMLDocument, ScriptAnalyzer
        doc = HTMLDocument.parse(html)
        return ScriptAnalyzer.analyze(doc)

    def find_reflections(self, html: str, canary: str) -> list[ReflectionContext]:
        """Find where a canary string reflects in the HTML and its context."""
        from secprobe.core.html_parser import HTMLDocument, ReflectionMapper
        doc = HTMLDocument.parse(html)
        return ReflectionMapper.find_reflections(doc, canary)

    def extract_metadata(self, html: str) -> PageMeta:
        """Extract page metadata (frameworks, technologies, CSP, etc.)."""
        from secprobe.core.html_parser import HTMLDocument, MetaExtractor
        doc = HTMLDocument.parse(html)
        return MetaExtractor.extract(doc)

    def analyze_comments(self, html: str) -> list[CommentFinding]:
        """Analyze HTML comments for sensitive information."""
        from secprobe.core.html_parser import HTMLDocument, CommentExtractor
        doc = HTMLDocument.parse(html)
        return CommentExtractor.analyze(doc)

    # ═══════════════════════════════════════════════════════════════
    # Response Analysis Integration
    # ═══════════════════════════════════════════════════════════════

    def make_response_model(self, url: str, status_code: int, headers: dict,
                            body: str, response_time: float = 0.0) -> ResponseModel:
        """Create a ResponseModel from raw response data."""
        from secprobe.core.response_analyzer import ResponseModel
        return ResponseModel(
            status_code=status_code,
            headers=headers,
            body=body,
            response_time=response_time,
        )

    def detect_errors(self, body: str) -> list[ErrorMatch]:
        """Detect error patterns in response body (SQL, template, stack traces)."""
        from secprobe.core.response_analyzer import ErrorDetector
        detector = ErrorDetector()
        return detector.detect(body)

    def has_errors(self, body: str) -> bool:
        """Quick check: does this response contain error patterns?"""
        from secprobe.core.response_analyzer import ErrorDetector
        return ErrorDetector().has_errors(body)

    def detect_technology(self, body: str) -> list[str]:
        """Detect technologies from error messages in response."""
        from secprobe.core.response_analyzer import ErrorDetector
        return ErrorDetector().detect_technology(body)

    # ═══════════════════════════════════════════════════════════════
    # Response Diffing & Anomaly Detection (previously dead code)
    # ═══════════════════════════════════════════════════════════════

    @property
    def dynamic_detector(self):
        """Lazy-init dynamic content detector."""
        if self._dynamic_detector is None:
            from secprobe.core.response_analyzer import DynamicDetector
            self._dynamic_detector = DynamicDetector()
        return self._dynamic_detector

    @property
    def diff_engine(self):
        """Lazy-init response diff engine (strips dynamic content)."""
        if self._diff_engine is None:
            from secprobe.core.response_analyzer import DiffEngine
            self._diff_engine = DiffEngine(self.dynamic_detector)
        return self._diff_engine

    @property
    def anomaly_detector(self):
        """Lazy-init statistical anomaly detector."""
        if self._anomaly_detector is None:
            from secprobe.core.response_analyzer import AnomalyDetector
            self._anomaly_detector = AnomalyDetector()
        return self._anomaly_detector

    def compare_responses(self, baseline, test):
        """
        Compare two HTTP responses, stripping dynamic content.

        Args:
            baseline: baseline response (requests.Response or ResponseModel)
            test: test response (requests.Response or ResponseModel)

        Returns:
            DiffResult with similarity, changes, and significance flag
        """
        baseline_model = self._to_response_model(baseline)
        test_model = self._to_response_model(test)
        return self.diff_engine.compare(baseline_model, test_model)

    def learn_baselines(self, url: str, count: int = 3):
        """
        Send multiple identical requests to learn dynamic content regions.

        Call this before boolean/blind testing to calibrate the diff engine
        and anomaly detector. Returns the last baseline response.
        """
        responses = []
        for _ in range(count):
            try:
                resp = self.http_client.get(url, allow_redirects=False)
                responses.append(resp)
                model = self._to_response_model(resp)
                self.anomaly_detector.add_baseline(model)
            except Exception:
                pass

        # Teach DynamicDetector which regions change between requests
        if len(responses) >= 2:
            texts = [r.text for r in responses]
            self.dynamic_detector.learn_from_baselines(texts)

        return responses[-1] if responses else None

    def is_response_anomalous(self, response):
        """
        Check if a response deviates from learned baselines.

        Returns AnomalyResult with score and reasons.
        Requires learn_baselines() to have been called first.
        """
        model = self._to_response_model(response)
        return self.anomaly_detector.analyze(model)

    def responses_differ(self, resp_a, resp_b, threshold: float = 0.85) -> bool:
        """
        Quick check: do two responses differ significantly?

        Useful for boolean-based injection tests. Returns True if
        similarity < threshold after stripping dynamic content.
        """
        diff = self.compare_responses(resp_a, resp_b)
        return diff.is_significant or diff.similarity < threshold

    def _to_response_model(self, resp):
        """Convert a requests.Response to ResponseModel if needed."""
        from secprobe.core.response_analyzer import ResponseModel
        if isinstance(resp, ResponseModel):
            return resp
        return ResponseModel(
            status_code=getattr(resp, "status_code", 0),
            headers=dict(getattr(resp, "headers", {})),
            body=getattr(resp, "text", ""),
            response_time=getattr(resp, "elapsed", None)
            and resp.elapsed.total_seconds() or 0.0,
        )

    # ═══════════════════════════════════════════════════════════════
    # Finding Verification — The Key Differentiator
    # ═══════════════════════════════════════════════════════════════

    def verify_finding(self, url: str, param: str, payload: str,
                       vuln_type: str, **kwargs) -> VerificationResult:
        """
        Verify a finding before reporting it.

        This is what separates professional scanners from toys.
        Sends additional requests to confirm the vulnerability is real.

        Args:
            url: Target URL
            param: Vulnerable parameter
            payload: Payload that triggered
            vuln_type: "xss", "sqli_error", "sqli_boolean", "sqli_timing",
                       "ssti", "cmdi", "lfi"
            **kwargs: Extra args for specific verification methods

        Returns:
            VerificationResult with confidence level
        """
        return self.verifier.verify(url, param, payload, vuln_type, **kwargs)

    def add_verified_finding(self, title: str, severity: str, description: str,
                             confidence=None,
                             verification_evidence: list[str] = None,
                             **kwargs):
        """
        Add a finding that has been verified.

        Appends verification details to the evidence.
        """
        evidence_parts = []
        if kwargs.get("evidence"):
            evidence_parts.append(kwargs.pop("evidence"))

        if confidence is not None:
            evidence_parts.append(f"Verification: {confidence.name}")

        if verification_evidence:
            evidence_parts.append("Verification details:")
            for ev in verification_evidence:
                evidence_parts.append(f"  - {ev}")

        combined_evidence = "\n".join(evidence_parts)
        self.add_finding(
            title=title,
            severity=severity,
            description=description,
            evidence=combined_evidence,
            **kwargs,
        )

    # ═══════════════════════════════════════════════════════════════
    # Safe Mode Integration
    # ═══════════════════════════════════════════════════════════════

    def can_request(self, url: str, method: str = "GET",
                    payload: str = "") -> bool:
        """
        Check if this request is allowed by safe mode policy.

        Returns True if no safe mode is set (backward compatible).
        """
        if self._safe_mode is None:
            return True
        allowed, reason = self._safe_mode.can_request(
            url=url, method=method, scanner=self.name, payload=payload,
        )
        if not allowed:
            log.debug(f"Request blocked by safe mode: {reason}")
        return allowed

    def safe_get(self, url: str, **kwargs):
        """GET request that respects safe mode."""
        if not self.can_request(url):
            return None
        if self._safe_mode:
            self._safe_mode.throttle.wait()
        resp = self.http_client.get(url, **kwargs)
        if self._safe_mode:
            self._safe_mode.record_response(resp.status_code)
        return resp

    def safe_post(self, url: str, **kwargs):
        """POST request that respects safe mode."""
        if not self.can_request(url, method="POST"):
            return None
        if self._safe_mode:
            self._safe_mode.throttle.wait()
        resp = self.http_client.post(url, **kwargs)
        if self._safe_mode:
            self._safe_mode.record_response(resp.status_code)
        return resp

    # ═══════════════════════════════════════════════════════════════
    # Context-Aware Payload Selection
    # ═══════════════════════════════════════════════════════════════

    def select_xss_payloads(self, url: str, param: str,
                            canary: str = None) -> list[str]:
        """
        Select XSS payloads based on reflection context.

        Instead of blindly trying all payloads (like basic scanners),
        this analyzes WHERE input reflects and picks payloads that
        will actually work in that context.

        Returns:
            Prioritized list of payloads for the detected context(s)
        """
        from secprobe.core.html_parser import ContextType
        import hashlib

        if canary is None:
            canary = f"xsscanary{hashlib.md5(f'{url}{param}'.encode()).hexdigest()[:8]}"

        # Inject canary and analyze reflection context
        try:
            from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [canary]
            new_query = urlencode({k: v[0] for k, v in params.items()}, safe="")
            canary_url = urlunparse(parsed._replace(query=new_query))

            resp = self.http_client.get(canary_url)
            reflections = self.find_reflections(resp.text, canary)
        except Exception:
            # Fallback to generic payloads
            return self._generic_xss_payloads()

        if not reflections:
            return self._generic_xss_payloads()

        # Pick payloads per context
        payloads = []
        for ref in reflections:
            ctx = ref.context_type
            if ctx == ContextType.HTML_TEXT:
                payloads.extend([
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg/onload=alert(1)>',
                    '<details/open/ontoggle=alert(1)>',
                ])
            elif ctx in (ContextType.HTML_ATTRIBUTE_DOUBLE, ContextType.HTML_ATTRIBUTE_SINGLE):
                quote = '"' if ctx == ContextType.HTML_ATTRIBUTE_DOUBLE else "'"
                payloads.extend([
                    f'{quote}><script>alert(1)</script>',
                    f'{quote} onmouseover=alert(1) x={quote}',
                    f'{quote} onfocus=alert(1) autofocus x={quote}',
                    f'{quote}><img src=x onerror=alert(1)>',
                ])
            elif ctx == ContextType.HTML_ATTRIBUTE_UNQUOTED:
                payloads.extend([
                    ' onmouseover=alert(1)',
                    '><script>alert(1)</script>',
                    ' onfocus=alert(1) autofocus',
                ])
            elif ctx == ContextType.HTML_ATTRIBUTE_HREF:
                payloads.extend([
                    'javascript:alert(1)',
                    'javascript:alert(1)//',
                    'data:text/html,<script>alert(1)</script>',
                ])
            elif ctx == ContextType.HTML_ATTRIBUTE_EVENT:
                payloads.extend([
                    'alert(1)',
                    'alert(document.cookie)',
                    'prompt(1)',
                ])
            elif ctx in (ContextType.SCRIPT_STRING_SINGLE, ContextType.SCRIPT_STRING_DOUBLE):
                quote = "'" if ctx == ContextType.SCRIPT_STRING_SINGLE else '"'
                payloads.extend([
                    f'{quote}-alert(1)-{quote}',
                    f'{quote};alert(1)//',
                    f'{quote}+alert(1)+{quote}',
                    f'</script><script>alert(1)</script>',
                ])
            elif ctx == ContextType.SCRIPT_CODE:
                payloads.extend([
                    'alert(1)',
                    ';alert(1)//',
                    '</script><script>alert(1)</script>',
                ])
            elif ctx == ContextType.SCRIPT_TEMPLATE_LIT:
                payloads.extend([
                    '${alert(1)}',
                    '`+alert(1)+`',
                ])
            elif ctx == ContextType.HTML_COMMENT:
                payloads.extend([
                    '--><script>alert(1)</script>',
                    '--><img src=x onerror=alert(1)>',
                ])
            elif ctx == ContextType.STYLE_PROPERTY:
                payloads.extend([
                    '}</style><script>alert(1)</script>',
                    'expression(alert(1))',
                ])
            else:
                payloads.extend(self._generic_xss_payloads())

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    @staticmethod
    def _generic_xss_payloads() -> list[str]:
        """Fallback XSS payloads when context is unknown."""
        return [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '</script><script>alert(1)</script>',
        ]
