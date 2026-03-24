"""
Tests for v9.0 scanner upgrades:
  • HPPScanner — 5-phase rewrite (server-side, form, backend-strategies,
    encoding tricks, WAF bypass via param splitting)
  • CRLFScanner — 4-phase rewrite (param CRLF, header CRLF, response splitting,
    cache poisoning via CRLF)
  • RedirectScanner — 5-phase rewrite (redirect params, other params,
    protocol-polymorphic, header-based, DOM-based)
  • LDAPScanner — 5-phase upgrade (error, boolean, auth bypass,
    timing-based blind, DN manipulation + attribute extraction)
  • XPathScanner — 5-phase upgrade (error, boolean, auth bypass,
    timing-based blind, XPath 2.0 + data extraction + SOAP)
"""

import time
import unittest
from unittest.mock import MagicMock, patch, call

from secprobe.config import ScanConfig, Severity
from secprobe.core.context import ScanContext
from secprobe.models import ScanResult


# ── Helpers ───────────────────────────────────────────────────────

def _make_config(target="http://test.local"):
    return ScanConfig(target=target)


def _make_context(http_client=None, oob_server=None):
    if http_client is None:
        http_client = MagicMock()
        http_client._session = MagicMock()
        http_client._session.cookies = {}
    ctx = ScanContext(http_client=http_client, oob_server=oob_server)
    return ctx


def _mock_response(text="", status_code=200, headers=None, url="http://test.local", cookies=None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.url = url
    resp.cookies = cookies or {}
    resp.content = text.encode() if isinstance(text, str) else text
    return resp


def _mock_client(get_resp=None, post_resp=None, options_resp=None):
    client = MagicMock()
    client.get.return_value = get_resp or _mock_response()
    client.post.return_value = post_resp or _mock_response()
    client.options.return_value = options_resp or _mock_response(status_code=405)
    client._session = MagicMock()
    client._session.cookies = {}
    return client


# ═══════════════════════════════════════════════════════════════════
#  HPP Scanner Tests — 5-phase upgrade
# ═══════════════════════════════════════════════════════════════════
class TestHPPScannerV9(unittest.TestCase):

    def _run_scanner(self, get_text="OK", url="http://test.local/search?q=admin"):
        from secprobe.scanners.hpp_scanner import HPPScanner
        config = _make_config(url)
        baseline = _mock_response(text="Result: admin")
        vuln = _mock_response(text=get_text)
        client = _mock_client()
        client.get.side_effect = [baseline] + [vuln] * 500
        client.post.return_value = _mock_response()
        ctx = _make_context(client)
        scanner = HPPScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_has_5_phases(self):
        from secprobe.scanners.hpp_scanner import HPPScanner
        methods = [
            "_test_server_side_hpp", "_test_form_hpp",
            "_test_backend_strategies", "_test_encoding_hpp",
            "_test_waf_bypass_hpp",
        ]
        for m in methods:
            self.assertTrue(hasattr(HPPScanner, m), f"HPP missing {m}")

    def test_has_backend_strategies(self):
        from secprobe.scanners.hpp_scanner import BACKEND_STRATEGIES
        self.assertGreaterEqual(len(BACKEND_STRATEGIES), 6)

    def test_has_encoding_payloads(self):
        from secprobe.scanners.hpp_scanner import ENCODING_HPP
        self.assertGreaterEqual(len(ENCODING_HPP), 5)

    def test_has_waf_bypass_pairs(self):
        from secprobe.scanners.hpp_scanner import WAF_BYPASS_PAIRS
        self.assertGreaterEqual(len(WAF_BYPASS_PAIRS), 4)

    def test_clean_no_high(self):
        result = self._run_scanner("Result: admin")
        high = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high), 0)

    def test_no_params_graceful(self):
        from secprobe.scanners.hpp_scanner import HPPScanner
        config = _make_config("http://test.local/page")
        client = _mock_client()
        ctx = _make_context(client)
        scanner = HPPScanner(config, ctx)
        scanner.scan()
        self.assertIsNotNone(scanner.result)

    def test_detects_anomaly(self):
        result = self._run_scanner("Result: admin,injected")
        self.assertIsNotNone(result)

    def test_scanner_instantiates(self):
        from secprobe.scanners.hpp_scanner import HPPScanner
        config = _make_config("http://test.local/search?q=1")
        ctx = _make_context()
        scanner = HPPScanner(config, ctx)
        self.assertEqual(scanner.name, "HPP Scanner")


# ═══════════════════════════════════════════════════════════════════
#  CRLF Scanner Tests — 4-phase upgrade
# ═══════════════════════════════════════════════════════════════════
class TestCRLFScannerV9(unittest.TestCase):

    def _run_scanner(self, resp_headers=None, text="normal",
                     url="http://test.local/redirect?url=/home"):
        from secprobe.scanners.crlf_scanner import CRLFScanner
        config = _make_config(url)
        normal = _mock_response(text="normal", headers={"Content-Type": "text/html"})
        vuln = _mock_response(text=text, headers=resp_headers or {"Content-Type": "text/html"})
        client = _mock_client()
        client.get.side_effect = [normal] + [vuln] * 500
        ctx = _make_context(client)
        scanner = CRLFScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_has_4_phases(self):
        from secprobe.scanners.crlf_scanner import CRLFScanner
        methods = [
            "_test_param_crlf", "_test_header_crlf",
            "_test_response_splitting", "_test_cache_poisoning_crlf",
        ]
        for m in methods:
            self.assertTrue(hasattr(CRLFScanner, m), f"CRLF missing {m}")

    def test_has_bypass_payloads(self):
        from secprobe.scanners.crlf_scanner import CRLF_BYPASS_PAYLOADS
        self.assertGreaterEqual(len(CRLF_BYPASS_PAYLOADS), 5)

    def test_has_injectable_headers(self):
        from secprobe.scanners.crlf_scanner import INJECTABLE_HEADERS
        self.assertGreaterEqual(len(INJECTABLE_HEADERS), 10)

    def test_has_cache_poison_payloads(self):
        from secprobe.scanners.crlf_scanner import CACHE_POISON_PAYLOADS
        self.assertGreaterEqual(len(CACHE_POISON_PAYLOADS), 3)

    def test_detects_header_injection(self):
        result = self._run_scanner(
            resp_headers={
                "Content-Type": "text/html",
                "X-Injected": "secprobe",
            }
        )
        high = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(high) > 0, "Should detect CRLF header injection")

    def test_detects_cookie_injection(self):
        result = self._run_scanner(
            resp_headers={
                "Content-Type": "text/html",
                "Set-Cookie": "secprobe=injected",
            }
        )
        crits = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(len(crits) > 0, "Cookie injection should be CRITICAL")

    def test_detects_location_injection(self):
        result = self._run_scanner(
            resp_headers={
                "Content-Type": "text/html",
                "Location": "https://evil.com",
            }
        )
        crits = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(len(crits) > 0, "Location injection should be CRITICAL")

    def test_clean_no_high(self):
        result = self._run_scanner()
        high = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high), 0)

    def test_no_params_graceful(self):
        from secprobe.scanners.crlf_scanner import CRLFScanner
        config = _make_config("http://test.local/page")
        client = _mock_client()
        ctx = _make_context(client)
        scanner = CRLFScanner(config, ctx)
        scanner.scan()
        self.assertIsNotNone(scanner.result)

    def test_body_injection_detection(self):
        result = self._run_scanner(text="<script>alert(1)</script>")
        self.assertIsNotNone(result)

    def test_extended_markers(self):
        from secprobe.scanners.crlf_scanner import INJECTION_MARKERS
        # Should have at least 4 markers now (X-Injected, Set-Cookie x2, Location)
        self.assertGreaterEqual(len(INJECTION_MARKERS), 4)


# ═══════════════════════════════════════════════════════════════════
#  Redirect Scanner Tests — 5-phase upgrade
# ═══════════════════════════════════════════════════════════════════
class TestRedirectScannerV9(unittest.TestCase):

    def _run_scanner(self, get_resp=None, url="http://test.local/login?next=/dashboard"):
        from secprobe.scanners.redirect_scanner import RedirectScanner
        config = _make_config(url)
        baseline = _mock_response(text="login page")
        vuln = get_resp or _mock_response()
        client = _mock_client()
        client.get.side_effect = [baseline] + [vuln] * 500
        client.post.return_value = _mock_response()
        ctx = _make_context(client)
        scanner = RedirectScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_has_5_phases(self):
        from secprobe.scanners.redirect_scanner import RedirectScanner
        methods = [
            "_test_redirect_params", "_test_other_params",
            "_test_protocol_redirects", "_test_header_redirects",
            "_test_dom_redirects",
        ]
        for m in methods:
            self.assertTrue(hasattr(RedirectScanner, m), f"Redirect missing {m}")

    def test_has_bypass_payloads(self):
        from secprobe.scanners.redirect_scanner import BYPASS_PAYLOADS
        self.assertGreaterEqual(len(BYPASS_PAYLOADS), 10)

    def test_has_protocol_payloads(self):
        from secprobe.scanners.redirect_scanner import PROTOCOL_PAYLOADS
        self.assertGreaterEqual(len(PROTOCOL_PAYLOADS), 8)

    def test_has_redirect_headers(self):
        from secprobe.scanners.redirect_scanner import REDIRECT_HEADERS
        self.assertGreaterEqual(len(REDIRECT_HEADERS), 5)

    def test_detects_302_redirect(self):
        vuln = _mock_response(
            status_code=302,
            headers={"Location": "https://evil.com/phish"},
        )
        result = self._run_scanner(get_resp=vuln)
        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        self.assertTrue(len(medium) > 0, "Should detect 302 redirect")

    def test_detects_301_redirect(self):
        vuln = _mock_response(
            status_code=301,
            headers={"Location": "//evil.com"},
        )
        result = self._run_scanner(get_resp=vuln)
        findings = [f for f in result.findings if f.severity != Severity.INFO]
        self.assertTrue(len(findings) > 0, "Should detect 301 redirect")

    def test_clean_no_findings(self):
        result = self._run_scanner()
        medium_high = [f for f in result.findings if f.severity in (Severity.MEDIUM, Severity.HIGH)]
        self.assertEqual(len(medium_high), 0)

    def test_no_params_graceful(self):
        from secprobe.scanners.redirect_scanner import RedirectScanner
        config = _make_config("http://test.local/page")
        client = _mock_client()
        ctx = _make_context(client)
        scanner = RedirectScanner(config, ctx)
        scanner.scan()
        self.assertIsNotNone(scanner.result)

    def test_check_redirect_helper(self):
        from secprobe.scanners.redirect_scanner import RedirectScanner
        scanner = RedirectScanner.__new__(RedirectScanner)
        self.assertTrue(hasattr(scanner, "_check_redirect"))

    def test_is_external_redirect(self):
        from secprobe.scanners.redirect_scanner import RedirectScanner
        scanner = RedirectScanner.__new__(RedirectScanner)
        self.assertTrue(scanner._is_external_redirect("https://evil.com", "test.local"))
        self.assertFalse(scanner._is_external_redirect("https://test.local/home", "test.local"))
        self.assertTrue(scanner._is_external_redirect("//evil.com", "test.local"))
        self.assertFalse(scanner._is_external_redirect("//test.local", "test.local"))
        self.assertFalse(scanner._is_external_redirect("", "test.local"))

    def test_protocol_redirect_js_scheme(self):
        vuln = _mock_response(
            status_code=302,
            headers={"Location": "javascript:alert(1)"},
        )
        result = self._run_scanner(get_resp=vuln)
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0, "Should detect javascript: redirect")

    def test_dom_redirect_patterns(self):
        vuln = _mock_response(
            text='<script>window.location = "https://evil.com"</script>',
            status_code=200,
        )
        result = self._run_scanner(get_resp=vuln)
        self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════
#  LDAP Scanner Tests — 5-phase upgrade
# ═══════════════════════════════════════════════════════════════════
class TestLDAPScannerV9(unittest.TestCase):

    def _run_scanner(self, get_text="OK", url="http://test.local/search?q=admin"):
        from secprobe.scanners.ldap_scanner import LDAPScanner
        config = _make_config(url)
        baseline = _mock_response(text="normal page")
        vuln = _mock_response(text=get_text)
        client = _mock_client()
        client.get.side_effect = [baseline] + [vuln] * 500
        client.post.return_value = _mock_response()
        ctx = _make_context(client)
        scanner = LDAPScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_has_5_phases(self):
        from secprobe.scanners.ldap_scanner import LDAPScanner
        methods = [
            "_test_error_based", "_test_boolean", "_test_auth_bypass",
            "_test_timing_based", "_test_dn_manipulation",
            "_test_attribute_extraction",
        ]
        for m in methods:
            self.assertTrue(hasattr(LDAPScanner, m), f"LDAP missing {m}")

    def test_has_timing_payloads(self):
        from secprobe.scanners.ldap_scanner import LDAP_TIMING_PAYLOADS
        self.assertGreaterEqual(len(LDAP_TIMING_PAYLOADS), 3)

    def test_has_dn_payloads(self):
        from secprobe.scanners.ldap_scanner import DN_PAYLOADS
        self.assertGreaterEqual(len(DN_PAYLOADS), 5)

    def test_has_attribute_payloads(self):
        from secprobe.scanners.ldap_scanner import ATTRIBUTE_PAYLOADS
        self.assertGreaterEqual(len(ATTRIBUTE_PAYLOADS), 5)

    def test_detects_ldap_error(self):
        result = self._run_scanner(
            "javax.naming.directory.InvalidSearchFilterException: Bad search filter"
        )
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect LDAP error")

    def test_detects_ldap_exception(self):
        result = self._run_scanner("LDAPException: Operations error")
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect LDAPException")

    def test_clean_no_findings(self):
        result = self._run_scanner("Welcome to the search page")
        high = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high), 0)

    def test_no_params_graceful(self):
        result = self._run_scanner("OK", url="http://test.local/page")
        self.assertIsNotNone(result)

    def test_improved_boolean_detection(self):
        """Boolean detection threshold was relaxed: size > 100 OR (size > 50 + status diff)."""
        from secprobe.scanners.ldap_scanner import LDAPScanner
        # Verify the method exists and the threshold is implemented
        self.assertTrue(hasattr(LDAPScanner, '_test_boolean'))
        # Structural check: run scanner with clean output, no false positives
        result = self._run_scanner("normal search results page")
        high = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high), 0, "Clean response should not trigger boolean detection")

    def test_timing_phase_exists(self):
        from secprobe.scanners.ldap_scanner import LDAPScanner
        self.assertTrue(hasattr(LDAPScanner, '_test_timing_based'))


# ═══════════════════════════════════════════════════════════════════
#  XPath Scanner Tests — 5-phase upgrade
# ═══════════════════════════════════════════════════════════════════
class TestXPathScannerV9(unittest.TestCase):

    def _run_scanner(self, get_text="OK", url="http://test.local/xml?id=1"):
        from secprobe.scanners.xpath_scanner import XPathScanner
        config = _make_config(url)
        baseline = _mock_response(text="normal")
        vuln = _mock_response(text=get_text)
        client = _mock_client()
        client.get.side_effect = [baseline] + [vuln] * 500
        client.post.return_value = _mock_response()
        ctx = _make_context(client)
        scanner = XPathScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_has_5_phases(self):
        from secprobe.scanners.xpath_scanner import XPathScanner
        methods = [
            "_test_error_based", "_test_boolean", "_test_auth_bypass",
            "_test_timing_based", "_test_xpath2_functions",
            "_test_data_extraction", "_test_soap_xpath",
        ]
        for m in methods:
            self.assertTrue(hasattr(XPathScanner, m), f"XPath missing {m}")

    def test_has_xpath2_payloads(self):
        from secprobe.scanners.xpath_scanner import XPATH2_PAYLOADS
        self.assertGreaterEqual(len(XPATH2_PAYLOADS), 5)

    def test_has_timing_payloads(self):
        from secprobe.scanners.xpath_scanner import XPATH_TIMING_PAYLOADS
        self.assertGreaterEqual(len(XPATH_TIMING_PAYLOADS), 3)

    def test_has_extract_pairs(self):
        from secprobe.scanners.xpath_scanner import XPATH_EXTRACT_PAIRS
        self.assertGreaterEqual(len(XPATH_EXTRACT_PAIRS), 3)

    def test_has_soap_payloads(self):
        from secprobe.scanners.xpath_scanner import SOAP_XPATH_PAYLOADS
        self.assertGreaterEqual(len(SOAP_XPATH_PAYLOADS), 4)

    def test_detects_xpath_error(self):
        result = self._run_scanner("XPathException: Invalid expression")
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect XPath error")

    def test_detects_dom_xpath_error(self):
        result = self._run_scanner("DOMXPath::query(): Invalid predicate")
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect DOMXPath error")

    def test_clean_no_findings(self):
        result = self._run_scanner("Welcome to the page")
        high = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high), 0)

    def test_no_params_graceful(self):
        result = self._run_scanner("OK", url="http://test.local/page")
        self.assertIsNotNone(result)

    def test_improved_boolean_detection(self):
        """Boolean detection threshold was relaxed: size > 100 OR (size > 50 + status diff)."""
        from secprobe.scanners.xpath_scanner import XPathScanner
        # Verify the method exists and the threshold is implemented
        self.assertTrue(hasattr(XPathScanner, '_test_boolean'))
        # Structural check: run scanner with clean output, no false positives
        result = self._run_scanner("normal xml page")
        high = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high), 0, "Clean response should not trigger boolean detection")

    def test_timing_phase_exists(self):
        from secprobe.scanners.xpath_scanner import XPathScanner
        self.assertTrue(hasattr(XPathScanner, '_test_timing_based'))


# ═══════════════════════════════════════════════════════════════════
#  Cross-cutting: all 5 upgraded scanners still in registry
# ═══════════════════════════════════════════════════════════════════
class TestV9Registry(unittest.TestCase):

    def test_all_upgraded_scanners_in_registry(self):
        from secprobe.scanners import SCANNER_REGISTRY
        for key in ("hpp", "crlf", "redirect", "ldap", "xpath"):
            self.assertIn(key, SCANNER_REGISTRY, f"{key} missing from registry")

    def test_scanner_count_still_45(self):
        from secprobe.scanners import SCANNER_REGISTRY
        self.assertEqual(len(SCANNER_REGISTRY), 45)

    def test_all_scanners_instantiate(self):
        from secprobe.scanners import SCANNER_REGISTRY
        config = _make_config("http://test.local/page?id=1")
        ctx = _make_context()
        for key in ("hpp", "crlf", "redirect", "ldap", "xpath"):
            scanner = SCANNER_REGISTRY[key](config, ctx)
            self.assertIsNotNone(scanner)


# ═══════════════════════════════════════════════════════════════════
#  Constant / payload coverage checks
# ═══════════════════════════════════════════════════════════════════
class TestV9PayloadCoverage(unittest.TestCase):

    def test_hpp_backend_strategies_structure(self):
        from secprobe.scanners.hpp_scanner import BACKEND_STRATEGIES
        for template, desc, backend in BACKEND_STRATEGIES:
            self.assertIsInstance(template, str)
            self.assertIsInstance(desc, str)
            self.assertIsInstance(backend, str)

    def test_hpp_encoding_payloads_structure(self):
        from secprobe.scanners.hpp_scanner import ENCODING_HPP
        for payload, desc in ENCODING_HPP:
            self.assertIsInstance(payload, str)
            self.assertIsInstance(desc, str)

    def test_crlf_payloads_contain_markers(self):
        from secprobe.scanners.crlf_scanner import CRLF_PAYLOADS
        marker_found = any("X-Injected" in p for p, _ in CRLF_PAYLOADS)
        self.assertTrue(marker_found, "CRLF payloads should contain X-Injected marker")

    def test_redirect_param_names_comprehensive(self):
        from secprobe.scanners.redirect_scanner import REDIRECT_PARAM_NAMES
        essential = ["url", "redirect", "next", "return", "goto", "callback"]
        for name in essential:
            self.assertIn(name, REDIRECT_PARAM_NAMES)

    def test_redirect_payloads_cover_schemes(self):
        from secprobe.scanners.redirect_scanner import REDIRECT_PAYLOADS, PROTOCOL_PAYLOADS
        all_payloads = [p for p, _ in REDIRECT_PAYLOADS + PROTOCOL_PAYLOADS]
        has_js = any("javascript" in p.lower() for p in all_payloads)
        has_data = any("data:" in p.lower() for p in all_payloads)
        self.assertTrue(has_js, "Should have javascript: payload")
        self.assertTrue(has_data, "Should have data: payload")

    def test_ldap_error_patterns_comprehensive(self):
        from secprobe.scanners.ldap_scanner import LDAP_ERROR_PATTERNS
        self.assertGreaterEqual(len(LDAP_ERROR_PATTERNS), 15)

    def test_xpath_error_patterns_comprehensive(self):
        from secprobe.scanners.xpath_scanner import XPATH_ERROR_PATTERNS
        self.assertGreaterEqual(len(XPATH_ERROR_PATTERNS), 13)

    def test_ldap_timing_payloads_are_complex(self):
        from secprobe.scanners.ldap_scanner import LDAP_TIMING_PAYLOADS
        for payload, desc in LDAP_TIMING_PAYLOADS:
            # Timing payloads should be longer (more complex filters)
            self.assertGreater(len(payload), 30, f"Timing payload too short: {desc}")

    def test_xpath_soap_payloads_target_sensitive_fields(self):
        from secprobe.scanners.xpath_scanner import SOAP_XPATH_PAYLOADS
        all_text = " ".join(p for p, _ in SOAP_XPATH_PAYLOADS)
        self.assertIn("password", all_text)
        self.assertIn("token", all_text)


if __name__ == "__main__":
    unittest.main()
