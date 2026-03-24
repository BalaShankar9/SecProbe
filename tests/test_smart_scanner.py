"""
Tests for secprobe.scanners.smart_scanner — SmartScanner v2 base class.

Tests cover:
  - SmartScanner inherits BaseScanner properly
  - Lazy initialization of verifier, response_analyzer, safe_mode
  - HTML parser integration (parse_html, extract_forms, find_reflections, etc.)
  - Response analysis integration (detect_errors, has_errors, detect_technology)
  - Finding verification (verify_finding, add_verified_finding)
  - Safe mode integration (can_request, safe_get, safe_post)
  - Context-aware payload selection (select_xss_payloads)
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.scanners.base import BaseScanner
from secprobe.config import ScanConfig, Severity
from secprobe.core.context import ScanContext
from secprobe.models import ScanResult


# ═══════════════════════════════════════════════════════════════════════
# Concrete SmartScanner for testing
# ═══════════════════════════════════════════════════════════════════════

class _TestableSmartScanner(SmartScanner):
    """Concrete implementation for testing."""
    name = "Test Smart Scanner"
    description = "A smart scanner for testing"

    def scan(self):
        pass


def _make_scanner(target="http://example.com", with_context=True):
    """Create a SmartScanner with optional mock context."""
    config = ScanConfig(target=target)
    if with_context:
        ctx = ScanContext(http_client=MagicMock())
        return _TestableSmartScanner(config, ctx)
    return _TestableSmartScanner(config)


def _mock_response(text="", status_code=200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {}
    return resp


# ═══════════════════════════════════════════════════════════════════════
# Inheritance & Init
# ═══════════════════════════════════════════════════════════════════════

class TestSmartScannerInheritance(unittest.TestCase):

    def test_is_subclass_of_base_scanner(self):
        self.assertTrue(issubclass(SmartScanner, BaseScanner))

    def test_init_without_context(self):
        scanner = _make_scanner(with_context=False)
        self.assertIsNone(scanner.context)
        self.assertIsInstance(scanner.result, ScanResult)

    def test_init_with_context(self):
        scanner = _make_scanner()
        self.assertIsNotNone(scanner.context)

    def test_has_base_scanner_methods(self):
        scanner = _make_scanner()
        self.assertTrue(hasattr(scanner, 'add_finding'))
        self.assertTrue(hasattr(scanner, 'scan'))
        self.assertTrue(hasattr(scanner, 'run'))

    def test_name_propagates(self):
        scanner = _make_scanner()
        self.assertEqual(scanner.name, "Test Smart Scanner")

    def test_config_accessible(self):
        scanner = _make_scanner(target="http://foo.test")
        self.assertEqual(scanner.config.target, "http://foo.test")


# ═══════════════════════════════════════════════════════════════════════
# Lazy Initialization
# ═══════════════════════════════════════════════════════════════════════

class TestLazyInit(unittest.TestCase):

    def test_verifier_lazy_init(self):
        scanner = _make_scanner()
        self.assertIsNone(scanner._verifier)
        v = scanner.verifier
        self.assertIsNotNone(v)
        # Second access returns same instance
        self.assertIs(scanner.verifier, v)

    def test_verifier_without_context_raises(self):
        scanner = _make_scanner(with_context=False)
        with self.assertRaises(RuntimeError):
            _ = scanner.verifier

    def test_response_analyzer_lazy_init(self):
        scanner = _make_scanner()
        self.assertIsNone(scanner._response_analyzer)
        ra = scanner.response_analyzer
        self.assertIsNotNone(ra)
        self.assertIs(scanner.response_analyzer, ra)

    def test_safe_mode_default_none(self):
        scanner = _make_scanner()
        self.assertIsNone(scanner.safe_mode)

    def test_safe_mode_setter(self):
        scanner = _make_scanner()
        mock_sm = MagicMock()
        scanner.safe_mode = mock_sm
        self.assertIs(scanner.safe_mode, mock_sm)


# ═══════════════════════════════════════════════════════════════════════
# HTML Parser Integration
# ═══════════════════════════════════════════════════════════════════════

class TestHTMLParserIntegration(unittest.TestCase):

    def test_parse_html_returns_document(self):
        scanner = _make_scanner()
        doc = scanner.parse_html("<html><body><p>Hello</p></body></html>")
        self.assertIsNotNone(doc)

    def test_extract_forms_from_html(self):
        scanner = _make_scanner()
        html = """
        <html><body>
            <form action="/login" method="POST">
                <input name="user" type="text">
                <input name="pass" type="password">
                <button type="submit">Login</button>
            </form>
        </body></html>
        """
        forms = scanner.extract_forms(html, "http://example.com")
        self.assertGreater(len(forms), 0)
        self.assertIn("/login", forms[0].action)

    def test_extract_links(self):
        scanner = _make_scanner()
        html = '<html><body><a href="/page1">Link</a><a href="/page2">Link2</a></body></html>'
        links = scanner.extract_links(html, "http://example.com")
        self.assertGreaterEqual(len(links), 2)

    def test_find_reflections(self):
        scanner = _make_scanner()
        html = '<html><body><p>Your search: CANARY123</p></body></html>'
        reflections = scanner.find_reflections(html, "CANARY123")
        self.assertGreater(len(reflections), 0)

    def test_find_reflections_not_found(self):
        scanner = _make_scanner()
        html = '<html><body><p>No input here</p></body></html>'
        reflections = scanner.find_reflections(html, "CANARY_NOT_PRESENT")
        self.assertEqual(len(reflections), 0)

    def test_extract_metadata(self):
        scanner = _make_scanner()
        html = '<html><head><meta charset="utf-8"><title>Test</title></head><body></body></html>'
        meta = scanner.extract_metadata(html)
        self.assertIsNotNone(meta)

    def test_analyze_scripts(self):
        scanner = _make_scanner()
        html = '<html><body><script>var x = document.location.hash;</script></body></html>'
        scripts = scanner.analyze_scripts(html)
        self.assertIsInstance(scripts, list)

    def test_analyze_comments(self):
        scanner = _make_scanner()
        html = '<html><!-- TODO: remove debug password admin123 --><body></body></html>'
        comments = scanner.analyze_comments(html)
        self.assertIsInstance(comments, list)


# ═══════════════════════════════════════════════════════════════════════
# Response Analysis Integration
# ═══════════════════════════════════════════════════════════════════════

class TestResponseAnalysisIntegration(unittest.TestCase):

    def test_make_response_model(self):
        scanner = _make_scanner()
        model = scanner.make_response_model(
            url="http://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html></html>",
            response_time=0.5,
        )
        self.assertIsNotNone(model)
        self.assertEqual(model.status_code, 200)
        self.assertEqual(model.body, "<html></html>")

    def test_detect_errors_finds_sql_error(self):
        scanner = _make_scanner()
        body = "Warning: mysql_fetch_array() expects parameter"
        errors = scanner.detect_errors(body)
        self.assertGreater(len(errors), 0)

    def test_detect_errors_clean_page(self):
        scanner = _make_scanner()
        body = "<html><body>Welcome to our site!</body></html>"
        errors = scanner.detect_errors(body)
        self.assertEqual(len(errors), 0)

    def test_has_errors_true(self):
        scanner = _make_scanner()
        body = "Warning: mysql_fetch_array() on line 45"
        self.assertTrue(scanner.has_errors(body))

    def test_has_errors_false(self):
        scanner = _make_scanner()
        body = "Welcome! Everything is fine."
        self.assertFalse(scanner.has_errors(body))

    def test_detect_technology(self):
        scanner = _make_scanner()
        body = "Fatal error: Call to undefined function in /var/www/html/index.php on line 42"
        techs = scanner.detect_technology(body)
        self.assertIsInstance(techs, list)


# ═══════════════════════════════════════════════════════════════════════
# Finding Verification
# ═══════════════════════════════════════════════════════════════════════

class TestFindingVerification(unittest.TestCase):

    def test_verify_finding_dispatches(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _mock_response("safe page")
        result = scanner.verify_finding(
            "http://test.com/?q=test", "q",
            "<script>alert(1)</script>", "xss",
        )
        from secprobe.core.verification import VerificationResult
        self.assertIsInstance(result, VerificationResult)

    def test_add_verified_finding(self):
        scanner = _make_scanner()
        from secprobe.core.verification import Confidence
        scanner.add_verified_finding(
            title="XSS Detected",
            severity="HIGH",
            description="Reflected XSS in q parameter",
            confidence=Confidence.CONFIRMED,
            verification_evidence=["Replay confirmed", "Variant confirmed"],
            url="http://test.com/page",
        )
        findings = scanner.result.findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "XSS Detected")
        self.assertIn("CONFIRMED", findings[0].evidence)
        self.assertIn("Replay confirmed", findings[0].evidence)

    def test_add_verified_finding_without_confidence(self):
        scanner = _make_scanner()
        scanner.add_verified_finding(
            title="Open Redirect",
            severity="MEDIUM",
            description="Redirects to external domain",
            url="http://test.com/redirect",
        )
        findings = scanner.result.findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Open Redirect")

    def test_add_verified_finding_merges_evidence(self):
        scanner = _make_scanner()
        from secprobe.core.verification import Confidence
        scanner.add_verified_finding(
            title="SQLi",
            severity="CRITICAL",
            description="SQL Injection",
            confidence=Confidence.FIRM,
            verification_evidence=["Error replayed"],
            evidence="Original evidence here",
            url="http://test.com/page",
        )
        finding = scanner.result.findings[0]
        self.assertIn("Original evidence here", finding.evidence)
        self.assertIn("FIRM", finding.evidence)
        self.assertIn("Error replayed", finding.evidence)


# ═══════════════════════════════════════════════════════════════════════
# Safe Mode Integration
# ═══════════════════════════════════════════════════════════════════════

class TestSafeModeIntegration(unittest.TestCase):

    def test_can_request_without_safe_mode(self):
        scanner = _make_scanner()
        self.assertTrue(scanner.can_request("http://test.com"))

    def test_can_request_allowed(self):
        scanner = _make_scanner()
        mock_sm = MagicMock()
        mock_sm.can_request.return_value = (True, "")
        scanner.safe_mode = mock_sm
        self.assertTrue(scanner.can_request("http://test.com"))

    def test_can_request_blocked(self):
        scanner = _make_scanner()
        mock_sm = MagicMock()
        mock_sm.can_request.return_value = (False, "budget exceeded")
        scanner.safe_mode = mock_sm
        self.assertFalse(scanner.can_request("http://test.com"))

    def test_safe_get_without_safe_mode(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _mock_response("ok")
        resp = scanner.safe_get("http://test.com")
        self.assertIsNotNone(resp)
        scanner.http_client.get.assert_called_once()

    def test_safe_get_with_safe_mode(self):
        scanner = _make_scanner()
        mock_sm = MagicMock()
        mock_sm.can_request.return_value = (True, "")
        mock_sm.throttle = MagicMock()
        scanner.safe_mode = mock_sm
        scanner.http_client.get.return_value = _mock_response("ok")
        resp = scanner.safe_get("http://test.com")
        self.assertIsNotNone(resp)
        mock_sm.throttle.wait.assert_called_once()
        mock_sm.record_response.assert_called_once_with(200)

    def test_safe_get_blocked(self):
        scanner = _make_scanner()
        mock_sm = MagicMock()
        mock_sm.can_request.return_value = (False, "blocked")
        scanner.safe_mode = mock_sm
        resp = scanner.safe_get("http://test.com")
        self.assertIsNone(resp)
        scanner.http_client.get.assert_not_called()

    def test_safe_post_without_safe_mode(self):
        scanner = _make_scanner()
        scanner.http_client.post.return_value = _mock_response("ok")
        resp = scanner.safe_post("http://test.com")
        self.assertIsNotNone(resp)

    def test_safe_post_with_safe_mode(self):
        scanner = _make_scanner()
        mock_sm = MagicMock()
        mock_sm.can_request.return_value = (True, "")
        mock_sm.throttle = MagicMock()
        scanner.safe_mode = mock_sm
        scanner.http_client.post.return_value = _mock_response("created", 201)
        resp = scanner.safe_post("http://test.com")
        self.assertIsNotNone(resp)
        mock_sm.record_response.assert_called_once_with(201)

    def test_safe_post_blocked(self):
        scanner = _make_scanner()
        mock_sm = MagicMock()
        mock_sm.can_request.return_value = (False, "blocked")
        scanner.safe_mode = mock_sm
        resp = scanner.safe_post("http://test.com")
        self.assertIsNone(resp)
        scanner.http_client.post.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════
# Context-Aware Payload Selection
# ═══════════════════════════════════════════════════════════════════════

class TestContextAwarePayloads(unittest.TestCase):

    def test_generic_payloads_fallback(self):
        payloads = SmartScanner._generic_xss_payloads()
        self.assertGreater(len(payloads), 0)
        self.assertIn('<script>alert(1)</script>', payloads)

    def test_select_xss_payloads_no_reflection_returns_generic(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _mock_response(
            "<html><body>No reflection here</body></html>"
        )
        payloads = scanner.select_xss_payloads(
            "http://test.com/page?q=test", "q"
        )
        self.assertGreater(len(payloads), 0)

    def test_select_xss_payloads_html_text_context(self):
        """When canary reflects in HTML text context, get tag-based payloads."""
        scanner = _make_scanner()

        # Mock: inject canary → response has canary in HTML text
        def mock_get(url, **kwargs):
            if "xsscanary" in url:
                # Return page with canary in text context
                canary = url.split("q=")[1].split("&")[0] if "q=" in url else "test"
                return _mock_response(
                    f"<html><body><p>Results for: {canary}</p></body></html>"
                )
            return _mock_response("<html><body>ok</body></html>")

        scanner.http_client.get.side_effect = mock_get
        payloads = scanner.select_xss_payloads(
            "http://test.com/search?q=test", "q"
        )
        self.assertGreater(len(payloads), 0)
        # Should include tag-based payloads for text context
        has_tag_payload = any('<' in p for p in payloads)
        self.assertTrue(has_tag_payload)

    def test_select_xss_payloads_exception_returns_generic(self):
        scanner = _make_scanner()
        scanner.http_client.get.side_effect = Exception("timeout")
        payloads = scanner.select_xss_payloads(
            "http://test.com/?q=test", "q"
        )
        self.assertGreater(len(payloads), 0)

    def test_select_xss_payloads_deduplicates(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _mock_response("<html></html>")
        payloads = scanner.select_xss_payloads(
            "http://test.com/?q=test", "q"
        )
        self.assertEqual(len(payloads), len(set(payloads)))


# ═══════════════════════════════════════════════════════════════════════
# Upgraded Scanner Tests — verify existing scanners still work
# ═══════════════════════════════════════════════════════════════════════

class TestUpgradedScanners(unittest.TestCase):

    def test_cors_scanner_is_smart(self):
        from secprobe.scanners.cors_scanner import CORSScanner
        self.assertTrue(issubclass(CORSScanner, SmartScanner))

    def test_crlf_scanner_is_smart(self):
        from secprobe.scanners.crlf_scanner import CRLFScanner
        self.assertTrue(issubclass(CRLFScanner, SmartScanner))

    def test_redirect_scanner_is_smart(self):
        from secprobe.scanners.redirect_scanner import RedirectScanner
        self.assertTrue(issubclass(RedirectScanner, SmartScanner))

    def test_hpp_scanner_is_smart(self):
        from secprobe.scanners.hpp_scanner import HPPScanner
        self.assertTrue(issubclass(HPPScanner, SmartScanner))

    def test_fuzzer_scanner_is_smart(self):
        from secprobe.scanners.fuzzer_scanner import FuzzerScanner
        self.assertTrue(issubclass(FuzzerScanner, SmartScanner))

    def test_cors_scanner_still_has_base_scanner_api(self):
        from secprobe.scanners.cors_scanner import CORSScanner
        config = ScanConfig(target="http://test.com")
        ctx = ScanContext(http_client=MagicMock())
        scanner = CORSScanner(config, ctx)
        self.assertTrue(hasattr(scanner, 'add_finding'))
        self.assertTrue(hasattr(scanner, 'run'))
        self.assertTrue(hasattr(scanner, 'scan'))
        # Also has SmartScanner methods
        self.assertTrue(hasattr(scanner, 'verify_finding'))
        self.assertTrue(hasattr(scanner, 'parse_html'))
        self.assertTrue(hasattr(scanner, 'safe_get'))


if __name__ == "__main__":
    unittest.main()
