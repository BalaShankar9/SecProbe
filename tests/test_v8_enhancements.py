"""
Tests for v8 enhancements:
  - PayloadMutator engine
  - SmartScanner DiffEngine/AnomalyDetector integration
  - Enhanced passive scanner checks
  - Enhanced header/cookie scanner checks
"""

from __future__ import annotations

import math
from collections import Counter
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# ═══════════════════════════════════════════════════════════════════════
# PayloadMutator Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPayloadEncoder:
    """Test individual encoding transforms."""

    def test_url_encode(self):
        from secprobe.core.payload_mutator import PayloadEncoder
        result = PayloadEncoder.url_encode("<script>alert(1)</script>")
        assert "%3C" in result or "%3c" in result
        assert "script" in result.lower()

    def test_double_url_encode(self):
        from secprobe.core.payload_mutator import PayloadEncoder
        result = PayloadEncoder.double_url_encode("<script>")
        assert "%25" in result  # double encoded

    def test_html_entity_encode(self):
        from secprobe.core.payload_mutator import PayloadEncoder
        result = PayloadEncoder.html_entity_encode("<script>")
        assert "&lt;" in result

    def test_html_numeric_encode(self):
        from secprobe.core.payload_mutator import PayloadEncoder
        result = PayloadEncoder.html_numeric_encode("<script>")
        assert "&#" in result

    def test_unicode_fullwidth(self):
        from secprobe.core.payload_mutator import PayloadEncoder
        result = PayloadEncoder.unicode_fullwidth("<script>")
        assert result != "<script>"
        assert len(result) > 0

    def test_case_swap(self):
        from secprobe.core.payload_mutator import PayloadEncoder
        result = PayloadEncoder.case_swap("script")
        assert result.lower() == "script"
        assert result != "script"  # At least some letters swapped

    def test_null_byte_inject(self):
        from secprobe.core.payload_mutator import PayloadEncoder
        result = PayloadEncoder.null_byte_inject("<script>alert(1)</script>")
        assert "%00" in result


class TestSQLMutator:
    """Test SQL injection mutation techniques."""

    def test_comment_inject(self):
        from secprobe.core.payload_mutator import SQLMutator
        result = SQLMutator.comment_inject("SELECT * FROM users")
        assert "/**/" in result or "/*" in result

    def test_space_to_comment(self):
        from secprobe.core.payload_mutator import SQLMutator
        result = SQLMutator.space_to_comment("SELECT * FROM users")
        assert "/**/" in result

    def test_hex_encode_strings(self):
        from secprobe.core.payload_mutator import SQLMutator
        result = SQLMutator.hex_encode_strings("' OR 'admin'='admin'")
        assert "0x" in result or result == "' OR 'admin'='admin'"

    def test_char_function(self):
        from secprobe.core.payload_mutator import SQLMutator
        result = SQLMutator.char_function("' OR 'admin'='admin'")
        assert "CHAR(" in result or result == "' OR 'admin'='admin'"


class TestXSSMutator:
    """Test XSS mutation techniques."""

    def test_tag_case_variation(self):
        from secprobe.core.payload_mutator import XSSMutator
        result = XSSMutator.tag_case_variation("<script>alert(1)</script>")
        assert "script" in result.lower()

    def test_svg_payload(self):
        from secprobe.core.payload_mutator import XSSMutator
        result = XSSMutator.svg_payload("<script>alert(1)</script>")
        assert "svg" in result.lower() or "onload" in result.lower()

    def test_js_fromcharcode(self):
        from secprobe.core.payload_mutator import XSSMutator
        result = XSSMutator.js_fromcharcode("<script>alert(1)</script>")
        assert "fromCharCode" in result or "String" in result

    def test_double_encoding(self):
        from secprobe.core.payload_mutator import XSSMutator
        result = XSSMutator.double_encoding("<script>alert(1)</script>")
        assert "%25" in result


class TestCMDiMutator:
    """Test command injection mutation techniques."""

    def test_variable_expansion(self):
        from secprobe.core.payload_mutator import CMDiMutator
        result = CMDiMutator.variable_expansion("; cat /etc/passwd")
        assert "$" in result or result == "; cat /etc/passwd"

    def test_ifs_separator(self):
        from secprobe.core.payload_mutator import CMDiMutator
        result = CMDiMutator.ifs_separator("; cat /etc/passwd")
        assert "${IFS}" in result

    def test_quote_break(self):
        from secprobe.core.payload_mutator import CMDiMutator
        result = CMDiMutator.quote_break("; cat /etc/passwd")
        assert "'" in result


class TestPayloadMutator:
    """Test the high-level PayloadMutator API."""

    def test_generate_returns_results(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        results = mutator.generate("' OR 1=1--", vuln_type="sqli")
        assert len(results) > 0
        assert results[0].original == "' OR 1=1--"

    def test_generate_variants_returns_strings(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("<script>alert(1)</script>",
                                             vuln_type="xss", max_variants=10)
        assert isinstance(variants, list)
        assert all(isinstance(v, str) for v in variants)
        assert len(variants) <= 10

    def test_generic_vuln_type(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("test", vuln_type="generic",
                                             max_variants=3)
        assert len(variants) <= 3

    def test_waf_specific_mutations(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        results_generic = mutator.generate("' OR 1=1--", vuln_type="sqli")
        results_cloudflare = mutator.generate("' OR 1=1--", vuln_type="sqli",
                                              waf_type="cloudflare")
        # WAF-specific should produce results (reorders/prioritizes)
        assert len(results_cloudflare) >= 2
        assert len(results_generic) >= 2

    def test_sqli_mutations(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("' OR 1=1--",
                                             vuln_type="sqli", max_variants=10)
        assert len(variants) > 1

    def test_xss_mutations(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("<script>alert(1)</script>",
                                             vuln_type="xss", max_variants=10)
        assert len(variants) > 1

    def test_cmdi_mutations(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("; cat /etc/passwd",
                                             vuln_type="cmdi", max_variants=10)
        assert len(variants) > 1

    def test_lfi_mutations(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("../../etc/passwd",
                                             vuln_type="lfi", max_variants=10)
        assert len(variants) > 1

    def test_ssti_mutations(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("{{7*7}}",
                                             vuln_type="ssti", max_variants=10)
        assert len(variants) > 1

    def test_max_variants_respected(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        for limit in [3, 5, 8]:
            variants = mutator.generate_variants("test", vuln_type="xss",
                                                 max_variants=limit)
            # generate_variants returns original + up to max_variants mutations
            assert len(variants) <= limit + 1

    def test_no_duplicates(self):
        from secprobe.core.payload_mutator import PayloadMutator
        mutator = PayloadMutator()
        variants = mutator.generate_variants("' OR 1=1--",
                                             vuln_type="sqli", max_variants=20)
        assert len(variants) == len(set(variants))

    def test_all_waf_profiles_exist(self):
        from secprobe.core.payload_mutator import WAF_PROFILES
        expected = ["cloudflare", "aws_waf", "akamai", "imperva",
                    "f5_bigip", "modsecurity", "sucuri", "wordfence"]
        for waf in expected:
            assert waf in WAF_PROFILES, f"Missing WAF profile: {waf}"


# ═══════════════════════════════════════════════════════════════════════
# SmartScanner DiffEngine Integration Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSmartScannerDiffEngine:
    """Test DiffEngine / AnomalyDetector wired into SmartScanner."""

    def _make_scanner(self):
        from secprobe.scanners.smart_scanner import SmartScanner
        from secprobe.config import ScanConfig

        config = ScanConfig(target="https://test.com")

        class TestScanner(SmartScanner):
            name = "Test"
            def scan(self):
                pass

        return TestScanner(config, None)

    def test_diff_engine_lazy_init(self):
        scanner = self._make_scanner()
        assert scanner._diff_engine is None
        engine = scanner.diff_engine
        assert engine is not None
        assert scanner._diff_engine is engine  # Cached

    def test_dynamic_detector_lazy_init(self):
        scanner = self._make_scanner()
        assert scanner._dynamic_detector is None
        dd = scanner.dynamic_detector
        assert dd is not None

    def test_anomaly_detector_lazy_init(self):
        scanner = self._make_scanner()
        assert scanner._anomaly_detector is None
        ad = scanner.anomaly_detector
        assert ad is not None

    def test_compare_responses_identical(self):
        from secprobe.core.response_analyzer import ResponseModel
        scanner = self._make_scanner()
        resp = ResponseModel(status_code=200, headers={}, body="Hello World")
        diff = scanner.compare_responses(resp, resp)
        assert diff.similarity == 1.0
        assert not diff.is_significant

    def test_compare_responses_different(self):
        from secprobe.core.response_analyzer import ResponseModel
        scanner = self._make_scanner()
        resp_a = ResponseModel(status_code=200, headers={}, body="Hello World")
        resp_b = ResponseModel(status_code=500, headers={}, body="Internal Error")
        diff = scanner.compare_responses(resp_a, resp_b)
        assert diff.status_changed
        assert diff.is_significant

    def test_responses_differ_method(self):
        from secprobe.core.response_analyzer import ResponseModel
        scanner = self._make_scanner()
        resp_a = ResponseModel(status_code=200, headers={}, body="Same")
        resp_b = ResponseModel(status_code=200, headers={}, body="Different response entirely")
        assert scanner.responses_differ(resp_a, resp_b)

    def test_to_response_model_from_mock(self):
        scanner = self._make_scanner()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "<html>test</html>"
        mock_resp.elapsed.total_seconds.return_value = 0.5
        model = scanner._to_response_model(mock_resp)
        assert model.status_code == 200
        assert model.body == "<html>test</html>"

    def test_to_response_model_passthrough(self):
        from secprobe.core.response_analyzer import ResponseModel
        scanner = self._make_scanner()
        model = ResponseModel(status_code=200, headers={}, body="test")
        result = scanner._to_response_model(model)
        assert result is model  # Should return same object

    def test_is_response_anomalous_no_baselines(self):
        from secprobe.core.response_analyzer import ResponseModel
        scanner = self._make_scanner()
        resp = ResponseModel(status_code=200, headers={}, body="test")
        result = scanner.is_response_anomalous(resp)
        assert not result.is_anomalous  # No baselines = no anomaly


# ═══════════════════════════════════════════════════════════════════════
# Enhanced Passive Scanner Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPassiveScannerEnhancements:
    """Test the new passive scanner checks."""

    def _make_scanner(self):
        from secprobe.scanners.passive_scanner import PassiveScanner
        from secprobe.config import ScanConfig
        from secprobe.core.context import ScanContext

        config = ScanConfig(target="https://test.com")
        mock_client = MagicMock()
        mock_client._session = MagicMock()
        mock_client._session.cookies = {}
        ctx = ScanContext(http_client=mock_client)
        scanner = PassiveScanner(config, ctx)
        return scanner

    def test_source_map_detection(self):
        scanner = self._make_scanner()
        found = set()
        body = '{"version":3}\n//# sourceMappingURL=app.js.map'
        scanner._check_source_maps("https://test.com/app.js", body, found)
        assert len(scanner.result.findings) == 1
        assert "Source Map" in scanner.result.findings[0].title

    def test_mixed_content_detection(self):
        scanner = self._make_scanner()
        found = set()
        body = '<img src="http://cdn.example.com/logo.png">'
        scanner._check_mixed_content("https://test.com", body, {}, found)
        assert len(scanner.result.findings) == 1
        assert "Mixed Content" in scanner.result.findings[0].title

    def test_mixed_content_ignored_on_http(self):
        scanner = self._make_scanner()
        found = set()
        body = '<img src="http://cdn.example.com/logo.png">'
        scanner._check_mixed_content("http://test.com", body, {}, found)
        assert len(scanner.result.findings) == 0

    def test_sri_missing_detection(self):
        scanner = self._make_scanner()
        found = set()
        body = '<script src="https://cdn.example.com/lib.js"></script>'
        scanner._check_sri_missing("https://test.com", body, found)
        assert len(scanner.result.findings) == 1
        assert "Subresource Integrity" in scanner.result.findings[0].title

    def test_sri_present_no_finding(self):
        scanner = self._make_scanner()
        found = set()
        body = '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc"></script>'
        scanner._check_sri_missing("https://test.com", body, found)
        assert len(scanner.result.findings) == 0

    def test_insecure_form_action(self):
        scanner = self._make_scanner()
        found = set()
        body = '<form action="http://insecure.com/login" method="POST">'
        scanner._check_insecure_form_action("https://test.com", body, found)
        assert len(scanner.result.findings) == 1

    def test_autocomplete_sensitive(self):
        scanner = self._make_scanner()
        found = set()
        body = '<input type="password" name="pass">'
        scanner._check_autocomplete_sensitive("https://test.com", body, found)
        assert len(scanner.result.findings) == 1

    def test_csp_details_unsafe_inline(self):
        scanner = self._make_scanner()
        found = set()
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        scanner._check_csp_details("https://test.com", headers, found)
        assert len(scanner.result.findings) == 1
        assert "Content Security Policy" in scanner.result.findings[0].title or "CSP" in scanner.result.findings[0].title

    def test_csp_details_multiple_issues(self):
        scanner = self._make_scanner()
        found = set()
        headers = {"Content-Security-Policy": "script-src 'unsafe-inline' 'unsafe-eval'"}
        scanner._check_csp_details("https://test.com", headers, found)
        assert len(scanner.result.findings) == 1
        # Should mention multiple issues
        desc = scanner.result.findings[0].description
        assert "unsafe-inline" in desc
        assert "unsafe-eval" in desc

    def test_hsts_details_low_max_age(self):
        scanner = self._make_scanner()
        found = set()
        headers = {"Strict-Transport-Security": "max-age=3600"}
        scanner._check_hsts_details("https://test.com", headers, found)
        assert len(scanner.result.findings) == 1
        assert "HSTS" in scanner.result.findings[0].title

    def test_cookie_scope_broad_domain(self):
        scanner = self._make_scanner()
        found = set()
        headers = {"Set-Cookie": "session=abc123; domain=.example.com; path=/"}
        scanner._check_cookie_scope("https://app.example.com", headers, found)
        assert any("Broad" in f.title or "scope" in f.title.lower()
                    for f in scanner.result.findings)


# ═══════════════════════════════════════════════════════════════════════
# Enhanced Header Scanner Tests
# ═══════════════════════════════════════════════════════════════════════

class TestHeaderScannerEnhancements:

    def test_cross_origin_headers_missing(self):
        from secprobe.scanners.header_scanner import HeaderScanner
        from secprobe.config import ScanConfig
        from secprobe.core.context import ScanContext

        config = ScanConfig(target="https://test.com")
        mock_client = MagicMock()
        mock_client._session = MagicMock()
        mock_client._session.cookies = {}
        ctx = ScanContext(http_client=mock_client)
        scanner = HeaderScanner(config, ctx)
        # Call the new method directly
        scanner._check_cross_origin_headers({})
        # Should flag COOP, COEP, CORP, X-Permitted-Cross-Domain-Policies
        co_findings = [f for f in scanner.result.findings
                       if "Cross-Origin" in f.title or "Cross-Domain" in f.title]
        assert len(co_findings) >= 3

    def test_cross_origin_headers_present(self):
        from secprobe.scanners.header_scanner import HeaderScanner
        from secprobe.config import ScanConfig
        from secprobe.core.context import ScanContext

        config = ScanConfig(target="https://test.com")
        mock_client = MagicMock()
        mock_client._session = MagicMock()
        mock_client._session.cookies = {}
        ctx = ScanContext(http_client=mock_client)
        scanner = HeaderScanner(config, ctx)
        headers = {
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
        }
        scanner._check_cross_origin_headers(headers)
        assert len(scanner.result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════
# Enhanced Cookie Scanner Tests
# ═══════════════════════════════════════════════════════════════════════

class TestCookieScannerEnhancements:

    def _make_scanner(self):
        from secprobe.scanners.cookie_scanner import CookieScanner
        from secprobe.config import ScanConfig
        from secprobe.core.context import ScanContext

        config = ScanConfig(target="https://test.com")
        mock_client = MagicMock()
        mock_client._session = MagicMock()
        mock_client._session.cookies = {}
        ctx = ScanContext(http_client=mock_client)
        scanner = CookieScanner(config, ctx)
        return scanner

    def test_shannon_entropy_high(self):
        from secprobe.scanners.cookie_scanner import CookieScanner
        # Random hex string should have high entropy
        entropy = CookieScanner._shannon_entropy("a1b2c3d4e5f6a7b8c9d0")
        assert entropy > 3.0

    def test_shannon_entropy_low(self):
        from secprobe.scanners.cookie_scanner import CookieScanner
        # Repetitive string should have low entropy
        entropy = CookieScanner._shannon_entropy("aaaaaaaaaa")
        assert entropy < 1.0

    def test_shannon_entropy_empty(self):
        from secprobe.scanners.cookie_scanner import CookieScanner
        assert CookieScanner._shannon_entropy("") == 0.0

    def test_entropy_check_low_entropy_session(self):
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "session_id"
        cookie.value = "00000000000000000000"  # Low entropy
        cookie.secure = True
        scanner._check_cookie_entropy(cookie, "https://test.com")
        assert any("entropy" in f.title.lower() for f in scanner.result.findings)

    def test_entropy_check_short_session(self):
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "session_id"
        cookie.value = "abc"  # Too short
        cookie.secure = True
        scanner._check_cookie_entropy(cookie, "https://test.com")
        assert any("short" in f.title.lower() for f in scanner.result.findings)

    def test_entropy_check_non_session_ignored(self):
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "theme_preference"
        cookie.value = "dark"
        scanner._check_cookie_entropy(cookie, "https://test.com")
        assert len(scanner.result.findings) == 0

    def test_host_prefix_validation(self):
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "__Host-session"
        cookie.secure = False
        cookie.path = "/"
        cookie.domain = ""
        scanner._check_cookie_prefix(cookie, "https://test.com")
        assert any("__Host-" in f.title for f in scanner.result.findings)

    def test_host_prefix_valid(self):
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "__Host-session"
        cookie.secure = True
        cookie.path = "/"
        cookie.domain = ""  # No domain attribute
        scanner._check_cookie_prefix(cookie, "https://test.com")
        assert len(scanner.result.findings) == 0

    def test_secure_prefix_validation(self):
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "__Secure-token"
        cookie.secure = False
        scanner._check_cookie_prefix(cookie, "https://test.com")
        assert any("__Secure-" in f.title for f in scanner.result.findings)

    def test_long_lived_session_cookie(self):
        import time
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "session_id"
        cookie.expires = time.time() + (90 * 86400)  # 90 days
        scanner._check_cookie_expiry(cookie, {"expires": "future"}, "https://test.com")
        assert any("Long-lived" in f.title for f in scanner.result.findings)

    def test_short_lived_session_no_finding(self):
        import time
        scanner = self._make_scanner()
        cookie = MagicMock()
        cookie.name = "session_id"
        cookie.expires = time.time() + (3600)  # 1 hour
        scanner._check_cookie_expiry(cookie, {"expires": "soon"}, "https://test.com")
        assert len(scanner.result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════
# Base Scanner _evade_payload Integration
# ═══════════════════════════════════════════════════════════════════════

class TestEvadePayloadIntegration:
    """Test that _evade_payload routes vuln_type to PayloadMutator."""

    def test_evade_with_vuln_type_xss(self):
        from secprobe.scanners.base import BaseScanner
        from secprobe.config import ScanConfig

        config = ScanConfig(target="https://test.com")
        config.waf_evasion = False

        class TestScanner(BaseScanner):
            name = "Test"
            def scan(self): pass

        scanner = TestScanner(config, None)
        variants = scanner._evade_payload("<script>alert(1)</script>",
                                          vuln_type="xss")
        assert variants[0] == "<script>alert(1)</script>"

    def test_evade_respects_max_variants(self):
        from secprobe.scanners.base import BaseScanner
        from secprobe.config import ScanConfig

        config = ScanConfig(target="https://test.com")
        config.waf_evasion = False

        class TestScanner(BaseScanner):
            name = "Test"
            def scan(self): pass

        scanner = TestScanner(config, None)
        # Even without WAF, PayloadMutator generates generic variants
        variants = scanner._evade_payload("test", max_variants=2)
        assert len(variants) <= 3  # original + up to 2

    def test_evade_with_waf_detected(self):
        from secprobe.scanners.base import BaseScanner
        from secprobe.config import ScanConfig
        from secprobe.core.context import ScanContext

        config = ScanConfig(target="https://test.com")
        config.waf_evasion = True

        mock_client = MagicMock()
        mock_waf = MagicMock()
        mock_waf.evade.return_value = ["evaded1"]
        mock_waf.detected_waf = "Cloudflare"

        context = ScanContext(http_client=mock_client, waf_detector=mock_waf)

        class TestScanner(BaseScanner):
            name = "Test"
            def scan(self): pass

        scanner = TestScanner(config, context)
        variants = scanner._evade_payload("' OR 1=1--",
                                          vuln_type="sqli", max_variants=5)
        assert variants[0] == "' OR 1=1--"
        assert len(variants) > 1


# ═══════════════════════════════════════════════════════════════════════
# DiffEngine / DynamicDetector / AnomalyDetector Unit Tests
# ═══════════════════════════════════════════════════════════════════════

class TestDynamicDetector:
    """Test dynamic content detection."""

    def test_strip_timestamps(self):
        from secprobe.core.response_analyzer import DynamicDetector
        dd = DynamicDetector()
        result = dd.strip_dynamic("Time: 2024-01-15T10:30:00Z data")
        assert "2024-01-15" not in result
        assert "data" in result

    def test_strip_uuids(self):
        from secprobe.core.response_analyzer import DynamicDetector
        dd = DynamicDetector()
        result = dd.strip_dynamic("id=550e8400-e29b-41d4-a716-446655440000")
        assert "550e8400" not in result

    def test_learn_from_baselines(self):
        from secprobe.core.response_analyzer import DynamicDetector
        dd = DynamicDetector()
        r1 = "Hello World token=abc123 end"
        r2 = "Hello World token=xyz789 end"
        dd.learn_from_baselines([r1, r2])
        assert dd.pattern_count > len(dd._compiled)  # Learned new patterns


class TestDiffEngine:
    """Test response comparison engine."""

    def test_identical_responses(self):
        from secprobe.core.response_analyzer import DiffEngine, ResponseModel
        engine = DiffEngine()
        resp = ResponseModel(status_code=200, headers={}, body="Same")
        diff = engine.compare(resp, resp)
        assert diff.similarity == 1.0
        assert not diff.is_significant

    def test_status_change_is_significant(self):
        from secprobe.core.response_analyzer import DiffEngine, ResponseModel
        engine = DiffEngine()
        a = ResponseModel(status_code=200, headers={}, body="OK")
        b = ResponseModel(status_code=500, headers={}, body="Error")
        diff = engine.compare(a, b)
        assert diff.status_changed
        assert diff.is_significant

    def test_body_diff_extracts_changes(self):
        from secprobe.core.response_analyzer import DiffEngine, ResponseModel
        engine = DiffEngine()
        a = ResponseModel(status_code=200, headers={},
                          body="Welcome to the site. Please login.")
        b = ResponseModel(status_code=200, headers={},
                          body="Welcome to the site. Error: invalid password.")
        diff = engine.compare(a, b)
        assert diff.similarity < 1.0
        assert len(diff.added_text) > 0 or len(diff.removed_text) > 0

    def test_json_similarity(self):
        from secprobe.core.response_analyzer import DiffEngine, ResponseModel, ContentType
        engine = DiffEngine()
        a = ResponseModel(status_code=200, headers={"Content-Type": "application/json"},
                          body='{"name": "test", "count": 5}')
        b = ResponseModel(status_code=200, headers={"Content-Type": "application/json"},
                          body='{"name": "test", "count": 10}')
        diff = engine.compare(a, b)
        assert 0 < diff.similarity < 1.0  # Similar but not identical


class TestAnomalyDetector:
    """Test statistical anomaly detection."""

    def test_no_baselines_not_anomalous(self):
        from secprobe.core.response_analyzer import AnomalyDetector, ResponseModel
        ad = AnomalyDetector()
        resp = ResponseModel(status_code=200, headers={}, body="test")
        result = ad.analyze(resp)
        assert not result.is_anomalous

    def test_size_anomaly(self):
        from secprobe.core.response_analyzer import AnomalyDetector, ResponseModel
        ad = AnomalyDetector()
        # Add baselines with consistent size
        for _ in range(5):
            ad.add_baseline(ResponseModel(status_code=200, headers={},
                                          body="A" * 1000))
        # Test with wildly different size
        result = ad.analyze(ResponseModel(status_code=200, headers={},
                                          body="A" * 100000))
        assert result.size_anomaly

    def test_status_anomaly(self):
        from secprobe.core.response_analyzer import AnomalyDetector, ResponseModel
        ad = AnomalyDetector()
        for _ in range(5):
            ad.add_baseline(ResponseModel(status_code=200, headers={}, body="OK"))
        result = ad.analyze(ResponseModel(status_code=500, headers={}, body="Error"))
        assert result.status_anomaly

    def test_baseline_count(self):
        from secprobe.core.response_analyzer import AnomalyDetector, ResponseModel
        ad = AnomalyDetector()
        assert ad.baseline_count == 0
        ad.add_baseline(ResponseModel(status_code=200, headers={}, body="test"))
        assert ad.baseline_count == 1
