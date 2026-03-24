"""
Core infrastructure tests — verify that the shared services
(WAF detection, Auth handling, Crawler, AttackSurface) work correctly
in isolation with mocked HTTP responses.
"""

import base64
import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from secprobe.core.context import ScanContext
from secprobe.core.auth import AuthConfig, AuthHandler, AuthType
from secprobe.core.exceptions import AuthenticationError
from secprobe.core.waf import WAFDetector, WAFResult, WAF_SIGNATURES
from secprobe.core.crawler import AttackSurface, FormData, Endpoint, Crawler
from secprobe.core.http_client import HTTPClientConfig, HTTPClient


# ═══════════════════════════════════════════════════════════════
# Auth Module Tests
# ═══════════════════════════════════════════════════════════════
class TestAuthConfig(unittest.TestCase):
    """Test AuthConfig parsing from CLI strings."""

    def test_basic_auth_parsing(self):
        cfg = AuthConfig.from_string("basic:admin:password123")
        self.assertEqual(cfg.auth_type, AuthType.BASIC)
        self.assertEqual(cfg.username, "admin")
        self.assertEqual(cfg.password, "password123")

    def test_bearer_token_parsing(self):
        cfg = AuthConfig.from_string("bearer:eyJhbGciOiJIUzI1NiJ9.test")
        self.assertEqual(cfg.auth_type, AuthType.BEARER)
        self.assertEqual(cfg.token, "eyJhbGciOiJIUzI1NiJ9.test")

    def test_header_auth_parsing(self):
        cfg = AuthConfig.from_string("header:X-API-Key:supersecret")
        self.assertEqual(cfg.auth_type, AuthType.HEADER)
        self.assertEqual(cfg.header_name, "X-API-Key")
        self.assertEqual(cfg.header_value, "supersecret")

    def test_cookie_auth_parsing(self):
        cfg = AuthConfig.from_string("cookie:session=abc123;token=xyz")
        self.assertEqual(cfg.auth_type, AuthType.COOKIE)
        self.assertEqual(cfg.token, "session=abc123;token=xyz")

    def test_empty_string_returns_none_auth(self):
        cfg = AuthConfig.from_string("")
        self.assertEqual(cfg.auth_type, AuthType.NONE)

    def test_unknown_format_raises_error(self):
        with self.assertRaises(AuthenticationError):
            AuthConfig.from_string("ftp:user:pass")


class TestAuthHandler(unittest.TestCase):
    """Test AuthHandler header/cookie generation."""

    def test_basic_auth_headers(self):
        cfg = AuthConfig(auth_type=AuthType.BASIC, username="admin", password="pass")
        handler = AuthHandler(cfg)
        headers = handler.get_headers()
        expected = base64.b64encode(b"admin:pass").decode()
        self.assertEqual(headers["Authorization"], f"Basic {expected}")

    def test_bearer_auth_headers(self):
        cfg = AuthConfig(auth_type=AuthType.BEARER, token="mytoken123")
        handler = AuthHandler(cfg)
        headers = handler.get_headers()
        self.assertEqual(headers["Authorization"], "Bearer mytoken123")

    def test_header_auth_headers(self):
        cfg = AuthConfig(auth_type=AuthType.HEADER, header_name="X-API-Key", header_value="key123")
        handler = AuthHandler(cfg)
        headers = handler.get_headers()
        self.assertEqual(headers["X-API-Key"], "key123")

    def test_none_auth_returns_empty(self):
        cfg = AuthConfig(auth_type=AuthType.NONE)
        handler = AuthHandler(cfg)
        headers = handler.get_headers()
        self.assertEqual(headers, {})

    def test_cookie_auth_cookies(self):
        cfg = AuthConfig(auth_type=AuthType.COOKIE, token="session=abc123; token=xyz789")
        handler = AuthHandler(cfg)
        cookies = handler.get_cookies()
        self.assertEqual(cookies["session"], "abc123")
        self.assertEqual(cookies["token"], "xyz789")

    def test_form_login_success(self):
        cfg = AuthConfig(
            auth_type=AuthType.FORM,
            login_url="http://test.local/login",
            username="admin",
            password="pass123",
            username_field="user",
            password_field="pw",
        )
        handler = AuthHandler(cfg)

        # Mock HTTP client with successful login response
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.text = "Welcome admin"
        mock_resp.status_code = 200
        mock_cookie = MagicMock()
        mock_cookie.name = "session"
        mock_cookie.value = "logged_in_abc"
        mock_resp.cookies = [mock_cookie]
        mock_client.post.return_value = mock_resp

        result = handler.perform_form_login(mock_client)
        self.assertTrue(result)
        # Verify post was called with correct data
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        self.assertEqual(call_args[1]["data"]["user"], "admin")
        self.assertEqual(call_args[1]["data"]["pw"], "pass123")

    def test_form_login_failure_indicator(self):
        cfg = AuthConfig(
            auth_type=AuthType.FORM,
            login_url="http://test.local/login",
            username="admin",
            password="wrong",
            failure_indicator="Invalid credentials",
        )
        handler = AuthHandler(cfg)

        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.text = "Invalid credentials. Please try again."
        mock_resp.status_code = 200
        mock_resp.cookies = []
        mock_client.post.return_value = mock_resp

        with self.assertRaises(AuthenticationError):
            handler.perform_form_login(mock_client)


# ═══════════════════════════════════════════════════════════════
# WAF Detection Tests
# ═══════════════════════════════════════════════════════════════
class TestWAFDetector(unittest.TestCase):
    """Test WAF fingerprinting and evasion."""

    def _mock_response(self, headers=None, body="", status_code=200, cookies=""):
        resp = MagicMock()
        _headers = dict(headers or {})
        if cookies:
            _headers["Set-Cookie"] = cookies
        # Use a real dict subclass so .get() works naturally and
        # attribute access (resp.headers["key"]) also works.
        resp.headers = _headers
        resp.text = body
        resp.status_code = status_code
        return resp

    def test_detects_cloudflare(self):
        detector = WAFDetector()
        resp = self._mock_response(
            headers={"Server": "cloudflare", "CF-RAY": "abc123-LAX"},
        )
        waf = detector._fingerprint_response(resp)
        self.assertEqual(waf, "Cloudflare")

    def test_detects_modsecurity(self):
        detector = WAFDetector()
        resp = self._mock_response(
            body="ModSecurity: Access denied with code 403",
        )
        waf = detector._fingerprint_response(resp)
        self.assertEqual(waf, "ModSecurity")

    def test_detects_imperva(self):
        detector = WAFDetector()
        resp = self._mock_response(
            headers={"X-CDN": "Incapsula"},
            cookies="visid_incap_1234=abc",
        )
        waf = detector._fingerprint_response(resp)
        self.assertEqual(waf, "Imperva / Incapsula")

    def test_no_waf_on_clean_response(self):
        detector = WAFDetector()
        resp = self._mock_response(
            headers={"Server": "Apache/2.4", "Content-Type": "text/html"},
            body="<html><body>Hello World</body></html>",
        )
        waf = detector._fingerprint_response(resp)
        self.assertIsNone(waf)

    def test_waf_signatures_has_entries(self):
        self.assertTrue(len(WAF_SIGNATURES) >= 20, "Should have 20+ WAF signatures")

    def test_waf_result_dataclass(self):
        result = WAFResult()
        self.assertFalse(result.detected)
        self.assertEqual(result.waf_name, "")
        self.assertEqual(result.evidence, [])

    def test_active_detection_with_blocking(self):
        """Test the full detect() flow with a WAF that blocks probes."""
        detector = WAFDetector()

        baseline = self._mock_response(status_code=200, body="OK")
        blocked = self._mock_response(
            status_code=403,
            headers={"Server": "cloudflare", "CF-RAY": "test-ray"},
            body="Attention Required! | Cloudflare",
        )

        mock_client = MagicMock()
        mock_client.get.side_effect = [baseline, blocked]

        result = detector.detect(mock_client, "http://test.local")
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "Cloudflare")
        self.assertGreater(result.confidence, 0.5)


class TestWAFEvasion(unittest.TestCase):
    """Test WAF evasion payload mutations."""

    def setUp(self):
        self.detector = WAFDetector()

    def test_url_encode(self):
        result = self.detector._evade_url_encode("<script>")
        self.assertNotIn("<", result)
        self.assertIn("%3C", result)

    def test_double_url_encode(self):
        result = self.detector._evade_double_url_encode("<")
        self.assertIn("%25", result)

    def test_case_swap_changes_case(self):
        # Run multiple times — at least one should differ from original
        payload = "SELECT * FROM users"
        results = set()
        for _ in range(20):
            results.add(self.detector._evade_case_swap(payload))
        # Should produce multiple variants
        self.assertTrue(len(results) > 1, "Case swap should produce variants")

    def test_comment_inject(self):
        result = self.detector._evade_comment_inject("SELECT * FROM users")
        self.assertIn("/**/", result)

    def test_html_entity_encode(self):
        result = self.detector._evade_html_entity("<script>")
        self.assertIn("&lt;", result)
        self.assertIn("&gt;", result)

    def test_null_byte(self):
        result = self.detector._evade_null_byte("test")
        self.assertIn("%00", result)

    def test_evade_produces_variants(self):
        variants = self.detector.evade("' OR 1=1--")
        self.assertTrue(len(variants) > 0, "Should produce at least one evasion variant")

    def test_hex_encode(self):
        result = self.detector._evade_hex_encode("admin' OR '1'='1")
        self.assertIn("0x27", result)  # ' = 0x27

    def test_concat_split(self):
        result = self.detector._evade_concat_split("admin")
        self.assertIn("||", result)


# ═══════════════════════════════════════════════════════════════
# Crawler / AttackSurface Tests
# ═══════════════════════════════════════════════════════════════
class TestAttackSurface(unittest.TestCase):
    """Test the AttackSurface data structure."""

    def test_empty_surface(self):
        surface = AttackSurface()
        self.assertEqual(len(surface.urls), 0)
        self.assertEqual(len(surface.forms), 0)
        self.assertEqual(len(surface.endpoints), 0)
        self.assertEqual(surface.total_inputs, 0)

    def test_total_inputs_counts_params_and_forms(self):
        surface = AttackSurface()
        surface.parameters = {"id", "name", "email"}
        surface.forms = [
            FormData(action="/login", method="POST", fields=[
                {"name": "user", "type": "text"},
                {"name": "pass", "type": "password"},
            ]),
        ]
        self.assertEqual(surface.total_inputs, 5)  # 3 params + 2 form fields

    def test_urls_are_set(self):
        surface = AttackSurface()
        surface.urls.add("http://test.local/a")
        surface.urls.add("http://test.local/a")  # Duplicate
        self.assertEqual(len(surface.urls), 1)


class TestFormData(unittest.TestCase):
    """Test FormData dataclass."""

    def test_field_names_property(self):
        form = FormData(
            action="/submit",
            method="POST",
            fields=[
                {"name": "username", "type": "text", "value": ""},
                {"name": "password", "type": "password", "value": ""},
                {"type": "submit", "value": "Login"},  # No name
            ],
        )
        self.assertEqual(form.field_names, ["username", "password"])

    def test_empty_form(self):
        form = FormData(action="/", method="GET")
        self.assertEqual(form.field_names, [])


class TestEndpoint(unittest.TestCase):
    """Test Endpoint dataclass."""

    def test_defaults(self):
        ep = Endpoint(url="http://test.local/api")
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.params, {})
        self.assertEqual(ep.source, "")

    def test_with_params(self):
        ep = Endpoint(
            url="http://test.local/api?id=1",
            method="GET",
            params={"id": "1"},
            source="link",
        )
        self.assertEqual(ep.params["id"], "1")
        self.assertEqual(ep.source, "link")


class TestCrawlerInit(unittest.TestCase):
    """Test Crawler initialization (no network)."""

    def test_crawler_setup(self):
        mock_client = MagicMock()
        crawler = Crawler(mock_client, "http://test.local", max_depth=2, max_pages=50)
        self.assertEqual(crawler.base_url, "http://test.local")
        self.assertEqual(crawler.max_depth, 2)
        self.assertEqual(crawler.max_pages, 50)
        self.assertEqual(crawler.base_domain, "test.local")

    def test_crawler_strips_trailing_slash(self):
        mock_client = MagicMock()
        crawler = Crawler(mock_client, "http://test.local/", max_depth=1)
        self.assertEqual(crawler.base_url, "http://test.local")


# ═══════════════════════════════════════════════════════════════
# HTTPClientConfig Tests
# ═══════════════════════════════════════════════════════════════
class TestHTTPClientConfigExtended(unittest.TestCase):
    """Extended tests for HTTPClientConfig beyond existing test file."""

    def test_defaults(self):
        cfg = HTTPClientConfig()
        self.assertEqual(cfg.timeout, 15)
        self.assertEqual(cfg.max_retries, 3)
        self.assertEqual(cfg.backoff_factor, 0.5)
        self.assertFalse(cfg.verify_ssl)
        # user_agent may be None by default (set at runtime)

    def test_custom_values(self):
        cfg = HTTPClientConfig(
            timeout=30,
            max_retries=5,
            backoff_factor=1.0,
            verify_ssl=False,
            user_agent="Custom/1.0",
            proxy="http://proxy:8080",
        )
        self.assertEqual(cfg.timeout, 30)
        self.assertEqual(cfg.max_retries, 5)
        self.assertFalse(cfg.verify_ssl)
        self.assertEqual(cfg.proxy, "http://proxy:8080")


# ═══════════════════════════════════════════════════════════════
# ScanContext Integration Tests
# ═══════════════════════════════════════════════════════════════
class TestScanContextIntegration(unittest.TestCase):
    """Test ScanContext wiring with attack surface and forms."""

    def test_injection_urls_from_surface(self):
        surface = AttackSurface()
        surface.endpoints = [
            Endpoint(url="http://test.local/api?id=1", params={"id": "1"}),
            Endpoint(url="http://test.local/page", params={}),  # No params — excluded
        ]
        surface.urls = {"http://test.local/search?q=test"}

        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client, attack_surface=surface)
        urls = ctx.get_injection_urls()
        self.assertIn("http://test.local/api?id=1", urls)
        self.assertIn("http://test.local/search?q=test", urls)
        self.assertNotIn("http://test.local/page", urls)  # No params

    def test_injectable_forms_from_surface(self):
        surface = AttackSurface()
        surface.forms = [
            FormData(
                action="/login",
                method="POST",
                fields=[{"name": "user", "type": "text"}, {"name": "pass", "type": "password"}],
                url="http://test.local/login",
            ),
        ]

        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client, attack_surface=surface)
        forms = ctx.get_injectable_forms()
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "/login")
        self.assertEqual(forms[0]["method"], "POST")
        self.assertIn("user", forms[0]["fields"])
        self.assertIn("pass", forms[0]["fields"])

    def test_discovered_urls_appended(self):
        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client)
        ctx.discovered_urls = ["http://test.local/found1", "http://test.local/found2"]
        urls = ctx.get_injection_urls()
        self.assertEqual(len(urls), 2)

    def test_crawled_urls_without_surface(self):
        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client)
        self.assertEqual(ctx.get_crawled_urls(), [])

    def test_crawled_urls_with_surface(self):
        surface = AttackSurface()
        surface.urls = {"http://a.com", "http://b.com"}
        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client, attack_surface=surface)
        crawled = ctx.get_crawled_urls()
        self.assertEqual(len(crawled), 2)


# ═══════════════════════════════════════════════════════════════
# Payload Loader Tests
# ═══════════════════════════════════════════════════════════════
class TestPayloadLoader(unittest.TestCase):
    """Test that all payload files load correctly."""

    def test_load_sqli_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("sqli")
        self.assertTrue(len(payloads) > 100, f"sqli should have 100+ payloads, got {len(payloads)}")

    def test_load_xss_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("xss")
        self.assertTrue(len(payloads) > 100, f"xss should have 100+ payloads, got {len(payloads)}")

    def test_load_lfi_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("lfi")
        self.assertTrue(len(payloads) > 50, f"lfi should have 50+ payloads, got {len(payloads)}")

    def test_load_directories_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("directories")
        self.assertTrue(len(payloads) > 500, f"directories should have 500+ paths, got {len(payloads)}")

    def test_load_subdomains_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("subdomains")
        self.assertTrue(len(payloads) > 500, f"subdomains should have 500+ entries, got {len(payloads)}")

    def test_load_nosql_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("nosql")
        self.assertTrue(len(payloads) > 50, f"nosql should have 50+ payloads, got {len(payloads)}")

    def test_load_ssti_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("ssti")
        self.assertTrue(len(payloads) > 50, f"ssti should have 50+ payloads, got {len(payloads)}")

    def test_load_xxe_payloads(self):
        from secprobe.payloads import load_payloads
        payloads = load_payloads("xxe")
        self.assertTrue(len(payloads) > 20, f"xxe should have 20+ payloads, got {len(payloads)}")

    def test_section_loader_sqli(self):
        from secprobe.payloads import load_payloads_by_section
        sections = load_payloads_by_section("sqli")
        self.assertIsInstance(sections, dict)
        self.assertTrue(len(sections) > 5, "sqli should have 5+ sections")
        # Non-separator sections should have payloads
        real_sections = {k: v for k, v in sections.items() if k.strip("─ ")}
        for name, payloads in real_sections.items():
            self.assertTrue(len(payloads) > 0, f"Section '{name}' should not be empty")

    def test_section_loader_lfi(self):
        from secprobe.payloads import load_payloads_by_section
        sections = load_payloads_by_section("lfi")
        self.assertIsInstance(sections, dict)
        self.assertTrue(len(sections) > 5, "lfi should have 5+ sections")


if __name__ == "__main__":
    unittest.main()
