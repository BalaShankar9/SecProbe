"""
Tests for the Passive Scanner and Session Management engine.
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from secprobe.config import ScanConfig, Severity
from secprobe.scanners.passive_scanner import (
    PassiveScanner,
    INTERNAL_IP_RE,
    SENSITIVE_PATTERNS,
    ERROR_PATTERNS,
    DIR_LISTING_RE,
    SOURCE_CODE_PATTERNS,
    INTERESTING_COMMENT_RE,
    SECURITY_HEADERS,
    INFO_LEAK_HEADERS,
)
from secprobe.core.session import (
    SessionManager,
    SessionCredentials,
    SessionState,
    CSRF_HTML_RE,
    CSRF_META_RE,
)


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _mock_response(body="", status_code=200, headers=None):
    resp = MagicMock()
    resp.text = body
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.cookies = MagicMock()
    resp.cookies.get_dict.return_value = {}
    resp.cookies.items.return_value = []
    return resp


def _make_scanner(target="https://example.com", response_body="",
                  response_headers=None, status_code=200):
    """Create a PassiveScanner with a mocked HTTP client."""
    config = ScanConfig(target=target)
    context = MagicMock()
    context.attack_surface = None
    context.get_crawled_urls.return_value = []
    context.get_injection_urls.return_value = []

    scanner = PassiveScanner(config, context)

    resp = _mock_response(response_body, status_code, response_headers or {})
    scanner.http_client.get.return_value = resp

    return scanner


# ═══════════════════════════════════════════════════════════════════
# Pattern Database Tests
# ═══════════════════════════════════════════════════════════════════

class TestInternalIPRegex(unittest.TestCase):

    def test_detects_10_x_range(self):
        self.assertRegex("ip: 10.0.0.1 end", INTERNAL_IP_RE)

    def test_detects_172_16_range(self):
        self.assertRegex("host 172.16.0.1 ok", INTERNAL_IP_RE)

    def test_detects_192_168_range(self):
        self.assertRegex("addr=192.168.1.100", INTERNAL_IP_RE)

    def test_detects_127_range(self):
        self.assertRegex("localhost 127.0.0.1", INTERNAL_IP_RE)

    def test_detects_169_254_link_local(self):
        self.assertRegex("169.254.169.254", INTERNAL_IP_RE)

    def test_ignores_public_ip(self):
        self.assertIsNone(INTERNAL_IP_RE.search("8.8.8.8"))

    def test_ignores_public_ip_2(self):
        self.assertIsNone(INTERNAL_IP_RE.search("1.2.3.4"))


class TestSensitivePatterns(unittest.TestCase):

    def test_detects_aws_key(self):
        text = "key=AKIAIOSFODNN7EXAMPLE1"
        matches = [name for name, pat, _, _ in SENSITIVE_PATTERNS if pat.search(text)]
        self.assertIn("AWS Access Key", matches)

    def test_detects_github_token(self):
        text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"
        matches = [name for name, pat, _, _ in SENSITIVE_PATTERNS if pat.search(text)]
        self.assertIn("GitHub Token", matches)

    def test_detects_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        matches = [name for name, pat, _, _ in SENSITIVE_PATTERNS if pat.search(text)]
        self.assertIn("Private Key Block", matches)

    def test_detects_stripe_key(self):
        text = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
        matches = [name for name, pat, _, _ in SENSITIVE_PATTERNS if pat.search(text)]
        self.assertIn("Stripe Secret Key", matches)

    def test_detects_db_connection_string(self):
        text = "postgres://user:pass@host:5432/db"
        matches = [name for name, pat, _, _ in SENSITIVE_PATTERNS if pat.search(text)]
        self.assertIn("Database Connection String", matches)

    def test_detects_password_assignment(self):
        text = 'password="SuperSecret123"'
        matches = [name for name, pat, _, _ in SENSITIVE_PATTERNS if pat.search(text)]
        self.assertIn("Generic Password Assignment", matches)

    def test_detects_jwt(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abcdefghijk"
        matches = [name for name, pat, _, _ in SENSITIVE_PATTERNS if pat.search(text)]
        self.assertIn("JWT Token", matches)


class TestErrorPatterns(unittest.TestCase):

    def test_php_error(self):
        text = "Fatal error: Uncaught Error in /var/www/html/index.php on line 42"
        matches = [name for name, pat, _ in ERROR_PATTERNS if pat.search(text)]
        self.assertIn("PHP Error/Warning", matches)

    def test_python_traceback(self):
        text = "Traceback (most recent call last):\n  File..."
        matches = [name for name, pat, _ in ERROR_PATTERNS if pat.search(text)]
        self.assertIn("Python Traceback", matches)

    def test_java_exception(self):
        text = "java.lang.NullPointerException\n\tat com.example.Main(Main.java:10)"
        matches = [name for name, pat, _ in ERROR_PATTERNS if pat.search(text)]
        self.assertIn("Java Exception", matches)

    def test_sql_error(self):
        text = "You have an error in your SQL syntax near MySQL"
        matches = [name for name, pat, _ in ERROR_PATTERNS if pat.search(text)]
        self.assertIn("SQL Error Message", matches)

    def test_debug_mode(self):
        text = "DJANGO_DEBUG=True"
        matches = [name for name, pat, _ in ERROR_PATTERNS if pat.search(text)]
        self.assertIn("Debug Mode Enabled", matches)

    def test_node_error(self):
        text = "TypeError: Cannot read property 'x'\n    at handler (/app/server.js:15:8)"
        matches = [name for name, pat, _ in ERROR_PATTERNS if pat.search(text)]
        self.assertIn("Node.js Error", matches)


class TestDirListingRegex(unittest.TestCase):

    def test_apache_listing(self):
        self.assertRegex("<title>Index of /uploads</title>", DIR_LISTING_RE)

    def test_nginx_listing(self):
        self.assertRegex("<h1>Index of /</h1>", DIR_LISTING_RE)

    def test_python_listing(self):
        self.assertRegex("Directory listing for /static", DIR_LISTING_RE)


class TestSourceCodePatterns(unittest.TestCase):

    def test_php_source(self):
        text = "<?php echo 'hello'; ?>"
        matches = [name for name, pat in SOURCE_CODE_PATTERNS if pat.search(text)]
        self.assertIn("PHP Source", matches)

    def test_asp_source(self):
        text = "<% Response.Write('test') %>"
        matches = [name for name, pat in SOURCE_CODE_PATTERNS if pat.search(text)]
        self.assertIn("ASP Source", matches)


class TestInterestingComments(unittest.TestCase):

    def test_todo_comment(self):
        text = "<!-- TODO: remove hardcoded password -->"
        self.assertIsNotNone(INTERESTING_COMMENT_RE.search(text))

    def test_password_comment(self):
        text = "<!-- password: admin123 -->"
        self.assertIsNotNone(INTERESTING_COMMENT_RE.search(text))

    def test_debug_comment(self):
        text = "<!-- DEBUG: enabled for staging -->"
        self.assertIsNotNone(INTERESTING_COMMENT_RE.search(text))

    def test_normal_comment_ignored(self):
        text = "<!-- Navigation menu -->"
        self.assertIsNone(INTERESTING_COMMENT_RE.search(text))


# ═══════════════════════════════════════════════════════════════════
# Passive Scanner Integration Tests
# ═══════════════════════════════════════════════════════════════════

class TestPassiveScannerMissingHeaders(unittest.TestCase):

    def test_reports_missing_security_headers(self):
        scanner = _make_scanner(response_headers={})
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(
            any("Missing Security Header" in t for t in titles),
            f"Expected missing header findings, got: {titles}",
        )

    def test_no_missing_header_finding_when_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }
        scanner = _make_scanner(response_headers=headers)
        scanner.scan()
        missing = [f for f in scanner.result.findings
                   if "Missing Security Header" in f.title]
        self.assertEqual(len(missing), 0, f"Unexpected findings: {[f.title for f in missing]}")


class TestPassiveScannerInfoLeak(unittest.TestCase):

    def test_detects_server_header(self):
        scanner = _make_scanner(response_headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(
            any("Server" in t and "Information Disclosure" in t for t in titles),
            f"Expected server info leak, got: {titles}",
        )

    def test_detects_x_powered_by(self):
        scanner = _make_scanner(response_headers={"X-Powered-By": "PHP/7.4.3"})
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("X-Powered-By" in t for t in titles))


class TestPassiveScannerErrors(unittest.TestCase):

    def test_detects_php_error(self):
        body = "<html>Fatal error: Uncaught Error in /var/www/html/index.php on line 42</html>"
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("PHP" in t for t in titles))

    def test_detects_python_traceback(self):
        body = "<html>Traceback (most recent call last):\n  File '/app/main.py'</html>"
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("Python" in t for t in titles))


class TestPassiveScannerSensitiveData(unittest.TestCase):

    def test_detects_aws_key_in_response(self):
        body = '<script>var key = "AKIAIOSFODNN7EXAMPLE1";</script>'
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("AWS" in t for t in titles))

    def test_detects_private_key(self):
        body = "<pre>-----BEGIN RSA PRIVATE KEY-----\nMIIBCgK...</pre>"
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("Private Key" in t for t in titles))


class TestPassiveScannerInternalIP(unittest.TestCase):

    def test_detects_internal_ip_in_body(self):
        body = "<html>Backend: 10.0.1.50:8080</html>"
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("Internal IP" in t for t in titles))

    def test_detects_internal_ip_in_header(self):
        scanner = _make_scanner(
            response_headers={"X-Backend-Server": "192.168.1.100:3000"}
        )
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("Internal IP" in t for t in titles))


class TestPassiveScannerDirListing(unittest.TestCase):

    def test_detects_directory_listing(self):
        body = "<html><title>Index of /uploads</title><h1>Index of /uploads</h1></html>"
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("Directory Listing" in t for t in titles))


class TestPassiveScannerSourceCode(unittest.TestCase):

    def test_detects_php_source(self):
        body = "<?php echo $_GET['name']; ?>"
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("PHP" in t and "Source" in t for t in titles))


class TestPassiveScannerComments(unittest.TestCase):

    def test_detects_sensitive_comments(self):
        body = '<html><!-- TODO: remove admin password from config --></html>'
        scanner = _make_scanner(response_body=body)
        scanner.scan()
        titles = [f.title for f in scanner.result.findings]
        self.assertTrue(any("Comment" in t for t in titles))


class TestPassiveScannerRegistered(unittest.TestCase):

    def test_passive_in_registry(self):
        from secprobe.scanners import SCANNER_REGISTRY
        self.assertIn("passive", SCANNER_REGISTRY)

    def test_passive_scanner_name(self):
        self.assertEqual(PassiveScanner.name, "Passive Analysis Scanner")


# ═══════════════════════════════════════════════════════════════════
# CSRF Token Extraction Tests
# ═══════════════════════════════════════════════════════════════════

class TestCSRFExtraction(unittest.TestCase):

    def test_extracts_from_input_field(self):
        html = '<input type="hidden" name="csrf_token" value="abc123">'
        match = CSRF_HTML_RE.search(html)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "csrf_token")
        self.assertEqual(match.group(2), "abc123")

    def test_extracts_django_csrf(self):
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="xyz789">'
        match = CSRF_HTML_RE.search(html)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(2), "xyz789")

    def test_extracts_laravel_token(self):
        html = '<input type="hidden" name="_token" value="laravel_token_123">'
        match = CSRF_HTML_RE.search(html)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(2), "laravel_token_123")

    def test_extracts_from_meta_tag(self):
        html = '<meta name="csrf-token" content="meta_token_456">'
        match = CSRF_META_RE.search(html)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "meta_token_456")


# ═══════════════════════════════════════════════════════════════════
# Session Manager Tests
# ═══════════════════════════════════════════════════════════════════

class TestSessionManager(unittest.TestCase):

    def setUp(self):
        self.http_client = MagicMock()

    def test_basic_auth(self):
        creds = SessionCredentials(
            auth_type="basic",
            username="admin",
            password="password",
        )
        mgr = SessionManager(self.http_client, creds)
        result = mgr.authenticate()
        self.assertTrue(result)
        self.assertTrue(mgr.state.is_authenticated)
        headers = mgr.get_headers()
        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("Basic "))

    def test_bearer_auth(self):
        creds = SessionCredentials(
            auth_type="bearer",
            token="my_jwt_token_here",
        )
        mgr = SessionManager(self.http_client, creds)
        result = mgr.authenticate()
        self.assertTrue(result)
        headers = mgr.get_headers()
        self.assertEqual(headers["Authorization"], "Bearer my_jwt_token_here")

    def test_api_key_auth(self):
        creds = SessionCredentials(
            auth_type="api_key",
            token="secret_api_key",
            header_name="X-API-Key",
        )
        mgr = SessionManager(self.http_client, creds)
        result = mgr.authenticate()
        self.assertTrue(result)
        headers = mgr.get_headers()
        self.assertEqual(headers["X-API-Key"], "secret_api_key")

    def test_cookie_auth(self):
        creds = SessionCredentials(
            auth_type="cookie",
            token="session=abc123; user=admin",
        )
        mgr = SessionManager(self.http_client, creds)
        result = mgr.authenticate()
        self.assertTrue(result)
        cookies = mgr.get_cookies()
        self.assertEqual(cookies["session"], "abc123")
        self.assertEqual(cookies["user"], "admin")

    def test_no_credentials_returns_false(self):
        mgr = SessionManager(self.http_client, None)
        result = mgr.authenticate()
        self.assertFalse(result)

    def test_form_login_success(self):
        creds = SessionCredentials(
            auth_type="form",
            login_url="https://example.com/login",
            username="admin",
            password="password",
            success_indicator="Welcome, admin",
        )

        # Mock GET login page (with CSRF token)
        login_page = _mock_response(
            '<html><input name="csrf_token" value="tok123"></html>',
            200,
            {},
        )

        # Mock POST login response (success)
        login_resp = _mock_response(
            "<html>Welcome, admin</html>",
            200,
            {"Set-Cookie": "session=abc123; Path=/"},
        )
        login_resp.cookies.get_dict.return_value = {"session": "abc123"}

        self.http_client.get.return_value = login_page
        self.http_client.post.return_value = login_resp

        mgr = SessionManager(self.http_client, creds)
        result = mgr.authenticate()
        self.assertTrue(result)
        self.assertTrue(mgr.state.is_authenticated)

    def test_form_login_failure(self):
        creds = SessionCredentials(
            auth_type="form",
            login_url="https://example.com/login",
            username="admin",
            password="wrong",
            failure_indicator="Invalid credentials",
        )

        login_page = _mock_response("<html><form></form></html>")
        login_resp = _mock_response("<html>Invalid credentials</html>", 200)
        login_resp.cookies.get_dict.return_value = {}

        self.http_client.get.return_value = login_page
        self.http_client.post.return_value = login_resp

        mgr = SessionManager(self.http_client, creds)
        result = mgr.authenticate()
        self.assertFalse(result)


class TestSessionManagerReauth(unittest.TestCase):

    def setUp(self):
        self.http_client = MagicMock()

    def test_reauth_on_401(self):
        creds = SessionCredentials(auth_type="basic", username="a", password="b")
        mgr = SessionManager(self.http_client, creds)
        mgr.authenticate()

        # Simulate 401 response
        resp_401 = _mock_response("Unauthorized", 401)
        result = mgr.handle_response(resp_401, "https://example.com/api")

        # Should have attempted re-auth
        self.assertTrue(result)  # Basic auth always succeeds
        self.assertEqual(mgr.state.reauth_count, 1)

    def test_max_reauth_attempts(self):
        creds = SessionCredentials(auth_type="form", login_url="https://example.com/login")

        # Make form login always fail
        self.http_client.get.return_value = _mock_response("<html></html>")
        self.http_client.post.return_value = _mock_response("Invalid credentials", 200)
        self.http_client.post.return_value.cookies.get_dict.return_value = {}

        mgr = SessionManager(self.http_client, creds, max_reauth_attempts=2)

        # Trigger auth failures
        for _ in range(3):
            resp_401 = _mock_response("Unauthorized", 401)
            mgr.handle_response(resp_401)

        self.assertGreaterEqual(mgr.state.auth_failures, 2)


class TestSessionManagerCookies(unittest.TestCase):

    def setUp(self):
        self.http_client = MagicMock()

    def test_updates_cookies_from_response(self):
        mgr = SessionManager(self.http_client)
        resp = _mock_response("ok", 200, {"Set-Cookie": "token=xyz; Path=/"})
        resp.cookies.get_dict.return_value = {"token": "xyz"}

        mgr.handle_response(resp)
        self.assertEqual(mgr.state.cookies.get("token"), "xyz")

    def test_csrf_extraction_from_response(self):
        mgr = SessionManager(self.http_client)
        body = '<html><input name="csrf_token" value="fresh_token"></html>'
        resp = _mock_response(body, 200)

        mgr.handle_response(resp)
        self.assertEqual(mgr.state.csrf_token, "fresh_token")
        self.assertEqual(mgr.state.csrf_field_name, "csrf_token")

    def test_get_csrf_form_data(self):
        mgr = SessionManager(self.http_client)
        mgr.state.csrf_token = "test_token"
        mgr.state.csrf_field_name = "_token"

        form_data = mgr.get_csrf_form_data()
        self.assertEqual(form_data, {"_token": "test_token"})


class TestSessionManagerValidity(unittest.TestCase):

    def test_session_valid_after_auth(self):
        creds = SessionCredentials(auth_type="basic", username="a", password="b")
        mgr = SessionManager(MagicMock(), creds)
        mgr.authenticate()
        self.assertTrue(mgr.is_session_valid())

    def test_session_invalid_when_not_authenticated(self):
        mgr = SessionManager(MagicMock())
        self.assertFalse(mgr.is_session_valid())

    def test_session_expired(self):
        creds = SessionCredentials(auth_type="basic", username="a", password="b")
        mgr = SessionManager(MagicMock(), creds, session_timeout=1)
        mgr.authenticate()
        mgr.state.last_auth_time -= 10  # Simulate 10s ago
        self.assertFalse(mgr.is_session_valid())

    def test_ensure_authenticated_reauths(self):
        creds = SessionCredentials(auth_type="basic", username="a", password="b")
        mgr = SessionManager(MagicMock(), creds, session_timeout=1)
        mgr.authenticate()
        mgr.state.last_auth_time -= 10  # Expired
        result = mgr.ensure_authenticated()
        self.assertTrue(result)
        self.assertTrue(mgr.state.is_authenticated)


class TestSessionManagerCallbacks(unittest.TestCase):

    def test_reauth_callback_called(self):
        callback = MagicMock()
        creds = SessionCredentials(auth_type="basic", username="a", password="b")
        mgr = SessionManager(MagicMock(), creds)
        mgr.on_reauth(callback)
        mgr.authenticate()

        # Trigger reauth
        resp_401 = _mock_response("Unauthorized", 401)
        mgr.handle_response(resp_401)

        callback.assert_called_once()


if __name__ == "__main__":
    unittest.main()
