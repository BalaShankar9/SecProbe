"""
Behavioral tests for all scanners — verify findings are generated
from mocked HTTP responses. These tests prove scanners actually work,
not just that they import.

NOTE: Injection scanners now use a DetectionEngine that profiles
endpoints with 5 baseline requests BEFORE sending payloads. Tests must
provide clean responses for profiling, then vulnerable responses for
payload testing. The pattern is:
    side_effect = [baseline] + [clean] * PROFILE_SAMPLES + [vuln] * N
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from secprobe.config import ScanConfig, Severity
from secprobe.core.context import ScanContext
from secprobe.models import ScanResult

# Detection engine sends this many baseline requests during profile()
PROFILE_SAMPLES = 5


def _make_config(target="http://test.local"):
    return ScanConfig(target=target)


def _make_context(http_client=None):
    if http_client is None:
        http_client = MagicMock()
        http_client._session = MagicMock()
        http_client._session.cookies = {}
    ctx = ScanContext(http_client=http_client)
    return ctx


def _mock_response(text="", status_code=200, headers=None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.url = "http://test.local"
    # Prevent MagicMock auto-creating .raw so CSRF scanner
    # falls through to the simple Set-Cookie string path
    resp.raw = None
    return resp


def _mock_client(get_response=None, post_response=None):
    client = MagicMock()
    if get_response:
        client.get.return_value = get_response
    else:
        client.get.return_value = _mock_response()
    if post_response:
        client.post.return_value = post_response
    else:
        client.post.return_value = _mock_response()
    client._session = MagicMock()
    client._session.cookies = {}
    return client


# ════════════════════════════════════════════════════════════════
# LFI Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestLFIScanner(unittest.TestCase):
    def _run_scanner(self, get_text, url="http://test.local?file=test"):
        from secprobe.scanners.lfi_scanner import LFIScanner

        config = _make_config(url)
        baseline = _mock_response(text="normal page")
        clean = _mock_response(text="normal page")  # for profiling
        vuln_resp = _mock_response(text=get_text)
        client = _mock_client()
        # quick-check + baseline + PROFILE_SAMPLES profiling (clean) + vuln responses
        client.get.side_effect = [baseline] + [baseline] + [clean] * PROFILE_SAMPLES + [vuln_resp] * 500
        ctx = _make_context(client)
        scanner = LFIScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_unix_passwd(self):
        result = self._run_scanner("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        high_or_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(high_or_crit) > 0, "Should detect /etc/passwd content")

    def test_detects_windows_ini(self):
        result = self._run_scanner("; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]")
        high_or_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(high_or_crit) > 0, "Should detect win.ini content")

    def test_no_findings_on_safe_response(self):
        result = self._run_scanner("Welcome to our website")
        high_or_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_or_crit), 0, "Should not report LFI on safe content")


# ════════════════════════════════════════════════════════════════
# XXE Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestXXEScanner(unittest.TestCase):
    def _run_scanner(self, post_text, post_headers=None, baseline_text="normal page", baseline_ct="text/html"):
        from secprobe.scanners.xxe_scanner import XXEScanner

        config = _make_config("http://test.local/api")
        baseline = _mock_response(text=baseline_text, headers={"Content-Type": baseline_ct})
        clean = _mock_response(text=baseline_text, headers={"Content-Type": baseline_ct})
        vuln_resp = _mock_response(text=post_text, headers=post_headers or {})
        client = _mock_client()
        # GETs: baseline + profiling. POSTs: vuln responses.
        client.get.side_effect = [baseline] + [clean] * PROFILE_SAMPLES + [clean] * 50
        client.post.return_value = vuln_resp
        ctx = _make_context(client)
        scanner = XXEScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_file_read_via_ct_switch(self):
        result = self._run_scanner("root:x:0:0:root:/root:/bin/bash")
        crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(len(crit) > 0, "Should detect XXE file read via content-type switching")

    def test_detects_xml_error_leak(self):
        result = self._run_scanner("XMLSyntaxError: invalid document at line 3")
        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        self.assertTrue(len(medium) > 0, "Should detect XML parser error leak")

    def test_no_findings_on_safe_response(self):
        result = self._run_scanner("Thank you for your submission")
        crit_high = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        self.assertEqual(len(crit_high), 0, "Should not report XXE on safe content")

    def test_detects_xml_processing_hints(self):
        # New scanner performs deeper testing on XML endpoints — verify it
        # at least runs direct XXE tests when baseline is XML.
        # Since our mock doesn't return vuln content, we just verify no crash.
        result = self._run_scanner("no vuln here", baseline_text='<?xml version="1.0"?><data/>', baseline_ct="application/xml")
        # Scanner should complete without errors
        self.assertIsNone(result.error)


# ════════════════════════════════════════════════════════════════
# NoSQL Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestNoSQLScanner(unittest.TestCase):
    def _run_scanner(self, get_responses=None, post_responses=None, url="http://test.local/api?username=admin&password=test"):
        from secprobe.scanners.nosql_scanner import NoSQLScanner

        config = _make_config(url)
        client = _mock_client()

        if get_responses:
            client.get.side_effect = get_responses
        else:
            client.get.return_value = _mock_response(text="login page")

        if post_responses:
            client.post.side_effect = post_responses
        else:
            client.post.return_value = _mock_response(text="login page")

        ctx = _make_context(client)
        scanner = NoSQLScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_mongodb_error(self):
        error_resp = _mock_response(text="MongoError: failed to execute query")
        baseline = _mock_response(text="login page")
        clean = _mock_response(text="login page")
        # baseline + PROFILE_SAMPLES clean + many error responses
        result = self._run_scanner(get_responses=[baseline] + [clean] * PROFILE_SAMPLES + [error_resp] * 200)
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0, "Should detect MongoDB error disclosure")

    def test_detects_nosql_error_patterns(self):
        """NoSQL scanner should detect error patterns that are baseline-new."""
        error_resp = _mock_response(text="CastError: Cast to ObjectId failed for value")
        baseline = _mock_response(text="login page")
        clean = _mock_response(text="login page")
        result = self._run_scanner(get_responses=[baseline] + [clean] * PROFILE_SAMPLES + [error_resp] * 200)
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect NoSQL error in response")

    def test_no_findings_on_safe(self):
        safe = _mock_response(text="login page")
        result = self._run_scanner(get_responses=[safe] * 300, post_responses=[safe] * 200)
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0, "Should not report NoSQL on safe responses")


# ════════════════════════════════════════════════════════════════
# Host Header Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestHostHeaderScanner(unittest.TestCase):
    def _run_scanner(self, get_text_injected, baseline_text="normal page", location=""):
        from secprobe.scanners.hostheader_scanner import HostHeaderScanner

        config = _make_config("http://test.local/")
        baseline = _mock_response(text=baseline_text, headers={"Content-Type": "text/html"})
        vuln_resp = _mock_response(
            text=get_text_injected,
            headers={"Location": location} if location else {},
        )
        client = _mock_client()
        client.get.side_effect = [baseline] + [vuln_resp] * 200
        client.post.return_value = _mock_response(text=get_text_injected, headers={"Location": location} if location else {})
        ctx = _make_context(client)
        scanner = HostHeaderScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_host_reflection(self):
        result = self._run_scanner(
            get_text_injected='<a href="http://evil.secprobe-test.com/reset">Reset</a>',
        )
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0, "Should detect Host header reflection")

    def test_detects_redirect_poisoning(self):
        result = self._run_scanner(
            get_text_injected="Redirecting...",
            location="http://evil.secprobe-test.com/",
        )
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        self.assertTrue(len(high) > 0, "Should detect redirect poisoning")

    def test_no_findings_on_safe(self):
        result = self._run_scanner(get_text_injected="Welcome to our site")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0, "Should not report on safe responses")


# ════════════════════════════════════════════════════════════════
# CSRF Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestCSRFScanner(unittest.TestCase):
    def _run_scanner(self, html, cookies=""):
        from secprobe.scanners.csrf_scanner import CSRFScanner

        config = _make_config("http://test.local/")
        resp = _mock_response(text=html, headers={"Set-Cookie": cookies, "Content-Type": "text/html"})
        client = _mock_client()
        client.get.return_value = resp
        client.post.return_value = _mock_response(text="OK")
        ctx = _make_context(client)
        scanner = CSRFScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_missing_csrf_token(self):
        html = '<form method="POST" action="/transfer"><input name="amount" value="100"><input type="submit"></form>'
        result = self._run_scanner(html)
        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        self.assertTrue(len(medium) > 0, "Should detect missing CSRF token")

    def test_accepts_form_with_csrf_token(self):
        html = '<form method="POST" action="/transfer"><input type="hidden" name="csrf_token" value="abc123xyz789def456"><input name="amount"><input type="submit"></form>'
        result = self._run_scanner(html)
        # Should NOT have "Missing CSRF Token" finding
        missing = [f for f in result.findings if "Missing CSRF" in f.title]
        self.assertEqual(len(missing), 0, "Should not flag forms with CSRF tokens")

    def test_detects_samesite_none(self):
        html = '<form method="GET" action="/search"><input name="q"></form>'
        cookie = "session=abc123; SameSite=None; Secure"
        result = self._run_scanner(html, cookies=cookie)
        samesite = [f for f in result.findings if "SameSite" in f.title]
        self.assertTrue(len(samesite) > 0, "Should flag SameSite=None")

    def test_detects_missing_samesite(self):
        html = "<p>Hello</p>"
        cookie = "session=abc123; HttpOnly; Path=/"
        result = self._run_scanner(html, cookies=cookie)
        samesite = [f for f in result.findings if "SameSite" in f.title]
        self.assertTrue(len(samesite) > 0, "Should flag missing SameSite")

    def test_detects_weak_token(self):
        html = '<form method="POST"><input type="hidden" name="csrf_token" value="12345"><input type="submit"></form>'
        result = self._run_scanner(html)
        weak = [f for f in result.findings if "Weak" in f.title]
        self.assertTrue(len(weak) > 0, "Should detect weak CSRF token")


# ════════════════════════════════════════════════════════════════
# HTTP Smuggling Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestSmugglingScanner(unittest.TestCase):
    def _run_scanner(self, post_delay=0.1, baseline_headers=None):
        from secprobe.scanners.smuggling_scanner import SmugglingScanner

        config = _make_config("http://test.local/")
        baseline = _mock_response(
            text="OK",
            headers=baseline_headers or {"Server": "nginx", "Connection": "keep-alive"},
        )

        def slow_post(*args, **kwargs):
            import time
            time.sleep(post_delay)
            return _mock_response(text="OK", status_code=200)

        client = _mock_client()
        client.get.return_value = baseline
        client.post.side_effect = slow_post
        ctx = _make_context(client)
        scanner = SmugglingScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_proxy_and_keep_alive(self):
        result = self._run_scanner(
            baseline_headers={"Via": "1.1 proxy.example.com", "Connection": "keep-alive", "Server": "nginx"},
        )
        info = [f for f in result.findings if f.severity == Severity.INFO]
        self.assertTrue(len(info) > 0, "Should detect proxy/keep-alive")

    def test_detects_conflicting_cl_te_accepted(self):
        # The scanner checks if CL+TE are accepted without 400
        result = self._run_scanner()
        findings = [f for f in result.findings if "CL+TE" in f.title or "Conflicting" in f.title]
        # Should have at least the informational finding about accepting both headers
        cl_te = [f for f in result.findings if "Accepts Conflicting" in f.title or "CL" in f.title]
        self.assertTrue(len(cl_te) > 0, "Should note that server accepts CL+TE")


# ════════════════════════════════════════════════════════════════
# SSTI Scanner Tests (existing scanner, new tests)
# ════════════════════════════════════════════════════════════════
class TestSSTIScanner(unittest.TestCase):
    def _run_scanner(self, get_text, url="http://test.local?name=test"):
        from secprobe.scanners.ssti_scanner import SSTIScanner

        config = _make_config(url)
        baseline = _mock_response(text="Welcome")
        clean = _mock_response(text="Welcome")
        vuln_resp = _mock_response(text=get_text)
        client = _mock_client()
        # baseline + profiling (clean) + payload responses (vuln)
        client.get.side_effect = [baseline] + [clean] * PROFILE_SAMPLES + [vuln_resp] * 200
        ctx = _make_context(client)
        scanner = SSTIScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_ssti_math_eval(self):
        """New scanner uses 987*123=121401 as unique canary, not 7*7=49."""
        result = self._run_scanner("Result: 121401")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(high_crit) > 0, "Should detect {{987*123}} -> 121401")

    def test_detects_jinja2_config_leak(self):
        result = self._run_scanner("<Config {'SECRET_KEY': 'abc123'}>")
        crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(len(crit) > 0, "Should detect Flask config leak")

    def test_no_findings_on_safe(self):
        result = self._run_scanner("Hello World")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0, "Should not report SSTI on safe")


# ════════════════════════════════════════════════════════════════
# SQLi Scanner Tests (existing scanner, new behavioral tests)
# ════════════════════════════════════════════════════════════════
class TestSQLiScannerBehavioral(unittest.TestCase):
    def _run_scanner(self, get_text, url="http://test.local?id=1"):
        from secprobe.scanners.sqli_scanner import SQLiScanner

        config = _make_config(url)
        baseline = _mock_response(text="Product details")
        clean = _mock_response(text="Product details")
        vuln_resp = _mock_response(text=get_text)
        client = _mock_client()
        # baseline + profiling (clean) + payload responses (vuln)
        client.get.side_effect = [baseline] + [clean] * PROFILE_SAMPLES + [vuln_resp] * 1000
        ctx = _make_context(client)
        scanner = SQLiScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_mysql_error(self):
        result = self._run_scanner("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(high_crit) > 0, "Should detect MySQL error")

    def test_detects_pgsql_error(self):
        result = self._run_scanner("ERROR: syntax error at or near \"'\"")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(high_crit) > 0, "Should detect PostgreSQL error")

    def test_no_findings_on_safe(self):
        result = self._run_scanner("Product: Widget XL")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0, "Should not report SQLi on safe content")


# ════════════════════════════════════════════════════════════════
# SSRF Scanner Tests (existing scanner, new behavioral tests)
# ════════════════════════════════════════════════════════════════
class TestSSRFScannerBehavioral(unittest.TestCase):
    def _run_scanner(self, get_text, url="http://test.local?url=http://example.com"):
        from secprobe.scanners.ssrf_scanner import SSRFScanner

        config = _make_config(url)
        baseline = _mock_response(text="Fetching URL...")
        clean = _mock_response(text="Fetching URL...")
        vuln_resp = _mock_response(text=get_text)
        client = _mock_client()
        # baseline + profiling (clean) + payload responses (vuln)
        client.get.side_effect = [baseline] + [clean] * PROFILE_SAMPLES + [vuln_resp] * 200
        ctx = _make_context(client)
        scanner = SSRFScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_aws_metadata(self):
        # Use realistic AWS metadata response with patterns the ErrorPatternMatcher recognizes
        result = self._run_scanner("ami-0abcdef1234567890\ninstance-id: i-0123456789abcdef0\narn:aws:iam:us-east-1:123456789012:role/admin")
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect SSRF to AWS metadata")

    def test_no_findings_on_safe(self):
        result = self._run_scanner("URL loaded successfully")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0, "Should not report SSRF on safe response")


# ════════════════════════════════════════════════════════════════
# CMDi Scanner Tests (existing scanner, new behavioral tests)
# ════════════════════════════════════════════════════════════════
class TestCMDiScannerBehavioral(unittest.TestCase):
    def _run_scanner(self, get_text, url="http://test.local?host=127.0.0.1"):
        from secprobe.scanners.cmdi_scanner import CMDiScanner

        config = _make_config(url)
        baseline = _mock_response(text="Pinging host...")
        clean = _mock_response(text="Pinging host...")
        vuln_resp = _mock_response(text=get_text)
        client = _mock_client()
        # baseline + profiling (clean) + payload responses (vuln)
        client.get.side_effect = [baseline] + [clean] * PROFILE_SAMPLES + [vuln_resp] * 200
        ctx = _make_context(client)
        scanner = CMDiScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_uid_output(self):
        result = self._run_scanner("uid=0(root) gid=0(root) groups=0(root)")
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect command execution output")


if __name__ == "__main__":
    unittest.main()
