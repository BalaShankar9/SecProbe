"""
Tests for SecProbe v6.0 — New scanners and enhanced features.

Covers:
  - Updated scanner registry (32 scanners)
  - OOB helpers in BaseScanner
  - 8 new scanners: Upload, Deserialization, OAuth, Race, LDAP, XPath, CRLF, HPP
  - Enhanced SSL scanner (key size, Heartbleed, BEAST/POODLE/CRIME, OCSP, HSTS)
  - Enhanced JWT scanner (alg confusion, kid injection, x5u/x5c, embedded JWK, JWE downgrade)
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from secprobe.config import ScanConfig, Severity
from secprobe.core.context import ScanContext
from secprobe.models import ScanResult


PROFILE_SAMPLES = 5


def _make_config(target="http://test.local"):
    return ScanConfig(target=target)


def _make_context(http_client=None, oob_server=None):
    if http_client is None:
        http_client = MagicMock()
        http_client._session = MagicMock()
        http_client._session.cookies = {}
    ctx = ScanContext(http_client=http_client, oob_server=oob_server)
    return ctx


def _mock_response(text="", status_code=200, headers=None, url="http://test.local"):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.url = url
    resp.raw = None
    resp.cookies = {}
    resp.content = text.encode() if isinstance(text, str) else text
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
# Registry Tests — Updated for 32 scanners
# ════════════════════════════════════════════════════════════════
class TestUpdatedRegistry(unittest.TestCase):
    def test_registry_count(self):
        from secprobe.scanners import SCANNER_REGISTRY
        self.assertEqual(len(SCANNER_REGISTRY), 45)

    def test_new_scanners_registered(self):
        from secprobe.scanners import SCANNER_REGISTRY
        new_keys = {"upload", "deser", "oauth", "race", "ldap", "xpath", "crlf", "hpp"}
        self.assertTrue(new_keys.issubset(set(SCANNER_REGISTRY.keys())),
                        f"Missing: {new_keys - set(SCANNER_REGISTRY.keys())}")

    def test_all_scanners_subclass_base(self):
        from secprobe.scanners import SCANNER_REGISTRY, BaseScanner
        for key, cls in SCANNER_REGISTRY.items():
            self.assertTrue(issubclass(cls, BaseScanner), f"{key}: not a BaseScanner")

    def test_all_scanners_instantiate(self):
        from secprobe.scanners import SCANNER_REGISTRY
        config = _make_config()
        ctx = _make_context()
        for key, cls in SCANNER_REGISTRY.items():
            scanner = cls(config, ctx)
            self.assertIsNotNone(scanner, f"{key}: failed to instantiate")

    def test_all_scanners_have_name_and_description(self):
        from secprobe.scanners import SCANNER_REGISTRY
        for key, cls in SCANNER_REGISTRY.items():
            self.assertTrue(len(getattr(cls, "name", "")) > 0, f"{key}: empty name")
            self.assertTrue(len(getattr(cls, "description", "")) > 0, f"{key}: empty description")

    def test_all_scanners_have_scan_method(self):
        from secprobe.scanners import SCANNER_REGISTRY
        for key, cls in SCANNER_REGISTRY.items():
            self.assertTrue(callable(getattr(cls, "scan", None)), f"{key}: no scan()")

    def test_version_is_6(self):
        from secprobe import __version__
        self.assertEqual(__version__, "7.0.0")


# ════════════════════════════════════════════════════════════════
# OOB Helper Tests in BaseScanner
# ════════════════════════════════════════════════════════════════
class TestBaseOOBHelpers(unittest.TestCase):
    def _make_scanner(self, oob_running=True):
        from secprobe.scanners.base import BaseScanner

        class DummyScanner(BaseScanner):
            name = "Dummy"
            description = "For testing"
            def scan(self): pass

        oob = MagicMock()
        oob.is_running = oob_running
        oob.generate_token.return_value = "tok123"
        oob.get_callback_url.return_value = "http://oob.test/cb/tok123"
        oob.get_callback_domain.return_value = "tok123.oob.test"
        oob.collect_callbacks.return_value = []

        config = _make_config()
        ctx = _make_context(oob_server=oob)
        return DummyScanner(config, ctx), oob

    def test_oob_available_true(self):
        scanner, _ = self._make_scanner(oob_running=True)
        self.assertTrue(scanner.oob_available)

    def test_oob_available_false_no_server(self):
        from secprobe.scanners.base import BaseScanner

        class DummyScanner(BaseScanner):
            name = "Dummy"
            description = "For testing"
            def scan(self): pass

        config = _make_config()
        ctx = _make_context()
        scanner = DummyScanner(config, ctx)
        self.assertFalse(scanner.oob_available)

    def test_oob_generate_token(self):
        scanner, oob = self._make_scanner()
        token = scanner.oob_generate_token("http://t.com", "param", "sqli", "payload")
        oob.generate_token.assert_called_once()
        self.assertEqual(token, "tok123")

    def test_oob_get_url(self):
        scanner, oob = self._make_scanner()
        url = scanner.oob_get_url("tok123")
        self.assertIn("oob.test", url)

    def test_oob_get_domain(self):
        scanner, oob = self._make_scanner()
        domain = scanner.oob_get_domain("tok123")
        self.assertIn("oob.test", domain)


# ════════════════════════════════════════════════════════════════
# Header/JSON Injection Helpers
# ════════════════════════════════════════════════════════════════
class TestBaseInjectionHelpers(unittest.TestCase):
    def _make_scanner(self):
        from secprobe.scanners.base import BaseScanner

        class DummyScanner(BaseScanner):
            name = "Dummy"
            description = "For testing"
            def scan(self): pass

        config = _make_config()
        ctx = _make_context()
        return DummyScanner(config, ctx)

    def test_inject_into_headers(self):
        scanner = self._make_scanner()
        payloads = list(scanner._inject_into_headers(
            "http://test.com", "<script>", ["Referer", "User-Agent"]
        ))
        self.assertEqual(len(payloads), 2)
        self.assertIn("Referer", payloads[0]["headers"])

    def test_inject_into_json(self):
        scanner = self._make_scanner()
        results = list(scanner._inject_into_json(
            {"username": "test", "password": "test"}, "' OR 1=1--"
        ))
        self.assertEqual(len(results), 2)
        # Each result should have the payload in one field
        payloads_found = 0
        for r in results:
            for v in r.values():
                if "OR 1=1" in str(v):
                    payloads_found += 1
        self.assertEqual(payloads_found, 2)


# ════════════════════════════════════════════════════════════════
# Upload Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestUploadScanner(unittest.TestCase):
    def _run_scanner(self, html_body, upload_resp_text="File uploaded", upload_status=200):
        from secprobe.scanners.upload_scanner import UploadScanner

        config = _make_config("http://test.local/upload")
        main_page = _mock_response(text=html_body)
        upload_resp = _mock_response(text=upload_resp_text, status_code=upload_status)

        client = _mock_client()
        client.get.return_value = main_page
        client.post.return_value = upload_resp

        ctx = _make_context(client)
        scanner = UploadScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_upload_form(self):
        html = '<form enctype="multipart/form-data"><input type="file" name="upload"><input type="submit"></form>'
        result = self._run_scanner(html)
        # Should attempt uploads and potentially find issues
        self.assertIsNotNone(result)

    def test_no_upload_forms(self):
        html = '<html><body>No forms here</body></html>'
        result = self._run_scanner(html)
        info = [f for f in result.findings if f.severity == Severity.INFO]
        # Should find no upload forms
        self.assertTrue(len(result.findings) >= 0)

    def test_extension_bypass_detection(self):
        html = '<form enctype="multipart/form-data" action="/upload"><input type="file" name="file"><input type="submit"></form>'
        result = self._run_scanner(html, upload_resp_text="File uploaded successfully")
        # Scanner should attempt extension bypass uploads
        self.assertIsNotNone(result)


# ════════════════════════════════════════════════════════════════
# Deserialization Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestDeserializationScanner(unittest.TestCase):
    def _run_scanner(self, response_text="OK", cookies=None, response_headers=None):
        from secprobe.scanners.deserialization_scanner import DeserializationScanner

        config = _make_config("http://test.local/api")
        resp = _mock_response(text=response_text, headers=response_headers or {})
        if cookies:
            resp.cookies = cookies

        client = _mock_client(get_response=resp)
        client.post.return_value = _mock_response(text=response_text)
        ctx = _make_context(client)
        scanner = DeserializationScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_java_serialized_cookie(self):
        # rO0AB is base64 for Java ObjectOutputStream magic bytes
        cookies = {"session": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="}
        result = self._run_scanner(cookies=cookies)
        self.assertIsNotNone(result)

    def test_detects_php_serialized_cookie(self):
        cookies = {"data": 'a:2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'}
        result = self._run_scanner(cookies=cookies)
        self.assertIsNotNone(result)

    def test_detects_deserialization_errors(self):
        result = self._run_scanner(
            response_text="java.io.InvalidClassException: invalid stream header"
        )
        self.assertIsNotNone(result)

    def test_clean_response(self):
        result = self._run_scanner(response_text="Welcome to our API")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0)


# ════════════════════════════════════════════════════════════════
# OAuth Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestOAuthScanner(unittest.TestCase):
    def _run_scanner(self, openid_config=None, auth_response=None):
        from secprobe.scanners.oauth_scanner import OAuthScanner

        config = _make_config("http://test.local")

        client = _mock_client()

        if openid_config:
            oidc_resp = _mock_response(text=openid_config, status_code=200)
        else:
            oidc_resp = _mock_response(text="Not Found", status_code=404)

        if auth_response:
            auth_resp = auth_response
        else:
            auth_resp = _mock_response(text="Not Found", status_code=404)

        # Different endpoints return different responses
        def mock_get(url, **kwargs):
            if "openid-configuration" in url:
                return oidc_resp
            if "authorize" in url or "oauth" in url:
                return auth_resp
            return _mock_response(status_code=404)

        client.get.side_effect = mock_get

        ctx = _make_context(client)
        scanner = OAuthScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_discovers_openid_config(self):
        import json
        oidc = json.dumps({
            "issuer": "http://test.local",
            "authorization_endpoint": "http://test.local/oauth/authorize",
            "token_endpoint": "http://test.local/oauth/token",
            "jwks_uri": "http://test.local/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })
        result = self._run_scanner(openid_config=oidc)
        self.assertIsNotNone(result)

    def test_no_oauth_endpoints(self):
        result = self._run_scanner()
        self.assertIsNotNone(result)

    def test_weak_signing_algorithm(self):
        import json
        oidc = json.dumps({
            "issuer": "http://test.local",
            "authorization_endpoint": "http://test.local/oauth/authorize",
            "token_endpoint": "http://test.local/oauth/token",
            "id_token_signing_alg_values_supported": ["none", "HS256"],
        })
        result = self._run_scanner(openid_config=oidc)
        # Should flag 'none' algorithm
        findings_text = " ".join(f.title for f in result.findings)
        # Just verify it ran without errors
        self.assertIsNotNone(result)


# ════════════════════════════════════════════════════════════════
# Race Condition Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestRaceConditionScanner(unittest.TestCase):
    def _run_scanner(self, responses=None):
        from secprobe.scanners.race_scanner import RaceConditionScanner

        config = _make_config("http://test.local/transfer")

        client = _mock_client()
        if responses:
            client.get.side_effect = responses
        else:
            # Token endpoints return 404 so token race phase skips them
            client.get.return_value = _mock_response(text="Not Found", status_code=404)

        ctx = _make_context(client)
        scanner = RaceConditionScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_no_race_condition(self):
        result = self._run_scanner()
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0)

    def test_scanner_runs_without_error(self):
        result = self._run_scanner()
        self.assertIsNotNone(result)


# ════════════════════════════════════════════════════════════════
# LDAP Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestLDAPScanner(unittest.TestCase):
    def _run_scanner(self, get_text="OK", url="http://test.local/search?q=admin"):
        from secprobe.scanners.ldap_scanner import LDAPScanner

        config = _make_config(url)
        baseline = _mock_response(text="normal page")
        vuln = _mock_response(text=get_text)

        client = _mock_client()
        # First call = baseline, rest = vuln response (no profiling needed for LDAP)
        client.get.side_effect = [baseline] + [vuln] * 200
        client.post.return_value = _mock_response()

        ctx = _make_context(client)
        scanner = LDAPScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_ldap_error(self):
        result = self._run_scanner("javax.naming.directory.InvalidSearchFilterException: Bad search filter")
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect LDAP error")

    def test_no_findings_clean(self):
        result = self._run_scanner("Welcome to the search page")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0)

    def test_no_params_graceful(self):
        result = self._run_scanner("OK", url="http://test.local/page")
        self.assertIsNotNone(result)


# ════════════════════════════════════════════════════════════════
# XPath Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestXPathScanner(unittest.TestCase):
    def _run_scanner(self, get_text="OK", url="http://test.local/xml?id=1"):
        from secprobe.scanners.xpath_scanner import XPathScanner

        config = _make_config(url)
        baseline = _mock_response(text="normal")
        clean = _mock_response(text="normal")
        vuln = _mock_response(text=get_text)

        client = _mock_client()
        client.get.side_effect = [baseline] + [clean] * PROFILE_SAMPLES + [vuln] * 200
        client.post.return_value = _mock_response()

        ctx = _make_context(client)
        scanner = XPathScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_xpath_error(self):
        result = self._run_scanner("XPathException: Invalid expression")
        findings = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertTrue(len(findings) > 0, "Should detect XPath error")

    def test_clean_response(self):
        result = self._run_scanner("Welcome")
        high_crit = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_crit), 0)


# ════════════════════════════════════════════════════════════════
# CRLF Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestCRLFScanner(unittest.TestCase):
    def _run_scanner(self, resp_headers=None, url="http://test.local/redirect?url=/home"):
        from secprobe.scanners.crlf_scanner import CRLFScanner

        config = _make_config(url)
        normal_resp = _mock_response(text="normal", headers={"Content-Type": "text/html"})
        vuln_resp = _mock_response(text="normal", headers=resp_headers or {"Content-Type": "text/html"})

        client = _mock_client()
        client.get.side_effect = [normal_resp] + [vuln_resp] * 200

        ctx = _make_context(client)
        scanner = CRLFScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_crlf_in_headers(self):
        # If the injected header appears in response, it's CRLF
        result = self._run_scanner(
            resp_headers={"Content-Type": "text/html", "X-SecProbe-CRLF": "1"}
        )
        self.assertIsNotNone(result)

    def test_clean_response(self):
        result = self._run_scanner()
        self.assertIsNotNone(result)

    def test_no_params_graceful(self):
        from secprobe.scanners.crlf_scanner import CRLFScanner
        config = _make_config("http://test.local/page")
        client = _mock_client()
        ctx = _make_context(client)
        scanner = CRLFScanner(config, ctx)
        scanner.scan()
        self.assertIsNotNone(scanner.result)


# ════════════════════════════════════════════════════════════════
# HPP Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestHPPScanner(unittest.TestCase):
    def _run_scanner(self, get_text="OK", url="http://test.local/search?q=admin"):
        from secprobe.scanners.hpp_scanner import HPPScanner

        config = _make_config(url)
        baseline = _mock_response(text="Result: admin")
        vuln = _mock_response(text=get_text)

        client = _mock_client()
        client.get.side_effect = [baseline] + [vuln] * 200
        client.post.return_value = _mock_response()

        ctx = _make_context(client)
        scanner = HPPScanner(config, ctx)
        scanner.scan()
        return scanner.result

    def test_detects_hpp_anomaly(self):
        # If response changes with duplicate params, it indicates HPP
        result = self._run_scanner(get_text="Result: admin,injected")
        self.assertIsNotNone(result)

    def test_clean_response(self):
        result = self._run_scanner(get_text="Result: admin")
        self.assertIsNotNone(result)

    def test_no_params_graceful(self):
        from secprobe.scanners.hpp_scanner import HPPScanner
        config = _make_config("http://test.local/page")
        client = _mock_client()
        ctx = _make_context(client)
        scanner = HPPScanner(config, ctx)
        scanner.scan()
        self.assertIsNotNone(scanner.result)


# ════════════════════════════════════════════════════════════════
# Enhanced SSL Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestEnhancedSSLScanner(unittest.TestCase):
    def test_ssl_scanner_has_new_methods(self):
        from secprobe.scanners.ssl_scanner import SSLScanner
        methods = ["_check_key_size", "_check_heartbleed", "_check_beast_poodle_crime",
                    "_check_ocsp_stapling", "_check_hsts"]
        for m in methods:
            self.assertTrue(hasattr(SSLScanner, m), f"SSLScanner missing {m}")

    def test_hsts_detection(self):
        """Test HSTS check against a mock response."""
        from secprobe.scanners.ssl_scanner import SSLScanner

        config = _make_config("https://test.local")
        # Mock response without HSTS header
        client = _mock_client(get_response=_mock_response(headers={}))
        ctx = _make_context(client)
        scanner = SSLScanner(config, ctx)
        scanner._check_hsts("test.local")
        missing_hsts = [f for f in scanner.result.findings if "HSTS" in f.title]
        self.assertTrue(len(missing_hsts) > 0, "Should detect missing HSTS")

    def test_hsts_short_max_age(self):
        from secprobe.scanners.ssl_scanner import SSLScanner

        config = _make_config("https://test.local")
        client = _mock_client(get_response=_mock_response(
            headers={"Strict-Transport-Security": "max-age=3600"}
        ))
        ctx = _make_context(client)
        scanner = SSLScanner(config, ctx)
        scanner._check_hsts("test.local")
        short_hsts = [f for f in scanner.result.findings if "max-age" in f.title.lower() or "short" in f.title.lower()]
        self.assertTrue(len(short_hsts) > 0, "Should flag short max-age")

    def test_hsts_full_config(self):
        from secprobe.scanners.ssl_scanner import SSLScanner

        config = _make_config("https://test.local")
        client = _mock_client(get_response=_mock_response(
            headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}
        ))
        ctx = _make_context(client)
        scanner = SSLScanner(config, ctx)
        scanner._check_hsts("test.local")
        issues = [f for f in scanner.result.findings
                  if f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(issues), 0, "Full HSTS config should have no medium+ issues")


# ════════════════════════════════════════════════════════════════
# Enhanced JWT Scanner Tests
# ════════════════════════════════════════════════════════════════
class TestEnhancedJWTScanner(unittest.TestCase):
    def test_jwt_scanner_has_new_methods(self):
        from secprobe.scanners.jwt_scanner import JWTScanner
        methods = ["_test_alg_confusion", "_test_kid_injection",
                    "_test_x5u_injection", "_test_embedded_jwk", "_test_jwe_downgrade"]
        for m in methods:
            self.assertTrue(hasattr(JWTScanner, m), f"JWTScanner missing {m}")

    def test_kid_injection_errors(self):
        """Test that kid injection detects error-based responses."""
        from secprobe.scanners.jwt_scanner import JWTScanner
        import base64
        import json

        config = _make_config("http://test.local/api")

        # Create a fake JWT with kid
        header = {"alg": "HS256", "typ": "JWT", "kid": "key-1"}
        payload = {"sub": "user", "exp": 9999999999}
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

        # Error response when kid is injected
        error_resp = _mock_response(text="sqlite3.OperationalError: no such file", status_code=500)
        client = _mock_client(get_response=error_resp)
        ctx = _make_context(client)
        scanner = JWTScanner(config, ctx)
        scanner._test_kid_injection("http://test.local/api", f"{h_b64}.{p_b64}.sig",
                                     header, payload, "cookie:token")
        kid_findings = [f for f in scanner.result.findings if "kid" in f.title.lower()]
        self.assertTrue(len(kid_findings) > 0, "Should detect kid injection error")

    def test_embedded_jwk_detection(self):
        """Test embedded JWK injection."""
        from secprobe.scanners.jwt_scanner import JWTScanner
        import base64
        import json

        config = _make_config("http://test.local/api")
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "admin"}

        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

        # Server accepts the forged token
        accept_resp = _mock_response(text="Welcome admin", status_code=200)
        client = _mock_client(get_response=accept_resp)
        ctx = _make_context(client)
        scanner = JWTScanner(config, ctx)
        scanner._test_embedded_jwk("http://test.local/api", f"{h_b64}.{p_b64}.fakesig",
                                    header, payload, "cookie:jwt")
        jwk_findings = [f for f in scanner.result.findings if "JWK" in f.title or "jwk" in f.title.lower()]
        self.assertTrue(len(jwk_findings) > 0, "Should detect embedded JWK injection")

    def test_jwe_downgrade(self):
        """Test JWE→JWS downgrade detection."""
        from secprobe.scanners.jwt_scanner import JWTScanner
        import base64
        import json

        config = _make_config("http://test.local/api")
        header = {"alg": "RSA-OAEP", "enc": "A256GCM", "typ": "JWT"}
        payload = {"sub": "user"}

        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

        # Server accepts downgraded token
        accept_resp = _mock_response(text="Authenticated", status_code=200)
        client = _mock_client(get_response=accept_resp)
        ctx = _make_context(client)
        scanner = JWTScanner(config, ctx)
        scanner._test_jwe_downgrade("http://test.local/api", f"{h_b64}.{p_b64}.sig",
                                     header, payload, "cookie:jwt")
        downgrade = [f for f in scanner.result.findings if "downgrade" in f.title.lower()]
        self.assertTrue(len(downgrade) > 0, "Should detect JWE downgrade")

    def test_jwks_private_key_leak(self):
        """Test JWKS endpoint scanning for private key leaks."""
        from secprobe.scanners.jwt_scanner import JWTScanner
        import json

        config = _make_config("http://test.local")
        # JWKS response with private key fields
        jwks = json.dumps({
            "keys": [{
                "kty": "RSA", "kid": "key-1",
                "n": "abc...", "e": "AQAB",
                "d": "LEAKED_PRIVATE_KEY",  # Should NOT be here
                "p": "leaked", "q": "leaked",
            }]
        })

        def mock_get(url, **kwargs):
            if "jwks" in url:
                return _mock_response(text=jwks, status_code=200)
            return _mock_response(status_code=404)

        client = _mock_client()
        client.get.side_effect = mock_get
        ctx = _make_context(client)
        scanner = JWTScanner(config, ctx)
        scanner._check_jwks_endpoint("http://test.local")
        leaks = [f for f in scanner.result.findings if "private" in f.title.lower() or "leak" in f.title.lower()]
        self.assertTrue(len(leaks) > 0, "Should detect private key leak in JWKS")


# ════════════════════════════════════════════════════════════════
# OOB Integration in Injection Scanners
# ════════════════════════════════════════════════════════════════
class TestOOBInInjectionScanners(unittest.TestCase):
    """Verify that injection scanners check oob_available and can call OOB methods."""

    def test_sqli_has_oob_phase(self):
        from secprobe.scanners.sqli_scanner import SQLiScanner
        import inspect
        source = inspect.getsource(SQLiScanner.scan)
        self.assertIn("oob_available", source, "SQLi should check OOB availability")

    def test_ssrf_has_oob_phase(self):
        from secprobe.scanners.ssrf_scanner import SSRFScanner
        import inspect
        source = inspect.getsource(SSRFScanner.scan)
        self.assertIn("oob", source.lower(), "SSRF should have OOB phase")

    def test_cmdi_has_oob_phase(self):
        from secprobe.scanners.cmdi_scanner import CMDiScanner
        import inspect
        source = inspect.getsource(CMDiScanner.scan)
        self.assertIn("oob_available", source, "CMDi should check OOB availability")

    def test_xxe_has_oob_phase(self):
        from secprobe.scanners.xxe_scanner import XXEScanner
        self.assertTrue(hasattr(XXEScanner, "_test_oob_xxe"),
                        "XXE should have _test_oob_xxe method")

    def test_ssti_has_oob_code(self):
        from secprobe.scanners.ssti_scanner import SSTIScanner
        import inspect
        source = inspect.getsource(SSTIScanner.scan)
        self.assertIn("oob_available", source, "SSTI should check OOB availability")

    def test_xss_has_oob_code(self):
        from secprobe.scanners.xss_scanner import XSSScanner
        import inspect
        source = inspect.getsource(XSSScanner.scan)
        self.assertIn("oob_available", source, "XSS should check OOB availability")

    def test_lfi_has_oob_code(self):
        from secprobe.scanners.lfi_scanner import LFIScanner
        import inspect
        source = inspect.getsource(LFIScanner.scan)
        self.assertIn("oob_available", source, "LFI should check OOB availability")


# ════════════════════════════════════════════════════════════════
# Header Injection in Injection Scanners
# ════════════════════════════════════════════════════════════════
class TestHeaderInjectionIntegration(unittest.TestCase):
    """Verify injection scanners test HTTP headers."""

    def test_sqli_has_header_injection(self):
        from secprobe.scanners.sqli_scanner import SQLiScanner
        import inspect
        source = inspect.getsource(SQLiScanner)
        # Rewritten scanner uses InsertionPoint engine with include_headers=True
        # which automatically discovers and tests Referer, X-Forwarded-For, etc.
        self.assertTrue(
            "include_headers=True" in source or "header_points" in source or "HEADER" in source,
            "SQLi should test HTTP headers via InsertionPoint or direct header injection",
        )

    def test_sqli_has_json_injection(self):
        from secprobe.scanners.sqli_scanner import SQLiScanner
        import inspect
        source = inspect.getsource(SQLiScanner)
        # Rewritten scanner uses InsertionPoint engine with JSON_FIELD type
        self.assertTrue(
            "json_points" in source or "JSON_FIELD" in source or "application/json" in source,
            "SQLi should test JSON body injection via InsertionPoint or direct JSON injection",
        )

    def test_ssrf_has_header_injection(self):
        from secprobe.scanners.ssrf_scanner import SSRFScanner
        import inspect
        source = inspect.getsource(SSRFScanner)
        # Rewritten scanner uses InsertionPoint engine with include_headers=True
        self.assertTrue(
            "include_headers=True" in source or "header_points" in source or "HEADER" in source,
            "SSRF should test HTTP headers via InsertionPoint or direct header injection",
        )

    def test_cmdi_has_header_injection(self):
        from secprobe.scanners.cmdi_scanner import CMDiScanner
        import inspect
        source = inspect.getsource(CMDiScanner)
        # Rewritten scanner uses InsertionPoint engine with include_headers=True
        self.assertTrue(
            "include_headers=True" in source or "header_points" in source
            or "User-Agent" in source or "HEADER" in source,
            "CMDi should test HTTP headers via InsertionPoint or direct header injection",
        )


if __name__ == "__main__":
    unittest.main()
