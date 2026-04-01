"""
Unit tests for JuiceShopScanner with mocked HTTP responses.

Tests cover authentication, injection, data exposure, access control,
misconfiguration, file attacks, and SSRF checks.
"""

import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from secprobe.scanners.juice_shop_scanner import JuiceShopScanner
from secprobe.config import ScanConfig, Severity


# ── Helpers ─────────────────────────────────────────────────────────


def _make_response(status_code=200, text="", headers=None):
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


def _make_scanner(target="http://localhost:3000"):
    """Create a JuiceShopScanner with a mocked http_client."""
    config = ScanConfig(target=target)
    scanner = JuiceShopScanner(config)
    scanner._context_http_client = MagicMock()
    # Patch the http_client property to return our mock
    type(scanner).http_client = PropertyMock(
        return_value=scanner._context_http_client
    )
    return scanner


# ── Basic tests ─────────────────────────────────────────────────────


class TestJuiceShopScannerBasic:
    def test_scanner_instantiates(self):
        config = ScanConfig(target="http://example.com")
        scanner = JuiceShopScanner(config)
        assert scanner.name == "Juice Shop Benchmark Scanner"

    def test_scanner_has_all_test_methods(self):
        config = ScanConfig(target="http://example.com")
        scanner = JuiceShopScanner(config)
        methods = [m for m in dir(scanner) if m.startswith("_test_")]
        assert len(methods) >= 25  # We have 25+ test methods

    def test_auth_headers_without_token(self):
        scanner = _make_scanner()
        headers = scanner._auth_headers()
        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"

    def test_auth_headers_with_token(self):
        scanner = _make_scanner()
        scanner._auth_token = "fake.jwt.token"
        headers = scanner._auth_headers()
        assert headers["Authorization"] == "Bearer fake.jwt.token"


# ── Authentication tests ────────────────────────────────────────────


class TestAuthentication:
    def test_register_user_success(self):
        scanner = _make_scanner()
        scanner.http_client.post.return_value = _make_response(
            201, json.dumps({"data": {"id": 99, "email": "secprobe_test@test.com"}})
        )
        assert scanner._register_user("http://localhost:3000") is True

    def test_register_user_already_exists(self):
        scanner = _make_scanner()
        scanner.http_client.post.return_value = _make_response(
            400, json.dumps({"message": "User already exists"})
        )
        assert scanner._register_user("http://localhost:3000") is True

    def test_login_success(self):
        scanner = _make_scanner()
        scanner.http_client.post.return_value = _make_response(
            200,
            json.dumps({"authentication": {"token": "eyJ.abc.xyz", "bid": 1}}),
        )
        assert scanner._login("http://localhost:3000") is True
        assert scanner._auth_token == "eyJ.abc.xyz"

    def test_login_failure(self):
        scanner = _make_scanner()
        scanner.http_client.post.return_value = _make_response(
            401, json.dumps({"message": "Invalid credentials"})
        )
        assert scanner._login("http://localhost:3000") is False
        assert scanner._auth_token is None


# ── Injection tests ─────────────────────────────────────────────────


class TestInjection:
    def test_sqli_login_detected(self):
        scanner = _make_scanner()
        scanner.http_client.post.return_value = _make_response(
            200,
            json.dumps({
                "authentication": {
                    "token": "eyJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AifX0.sig",
                    "bid": 1,
                    "umail": "admin@juice-sh.op",
                }
            }),
        )
        assert scanner._test_sqli_login("http://localhost:3000") is True
        assert len(scanner.result.findings) == 1
        assert scanner.result.findings[0].severity == Severity.CRITICAL
        assert "SQL Injection" in scanner.result.findings[0].title

    def test_sqli_search_union_detected(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200,
            json.dumps({
                "data": [
                    {"id": 1, "name": "2", "description": "3", "price": 4,
                     "deluxePrice": 5, "image": "6", "createdAt": "7",
                     "updatedAt": "8", "deletedAt": "9"}
                ]
            }),
        )
        assert scanner._test_sqli_search("http://localhost:3000") is True
        assert scanner.result.findings[0].cwe == "CWE-89"

    def test_xss_search_detected(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200, json.dumps({"data": []})
        )
        assert scanner._test_xss_search("http://localhost:3000") is True
        assert scanner.result.findings[0].severity == Severity.HIGH

    def test_reflected_xss_detected(self):
        scanner = _make_scanner()
        payload = '<iframe src="javascript:alert(1)">'
        scanner.http_client.get.return_value = _make_response(
            200, f'{{"message": "{payload}"}}'
        )
        assert scanner._test_reflected_xss("http://localhost:3000") is True


# ── Sensitive data exposure tests ───────────────────────────────────


class TestDataExposure:
    def test_exposed_users_api(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200,
            json.dumps({
                "data": [
                    {"id": 1, "email": "admin@juice-sh.op"},
                    {"id": 2, "email": "jim@juice-sh.op"},
                ]
            }),
        )
        assert scanner._test_exposed_users_api("http://localhost:3000") is True
        finding = scanner.result.findings[0]
        assert finding.severity == Severity.HIGH
        assert "admin@juice-sh.op" in finding.evidence

    def test_exposed_metrics(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200, "# HELP node_cpu_seconds_total\nnode_cpu_seconds_total 123.45"
        )
        assert scanner._test_exposed_metrics("http://localhost:3000") is True

    def test_exposed_security_questions(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200,
            json.dumps({
                "data": [
                    {"id": 1, "question": "Your eldest siblings middle name?"},
                    {"id": 2, "question": "Mother's maiden name?"},
                ]
            }),
        )
        assert scanner._test_exposed_security_questions("http://localhost:3000") is True

    def test_ftp_directory_listing(self):
        scanner = _make_scanner()

        def side_effect(url, **kwargs):
            if url.endswith("/ftp/"):
                return _make_response(200, "acquisitions.md\npackage.json.bak")
            return _make_response(404, "")

        scanner.http_client.get.side_effect = side_effect
        assert scanner._test_ftp_directory("http://localhost:3000") is True

    def test_exposed_swagger(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200, '{"swagger":"2.0","info":{"title":"juice-shop"}}'
        )
        assert scanner._test_exposed_swagger("http://localhost:3000") is True

    def test_whoami_info_leak(self):
        scanner = _make_scanner()
        scanner._auth_token = "fake.token"
        scanner.http_client.get.return_value = _make_response(
            200,
            json.dumps({"user": {"id": 1, "email": "test@test.com", "role": "customer"}}),
        )
        assert scanner._test_whoami_info_leak("http://localhost:3000") is True
        assert "id" in scanner.result.findings[0].description


# ── Access control tests ────────────────────────────────────────────


class TestAccessControl:
    def test_basket_idor(self):
        scanner = _make_scanner()
        scanner._auth_token = "fake.token"
        scanner.http_client.get.return_value = _make_response(
            200,
            json.dumps({"data": {"id": 1, "Products": [{"id": 1, "name": "Apple"}]}}),
        )
        assert scanner._test_basket_idor("http://localhost:3000") is True
        assert "IDOR" in scanner.result.findings[0].title

    def test_admin_section_accessible(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200, "<html><body>Administration Panel</body></html>"
        )
        assert scanner._test_admin_section("http://localhost:3000") is True

    def test_forged_feedback(self):
        scanner = _make_scanner()
        scanner._auth_token = "fake.token"
        scanner.http_client.post.return_value = _make_response(
            201,
            json.dumps({"data": {"id": 99, "UserId": 1, "comment": "test", "rating": 5}}),
        )
        assert scanner._test_forged_feedback("http://localhost:3000") is True
        assert scanner.result.findings[0].severity == Severity.HIGH

    def test_zero_star_review(self):
        scanner = _make_scanner()
        scanner._auth_token = "fake.token"
        scanner.http_client.post.return_value = _make_response(
            201,
            json.dumps({"data": {"id": 100, "rating": 0, "comment": "zero star"}}),
        )
        assert scanner._test_zero_star_review("http://localhost:3000") is True

    def test_forged_feedback_requires_auth(self):
        scanner = _make_scanner()
        scanner._auth_token = None
        assert scanner._test_forged_feedback("http://localhost:3000") is False


# ── Security misconfiguration tests ─────────────────────────────────


class TestMisconfiguration:
    def test_missing_security_headers(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200, "<html></html>", headers={"Server": "Express"}
        )
        assert scanner._test_missing_security_headers("http://localhost:3000") is True
        finding = scanner.result.findings[0]
        assert "x-content-type-options" in finding.description.lower()

    def test_error_handling_verbose(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            500,
            json.dumps({
                "error": {
                    "message": "SQLITE_ERROR: ...",
                    "stack": "Error: SQLITE_ERROR at ...",
                }
            }),
        )
        assert scanner._test_error_handling("http://localhost:3000") is True

    def test_score_board_accessible(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200, "<html><body>Score Board</body></html>"
        )
        assert scanner._test_score_board("http://localhost:3000") is True


# ── File attack tests ───────────────────────────────────────────────


class TestFileAttacks:
    def test_path_traversal_blocked_with_info(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            403, '{"error":"Only .md and .pdf files are allowed! Directory traversal detected."}'
        )
        assert scanner._test_path_traversal_ftp("http://localhost:3000") is True

    def test_null_byte_injection(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            200, "this is the content of eastere.gg file with secrets"
        )
        assert scanner._test_null_byte_ftp("http://localhost:3000") is True
        assert scanner.result.findings[0].severity == Severity.HIGH


# ── SSRF tests ──────────────────────────────────────────────────────


class TestSSRF:
    def test_ssrf_profile_image(self):
        scanner = _make_scanner()
        scanner._auth_token = "fake.token"
        scanner.http_client.post.return_value = _make_response(
            200,
            json.dumps({"data": [{"id": 1, "email": "admin@juice-sh.op"}]}),
        )
        assert scanner._test_ssrf_profile_image("http://localhost:3000") is True
        assert scanner.result.findings[0].cwe == "CWE-918"

    def test_ssrf_requires_auth(self):
        scanner = _make_scanner()
        scanner._auth_token = None
        assert scanner._test_ssrf_profile_image("http://localhost:3000") is False


# ── Negative / not-found tests ──────────────────────────────────────


class TestNegativeCases:
    def test_sqli_login_not_found(self):
        scanner = _make_scanner()
        scanner.http_client.post.return_value = _make_response(
            401, json.dumps({"message": "Invalid email or password."})
        )
        assert scanner._test_sqli_login("http://localhost:3000") is False
        assert len(scanner.result.findings) == 0

    def test_exposed_users_not_accessible(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(
            401, json.dumps({"message": "Unauthorized"})
        )
        assert scanner._test_exposed_users_api("http://localhost:3000") is False

    def test_metrics_not_exposed(self):
        scanner = _make_scanner()
        scanner.http_client.get.return_value = _make_response(404, "Not Found")
        assert scanner._test_exposed_metrics("http://localhost:3000") is False

    def test_exception_handled_gracefully(self):
        scanner = _make_scanner()
        scanner.http_client.get.side_effect = ConnectionError("refused")
        assert scanner._test_exposed_metrics("http://localhost:3000") is False
        assert len(scanner.result.findings) == 0
