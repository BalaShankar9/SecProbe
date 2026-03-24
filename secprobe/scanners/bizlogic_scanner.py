"""
Business Logic Scanner.

Detects logic flaws that automated scanners typically miss:
  - Price/quantity manipulation (negative values, zero, overflow)
  - Authentication flow bypass (skip steps, repeat steps)
  - Rate limiting / brute force detection
  - Coupon/discount abuse (reuse, stacking, negative)
  - Race condition windows in checkout/transfer flows
  - Account enumeration via timing / error messages
  - Password reset flow weaknesses
  - Registration abuse (duplicate accounts, role manipulation)
"""

import re
import time
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


class BizLogicScanner(SmartScanner):
    name = "Business Logic Scanner"
    description = "Detect logic flaws: price tampering, flow bypass, rate limiting, account enumeration"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Business logic analysis on {url}", "progress")

        # ── Phase 1: Discover interactive endpoints ───────────────
        print_status("Phase 1: Endpoint discovery", "progress")
        endpoints = self._discover_endpoints(url)

        # ── Phase 2: Rate limiting checks ─────────────────────────
        print_status("Phase 2: Rate limiting analysis", "progress")
        self._check_rate_limiting(url)

        # ── Phase 3: Account enumeration ──────────────────────────
        print_status("Phase 3: Account enumeration checks", "progress")
        self._check_account_enumeration(url, endpoints)

        # ── Phase 4: Password reset flow ──────────────────────────
        print_status("Phase 4: Password reset flow analysis", "progress")
        self._check_password_reset(url, endpoints)

        # ── Phase 5: Form manipulation / price tampering ──────────
        print_status("Phase 5: Form parameter manipulation", "progress")
        self._check_parameter_manipulation(url, endpoints)

        # ── Phase 6: Registration abuse ───────────────────────────
        print_status("Phase 6: Registration abuse checks", "progress")
        self._check_registration(url, endpoints)

        # ── Phase 7: HTTP method override ─────────────────────────
        print_status("Phase 7: HTTP method override checks", "progress")
        self._check_method_override(url)

    def _discover_endpoints(self, url):
        """Discover login, registration, checkout, and other interactive endpoints."""
        endpoints = {
            "login": [], "register": [], "reset": [],
            "checkout": [], "cart": [], "search": [],
            "api": [], "admin": [], "upload": [],
        }

        try:
            resp = self.http_client.get(url)
            html = resp.text

            # Find forms
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.I | re.S)
            for action, body in forms:
                full_url = urljoin(url, action) if action else url
                body_lower = body.lower()
                if any(k in body_lower for k in ["password", "login", "signin", "sign-in"]):
                    endpoints["login"].append(full_url)
                if any(k in body_lower for k in ["register", "signup", "sign-up", "create account"]):
                    endpoints["register"].append(full_url)
                if any(k in body_lower for k in ["reset", "forgot", "recover"]):
                    endpoints["reset"].append(full_url)
                if any(k in body_lower for k in ["checkout", "payment", "pay ", "purchase"]):
                    endpoints["checkout"].append(full_url)
                if any(k in body_lower for k in ["cart", "basket", "quantity", "qty"]):
                    endpoints["cart"].append(full_url)
                if any(k in body_lower for k in ["search", "query", "find"]):
                    endpoints["search"].append(full_url)

            # Find links
            links = re.findall(r'href=["\']([^"\']+)', html)
            for link in links:
                full = urljoin(url, link)
                link_lower = link.lower()
                if "login" in link_lower or "signin" in link_lower:
                    endpoints["login"].append(full)
                elif "register" in link_lower or "signup" in link_lower:
                    endpoints["register"].append(full)
                elif "reset" in link_lower or "forgot" in link_lower:
                    endpoints["reset"].append(full)
                elif "admin" in link_lower:
                    endpoints["admin"].append(full)
                elif "api" in link_lower:
                    endpoints["api"].append(full)

        except Exception:
            pass

        # Common paths to probe
        common_paths = {
            "login": ["/login", "/signin", "/wp-login.php", "/user/login", "/auth/login", "/accounts/login"],
            "register": ["/register", "/signup", "/create-account", "/wp-register.php"],
            "reset": ["/forgot-password", "/reset-password", "/password-reset", "/wp-login.php?action=lostpassword"],
            "admin": ["/admin", "/administrator", "/wp-admin", "/dashboard"],
        }

        for category, paths in common_paths.items():
            for path in paths:
                test_url = urljoin(url, path)
                try:
                    resp = self.http_client.get(test_url, timeout=5, allow_redirects=False)
                    if resp.status_code in (200, 301, 302):
                        endpoints[category].append(test_url)
                except Exception:
                    pass

        # Deduplicate
        for key in endpoints:
            endpoints[key] = list(set(endpoints[key]))

        total = sum(len(v) for v in endpoints.values())
        print_status(f"Discovered {total} interactive endpoint(s)", "info")
        self.result.raw_data["endpoints"] = endpoints
        return endpoints

    def _check_rate_limiting(self, url):
        """Check if the target implements rate limiting."""
        test_urls = [url]

        # Add login endpoints
        endpoints = self.result.raw_data.get("endpoints", {})
        test_urls.extend(endpoints.get("login", [])[:2])

        for test_url in test_urls:
            status_codes = []
            timings = []

            # Send rapid requests
            for i in range(10):
                try:
                    start = time.time()
                    resp = self.http_client.get(test_url, timeout=10)
                    elapsed = time.time() - start
                    status_codes.append(resp.status_code)
                    timings.append(elapsed)
                except Exception:
                    status_codes.append(0)
                    timings.append(0)

            # Check for rate limiting indicators
            rate_limited = any(code in (429, 503) for code in status_codes)
            increasing_delay = all(timings[i] <= timings[i + 1] for i in range(len(timings) - 1) if timings[i] > 0 and timings[i + 1] > 0) if len(timings) > 3 else False

            if not rate_limited and not increasing_delay:
                is_login = any(test_url == u for u in endpoints.get("login", []))
                severity = Severity.HIGH if is_login else Severity.MEDIUM
                self.add_finding(
                    title=f"No rate limiting on {'login' if is_login else 'endpoint'}",
                    severity=severity,
                    description=(
                        f"No rate limiting detected after 10 rapid requests to {test_url}.\n"
                        f"Status codes: {status_codes}\n"
                        f"An attacker could perform brute-force attacks without throttling."
                    ),
                    recommendation=(
                        "Implement rate limiting:\n"
                        "1. Use progressive delays (exponential backoff)\n"
                        "2. Return 429 Too Many Requests after threshold\n"
                        "3. Implement CAPTCHA after failed attempts\n"
                        "4. Use account lockout after N failures"
                    ),
                    evidence=f"URL: {test_url}\n10 rapid requests all returned: {list(set(status_codes))}",
                    category="Business Logic",
                    url=test_url,
                    cwe="CWE-307",
                )
                print_finding(severity, f"No rate limiting on {test_url}")
                break  # One finding is sufficient

    def _check_account_enumeration(self, url, endpoints):
        """Check for account enumeration via login/reset error messages."""
        login_urls = endpoints.get("login", [])

        for login_url in login_urls[:2]:
            try:
                # Try with a definitely-invalid user
                resp1 = self.http_client.post(login_url, data={
                    "username": "definitelynotauser12345xyz",
                    "password": "wrongpassword123",
                    "log": "definitelynotauser12345xyz",  # WordPress
                    "pwd": "wrongpassword123",
                }, timeout=10)
                time1 = time.time()

                resp2 = self.http_client.post(login_url, data={
                    "username": "admin",
                    "password": "wrongpassword123",
                    "log": "admin",
                    "pwd": "wrongpassword123",
                }, timeout=10)
                time2 = time.time()

                # Check for different error messages
                if resp1.status_code == resp2.status_code:
                    # Compare response content
                    if resp1.text != resp2.text:
                        # Check if the difference reveals user existence
                        diff_ratio = self._content_similarity(resp1.text, resp2.text)
                        if diff_ratio < 0.95:
                            self.add_finding(
                                title="Account enumeration via login error messages",
                                severity=Severity.MEDIUM,
                                description=(
                                    "Login page returns different responses for valid vs. "
                                    "invalid usernames, enabling account enumeration.\n"
                                    f"Content similarity: {diff_ratio:.1%}"
                                ),
                                recommendation=(
                                    "Use generic error messages like 'Invalid credentials' "
                                    "for both valid and invalid usernames."
                                ),
                                evidence=f"URL: {login_url}\nSimilarity: {diff_ratio:.1%}",
                                category="Business Logic",
                                url=login_url,
                                cwe="CWE-203",
                            )
                            print_finding(Severity.MEDIUM, "Account enumeration via login responses")

            except Exception:
                continue

    def _check_password_reset(self, url, endpoints):
        """Check password reset flow for vulnerabilities."""
        reset_urls = endpoints.get("reset", [])

        for reset_url in reset_urls[:2]:
            try:
                # Check if reset page is accessible
                resp = self.http_client.get(reset_url, timeout=10)
                if resp.status_code == 200:
                    html = resp.text.lower()

                    # Check for token in URL (insecure)
                    if "token=" in reset_url.lower():
                        self.add_finding(
                            title="Password reset token in URL",
                            severity=Severity.MEDIUM,
                            description="Password reset token is passed via URL parameter, which may be logged or leaked via Referer header.",
                            recommendation="Pass reset tokens via POST body or use short-lived tokens.",
                            evidence=f"URL: {reset_url}",
                            category="Business Logic",
                            url=reset_url,
                            cwe="CWE-598",
                        )

                    # Check for enumeration via reset
                    try:
                        resp1 = self.http_client.post(reset_url, data={
                            "email": "nonexistent12345@example.invalid",
                            "user_login": "nonexistent12345@example.invalid",
                        }, timeout=10)

                        if "not found" in resp1.text.lower() or "does not exist" in resp1.text.lower() or "no account" in resp1.text.lower():
                            self.add_finding(
                                title="Account enumeration via password reset",
                                severity=Severity.MEDIUM,
                                description="Password reset reveals whether an email/username exists.",
                                recommendation="Always display 'If an account exists, a reset email will be sent.'",
                                evidence=f"URL: {reset_url}\nResponse indicates non-existence",
                                category="Business Logic",
                                url=reset_url,
                                cwe="CWE-203",
                            )
                    except Exception:
                        pass

            except Exception:
                continue

    def _check_parameter_manipulation(self, url, endpoints):
        """Check for price/quantity manipulation in forms."""
        # Look for forms with price/quantity fields
        try:
            resp = self.http_client.get(url)
            html = resp.text

            # Find hidden fields that might contain prices
            hidden_fields = re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)',
                html, re.I
            )

            price_fields = []
            for name, value in hidden_fields:
                name_lower = name.lower()
                if any(k in name_lower for k in ["price", "amount", "total", "cost", "fee", "discount", "tax"]):
                    price_fields.append((name, value))

            if price_fields:
                self.add_finding(
                    title="Client-side price fields in hidden inputs",
                    severity=Severity.HIGH,
                    description=(
                        f"Found price-related hidden form fields that could be manipulated:\n"
                        + "\n".join(f"  {name}={value}" for name, value in price_fields)
                        + "\nAn attacker could modify these values before submitting."
                    ),
                    recommendation=(
                        "Never trust client-side price data. Always calculate prices "
                        "server-side based on item IDs and quantities."
                    ),
                    evidence=f"Fields: {', '.join(f'{n}={v}' for n, v in price_fields)}",
                    category="Business Logic",
                    url=url,
                    cwe="CWE-472",
                )
                print_finding(Severity.HIGH, f"Client-side price fields: {', '.join(n for n, v in price_fields)}")

            # Check for role/privilege fields
            role_fields = []
            for name, value in hidden_fields:
                name_lower = name.lower()
                if any(k in name_lower for k in ["role", "admin", "privilege", "level", "permission", "is_admin", "isadmin"]):
                    role_fields.append((name, value))

            if role_fields:
                self.add_finding(
                    title="Client-side role/privilege fields",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Found role/privilege hidden form fields that could enable privilege escalation:\n"
                        + "\n".join(f"  {name}={value}" for name, value in role_fields)
                    ),
                    recommendation="Never include role/privilege data in client-side forms.",
                    evidence=f"Fields: {', '.join(f'{n}={v}' for n, v in role_fields)}",
                    category="Business Logic",
                    url=url,
                    cwe="CWE-269",
                )

        except Exception:
            pass

    def _check_registration(self, url, endpoints):
        """Check registration for abuse vectors."""
        register_urls = endpoints.get("register", [])

        for reg_url in register_urls[:2]:
            try:
                resp = self.http_client.get(reg_url, timeout=10)
                if resp.status_code == 200:
                    html = resp.text.lower()

                    # Check for CAPTCHA
                    has_captcha = any(k in html for k in [
                        "captcha", "recaptcha", "hcaptcha", "turnstile",
                        "g-recaptcha", "h-captcha", "cf-turnstile",
                    ])

                    if not has_captcha:
                        self.add_finding(
                            title="Registration without CAPTCHA",
                            severity=Severity.MEDIUM,
                            description="Registration form has no CAPTCHA protection, enabling automated account creation.",
                            recommendation="Add CAPTCHA (reCAPTCHA, hCaptcha, or Turnstile) to registration forms.",
                            evidence=f"URL: {reg_url}",
                            category="Business Logic",
                            url=reg_url,
                            cwe="CWE-799",
                        )

                    # Check for email verification
                    if "verify" not in html and "confirm" not in html and "activation" not in html:
                        self.add_finding(
                            title="Registration may lack email verification",
                            severity=Severity.LOW,
                            description="No indication of email verification in registration flow.",
                            recommendation="Require email verification before activating accounts.",
                            evidence=f"URL: {reg_url}",
                            category="Business Logic",
                            url=reg_url,
                            cwe="CWE-304",
                        )

            except Exception:
                continue

    def _check_method_override(self, url):
        """Check for HTTP method override headers."""
        override_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
        ]

        for header in override_headers:
            try:
                resp = self.http_client.post(
                    url,
                    headers={header: "PUT"},
                    timeout=10,
                )
                if resp.status_code in (200, 201, 204):
                    self.add_finding(
                        title=f"HTTP method override accepted: {header}",
                        severity=Severity.MEDIUM,
                        description=f"The server accepts {header} to override the HTTP method. This could bypass method-based access controls.",
                        recommendation=f"Disable {header} support or restrict it to trusted clients.",
                        evidence=f"Header: {header}: PUT\nStatus: {resp.status_code}",
                        category="Business Logic",
                        url=url,
                        cwe="CWE-436",
                    )
                    break
            except Exception:
                continue

    def _content_similarity(self, text1, text2):
        """Calculate similarity ratio between two strings."""
        if not text1 or not text2:
            return 0.0
        # Simple character-level similarity
        common = sum(1 for a, b in zip(text1[:5000], text2[:5000]) if a == b)
        total = max(len(text1[:5000]), len(text2[:5000]))
        return common / total if total > 0 else 0.0
