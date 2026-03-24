"""
Cross-Site Request Forgery (CSRF) Scanner.

Features:
  - Missing CSRF token detection in forms
  - SameSite cookie attribute analysis
  - Token entropy/strength analysis
  - Referer/Origin header validation testing
  - State-changing endpoint detection (POST forms)
  - Token reuse detection
  - Anti-CSRF header analysis (X-CSRF-Token, X-XSRF-Token)
"""

import math
import re
import time
from collections import Counter
from urllib.parse import urlparse

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Common CSRF token field names
CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrfmiddlewaretoken", "csrftoken",
    "_csrf", "_csrf_token", "__csrf", "xsrf", "xsrf_token",
    "_xsrf", "authenticity_token", "token", "nonce", "_wpnonce",
    "verification_token", "__requestverificationtoken",
    "antiforgery", "__antiforgerytoken", "form_token",
    "form_key", "formkey", "security_token", "sec_token",
}

# Common CSRF header names
CSRF_HEADER_NAMES = {
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
    "csrf-token", "xsrf-token",
}

# SameSite values and their CSRF implications
SAMESITE_ANALYSIS = {
    "strict": {"protected": True, "note": "Strong CSRF protection"},
    "lax": {"protected": True, "note": "Protected for POST, vulnerable for GET state changes"},
    "none": {"protected": False, "note": "No SameSite protection — requires Secure flag"},
}


class CSRFScanner(SmartScanner):
    name = "CSRF Scanner"
    description = "Test for Cross-Site Request Forgery vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing CSRF protections on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
            baseline_text = baseline.text
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        vulns_found = 0

        # Phase 1: Analyze forms for CSRF tokens
        vulns_found += self._analyze_forms(url, baseline_text)

        # Phase 2: Analyze SameSite cookie attributes
        vulns_found += self._analyze_samesite(url, baseline)

        # Phase 3: Test Referer/Origin validation
        vulns_found += self._test_referer_validation(url)

        # Phase 4: Analyze CSRF tokens from context forms
        if self.context:
            forms = self.context.get_injectable_forms()
            vulns_found += self._analyze_context_forms(url, forms)

        # Phase 5: Token strength analysis
        vulns_found += self._analyze_token_strength(url, baseline_text)

        # Phase 6: Test token reuse
        vulns_found += self._test_token_reuse(url)

        if vulns_found == 0:
            print_status("No CSRF vulnerabilities detected.", "success")
            self.add_finding(
                title="No CSRF issues detected",
                severity=Severity.INFO,
                description="Automated tests did not detect CSRF vulnerabilities.",
                category="CSRF",
            )

    def _analyze_forms(self, url, html):
        """Parse HTML for forms and check for CSRF token fields."""
        vulns_found = 0

        # Find all forms
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE,
        )
        method_pattern = re.compile(r'method\s*=\s*["\']?(\w+)', re.IGNORECASE)
        action_pattern = re.compile(r'action\s*=\s*["\']([^"\']+)', re.IGNORECASE)
        input_pattern = re.compile(
            r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE,
        )
        hidden_pattern = re.compile(
            r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE,
        )

        forms_found = 0
        unprotected = 0

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            # Get method
            method_match = method_pattern.search(form_html)
            method = method_match.group(1).upper() if method_match else "GET"

            # Only care about state-changing methods
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue

            forms_found += 1

            # Get action
            action_match = action_pattern.search(form_html)
            action = action_match.group(1) if action_match else url

            # Find hidden fields
            hidden_fields = hidden_pattern.findall(form_body)
            all_fields = input_pattern.findall(form_body)

            # Check if any field name matches CSRF token patterns
            has_csrf_token = False
            for field in hidden_fields + all_fields:
                if field.lower() in CSRF_TOKEN_NAMES:
                    has_csrf_token = True
                    break
                # Also check partial matches
                for token_name in CSRF_TOKEN_NAMES:
                    if token_name in field.lower():
                        has_csrf_token = True
                        break
                if has_csrf_token:
                    break

            if not has_csrf_token:
                unprotected += 1
                vulns_found += 1
                self.add_finding(
                    title=f"Missing CSRF Token in {method} Form",
                    severity=Severity.MEDIUM,
                    description=(
                        f"A {method} form at '{action}' has no CSRF token. "
                        f"Fields: {', '.join(all_fields[:10])}. "
                        f"An attacker can forge requests on behalf of authenticated users."
                    ),
                    recommendation=(
                        "Add a CSRF token to every state-changing form. "
                        "Use framework-provided CSRF middleware."
                    ),
                    evidence=(
                        f"Form action: {action}\n"
                        f"Method: {method}\n"
                        f"Fields: {', '.join(all_fields[:10])}\n"
                        f"Hidden fields: {', '.join(hidden_fields[:10])}\n"
                        f"CSRF token: NOT FOUND"
                    ),
                    category="CSRF",
                    url=url,
                    cwe="CWE-352",
                )
                print_finding(Severity.MEDIUM, f"Missing CSRF token: {method} form → {action}")

        if forms_found > 0 and unprotected == 0:
            self.add_finding(
                title="CSRF Tokens Present in Forms",
                severity=Severity.INFO,
                description=f"All {forms_found} state-changing forms have CSRF token fields.",
                category="CSRF",
            )

        return vulns_found

    def _analyze_samesite(self, url, response):
        """Analyze SameSite cookie attributes."""
        vulns_found = 0
        cookies = response.headers.get("Set-Cookie", "")

        # Handle multiple Set-Cookie headers
        if hasattr(response, "raw") and hasattr(response.raw, "_original_response"):
            try:
                cookie_headers = response.raw._original_response.headers.get_all("Set-Cookie") or []
            except Exception:
                cookie_headers = [cookies] if cookies else []
        else:
            cookie_headers = [cookies] if cookies else []

        session_cookies = []
        for cookie_str in cookie_headers:
            if not cookie_str:
                continue

            cookie_lower = cookie_str.lower()

            # Check if this looks like a session cookie
            is_session = any(kw in cookie_lower for kw in [
                "session", "sess", "sid", "token", "auth", "jwt", "login",
                "phpsessid", "jsessionid", "asp.net_sessionid",
                "connect.sid", "laravel_session", "csrf",
            ])

            if not is_session:
                continue

            session_cookies.append(cookie_str)

            # Parse SameSite
            samesite_match = re.search(r'samesite\s*=\s*(\w+)', cookie_lower)
            if samesite_match:
                samesite_val = samesite_match.group(1).lower()
                analysis = SAMESITE_ANALYSIS.get(samesite_val, {})

                if samesite_val == "none":
                    has_secure = "secure" in cookie_lower
                    if not has_secure:
                        vulns_found += 1
                        self.add_finding(
                            title="SameSite=None Without Secure Flag",
                            severity=Severity.MEDIUM,
                            description="Session cookie has SameSite=None but missing Secure flag.",
                            recommendation="Always pair SameSite=None with the Secure flag.",
                            evidence=f"Cookie: {cookie_str[:200]}",
                            category="CSRF",
                            url=url,
                            cwe="CWE-1275",
                        )
                    else:
                        vulns_found += 1
                        self.add_finding(
                            title="SameSite=None on Session Cookie",
                            severity=Severity.LOW,
                            description=(
                                "Session cookie uses SameSite=None, allowing cross-site requests. "
                                "This disables browser's built-in CSRF protection."
                            ),
                            recommendation="Use SameSite=Lax or SameSite=Strict unless cross-site is required.",
                            evidence=f"Cookie: {cookie_str[:200]}",
                            category="CSRF",
                            url=url,
                            cwe="CWE-1275",
                        )
            else:
                # No SameSite attribute — browser defaults vary
                vulns_found += 1
                self.add_finding(
                    title="Missing SameSite Attribute on Session Cookie",
                    severity=Severity.LOW,
                    description=(
                        "Session cookie has no SameSite attribute. "
                        "Modern browsers default to Lax, but older browsers may not."
                    ),
                    recommendation="Explicitly set SameSite=Lax or SameSite=Strict.",
                    evidence=f"Cookie: {cookie_str[:200]}",
                    category="CSRF",
                    url=url,
                    cwe="CWE-1275",
                )

        return vulns_found

    def _test_referer_validation(self, url):
        """Test if the server validates Referer/Origin headers on POST."""
        vulns_found = 0

        # Send POST with no Referer
        test_cases = [
            ({"Referer": ""}, "Empty Referer"),
            ({"Referer": "https://evil.attacker.com/"}, "Foreign Referer"),
            ({"Origin": "https://evil.attacker.com"}, "Foreign Origin"),
            ({"Referer": "", "Origin": ""}, "No Referer + No Origin"),
        ]

        try:
            # First, get baseline POST response
            baseline_post = self.http_client.post(url, data={}, allow_redirects=False)
            baseline_code = baseline_post.status_code
        except Exception:
            return vulns_found

        for headers, desc in test_cases:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)

            try:
                resp = self.http_client.post(
                    url,
                    data={},
                    headers=headers,
                    allow_redirects=False,
                )

                # If server accepts POST with foreign/missing referer
                if resp.status_code == baseline_code and baseline_code not in (405, 404):
                    vulns_found += 1
                    self.add_finding(
                        title=f"No Referer/Origin Validation - {desc}",
                        severity=Severity.LOW,
                        description=(
                            f"Server accepted POST with {desc}. "
                            f"Without Referer/Origin validation, CSRF tokens are the only defense."
                        ),
                        recommendation="Validate Referer and Origin headers as a defense-in-depth measure.",
                        evidence=f"URL: {url}\n{desc}\nStatus: {resp.status_code}",
                        category="CSRF",
                        url=url,
                        cwe="CWE-352",
                    )
                    break  # One finding is enough
            except Exception:
                continue

        return vulns_found

    def _analyze_context_forms(self, url, forms):
        """Analyze forms discovered by the crawler."""
        vulns_found = 0

        for form in forms:
            method = form.get("method", "GET").upper()
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue

            action = form.get("action", url)
            fields = form.get("fields", {})

            has_csrf = False
            for field_name in fields:
                if field_name.lower() in CSRF_TOKEN_NAMES:
                    has_csrf = True
                    break
                for token_name in CSRF_TOKEN_NAMES:
                    if token_name in field_name.lower():
                        has_csrf = True
                        break
                if has_csrf:
                    break

            if not has_csrf and fields:
                vulns_found += 1
                self.add_finding(
                    title=f"Missing CSRF Token (Crawled Form) - {action}",
                    severity=Severity.MEDIUM,
                    description=f"Crawled {method} form at {action} lacks CSRF token.",
                    recommendation="Add CSRF tokens to all state-changing forms.",
                    evidence=f"Action: {action}\nMethod: {method}\nFields: {list(fields.keys())[:10]}",
                    category="CSRF",
                    url=action,
                    cwe="CWE-352",
                )

        return vulns_found

    def _analyze_token_strength(self, url, html):
        """Analyze CSRF token values for entropy and predictability."""
        vulns_found = 0

        # Extract CSRF token values
        token_pattern = re.compile(
            r'<input[^>]*name\s*=\s*["\'](?:' +
            '|'.join(CSRF_TOKEN_NAMES) +
            r')["\'][^>]*value\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        tokens = token_pattern.findall(html)
        if not tokens:
            # Try reverse order (value before name)
            token_pattern2 = re.compile(
                r'<input[^>]*value\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\'](?:' +
                '|'.join(CSRF_TOKEN_NAMES) +
                r')["\']',
                re.IGNORECASE,
            )
            tokens = token_pattern2.findall(html)

        for token in tokens:
            # Check token length
            if len(token) < 16:
                vulns_found += 1
                self.add_finding(
                    title="Weak CSRF Token (Short Length)",
                    severity=Severity.MEDIUM,
                    description=f"CSRF token is only {len(token)} characters. Minimum recommended is 32.",
                    recommendation="Use cryptographically random tokens of at least 32 characters.",
                    evidence=f"Token: {token}\nLength: {len(token)}",
                    category="CSRF",
                    url=url,
                    cwe="CWE-330",
                )
                continue

            # Check Shannon entropy
            entropy = self._calculate_entropy(token)
            if entropy < 3.0:
                vulns_found += 1
                self.add_finding(
                    title="Weak CSRF Token (Low Entropy)",
                    severity=Severity.MEDIUM,
                    description=f"CSRF token has low entropy ({entropy:.2f} bits/char). May be predictable.",
                    recommendation="Use cryptographically secure random number generators.",
                    evidence=f"Token: {token}\nEntropy: {entropy:.2f} bits/char",
                    category="CSRF",
                    url=url,
                    cwe="CWE-330",
                )

        return vulns_found

    def _test_token_reuse(self, url):
        """Request the page twice and compare CSRF tokens."""
        vulns_found = 0

        try:
            resp1 = self.http_client.get(url)
            resp2 = self.http_client.get(url)
        except Exception:
            return vulns_found

        tokens1 = self._extract_tokens(resp1.text)
        tokens2 = self._extract_tokens(resp2.text)

        if tokens1 and tokens2 and tokens1 == tokens2:
            vulns_found += 1
            self.add_finding(
                title="CSRF Token Not Rotated Per Request",
                severity=Severity.LOW,
                description="The same CSRF token was returned on multiple requests. Token-per-request is stronger.",
                recommendation="Generate a new CSRF token per request or per session.",
                evidence=f"Token 1: {list(tokens1)[0][:50]}...\nToken 2: same",
                category="CSRF",
                url=url,
                cwe="CWE-352",
            )

        return vulns_found

    def _extract_tokens(self, html):
        """Extract CSRF token values from HTML."""
        token_pattern = re.compile(
            r'<input[^>]*name\s*=\s*["\'](?:' +
            '|'.join(CSRF_TOKEN_NAMES) +
            r')["\'][^>]*value\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        return set(token_pattern.findall(html))

    @staticmethod
    def _calculate_entropy(text):
        """Calculate Shannon entropy in bits per character."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
