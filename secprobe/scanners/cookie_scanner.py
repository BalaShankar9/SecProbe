"""
Cookie Security Scanner — uses shared HTTPClient.

Enhanced with:
  - Standard flag checks (Secure, HttpOnly, SameSite)
  - Cookie value entropy analysis (predictable session detection)
  - Prefix validation (__Host- / __Secure-)
  - Expiration analysis
"""

import math
import re
from collections import Counter

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding, Colors


class CookieScanner(SmartScanner):
    name = "Cookie Scanner"
    description = "Analyze cookies for security misconfigurations"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Analyzing cookies from {url}", "progress")

        try:
            resp = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Target unreachable: {e}", "error")
            self.result.error = str(e)
            return
        except Exception as e:
            print_status(f"Request failed: {e}", "error")
            self.result.error = str(e)
            return

        cookies = self.http_client._session.cookies
        raw_set_cookie = resp.headers.get("Set-Cookie", "")

        if not cookies and not raw_set_cookie:
            print_status("No cookies set by the server.", "info")
            self.add_finding(
                title="No cookies detected",
                severity=Severity.INFO,
                description="The server did not set any cookies.",
                category="Cookies",
            )
            return

        self.result.raw_data["cookies"] = []
        print(f"\n  {Colors.BOLD}Cookies Found:{Colors.RESET}")

        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": bool(cookie._rest.get("HttpOnly", False) or
                                 cookie.has_nonstandard_attr("HttpOnly")),
                "samesite": cookie._rest.get("SameSite", "Not Set"),
                "expires": str(cookie.expires) if cookie.expires else "Session",
            }
            self.result.raw_data["cookies"].append(cookie_info)

            print(f"\n    {Colors.CYAN}Cookie: {cookie.name}{Colors.RESET}")
            print(f"       Domain:   {cookie.domain}")
            print(f"       Path:     {cookie.path}")
            print(f"       Secure:   {'Y' if cookie.secure else 'N'}")
            print(f"       HttpOnly: {'Y' if cookie_info['httponly'] else 'N'}")
            print(f"       SameSite: {cookie_info['samesite']}")

            if not cookie.secure:
                self.add_finding(
                    title=f"Cookie '{cookie.name}' missing Secure flag",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{cookie.name}' can be transmitted over unencrypted HTTP.",
                    recommendation="Add the Secure flag.",
                    evidence=f"Cookie: {cookie.name}",
                    category="Cookies",
                    cwe="CWE-614",
                )
                print_finding(Severity.MEDIUM, f"'{cookie.name}' missing Secure flag")

            if not cookie_info["httponly"]:
                severity = Severity.MEDIUM
                if any(kw in cookie.name.lower() for kw in ["session", "sess", "token", "auth", "jwt"]):
                    severity = Severity.HIGH
                self.add_finding(
                    title=f"Cookie '{cookie.name}' missing HttpOnly flag",
                    severity=severity,
                    description=f"Cookie '{cookie.name}' is accessible via JavaScript (XSS risk).",
                    recommendation="Add the HttpOnly flag.",
                    evidence=f"Cookie: {cookie.name}",
                    category="Cookies",
                    cwe="CWE-1004",
                )
                print_finding(severity, f"'{cookie.name}' missing HttpOnly flag")

            samesite = cookie_info["samesite"]
            if samesite == "Not Set" or samesite.lower() == "none":
                self.add_finding(
                    title=f"Cookie '{cookie.name}' has weak SameSite policy",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{cookie.name}' SameSite is '{samesite}' (CSRF risk).",
                    recommendation="Set SameSite=Lax or SameSite=Strict.",
                    evidence=f"Cookie: {cookie.name}, SameSite: {samesite}",
                    category="Cookies",
                    cwe="CWE-1275",
                )

            sensitive_names = ["session", "token", "auth", "jwt", "api_key", "apikey",
                               "access_token", "refresh_token", "password", "secret"]
            if any(sn in cookie.name.lower() for sn in sensitive_names):
                if not cookie.secure or not cookie_info["httponly"]:
                    self.add_finding(
                        title=f"Sensitive cookie '{cookie.name}' lacks protections",
                        severity=Severity.HIGH,
                        description=f"Sensitive cookie '{cookie.name}' is not fully protected.",
                        recommendation="Ensure Secure, HttpOnly, and SameSite flags are all set.",
                        category="Cookies",
                        cwe="CWE-614",
                    )

            # ── Entropy analysis (predictable session detection) ─────
            self._check_cookie_entropy(cookie, url)

            # ── Cookie prefix validation ─────────────────────────────
            self._check_cookie_prefix(cookie, url)

            # ── Long-lived session cookies ───────────────────────────
            self._check_cookie_expiry(cookie, cookie_info, url)

    # ── Entropy analysis ─────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _check_cookie_entropy(self, cookie, url: str):
        """Detect predictable / low-entropy session cookie values."""
        sensitive_names = ["session", "sess", "token", "auth", "jwt", "sid"]
        if not any(sn in cookie.name.lower() for sn in sensitive_names):
            return

        value = cookie.value or ""
        if len(value) < 8:
            self.add_finding(
                title=f"Session cookie '{cookie.name}' is too short",
                severity=Severity.HIGH,
                description=(
                    f"Cookie '{cookie.name}' value is only {len(value)} chars. "
                    "Short session IDs are brute-forceable."
                ),
                recommendation="Use at least 128 bits (32 hex chars) of randomness.",
                evidence=f"Cookie: {cookie.name}, Length: {len(value)}",
                category="Cookies",
                url=url,
                cwe="CWE-330",
            )
            return

        entropy = self._shannon_entropy(value)
        # Typical secure random hex: ~4.0 bits/char; base64: ~5.2 bits/char
        # Low entropy (< 3.0) suggests sequential/predictable values
        if entropy < 3.0 and len(value) >= 8:
            self.add_finding(
                title=f"Low entropy session cookie: {cookie.name}",
                severity=Severity.HIGH,
                description=(
                    f"Cookie '{cookie.name}' has low entropy ({entropy:.2f} bits/char). "
                    "This suggests predictable session IDs vulnerable to brute-force."
                ),
                recommendation="Use a cryptographically secure random generator for session IDs.",
                evidence=f"Cookie: {cookie.name}, Entropy: {entropy:.2f} bits/char, Length: {len(value)}",
                category="Cookies",
                url=url,
                cwe="CWE-330",
            )
            print_finding(Severity.HIGH, f"'{cookie.name}' low entropy: {entropy:.2f}")

    def _check_cookie_prefix(self, cookie, url: str):
        """Validate __Host- and __Secure- cookie prefix requirements."""
        name = cookie.name
        if name.startswith("__Host-"):
            issues = []
            if not cookie.secure:
                issues.append("must have Secure flag")
            if cookie.path != "/":
                issues.append("must have Path=/")
            if cookie.domain:
                issues.append("must NOT have Domain attribute")
            if issues:
                self.add_finding(
                    title=f"__Host- cookie prefix violation: {name}",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{name}' uses __Host- prefix but: {'; '.join(issues)}.",
                    recommendation="Ensure __Host- cookies have Secure, Path=/, and no Domain.",
                    category="Cookies",
                    url=url,
                    cwe="CWE-614",
                )
        elif name.startswith("__Secure-"):
            if not cookie.secure:
                self.add_finding(
                    title=f"__Secure- cookie prefix violation: {name}",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{name}' uses __Secure- prefix but lacks Secure flag.",
                    recommendation="Ensure __Secure- cookies have the Secure flag.",
                    category="Cookies",
                    url=url,
                    cwe="CWE-614",
                )

    def _check_cookie_expiry(self, cookie, cookie_info: dict, url: str):
        """Flag session cookies with excessively long lifetimes."""
        import time
        if not cookie.expires:
            return  # Session cookie (expires on browser close) — fine
        sensitive_names = ["session", "sess", "token", "auth", "jwt", "sid"]
        if not any(sn in cookie.name.lower() for sn in sensitive_names):
            return
        now = time.time()
        lifetime_days = (cookie.expires - now) / 86400
        if lifetime_days > 30:
            self.add_finding(
                title=f"Long-lived session cookie: {cookie.name}",
                severity=Severity.LOW,
                description=(
                    f"Session cookie '{cookie.name}' expires in {lifetime_days:.0f} days. "
                    "Long-lived sessions increase the window for session hijacking."
                ),
                recommendation="Set session cookie lifetimes to 24 hours or less.",
                evidence=f"Cookie: {cookie.name}, Expires in: {lifetime_days:.0f} days",
                category="Cookies",
                url=url,
                cwe="CWE-613",
            )
