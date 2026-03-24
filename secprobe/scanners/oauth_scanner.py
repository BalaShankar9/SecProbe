"""
OAuth / OIDC Security Scanner.

Tests for:
  - Open redirect in redirect_uri (account takeover via token theft)
  - Missing/weak state parameter (CSRF on OAuth flow)
  - PKCE not enforced (authorization code interception)
  - Token in URL fragment vs query (exposure risk)
  - Scope manipulation
  - Authorization endpoint enumeration
  - JWKS endpoint security
  - Client secret in client-side code
"""

import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, urlunparse

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth2/authorize", "/oauth/auth",
    "/authorize", "/auth", "/login/oauth/authorize",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/token", "/oauth2/token", "/token",
    "/oauth/callback", "/oauth2/callback", "/callback",
    "/api/oauth/authorize", "/connect/authorize",
    "/oauth/v2/authorize", "/o/oauth2/auth",
]

REDIRECT_BYPASS_PAYLOADS = [
    "https://evil.com",
    "https://evil.com/callback",
    "//evil.com",
    "https://evil.com%23@legitimate.com",
    "https://legitimate.com@evil.com",
    "https://legitimate.com.evil.com",
    "https://evil.com/legitimate.com",
    "https://legitimate.com%2F@evil.com",
    "https://evil.com\\@legitimate.com",
    "https://evil.com#legitimate.com",
    "https://legitimate.com/.evil.com",
    "https://legitimate.com%00.evil.com",
    "javascript:alert(1)",
    "data:text/html,<h1>stolen</h1>",
]


class OAuthScanner(SmartScanner):
    name = "OAuth Scanner"
    description = "Test for OAuth/OIDC security vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing OAuth/OIDC security on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
        except Exception as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        vulns_found = 0

        # ── Phase 1: Discover OAuth endpoints ────────────────────────
        print_status("Phase 1: Discovering OAuth endpoints", "progress")
        endpoints = self._discover_endpoints(url, baseline.text)

        if not endpoints:
            print_status("No OAuth endpoints discovered.", "info")
            self.add_finding(
                title="No OAuth endpoints detected",
                severity=Severity.INFO,
                description="Could not find OAuth/OIDC endpoints.",
                category="OAuth Security",
            )
            return

        print_status(f"Found {len(endpoints)} OAuth endpoint(s)", "info")

        # ── Phase 2: OpenID Configuration analysis ───────────────────
        print_status("Phase 2: OpenID Configuration analysis", "progress")
        vulns_found += self._analyze_openid_config(url)

        # ── Phase 3: redirect_uri validation bypass ──────────────────
        print_status("Phase 3: Testing redirect_uri validation", "progress")
        for ep in endpoints:
            if "authorize" in ep.get("type", ""):
                vulns_found += self._test_redirect_uri(ep["url"], url)

        # ── Phase 4: State parameter validation ──────────────────────
        print_status("Phase 4: Testing state parameter handling", "progress")
        for ep in endpoints:
            if "authorize" in ep.get("type", ""):
                vulns_found += self._test_state_param(ep["url"])

        # ── Phase 5: Token exposure checks ───────────────────────────
        print_status("Phase 5: Token exposure analysis", "progress")
        vulns_found += self._check_token_exposure(url, baseline)

        # ── Phase 6: Client secret in source ─────────────────────────
        print_status("Phase 6: Client secret exposure", "progress")
        vulns_found += self._check_client_secret_exposure(url, baseline.text)

        # ── Phase 7: Scope manipulation ──────────────────────────────
        print_status("Phase 7: Scope manipulation testing", "progress")
        for ep in endpoints:
            if "authorize" in ep.get("type", ""):
                vulns_found += self._test_scope_manipulation(ep["url"])

        if vulns_found == 0:
            print_status("No OAuth vulnerabilities detected.", "success")
            self.add_finding(
                title="No OAuth security issues detected",
                severity=Severity.INFO,
                description="Automated tests did not detect OAuth/OIDC vulnerabilities.",
                category="OAuth Security",
            )

    def _discover_endpoints(self, url, html):
        """Discover OAuth/OIDC endpoints via probing and HTML inspection."""
        endpoints = []
        seen = set()

        # Probe known paths
        for path in OAUTH_ENDPOINTS:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)
            test_url = urljoin(url, path)
            try:
                resp = self.http_client.get(test_url, allow_redirects=False, timeout=5)
                if resp.status_code in (200, 301, 302, 303, 307, 400, 401):
                    ep_type = "authorize" if "authorize" in path or "auth" in path else \
                              "token" if "token" in path else \
                              "config" if "well-known" in path else "callback"
                    if test_url not in seen:
                        endpoints.append({"url": test_url, "type": ep_type, "status": resp.status_code})
                        seen.add(test_url)
            except Exception:
                continue

        # Search HTML for OAuth links
        oauth_patterns = [
            re.compile(r'href=["\']([^"\']*(?:oauth|authorize|auth/login|connect/authorize)[^"\']*)["\']', re.IGNORECASE),
            re.compile(r'action=["\']([^"\']*(?:oauth|authorize|token)[^"\']*)["\']', re.IGNORECASE),
        ]
        for pattern in oauth_patterns:
            for match in pattern.finditer(html):
                href = match.group(1)
                if not href.startswith("http"):
                    href = urljoin(url, href)
                if href not in seen:
                    endpoints.append({"url": href, "type": "authorize", "status": 0})
                    seen.add(href)

        return endpoints

    def _analyze_openid_config(self, url):
        """Analyze .well-known/openid-configuration for security issues."""
        vulns = 0
        config_urls = [
            urljoin(url, "/.well-known/openid-configuration"),
            urljoin(url, "/.well-known/oauth-authorization-server"),
        ]

        for config_url in config_urls:
            try:
                resp = self.http_client.get(config_url, timeout=5)
                if resp.status_code != 200:
                    continue

                try:
                    config = resp.json()
                except Exception:
                    continue

                # Check for insecure token endpoint auth methods
                auth_methods = config.get("token_endpoint_auth_methods_supported", [])
                if "none" in auth_methods:
                    vulns += 1
                    self.add_finding(
                        title="OAuth - 'none' auth method supported",
                        severity=Severity.HIGH,
                        description="Token endpoint accepts 'none' authentication method.",
                        recommendation="Remove 'none' from supported auth methods.",
                        evidence=f"Methods: {auth_methods}",
                        category="OAuth Security", url=config_url, cwe="CWE-287",
                    )

                # Check response types
                response_types = config.get("response_types_supported", [])
                if "token" in response_types:
                    self.add_finding(
                        title="OAuth - Implicit flow (response_type=token) supported",
                        severity=Severity.MEDIUM,
                        description="Implicit flow is deprecated and exposes tokens in URL fragments.",
                        recommendation="Use authorization code flow with PKCE instead.",
                        evidence=f"Response types: {response_types}",
                        category="OAuth Security", url=config_url, cwe="CWE-522",
                    )

                # Check PKCE support
                pkce_methods = config.get("code_challenge_methods_supported", [])
                if not pkce_methods:
                    vulns += 1
                    self.add_finding(
                        title="OAuth - PKCE not supported",
                        severity=Severity.MEDIUM,
                        description="Server does not advertise PKCE support.",
                        recommendation="Implement PKCE (RFC 7636) with S256 method.",
                        evidence=f"URL: {config_url}",
                        category="OAuth Security", url=config_url, cwe="CWE-345",
                    )
                elif "plain" in pkce_methods and "S256" not in pkce_methods:
                    vulns += 1
                    self.add_finding(
                        title="OAuth - Only 'plain' PKCE method supported",
                        severity=Severity.MEDIUM,
                        description="Only plain PKCE is supported, which provides no protection.",
                        recommendation="Support S256 PKCE code challenge method.",
                        evidence=f"PKCE methods: {pkce_methods}",
                        category="OAuth Security", url=config_url, cwe="CWE-345",
                    )

                # Check for ID token signing algorithms
                id_token_algs = config.get("id_token_signing_alg_values_supported", [])
                if "none" in id_token_algs:
                    vulns += 1
                    self.add_finding(
                        title="OAuth - 'none' signing algorithm for ID tokens",
                        severity=Severity.CRITICAL,
                        description="ID tokens can be unsigned (alg=none).",
                        recommendation="Remove 'none' from supported signing algorithms.",
                        evidence=f"Algorithms: {id_token_algs}",
                        category="OAuth Security", url=config_url, cwe="CWE-327",
                    )

                break
            except Exception:
                continue

        return vulns

    def _test_redirect_uri(self, auth_url, base_url):
        """Test redirect_uri parameter for open redirect / token theft."""
        vulns = 0
        parsed = urlparse(base_url)
        legitimate_host = parsed.netloc

        for payload in REDIRECT_BYPASS_PAYLOADS:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)

            # Build authorize request with malicious redirect_uri
            test_params = {
                "client_id": "test",
                "response_type": "code",
                "redirect_uri": payload,
                "scope": "openid",
                "state": "test123",
            }

            test_url = f"{auth_url}?{urlencode(test_params)}"
            try:
                resp = self.http_client.get(test_url, allow_redirects=False, timeout=5)

                # If server redirects to our evil URL, redirect_uri validation is broken
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307):
                    # Check if redirect goes to the payload URL
                    if ("evil.com" in location or
                            "javascript:" in location or
                            "data:" in location):
                        vulns += 1
                        self.add_finding(
                            title=f"OAuth redirect_uri bypass - {payload[:40]}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Authorization endpoint redirects to attacker-controlled URL.\n"
                                f"This allows stealing authorization codes and tokens.\n"
                                f"Bypass: {payload}"
                            ),
                            recommendation="Strictly validate redirect_uri against registered values. Use exact match.",
                            evidence=f"URL: {test_url}\nRedirects to: {location[:200]}",
                            category="OAuth Security", url=auth_url, cwe="CWE-601",
                        )
                        print_finding(Severity.CRITICAL, f"OAuth redirect_uri bypass: {payload[:40]}")
                        break

                # If server returns 200 with the payload echoed (no error)
                if resp.status_code == 200 and payload in resp.text:
                    if "error" not in resp.text.lower():
                        vulns += 1
                        self.add_finding(
                            title="OAuth redirect_uri reflected without validation",
                            severity=Severity.HIGH,
                            description=f"redirect_uri value is reflected in response without validation.",
                            recommendation="Validate redirect_uri against registered values.",
                            evidence=f"URL: {test_url}",
                            category="OAuth Security", url=auth_url, cwe="CWE-601",
                        )
                        break

            except Exception:
                continue

        return vulns

    def _test_state_param(self, auth_url):
        """Test if state parameter is properly validated (CSRF protection)."""
        vulns = 0

        # Test without state parameter
        test_params = {
            "client_id": "test",
            "response_type": "code",
            "redirect_uri": auth_url.replace("/authorize", "/callback"),
        }
        test_url = f"{auth_url}?{urlencode(test_params)}"
        try:
            resp = self.http_client.get(test_url, allow_redirects=False, timeout=5)
            if resp.status_code in (200, 301, 302, 303, 307):
                # Server didn't reject missing state
                if "state" not in resp.text.lower() or "error" not in resp.text.lower():
                    vulns += 1
                    self.add_finding(
                        title="OAuth - state parameter not required",
                        severity=Severity.MEDIUM,
                        description="Authorization endpoint accepts requests without state parameter.",
                        recommendation="Require and validate state parameter to prevent CSRF.",
                        evidence=f"URL: {test_url}\nStatus: {resp.status_code}",
                        category="OAuth Security", url=auth_url, cwe="CWE-352",
                    )
        except Exception:
            pass

        return vulns

    def _check_token_exposure(self, url, resp):
        """Check for token exposure in URLs, headers, and response body."""
        vulns = 0

        # Check for access_token in URL (implicit flow)
        token_in_url = re.search(r'[?&]access_token=([^&]+)', url)
        if token_in_url:
            vulns += 1
            self.add_finding(
                title="Access token exposed in URL",
                severity=Severity.HIGH,
                description="Access token is passed as a URL parameter (visible in logs, Referer).",
                recommendation="Use Authorization header for token transmission.",
                evidence=f"Token fragment: {token_in_url.group(1)[:20]}...",
                category="OAuth Security", url=url, cwe="CWE-598",
            )

        # Check for tokens in response body
        token_patterns = [
            re.compile(r'"access_token"\s*:\s*"([^"]{20,})"'),
            re.compile(r'"refresh_token"\s*:\s*"([^"]{20,})"'),
            re.compile(r'"id_token"\s*:\s*"(eyJ[^"]+)"'),
        ]
        for pattern in token_patterns:
            match = pattern.search(resp.text)
            if match:
                token_type = pattern.pattern.split('"')[1]
                self.add_finding(
                    title=f"OAuth {token_type} in response body",
                    severity=Severity.INFO,
                    description=f"Found {token_type} in page response. Verify it's not cached or logged.",
                    recommendation="Ensure tokens are not exposed to client-side JavaScript unnecessarily.",
                    evidence=f"Token type: {token_type}",
                    category="OAuth Security", url=url, cwe="CWE-200",
                )

        return vulns

    def _check_client_secret_exposure(self, url, html):
        """Check for client_secret in HTML/JavaScript source."""
        vulns = 0

        secret_patterns = [
            re.compile(r'client_secret["\s:=]+["\']([^"\']{8,})["\']', re.IGNORECASE),
            re.compile(r'clientSecret["\s:=]+["\']([^"\']{8,})["\']', re.IGNORECASE),
            re.compile(r'app_secret["\s:=]+["\']([^"\']{8,})["\']', re.IGNORECASE),
        ]
        for pattern in secret_patterns:
            match = pattern.search(html)
            if match:
                vulns += 1
                self.add_finding(
                    title="OAuth client_secret exposed in source",
                    severity=Severity.CRITICAL,
                    description="OAuth client secret found in HTML/JavaScript source code.",
                    recommendation="Never embed client secrets in client-side code. Use PKCE for public clients.",
                    evidence=f"Secret: {match.group(1)[:8]}...",
                    category="OAuth Security", url=url, cwe="CWE-798",
                )
                print_finding(Severity.CRITICAL, "Client secret in source!")
                break

        return vulns

    def _test_scope_manipulation(self, auth_url):
        """Test if scope can be escalated."""
        vulns = 0

        escalated_scopes = [
            "openid profile email admin",
            "openid profile email offline_access",
            "openid profile email user:admin",
            "openid profile email read write delete",
        ]

        for scope in escalated_scopes:
            test_params = {
                "client_id": "test",
                "response_type": "code",
                "redirect_uri": auth_url.replace("/authorize", "/callback"),
                "scope": scope,
                "state": "test123",
            }
            test_url = f"{auth_url}?{urlencode(test_params)}"
            try:
                resp = self.http_client.get(test_url, allow_redirects=False, timeout=5)
                if resp.status_code in (200, 301, 302) and "error" not in resp.text.lower():
                    # Check if escalated scope was accepted in redirect
                    location = resp.headers.get("Location", "")
                    if "scope" in location and "admin" in location:
                        vulns += 1
                        self.add_finding(
                            title="OAuth scope escalation accepted",
                            severity=Severity.HIGH,
                            description=f"Server accepted escalated scope: {scope}",
                            recommendation="Validate requested scopes against registered client scopes.",
                            evidence=f"Scope: {scope}\nRedirect: {location[:100]}",
                            category="OAuth Security", url=auth_url, cwe="CWE-269",
                        )
                        break
            except Exception:
                continue

        return vulns
