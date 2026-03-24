"""
CORS Misconfiguration Scanner — comprehensive cross-origin testing.

Tests per PortSwigger / Burp Suite research:
  Phase 1: Origin reflection tests (7 origins)
  Phase 2: Credential-bearing cross-origin checks
  Phase 3: Preflight analysis (methods, headers, max-age)
  Phase 4: Exposed headers leak check
  Phase 5: Per-endpoint CORS variation (if crawl data available)
  Phase 6: Null origin via sandboxed iframe / data URI
  Phase 7: Regex bypass patterns (subdomain, suffix, unicode)
"""

import re
from urllib.parse import urljoin, urlparse

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, extract_hostname, print_status, print_finding, Colors


# Sensitive headers that should not be exposed cross-origin
SENSITIVE_EXPOSED_HEADERS = {
    "authorization", "set-cookie", "x-csrf-token", "x-xsrf-token",
    "x-api-key", "x-session-id", "x-auth-token",
}


class CORSScanner(SmartScanner):
    name = "CORS Scanner"
    description = "Test for Cross-Origin Resource Sharing misconfigurations"

    def scan(self):
        url = normalize_url(self.config.target)
        hostname = extract_hostname(self.config.target)
        print_status(f"Testing CORS on {url}", "progress")

        found_vulns = set()

        # Phase 1: Origin reflection tests
        print_status("Phase 1: Origin reflection tests", "progress")
        self._test_origin_reflection(url, hostname, found_vulns)

        # Phase 2: Wildcard + credentials
        print_status("Phase 2: Wildcard & credential checks", "progress")
        self._test_wildcard_credentials(url, found_vulns)

        # Phase 3: Preflight analysis
        print_status("Phase 3: Preflight analysis", "progress")
        self._test_preflight(url, found_vulns)

        # Phase 4: Exposed headers
        print_status("Phase 4: Exposed headers analysis", "progress")
        self._test_exposed_headers(url, hostname, found_vulns)

        # Phase 5: Per-endpoint CORS variation
        print_status("Phase 5: Per-endpoint CORS variation", "progress")
        self._test_per_endpoint(url, hostname, found_vulns)

        # Phase 6: Null origin
        print_status("Phase 6: Null origin testing", "progress")
        self._test_null_origin(url, found_vulns)

        # Phase 7: Regex-bypassing origins
        print_status("Phase 7: Regex bypass patterns", "progress")
        self._test_regex_bypass(url, hostname, found_vulns)

        if not found_vulns:
            print_status("No CORS misconfigurations detected.", "success")
            self.add_finding(
                title="No CORS misconfigurations detected",
                severity=Severity.INFO,
                description="The server either has no CORS headers or a correctly restrictive policy.",
                category="CORS",
            )

    # ── Phase 1: Origin reflection ───────────────────────────────────

    def _test_origin_reflection(self, url, hostname, found_vulns):
        """Test if the server reflects arbitrary origins."""
        test_origins = [
            (f"https://evil.com", "Arbitrary foreign domain"),
            (f"https://{hostname}.evil.com", "Subdomain-suffix attack"),
            (f"https://evil{hostname}", "Domain prefix attack"),
            (f"http://localhost", "Localhost origin"),
            (f"https://attacker.com", "Attacker domain"),
            (f"https://{hostname}.attacker.com", "Attacker subdomain wrap"),
            (f"https://not{hostname}.com", "Partial match bypass"),
        ]

        for origin, desc in test_origins:
            try:
                resp = self.http_client.get(url, headers={"Origin": origin})
            except (TargetUnreachableError, Exception):
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == origin:
                severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
                key = ("origin_reflect", origin)
                if key not in found_vulns:
                    found_vulns.add(key)
                    self.add_finding(
                        title=f"CORS: Reflects arbitrary origin ({desc})",
                        severity=severity,
                        description=(
                            f"The server reflects the Origin header value '{origin}' back "
                            f"in Access-Control-Allow-Origin. "
                            f"Credentials allowed: {acac}. "
                            f"An attacker can read authenticated responses cross-origin."
                        ),
                        recommendation="Maintain a strict allowlist of permitted origins.",
                        evidence=f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                        category="CORS", url=url, cwe="CWE-942",
                    )
                    print_finding(severity, f"Reflects origin: {origin}")

    # ── Phase 2: Wildcard + credentials ──────────────────────────────

    def _test_wildcard_credentials(self, url, found_vulns):
        """Test for wildcard ACAO with credentials — an impossible-but-tested combination."""
        try:
            resp = self.http_client.get(url, headers={"Origin": "https://test.com"})
        except Exception:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            if acac == "true":
                key = ("wildcard_creds",)
                if key not in found_vulns:
                    found_vulns.add(key)
                    self.add_finding(
                        title="CORS: Wildcard origin with credentials",
                        severity=Severity.CRITICAL,
                        description=(
                            "The server returns Access-Control-Allow-Origin: * alongside "
                            "Access-Control-Allow-Credentials: true. While browsers block this "
                            "combination, it reveals a severe misconfiguration that may be "
                            "exploitable with non-browser clients or future browser changes."
                        ),
                        recommendation="Never combine wildcard ACAO with credentials. Use explicit origins.",
                        evidence=f"ACAO: *\nACAC: true",
                        category="CORS", url=url, cwe="CWE-942",
                    )
                    print_finding(Severity.CRITICAL, "Wildcard + Credentials")
            else:
                # Wildcard without credentials — informational in most cases
                found_vulns.add(("wildcard_no_creds",))
                self.add_finding(
                    title="CORS: Wildcard origin (no credentials)",
                    severity=Severity.LOW,
                    description=(
                        "The server allows any origin (ACAO: *) but without credentials. "
                        "This is safe for public APIs but may not be intended."
                    ),
                    recommendation="Confirm this is intentional for a public API. Otherwise, restrict origins.",
                    category="CORS", url=url,
                )

    # ── Phase 3: Preflight analysis ──────────────────────────────────

    def _test_preflight(self, url, found_vulns):
        """Analyze preflight OPTIONS response for overly permissive configuration."""
        dangerous_methods = {"PUT", "DELETE", "PATCH", "TRACE"}
        test_headers = "Authorization, X-Custom-Header, Content-Type"

        try:
            resp = self.http_client.options(url, headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": test_headers,
            })
        except Exception:
            return

        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")
        max_age = resp.headers.get("Access-Control-Max-Age", "")

        if acam:
            allowed = {m.strip().upper() for m in acam.split(",")}

            # Wildcard methods
            if "*" in acam:
                found_vulns.add(("preflight_wildcard_methods",))
                self.add_finding(
                    title="CORS: Preflight allows all HTTP methods",
                    severity=Severity.MEDIUM,
                    description="The preflight response allows all HTTP methods via wildcard.",
                    recommendation="Restrict allowed methods to those actually needed.",
                    evidence=f"Access-Control-Allow-Methods: {acam}",
                    category="CORS", url=url, cwe="CWE-942",
                )
                print_finding(Severity.MEDIUM, "Preflight allows all methods")

            # Dangerous methods
            exposed_dangerous = allowed & dangerous_methods
            if exposed_dangerous and "*" not in acam:
                found_vulns.add(("preflight_dangerous_methods",))
                self.add_finding(
                    title=f"CORS: Preflight allows dangerous methods: {', '.join(exposed_dangerous)}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The preflight response permits these potentially dangerous methods: "
                        f"{', '.join(exposed_dangerous)}."
                    ),
                    recommendation="Only allow methods that the API actually requires.",
                    evidence=f"ACAM: {acam}",
                    category="CORS", url=url,
                )

        # Wildcard headers
        if acah and "*" in acah:
            found_vulns.add(("preflight_wildcard_headers",))
            self.add_finding(
                title="CORS: Preflight allows all headers",
                severity=Severity.MEDIUM,
                description="Preflight response permits any custom header via wildcard.",
                recommendation="Restrict allowed headers explicitly.",
                evidence=f"Access-Control-Allow-Headers: {acah}",
                category="CORS", url=url,
            )

        # Excessively long max-age
        if max_age:
            try:
                age_seconds = int(max_age)
                if age_seconds > 86400:  # > 1 day
                    found_vulns.add(("preflight_long_cache",))
                    self.add_finding(
                        title=f"CORS: Excessive preflight cache ({age_seconds}s)",
                        severity=Severity.LOW,
                        description=(
                            f"Access-Control-Max-Age is {age_seconds} seconds "
                            f"({age_seconds / 3600:.0f} hours). "
                            f"Long preflight caching delays revocation of CORS policy changes."
                        ),
                        recommendation="Set Access-Control-Max-Age to 3600 (1 hour) or less.",
                        evidence=f"Max-Age: {max_age}",
                        category="CORS", url=url,
                    )
            except ValueError:
                pass

    # ── Phase 4: Exposed headers ─────────────────────────────────────

    def _test_exposed_headers(self, url, hostname, found_vulns):
        """Check what response headers are exposed cross-origin."""
        try:
            resp = self.http_client.get(url, headers={"Origin": f"https://{hostname}"})
        except Exception:
            return

        aceh = resp.headers.get("Access-Control-Expose-Headers", "")
        if not aceh:
            return

        # Wildcard expose
        if "*" in aceh:
            found_vulns.add(("expose_wildcard",))
            self.add_finding(
                title="CORS: All response headers exposed cross-origin",
                severity=Severity.MEDIUM,
                description="Access-Control-Expose-Headers: * exposes all custom response headers.",
                recommendation="Only expose headers that cross-origin consumers need.",
                evidence=f"ACEH: {aceh}",
                category="CORS", url=url, cwe="CWE-942",
            )
            return

        exposed = {h.strip().lower() for h in aceh.split(",")}
        sensitive_exposed = exposed & SENSITIVE_EXPOSED_HEADERS
        if sensitive_exposed:
            found_vulns.add(("expose_sensitive",))
            self.add_finding(
                title=f"CORS: Sensitive headers exposed cross-origin",
                severity=Severity.HIGH,
                description=(
                    f"These sensitive response headers are exposed to cross-origin requests: "
                    f"{', '.join(sensitive_exposed)}"
                ),
                recommendation="Remove sensitive headers from Access-Control-Expose-Headers.",
                evidence=f"ACEH: {aceh}\nSensitive: {', '.join(sensitive_exposed)}",
                category="CORS", url=url, cwe="CWE-200",
            )
            print_finding(Severity.HIGH, f"Sensitive headers exposed: {', '.join(sensitive_exposed)}")

    # ── Phase 5: Per-endpoint CORS variation ─────────────────────────

    def _test_per_endpoint(self, url, hostname, found_vulns):
        """Test CORS on additional endpoints beyond the root."""
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/graphql",
            "/auth", "/login", "/account", "/users", "/admin",
        ]

        evil = "https://evil.com"
        for path in api_paths:
            test_url = urljoin(url + "/", path.lstrip("/"))
            try:
                resp = self.http_client.get(test_url, headers={"Origin": evil})
                if resp.status_code == 404:
                    continue
            except Exception:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == evil:
                key = ("endpoint_reflect", path)
                if key not in found_vulns:
                    found_vulns.add(key)
                    severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
                    self.add_finding(
                        title=f"CORS: Origin reflected on {path}",
                        severity=severity,
                        description=(
                            f"Endpoint {path} reflects arbitrary origins. "
                            f"Credentials: {acac}."
                        ),
                        recommendation="Apply consistent CORS policy across all endpoints.",
                        evidence=f"URL: {test_url}\nOrigin: {evil}\nACAO: {acao}\nACAC: {acac}",
                        category="CORS", url=test_url, cwe="CWE-942",
                    )
                    print_finding(severity, f"CORS misconfiguration on {path}")

    # ── Phase 6: Null origin ─────────────────────────────────────────

    def _test_null_origin(self, url, found_vulns):
        """Test if 'null' origin is accepted (exploitable via sandboxed iframe / data URI)."""
        try:
            resp = self.http_client.get(url, headers={"Origin": "null"})
        except Exception:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "null":
            severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
            found_vulns.add(("null_origin",))
            self.add_finding(
                title="CORS: Null origin allowed",
                severity=severity,
                description=(
                    "The server allows 'null' as an origin. An attacker can exploit this "
                    "using a sandboxed iframe (sandbox='allow-scripts') or data: URI "
                    "to send requests with Origin: null and read responses."
                ),
                recommendation="Do not allow 'null' as a CORS origin.",
                evidence=f"ACAO: null\nACAC: {acac}",
                category="CORS", url=url, cwe="CWE-942",
            )
            print_finding(severity, "Null origin accepted")

    # ── Phase 7: Regex bypass patterns ───────────────────────────────

    def _test_regex_bypass(self, url, hostname, found_vulns):
        """Test origins designed to bypass flawed regex-based allowlists."""
        parts = hostname.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        bypass_origins = [
            (f"https://{domain}.evil.com", "Domain as subdomain of attacker"),
            (f"https://evil-{domain}", "Hyphen prefix bypass"),
            (f"https://{domain}%60.evil.com", "Backtick encoding bypass"),
            (f"https://{domain}%2F.evil.com", "Encoded slash bypass"),
            (f"https://sub.{domain}", "Arbitrary subdomain"),
            (f"https://{domain}_.evil.com", "Underscore bypass"),
        ]

        for origin, desc in bypass_origins:
            try:
                resp = self.http_client.get(url, headers={"Origin": origin})
            except Exception:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == origin:
                key = ("regex_bypass", origin)
                if key not in found_vulns:
                    found_vulns.add(key)
                    severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
                    self.add_finding(
                        title=f"CORS: Regex bypass ({desc})",
                        severity=severity,
                        description=(
                            f"The server's origin validation is vulnerable to regex bypass. "
                            f"Origin '{origin}' was accepted. "
                            f"This likely means the server uses a substring or regex check "
                            f"rather than exact match."
                        ),
                        recommendation=(
                            "Use exact string matching for origin validation, not regex or substring checks."
                        ),
                        evidence=f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                        category="CORS", url=url, cwe="CWE-942",
                    )
                    print_finding(severity, f"Regex bypass: {desc}")
