"""
HTTP Header Security Scanner — uses shared HTTPClient.

Features:
  - Missing security header detection
  - Information leakage via headers
  - CSP policy analysis
  - HSTS configuration validation
  - Auth/proxy/rate-limiting via shared HTTPClient
"""

from secprobe.config import Severity, SECURITY_HEADERS, INSECURE_HEADERS
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding, Colors


class HeaderScanner(SmartScanner):
    name = "Header Scanner"
    description = "Analyze HTTP response headers for security issues"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Fetching headers from {url}", "progress")

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

        headers = resp.headers
        self.result.raw_data["status_code"] = resp.status_code
        self.result.raw_data["headers"] = dict(headers)
        self.result.raw_data["url"] = resp.url

        print(f"\n  {Colors.BOLD}Response Headers:{Colors.RESET}")
        for k, v in headers.items():
            print(f"    {Colors.CYAN}{k}:{Colors.RESET} {v[:100]}")

        print(f"\n  {Colors.BOLD}Security Header Analysis:{Colors.RESET}")

        # ── Check for MISSING security headers ───────────────────────
        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower() for k in headers}:
                self.add_finding(
                    title=f"Missing header: {header_name}",
                    severity=info["severity"],
                    description=info["description"],
                    recommendation=info["recommendation"],
                    category="HTTP Headers",
                    cwe="CWE-693",
                )
                print_finding(info["severity"], f"Missing: {header_name}", info["description"])
            else:
                print_finding(Severity.INFO, f"Present: {header_name}")

        # ── Check for INSECURE headers that leak info ────────────────
        print(f"\n  {Colors.BOLD}Information Leakage:{Colors.RESET}")
        for header_name, info in INSECURE_HEADERS.items():
            value = headers.get(header_name)
            if value:
                self.add_finding(
                    title=f"Information leakage: {header_name}",
                    severity=info["severity"],
                    description=f"{info['description']} - Value: {value}",
                    recommendation=info["recommendation"],
                    evidence=f"{header_name}: {value}",
                    category="HTTP Headers",
                    cwe="CWE-200",
                )
                print_finding(info["severity"], f"{header_name}: {value}", info["description"])

        # ── CSP Analysis ─────────────────────────────────────────────
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            self._analyze_csp(csp)

        # ── HSTS Analysis ────────────────────────────────────────────
        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            import re
            match = re.search(r"max-age=(\d+)", hsts)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:
                    self.add_finding(
                        title="HSTS max-age is too low",
                        severity=Severity.MEDIUM,
                        description=f"HSTS max-age is {max_age}s (< 1 year).",
                        recommendation="Set max-age to at least 31536000 (1 year).",
                        category="HTTP Headers",
                        cwe="CWE-319",
                    )
            if "includesubdomains" not in hsts.lower():
                self.add_finding(
                    title="HSTS missing includeSubDomains",
                    severity=Severity.LOW,
                    description="HSTS does not include subdomains.",
                    recommendation="Add includeSubDomains to HSTS header.",
                    category="HTTP Headers",
                )
            if "preload" not in hsts.lower():
                self.add_finding(
                    title="HSTS missing preload directive",
                    severity=Severity.INFO,
                    description="HSTS is not eligible for browser preload lists.",
                    recommendation="Add preload to HSTS header after meeting requirements.",
                    category="HTTP Headers",
                )

        # ── Cross-Origin headers ─────────────────────────────────────
        self._check_cross_origin_headers(headers)

        # ── Cookie flags in Set-Cookie ───────────────────────────────
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            if "secure" not in cookies.lower():
                self.add_finding(
                    title="Cookie missing Secure flag",
                    severity=Severity.MEDIUM,
                    description="Cookies set without the Secure flag.",
                    recommendation="Add the Secure flag to all cookies.",
                    evidence=cookies[:200],
                    category="HTTP Headers",
                    cwe="CWE-614",
                )
            if "httponly" not in cookies.lower():
                self.add_finding(
                    title="Cookie missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    description="Cookies set without the HttpOnly flag.",
                    recommendation="Add the HttpOnly flag to sensitive cookies.",
                    evidence=cookies[:200],
                    category="HTTP Headers",
                    cwe="CWE-1004",
                )

    def _analyze_csp(self, csp: str):
        """Deep CSP policy analysis."""
        dangerous_directives = {
            "unsafe-inline": ("CSP allows unsafe-inline", Severity.HIGH, "CWE-79"),
            "unsafe-eval": ("CSP allows unsafe-eval", Severity.HIGH, "CWE-95"),
            "data:": ("CSP allows data: URIs", Severity.MEDIUM, "CWE-79"),
            "*": ("CSP contains wildcard source", Severity.MEDIUM, "CWE-942"),
        }
        for directive, (desc, sev, cwe) in dangerous_directives.items():
            if directive in csp:
                self.add_finding(
                    title=f"Weak CSP: {directive}",
                    severity=sev,
                    description=desc,
                    recommendation=f"Remove '{directive}' from Content-Security-Policy.",
                    evidence=f"CSP: {csp[:200]}",
                    category="HTTP Headers",
                    cwe=cwe,
                )
                print_finding(sev, f"CSP: {directive} found")

        if "default-src" not in csp and "script-src" not in csp:
            self.add_finding(
                title="CSP missing default-src and script-src",
                severity=Severity.MEDIUM,
                description="CSP lacks both default-src and script-src directives.",
                recommendation="Add a restrictive default-src directive.",
                category="HTTP Headers",
                cwe="CWE-693",
            )

        # Additional CSP directive checks
        if "frame-ancestors" not in csp:
            self.add_finding(
                title="CSP missing frame-ancestors",
                severity=Severity.LOW,
                description="CSP lacks frame-ancestors directive (clickjacking protection).",
                recommendation="Add frame-ancestors 'self' or 'none'.",
                category="HTTP Headers",
                cwe="CWE-1021",
            )
        if "base-uri" not in csp:
            self.add_finding(
                title="CSP missing base-uri",
                severity=Severity.LOW,
                description="Without base-uri, attackers can inject <base> tags to redirect relative URLs.",
                recommendation="Add base-uri 'self' or 'none'.",
                category="HTTP Headers",
                cwe="CWE-693",
            )
        if "form-action" not in csp:
            self.add_finding(
                title="CSP missing form-action",
                severity=Severity.LOW,
                description="Without form-action, forms can be submitted to any origin.",
                recommendation="Add form-action 'self'.",
                category="HTTP Headers",
                cwe="CWE-693",
            )
        if "object-src" not in csp:
            self.add_finding(
                title="CSP missing object-src",
                severity=Severity.LOW,
                description="Without object-src, Flash/Java plugins can be loaded for XSS.",
                recommendation="Add object-src 'none'.",
                category="HTTP Headers",
                cwe="CWE-693",
            )

    def _check_cross_origin_headers(self, headers):
        """Check Cross-Origin resource policy headers."""
        cross_origin_checks = [
            ("Cross-Origin-Opener-Policy", "COOP prevents Spectre-class side-channel attacks"),
            ("Cross-Origin-Embedder-Policy", "COEP restricts cross-origin resource loading"),
            ("Cross-Origin-Resource-Policy", "CORP prevents cross-origin reads of resources"),
        ]
        for header_name, desc in cross_origin_checks:
            if header_name.lower() not in {k.lower() for k in headers}:
                self.add_finding(
                    title=f"Missing {header_name}",
                    severity=Severity.INFO,
                    description=f"Response lacks {header_name}. {desc}.",
                    recommendation=f"Add {header_name} header.",
                    category="HTTP Headers",
                    cwe="CWE-693",
                )

        # Check X-Permitted-Cross-Domain-Policies
        xpcdp = headers.get("X-Permitted-Cross-Domain-Policies", "")
        if not xpcdp:
            self.add_finding(
                title="Missing X-Permitted-Cross-Domain-Policies",
                severity=Severity.INFO,
                description="Flash/PDF cross-domain policy header not set.",
                recommendation="Add X-Permitted-Cross-Domain-Policies: none",
                category="HTTP Headers",
                cwe="CWE-942",
            )
