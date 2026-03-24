"""
Host Header Injection Scanner — per-header isolation (CWE-644).

Architecture:
  - Tests Host header manipulation payloads one at a time
  - Tests X-Forwarded-Host and override headers individually
  - Password reset poisoning, cache poisoning, absolute URL tests
  - Uses found_vulns set to avoid duplicates
"""

import re
import time
from urllib.parse import urlparse

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


EVIL_HOST = "evil.secprobe-test.com"
EVIL_HOST_PORT = "evil.secprobe-test.com:443"

HOST_OVERRIDE_HEADERS = [
    ("X-Forwarded-Host", EVIL_HOST),
    ("X-Host", EVIL_HOST),
    ("X-Forwarded-Server", EVIL_HOST),
    ("X-Original-URL", f"http://{EVIL_HOST}/"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-ProxyUser-Ip", "127.0.0.1"),
    ("X-Original-Host", EVIL_HOST),
    ("Forwarded", f"host={EVIL_HOST}"),
    ("True-Client-IP", "127.0.0.1"),
]

HOST_PAYLOADS = [
    {"host": EVIL_HOST, "desc": "Direct Host replacement"},
    {"host": f"{{ORIGINAL}}:{EVIL_HOST}", "desc": "Port-based injection"},
    {"host": f"{EVIL_HOST}.{{ORIGINAL}}", "desc": "Subdomain prefix"},
    {"host": f"{{ORIGINAL}}@{EVIL_HOST}", "desc": "@ symbol bypass"},
    {"host": f"{{ORIGINAL}} {EVIL_HOST}", "desc": "Space injection"},
    {"host": f"{{ORIGINAL}}\t{EVIL_HOST}", "desc": "Tab injection"},
    {"host": f"{{ORIGINAL}}%00{EVIL_HOST}", "desc": "Null byte injection"},
    {"host": f"{{ORIGINAL}}\r\nHost: {EVIL_HOST}", "desc": "Duplicate Host (CRLF)"},
]


class HostHeaderScanner(SmartScanner):
    name = "Host Header Scanner"
    description = "Test for Host Header Injection and cache poisoning vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing Host Header Injection on {url}", "progress")

        parsed = urlparse(url)
        original_host = parsed.netloc or parsed.hostname or self.config.target

        try:
            baseline = self.http_client.get(url)
            baseline_text = baseline.text
            baseline_code = baseline.status_code
            baseline_headers = dict(baseline.headers)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        found_vulns = set()

        # Phase 1: Host header manipulation
        self._test_host_manipulation(url, original_host, baseline_text, found_vulns)

        # Phase 2: Override headers
        self._test_override_headers(url, baseline_text, baseline_code, found_vulns)

        # Phase 3: Password reset poisoning
        self._test_password_reset_poisoning(url, original_host, found_vulns)

        # Phase 4: Cache poisoning
        self._test_cache_poisoning(url, original_host, baseline_headers, found_vulns)

        # Phase 5: Absolute URL handling
        self._test_absolute_url(url, original_host, baseline_text, found_vulns)

        if not found_vulns:
            print_status("No Host Header Injection vulnerabilities detected.", "success")
            self.add_finding(
                title="No Host Header Injection detected",
                severity=Severity.INFO,
                description="Automated tests did not detect host header injection.",
                category="Host Header Injection",
            )

    def _test_host_manipulation(self, url, original_host, baseline_text, found_vulns):
        """Phase 1: Test direct Host header manipulation — one payload at a time."""
        for item in HOST_PAYLOADS:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)

            host_value = item["host"].replace("{ORIGINAL}", original_host)
            try:
                resp = self.http_client.get(url, headers={"Host": host_value}, allow_redirects=False)
            except Exception:
                continue

            if EVIL_HOST in resp.text and EVIL_HOST not in baseline_text:
                found_vulns.add(("host_reflected", item["desc"]))
                self.add_finding(
                    title=f"Host Header Reflected - {item['desc']}",
                    severity=Severity.HIGH,
                    description=(
                        f"Host header '{host_value}' reflected in response. "
                        f"Enables password reset poisoning, cache poisoning, or phishing."
                    ),
                    recommendation="Validate Host header against an allowlist.",
                    evidence=f"URL: {url}\nInjected Host: {host_value}\nStatus: {resp.status_code}",
                    category="Host Header Injection", url=url, cwe="CWE-644",
                )
                print_finding(Severity.HIGH, f"Host reflected: {item['desc']}")

            location = resp.headers.get("Location", "")
            if EVIL_HOST in location:
                found_vulns.add(("host_redirect", item["desc"]))
                self.add_finding(
                    title=f"Host Header Redirect Poisoning - {item['desc']}",
                    severity=Severity.HIGH,
                    description="Host header injection caused redirect to attacker domain.",
                    recommendation="Never use the Host header for redirect targets.",
                    evidence=f"URL: {url}\nHost: {host_value}\nLocation: {location}",
                    category="Host Header Injection", url=url, cwe="CWE-601",
                )
                print_finding(Severity.HIGH, f"Redirect poisoning: {item['desc']}")

    def _test_override_headers(self, url, baseline_text, baseline_code, found_vulns):
        """Phase 2: X-Forwarded-Host and override headers — one at a time."""
        for header_name, header_value in HOST_OVERRIDE_HEADERS:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)
            try:
                resp = self.http_client.get(
                    url, headers={header_name: header_value}, allow_redirects=False)
            except Exception:
                continue

            if EVIL_HOST in resp.text and EVIL_HOST not in baseline_text:
                found_vulns.add(("override_reflected", header_name))
                self.add_finding(
                    title=f"Header Override Reflected: {header_name}",
                    severity=Severity.HIGH,
                    description=f"{header_name}: {header_value} reflected in response.",
                    recommendation=f"Ignore or validate the {header_name} header.",
                    evidence=f"URL: {url}\nHeader: {header_name}: {header_value}",
                    category="Host Header Injection", url=url, cwe="CWE-644",
                )
                print_finding(Severity.HIGH, f"Override reflected: {header_name}")

            location = resp.headers.get("Location", "")
            if EVIL_HOST in location:
                found_vulns.add(("override_redirect", header_name))
                self.add_finding(
                    title=f"Redirect via {header_name}",
                    severity=Severity.HIGH,
                    description=f"{header_name} caused redirect to attacker domain.",
                    recommendation=f"Do not use {header_name} for URL generation.",
                    evidence=f"URL: {url}\nHeader: {header_name}\nLocation: {location}",
                    category="Host Header Injection", url=url, cwe="CWE-601",
                )

            if "127.0.0.1" in header_value:
                if resp.status_code != baseline_code and resp.status_code in (200, 302):
                    if baseline_code in (403, 401):
                        found_vulns.add(("acl_bypass", header_name))
                        self.add_finding(
                            title=f"IP-Based ACL Bypass via {header_name}",
                            severity=Severity.HIGH,
                            description=f"{header_name}: 127.0.0.1 bypassed access control.",
                            recommendation="Don't trust client IP headers for access control.",
                            evidence=f"Baseline: {baseline_code}, Injected: {resp.status_code}",
                            category="Host Header Injection", url=url, cwe="CWE-290",
                        )
                        print_finding(Severity.HIGH, f"ACL bypass via {header_name}")

    def _test_password_reset_poisoning(self, url, original_host, found_vulns):
        """Phase 3: Password reset endpoints."""
        reset_paths = [
            "/forgot-password", "/password-reset", "/reset-password",
            "/forgot", "/account/recover", "/auth/forgot",
            "/users/password", "/api/auth/forgot-password",
        ]

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in reset_paths:
            reset_url = f"{base}{path}"
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)
            try:
                resp = self.http_client.get(reset_url, allow_redirects=False)
                if resp.status_code == 404:
                    continue

                resp2 = self.http_client.post(
                    reset_url, data={"email": "test@example.com"},
                    headers={"Host": EVIL_HOST}, allow_redirects=False)

                if resp2.status_code in (200, 302) and EVIL_HOST not in resp.text:
                    if EVIL_HOST in resp2.text or EVIL_HOST in resp2.headers.get("Location", ""):
                        found_vulns.add(("reset_poison", path))
                        self.add_finding(
                            title="Password Reset Poisoning",
                            severity=Severity.CRITICAL,
                            description=f"Reset endpoint {path} uses Host header for link generation.",
                            recommendation="Hardcode base URL. Never use Host header for links.",
                            evidence=f"Reset URL: {reset_url}\nHost: {EVIL_HOST}",
                            category="Host Header Injection", url=reset_url, cwe="CWE-640",
                        )
                        print_finding(Severity.CRITICAL, f"Reset poisoning at {path}")
            except Exception:
                continue

    def _test_cache_poisoning(self, url, original_host, baseline_headers, found_vulns):
        """Phase 4: Cache poisoning via X-Forwarded-Host."""
        cache_indicators = [
            "X-Cache", "X-Cache-Hit", "CF-Cache-Status",
            "X-Varnish", "X-Proxy-Cache", "Age", "X-CDN", "X-Edge-Cache",
        ]
        has_cache = any(h.lower() in [k.lower() for k in baseline_headers] for h in cache_indicators)

        if has_cache:
            try:
                resp = self.http_client.get(url, headers={"X-Forwarded-Host": EVIL_HOST})
                if EVIL_HOST in resp.text:
                    found_vulns.add(("cache_poison", "X-Forwarded-Host"))
                    self.add_finding(
                        title="Cache Poisoning via X-Forwarded-Host",
                        severity=Severity.CRITICAL,
                        description="Caching + X-Forwarded-Host reflection = cache poisoning.",
                        recommendation="Don't cache responses that vary by Host-like headers.",
                        evidence=f"URL: {url}\nCache: Yes\nReflected: Yes",
                        category="Cache Poisoning", url=url, cwe="CWE-349",
                    )
                    print_finding(Severity.CRITICAL, "Cache poisoning via X-Forwarded-Host")
            except Exception:
                pass

    def _test_absolute_url(self, url, original_host, baseline_text, found_vulns):
        """Phase 5: Test if forwarded headers influence URL generation."""
        try:
            resp = self.http_client.get(
                url, headers={
                    "Host": original_host,
                    "X-Forwarded-Host": EVIL_HOST,
                    "X-Forwarded-Proto": "https",
                }, allow_redirects=False)

            link_pattern = re.compile(
                rf"(?:href|src|action|url)\s*=\s*[\"'']https?://{re.escape(EVIL_HOST)}",
                re.IGNORECASE,
            )
            if link_pattern.search(resp.text) and not link_pattern.search(baseline_text):
                found_vulns.add(("abs_url", "X-Forwarded-Host"))
                self.add_finding(
                    title="URL Generation Uses Forwarded Headers",
                    severity=Severity.MEDIUM,
                    description="Application generates URLs using X-Forwarded-Host.",
                    recommendation="Use a configured base URL for link generation.",
                    evidence=f"Evil host in links: {EVIL_HOST}\nURL: {url}",
                    category="Host Header Injection", url=url, cwe="CWE-644",
                )
                print_finding(Severity.MEDIUM, "URL generation uses forwarded headers")
        except Exception:
            pass
