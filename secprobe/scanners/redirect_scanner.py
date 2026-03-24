"""
Open Redirect Scanner — InsertionPoint per-parameter isolation (CWE-601).

Architecture:
  Phase 1: Redirect-likely URL params (full payload set, 30+ bypass variants)
  Phase 2: Other URL params (subset, catch unexpected redirects)
  Phase 3: Protocol-polymorphic / JS-scheme redirects
  Phase 4: Header-based redirect injection (Host, X-Forwarded-Host)
  Phase 5: DOM-based redirect detection (JS/meta patterns in response body)
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


REDIRECT_PARAM_NAMES = [
    "url", "redirect", "redir", "next", "return", "returnto",
    "redirect_uri", "redirect_url", "goto", "target", "dest",
    "destination", "rurl", "return_url", "continue", "forward",
    "out", "view", "login_url", "callback", "path", "to",
    "ref", "referrer", "ret", "r", "u", "link", "jump",
]

REDIRECT_PAYLOADS = [
    ("https://evil.com", "Direct URL"),
    ("//evil.com", "Protocol-relative"),
    ("///evil.com", "Triple-slash"),
    ("/\\evil.com", "Backslash bypass"),
    ("////evil.com", "Quad-slash"),
    ("https://evil.com%00.target.com", "Null byte"),
    ("https://evil.com%0d%0a", "CRLF injection"),
    ("https://target.com@evil.com", "Authority confusion"),
    ("https://evil.com#target.com", "Fragment"),
    ("https://evil.com?.target.com", "Query bypass"),
    ("java%0d%0ascript:alert(1)", "JavaScript protocol"),
    ("data:text/html,<script>alert(1)</script>", "Data URI"),
    ("%2f%2fevil.com", "Double-encoded slashes"),
    ("https:%0a%0d//evil.com", "Newline in scheme"),
    ("http://0x7f000001/", "Hex IP localhost"),
    ("https://evil\u3002com", "Unicode dot"),
    ("htTps://evil.com", "Mixed case scheme"),
    ("https://evil.com/", "Trailing slash"),
]

# Extended bypass payloads for WAF evasion
BYPASS_PAYLOADS = [
    ("/%0d/evil.com", "Encoded CR in path"),
    ("/%09/evil.com", "Tab in path"),
    ("/evil.com%2f%2e%2e", "Double-encoded path traversal"),
    ("//evil%252ecom", "Double-encoded dot"),
    ("https://evil。com", "Fullwidth dot"),
    ("//evil.com%23.target.com", "Encoded fragment"),
    ("//%2Fevil.com", "Encoded slash prefix"),
    ("https://evil.com\\@target.com", "Backslash in auth"),
    ("//evil.com:80", "Port suffix"),
    ("//evil.com:443@target.com", "Port in auth"),
    ("/%5cevil.com", "Encoded backslash"),
    ("//evil.com/%2e%2e/target.com", "Parent traversal"),
]

# Protocol/scheme based redirect payloads
PROTOCOL_PAYLOADS = [
    ("javascript:alert(document.domain)", "javascript: scheme"),
    ("javascript://anything%0aalert(1)", "JS with comment bypass"),
    ("JaVaScRiPt:alert(1)", "Mixed case JS"),
    ("javascript://%0aalert(1)", "JS double-slash"),
    ("vbscript:MsgBox(1)", "vbscript: scheme"),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "Data URI base64"),
    ("data:text/html,<script>alert(1)</script>", "Data URI inline"),
    ("\\x6Aavascript:alert(1)", "Hex escape JS"),
    ("j%0aavascript:alert(1)", "Newline in JS scheme"),
    ("javascript%3aalert(1)", "Encoded colon"),
]

# Headers to test for redirect injection
REDIRECT_HEADERS = [
    ("Host", "evil.com"),
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-For", "evil.com"),
    ("X-Original-URL", "https://evil.com"),
    ("X-Rewrite-URL", "https://evil.com"),
]


class RedirectScanner(SmartScanner):
    name = "Open Redirect Scanner"
    description = "Test for open redirect vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing open redirects on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        target_host = urlparse(url).netloc
        baseline_text = baseline.text
        found_vulns = set()

        # ── Discover insertion points ────────────────────────────────
        discovery = InsertionPointDiscovery(
            include_headers=False,
            include_cookies=False,
            include_paths=False,
        )
        points = discovery.discover(url, response=baseline)
        query_points = [p for p in points if p.type == InsertionType.QUERY_PARAM]

        # Separate redirect-likely vs other params
        redirect_points = [p for p in query_points if p.name.lower() in REDIRECT_PARAM_NAMES]
        other_points = [p for p in query_points if p.name.lower() not in REDIRECT_PARAM_NAMES]

        # If no redirect params found, synthesise common ones
        if not redirect_points:
            for pname in REDIRECT_PARAM_NAMES[:8]:
                test_url = f"{url}{'&' if '?' in url else '?'}{pname}=https://example.com"
                pts = discovery.discover(test_url)
                redirect_points.extend(
                    pt for pt in pts
                    if pt.type == InsertionType.QUERY_PARAM and pt.name == pname
                )

        # Also gather from context
        if self.context:
            for u in self.context.get_injection_urls():
                ctx_pts = discovery.discover(u)
                for p in ctx_pts:
                    if p.type == InsertionType.QUERY_PARAM:
                        if p.name.lower() in REDIRECT_PARAM_NAMES:
                            redirect_points.append(p)
                        elif p not in other_points:
                            other_points.append(p)

        # ── Phase 1: Redirect-likely params (full payload set) ───────
        self._test_redirect_params(redirect_points, target_host, baseline_text, found_vulns)

        # ── Phase 2: Other params (subset) ───────────────────────────
        self._test_other_params(other_points[:5], target_host, baseline_text, found_vulns)

        # ── Phase 3: Protocol-polymorphic redirects ──────────────────
        self._test_protocol_redirects(redirect_points, target_host, baseline_text, found_vulns)

        # ── Phase 4: Header-based redirect injection ─────────────────
        self._test_header_redirects(url, target_host, baseline_text, found_vulns)

        # ── Phase 5: DOM-based redirect detection ────────────────────
        self._test_dom_redirects(redirect_points, target_host, baseline_text, found_vulns)

        if not found_vulns:
            print_status("No open redirect vulnerabilities detected.", "success")
            self.add_finding(
                title="No open redirect detected",
                severity=Severity.INFO,
                description="Automated tests did not detect open redirect vulnerabilities.",
                category="Open Redirect",
            )

    def _test_redirect_params(self, points, target_host, baseline_text, found_vulns):
        """Phase 1: Test redirect-like params — full payload set + bypass variants."""
        print_status("Phase 1: Per-param redirect testing", "progress")

        all_payloads = REDIRECT_PAYLOADS + BYPASS_PAYLOADS
        for point in points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in all_payloads:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                if self._check_redirect(resp, spec, point, payload, desc, target_host, found_vulns):
                    break

    def _test_other_params(self, points, target_host, baseline_text, found_vulns):
        """Phase 2: Test non-redirect params with a small payload subset."""
        for point in points:
            for payload, desc in REDIRECT_PAYLOADS[:4]:
                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if self._is_external_redirect(location, target_host):
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"Open Redirect via '{point.name}' - {desc}",
                            severity=Severity.MEDIUM,
                            description=f"Unexpected redirect param {point.display_name} -> {location}",
                            recommendation="Validate all parameters that influence redirects.",
                            evidence=f"Param: {point.name}\nLocation: {location}",
                            category="Open Redirect", url=spec.url, cwe="CWE-601",
                        )
                        break

    def _test_protocol_redirects(self, points, target_host, baseline_text, found_vulns):
        """Phase 3: Protocol-polymorphic redirect — javascript:, data:, vbscript:."""
        print_status("Phase 3: Protocol-polymorphic redirects", "progress")

        for point in points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in PROTOCOL_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                # Check Location header for JS/data scheme
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    loc_lower = location.lower().strip()
                    if any(loc_lower.startswith(s) for s in ["javascript:", "data:", "vbscript:"]):
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"XSS via redirect ({desc}) — '{point.name}'",
                            severity=Severity.HIGH,
                            description=(
                                f"Server redirects to {desc} scheme via {point.display_name}.\n"
                                f"Payload: {payload}\nLocation: {location[:200]}"
                            ),
                            recommendation="Block javascript:, data:, and vbscript: in redirect targets.",
                            evidence=f"Param: {point.name}\nLocation: {location[:200]}",
                            category="Open Redirect", url=spec.url, cwe="CWE-601",
                        )
                        print_finding(Severity.HIGH, f"Protocol redirect: {desc} via {point.name}")
                        break

                # Check for reflection in body (some apps echo payload into href/src attributes)
                if resp.status_code == 200:
                    body_lower = resp.text[:5000].lower()
                    if payload.lower() in body_lower and payload.lower() not in baseline_text.lower():
                        # Check if it appears in a dangerous context
                        dangerous = re.search(
                            r'(?:href|src|action|formaction)\s*=\s*["\']?' + re.escape(payload[:20].lower()),
                            body_lower,
                        )
                        if dangerous:
                            found_vulns.add((spec.url, point.name))
                            self.add_finding(
                                title=f"Reflected protocol redirect ({desc}) — '{point.name}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"Payload reflected in dangerous HTML context.\n"
                                    f"Scheme: {desc}"
                                ),
                                recommendation="Sanitize URL values before placing in href/src attributes.",
                                evidence=f"Param: {point.name}\nContext: {dangerous.group(0)[:100]}",
                                category="Open Redirect", url=spec.url, cwe="CWE-601",
                            )
                            break

    def _test_header_redirects(self, url, target_host, baseline_text, found_vulns):
        """Phase 4: Header-based redirect injection (Host header override)."""
        print_status("Phase 4: Header-based redirect injection", "progress")

        for header_name, header_val in REDIRECT_HEADERS:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)

            try:
                resp = self.http_client.get(
                    url,
                    headers={header_name: header_val},
                    allow_redirects=False,
                )
            except Exception:
                continue

            # Check if the host header influenced a redirect
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if self._is_external_redirect(location, target_host):
                    found_vulns.add((url, header_name))
                    self.add_finding(
                        title=f"Open Redirect via {header_name} header",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Server uses {header_name} header for redirect target.\n"
                            f"Injected: {header_val}\nLocation: {location}"
                        ),
                        recommendation=(
                            f"Do not trust {header_name} header for redirect generation. "
                            "Use server-configured hostname."
                        ),
                        evidence=f"Header: {header_name}: {header_val}\nLocation: {location}",
                        category="Open Redirect", url=url, cwe="CWE-601",
                    )
                    print_finding(Severity.MEDIUM, f"Redirect via {header_name}")

            # Also check if reflected in body (password reset hosts, etc.)
            if resp.status_code == 200 and header_val in resp.text:
                if header_val not in baseline_text:
                    found_vulns.add((url, header_name))
                    self.add_finding(
                        title=f"Host header injection via {header_name}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"{header_name}: {header_val} reflected in response body.\n"
                            "May enable password reset poisoning or link injection."
                        ),
                        recommendation=f"Ignore untrusted {header_name} header values.",
                        evidence=f"Header: {header_name}\nReflected: {header_val}",
                        category="Open Redirect", url=url, cwe="CWE-601",
                    )

    def _test_dom_redirects(self, points, target_host, baseline_text, found_vulns):
        """Phase 5: DOM-based redirect detection — JS/meta patterns in body."""
        print_status("Phase 5: DOM-based redirect detection", "progress")

        dom_redirect_patterns = [
            (re.compile(r'(window\.location|document\.location|location\.href)\s*=\s*["\'][^"\']*evil\.com', re.I),
             "JavaScript location assignment"),
            (re.compile(r'location\.replace\s*\(\s*["\'][^"\']*evil\.com', re.I),
             "location.replace()"),
            (re.compile(r'location\.assign\s*\(\s*["\'][^"\']*evil\.com', re.I),
             "location.assign()"),
            (re.compile(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=\s*[^"\']*evil\.com', re.I),
             "Meta refresh redirect"),
            (re.compile(r'window\.open\s*\(\s*["\'][^"\']*evil\.com', re.I),
             "window.open()"),
        ]

        for point in points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            # Test with evil.com payloads that don't trigger 3xx
            dom_payloads = [
                ("https://evil.com", "Direct URL"),
                ("//evil.com", "Protocol-relative"),
                ("https://evil.com#", "Fragment terminator"),
            ]
            for payload, desc in dom_payloads:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                if resp.status_code == 200:
                    body = resp.text[:10000]
                    for pattern, redir_type in dom_redirect_patterns:
                        if pattern.search(body) and not pattern.search(baseline_text[:10000]):
                            found_vulns.add((spec.url, point.name))
                            self.add_finding(
                                title=f"DOM-based redirect ({redir_type}) via '{point.name}'",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Client-side redirect detected via {point.display_name}.\n"
                                    f"Pattern: {redir_type}\nPayload: {payload}"
                                ),
                                recommendation=(
                                    "Validate redirect targets on the client side. "
                                    "Use allowlists for redirect destinations."
                                ),
                                evidence=f"Param: {point.name}\nType: {redir_type}",
                                category="Open Redirect", url=spec.url, cwe="CWE-601",
                            )
                            print_finding(Severity.MEDIUM, f"DOM redirect: {redir_type}")
                            break
                    else:
                        continue
                    break

    def _check_redirect(self, resp, spec, point, payload, desc, target_host, found_vulns):
        """Unified redirect check for Location header + JS/meta."""
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if self._is_external_redirect(location, target_host):
                found_vulns.add((spec.url, point.name))
                self.add_finding(
                    title=f"Open Redirect via '{point.name}' - {desc}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Server redirects to attacker URL via {point.display_name}.\n"
                        f"Payload: {payload}\nLocation: {location}"
                    ),
                    recommendation="Validate redirect targets against a whitelist.",
                    evidence=f"Param: {point.name}\nLocation: {location}\nStatus: {resp.status_code}",
                    category="Open Redirect", url=spec.url, cwe="CWE-601",
                )
                print_finding(Severity.MEDIUM, f"Redirect: {desc} via {point.name}")
                return True
        return False

    def _is_external_redirect(self, location, target_host):
        if not location:
            return False
        if location.startswith("//"):
            loc_host = location.lstrip("/").split("/")[0].split("?")[0].split("#")[0]
            return loc_host and loc_host != target_host
        try:
            parsed = urlparse(location)
            if parsed.netloc and parsed.netloc != target_host:
                return True
        except Exception:
            pass
        return False
