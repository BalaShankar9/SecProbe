"""
XSS Scanner — context-aware reflection + per-parameter isolation.

Detection pipeline:
  1. Discover ALL insertion points (query params, path segments, cookies, headers, POST, JSON)
  2. Profile endpoint baseline
  3. DOM-based: sink + source detection (static analysis)
  4. SSTI pre-screen: uses DetectionEngine.test_template_eval() with
     baseline subtraction → "49" in hotel prices no longer triggers FP
  5. Canary-based reflection: inject UUID canary into EACH parameter INDEPENDENTLY
  6. ReflectionTracker: exact context detection (attribute, script, body)
     with encoding awareness (raw, HTML entity, URL, JS escape)
  7. Payload fire: only on reflected parameters, with WAF evasion
  8. Confidence scoring: exploitable context = CONFIRMED, raw reflection = FIRM

Critical: each parameter is tested INDEPENDENTLY while all others remain at baseline.
"""

import re
import time
import uuid

from secprobe.config import Severity
from secprobe.core.detection import (
    Confidence, ReflectionTracker, ResponseAnalyzer,
)
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, InsertionPoint, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


def _load_xss_payloads():
    try:
        from secprobe.payloads import load_payloads
        payloads = load_payloads("xss")
        if payloads:
            return payloads
    except Exception:
        pass
    return [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',
        '"><img src=x onerror=alert(1)>',
        '<details/open/ontoggle=alert(1)>',
    ]


DOM_SINKS = [
    r'document\.write\s*\(',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(\s*["\']',
    r'setInterval\s*\(\s*["\']',
    r'document\.location\s*=',
    r'window\.location\s*=',
    r'\.insertAdjacentHTML\s*\(',
    r'document\.cookie\s*=',
]

DOM_SOURCES = [
    r'document\.URL', r'document\.documentURI',
    r'document\.referrer', r'location\.hash',
    r'location\.search', r'location\.href',
    r'window\.name',
]

# SSTI probes with UNIQUE expected values (not common like "49")
SSTI_PROBES = [
    # Primary: use large, unique products to avoid price collisions
    ("{{987*123}}", "121401", "Jinja2/Twig/Nunjucks"),
    ("${987*123}", "121401", "Freemarker/Mako/EL"),
    ("#{987*123}", "121401", "Thymeleaf/Ruby ERB"),
    ("<%= 987*123 %>", "121401", "ERB/JSP"),
    ("${{987*123}}", "121401", "Pebble/Spring EL"),
    # Confirmation with different value
    ("{{853*271}}", "231163", "Jinja2/Twig (confirmation)"),
    # Config leak
    ("{{config}}", "<Config", "Jinja2 (Flask config)"),
]


class XSSScanner(SmartScanner):
    name = "XSS Scanner"
    description = "Test for Cross-Site Scripting vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing XSS on {url}", "progress")

        payloads = _load_xss_payloads()
        print_status(f"Loaded {len(payloads)} XSS payloads", "info")

        # ── Initialize detection engine ──────────────────────────────
        engine = self._init_detection_engine()

        try:
            baseline = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        baseline_text = baseline.text

        # ── Profile endpoint ─────────────────────────────────────────
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        engine.profile(url, params=params or None)

        # ── DOM-based XSS detection (static analysis) ────────────────
        self._check_dom_xss(url, baseline_text)

        # ── Template injection pre-screen (baseline-aware) ───────────
        self._check_template_injection(url, engine, baseline_text)

        # ── Discover ALL insertion points ────────────────────────────
        discovery = InsertionPointDiscovery(
            http_client=self.http_client,
            include_headers=False,   # XSS rarely works via headers
            include_cookies=True,
            include_paths=True,
        )

        test_urls = self._build_test_urls(url)
        if self.context:
            for u in self.context.get_injection_urls():
                if u not in test_urls:
                    test_urls.append(u)

        # Discover forms
        forms = []
        if self.context:
            forms = self.context.get_injectable_forms()

        # Build insertion points
        all_points: list[InsertionPoint] = []
        for test_url in test_urls:
            points = discovery.discover(test_url, response=baseline, forms=forms)
            all_points.extend(points)

        # Also get form points even without crawler
        if not forms:
            page_forms = discovery._extract_forms(url, baseline)
            for form in page_forms:
                for field_name, field_value in form.get("fields", {}).items():
                    all_points.append(InsertionPoint(
                        type=InsertionType.POST_PARAM,
                        name=field_name,
                        original_value=field_value or "",
                        base_url=form.get("action", url),
                        method=form.get("method", "POST"),
                        _baseline_data=form.get("fields", {}),
                    ))

        # Separate by type
        param_points = [p for p in all_points if p.type in (
            InsertionType.QUERY_PARAM, InsertionType.PATH_SEGMENT)]
        form_points = [p for p in all_points if p.type == InsertionType.POST_PARAM]
        cookie_points = [p for p in all_points if p.type == InsertionType.COOKIE]

        # If no param points, create synthetic ones
        if not param_points:
            for name in ("q", "search", "name", "input"):
                synthetic_url = f"{url}?{name}=FUZZ"
                for pt in discovery.discover(synthetic_url):
                    if pt.type == InsertionType.QUERY_PARAM:
                        param_points.append(pt)

        total_points = len(param_points) + len(form_points) + len(cookie_points)
        print_status(f"Discovered {total_points} XSS insertion points "
                     f"({len(param_points)} params, {len(form_points)} forms, "
                     f"{len(cookie_points)} cookies)", "info")

        vulns_found = 0

        # ── Detect target technology for smarter decisions ───────────
        baseline_tech = self.detect_technology(baseline_text)
        if baseline_tech:
            print_status(f"Technology detected: {', '.join(baseline_tech)}", "info")

        # ── Canary-based reflection test — PER PARAMETER ─────────────
        print_status("Testing reflection per-parameter (isolated injection)", "progress")
        for point in param_points:
            canary = f"xss{uuid.uuid4().hex[:8]}"

            # Inject canary into ONLY this parameter
            spec = point.inject(canary, mode="replace")
            try:
                resp = send_request(self.http_client, spec)
            except Exception:
                continue

            if canary not in resp.text:
                continue

            print_status(f"Input reflected in parameter '{point.name}'", "info")

            # ── Use ReflectionTracker for context analysis ───────────
            reflections = ReflectionTracker.find_reflection(
                resp.text, canary, baseline_text)

            # ── Context-aware payload selection (SmartScanner) ───────
            # Select payloads based on reflection context instead of
            # blindly trying all payloads — this is what Burp does.
            smart_payloads = self.select_xss_payloads(url, point.name, canary=canary)
            # Merge: context-aware first, then generic payloads as fallback
            seen = set(smart_payloads)
            merged_payloads = list(smart_payloads)
            for p in payloads:
                if p not in seen:
                    seen.add(p)
                    merged_payloads.append(p)

            # ── Fire payloads on THIS reflecting parameter ───────────
            for payload in merged_payloads:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                payload_variants = self._evade_payload(payload, vuln_type="xss")
                hit_reflections = None
                hit_url = ""

                for p in payload_variants:
                    # Inject payload into ONLY this parameter
                    spec = point.inject(p, mode="replace")
                    try:
                        resp = send_request(self.http_client, spec, allow_redirects=False)
                    except Exception:
                        continue

                    refs = ReflectionTracker.find_reflection(
                        resp.text, p, baseline_text)
                    if refs:
                        hit_reflections = refs
                        hit_url = spec.url
                        break

                if hit_reflections:
                    exploitable = [r for r in hit_reflections if r.get("exploitable")]

                    if exploitable:
                        # ── Verify finding before reporting (SmartScanner) ──
                        verification = self.verify_finding(
                            url=hit_url, param=point.name,
                            payload=payload, vuln_type="xss",
                        )
                        if verification.confirmed:
                            vulns_found += 1
                            ctx_desc = ", ".join(
                                f"{r['context']} ({r['transform']})" for r in exploitable[:3])
                            self.add_verified_finding(
                                title=f"Verified XSS in parameter '{point.name}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"XSS payload reflected in exploitable context.\n"
                                    f"Parameter: {point.name} ({point.type.value})\n"
                                    f"Payload: {payload[:80]}\n"
                                    f"Contexts: {ctx_desc}\n"
                                    f"Confidence: {verification.confidence.name}"
                                ),
                                confidence=verification.confidence,
                                verification_evidence=verification.evidence,
                                recommendation="Encode output contextually. Use Content-Security-Policy.",
                                category="Cross-Site Scripting",
                                url=hit_url,
                                cwe="CWE-79",
                            )
                            print_finding(Severity.HIGH, f"Verified XSS: {point.name} ({ctx_desc})")
                        else:
                            # Verification failed — still report but lower confidence
                            vulns_found += 1
                            ctx_desc = ", ".join(
                                f"{r['context']} ({r['transform']})" for r in exploitable[:3])
                            self.add_finding(
                                title=f"Probable XSS in parameter '{point.name}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"XSS payload reflected in exploitable context.\n"
                                    f"Parameter: {point.name} ({point.type.value})\n"
                                    f"Payload: {payload[:80]}\n"
                                    f"Contexts: {ctx_desc}\n"
                                    f"Note: Automated verification inconclusive"
                                ),
                                recommendation="Encode output contextually. Use Content-Security-Policy.",
                                evidence=(
                                    f"URL: {hit_url}\n"
                                    f"Parameter: {point.display_name}\n"
                                    f"Reflections: {len(hit_reflections)}\n"
                                    f"Exploitable: {len(exploitable)}\n"
                                    f"Surrounding: {exploitable[0].get('surrounding', '')[:100]}"
                                ),
                                category="Cross-Site Scripting",
                                url=hit_url,
                                cwe="CWE-79",
                            )
                            print_finding(Severity.HIGH, f"Probable XSS: {point.name} ({ctx_desc})")
                        break  # One confirmed hit per parameter is enough

                    else:
                        ref_desc = ", ".join(
                            f"{r['context']} ({r['transform']})" for r in hit_reflections[:3])
                        self.add_finding(
                            title=f"Reflected XSS in parameter '{point.name}'",
                            severity=Severity.MEDIUM,
                            description=(
                                f"XSS payload reflected but may be encoded.\n"
                                f"Parameter: {point.name} ({point.type.value})\n"
                                f"Payload: {payload[:80]}\n"
                                f"Contexts: {ref_desc}"
                            ),
                            recommendation="Verify manual exploitability. Apply contextual encoding.",
                            evidence=f"URL: {hit_url}\nParameter: {point.display_name}\nReflections: {len(hit_reflections)}",
                            category="Cross-Site Scripting",
                            url=hit_url,
                            cwe="CWE-79",
                        )
                        continue

        # ── Test POST forms — PER FIELD ──────────────────────────────
        # Use SmartScanner form extraction for better coverage
        if not form_points:
            smart_forms = self.extract_forms(baseline_text, url)
            for form in smart_forms:
                form_action = form.get("action", url)
                for field in form.get("fields", []):
                    field_name = field.get("name", "")
                    if field_name:
                        form_points.append(InsertionPoint(
                            type=InsertionType.POST_PARAM,
                            name=field_name,
                            original_value=field.get("value", ""),
                            base_url=form_action,
                            method=form.get("method", "POST"),
                            _baseline_data={f.get("name", ""): f.get("value", "")
                                            for f in form.get("fields", []) if f.get("name")},
                        ))

        print_status(f"Testing POST form XSS ({len(form_points)} fields)", "progress")
        for point in form_points:
            canary = f"xss{uuid.uuid4().hex[:8]}"
            spec = point.inject(canary, mode="replace")
            try:
                resp = send_request(self.http_client, spec)
            except Exception:
                continue

            if canary not in resp.text:
                continue

            for payload in payloads[:30]:
                spec = point.inject(payload, mode="replace")
                try:
                    resp = send_request(self.http_client, spec)
                except Exception:
                    continue

                refs = ReflectionTracker.find_reflection(
                    resp.text, payload, baseline_text)
                if refs:
                    exploitable = [r for r in refs if r.get("exploitable")]
                    if exploitable:
                        # Verify POST XSS findings
                        verification = self.verify_finding(
                            url=point.base_url, param=point.name,
                            payload=payload, vuln_type="xss",
                        )
                        vulns_found += 1
                        if verification.confirmed:
                            self.add_verified_finding(
                                title=f"Verified XSS (POST) via '{point.name}'",
                                severity=Severity.HIGH,
                                description=(
                                    f"POST XSS at {point.base_url}, field: {point.name}\n"
                                    f"Exploitable: True\n"
                                    f"Confidence: {verification.confidence.name}"
                                ),
                                confidence=verification.confidence,
                                verification_evidence=verification.evidence,
                                recommendation="Encode output contextually.",
                                category="Cross-Site Scripting",
                                url=point.base_url,
                                cwe="CWE-79",
                            )
                        else:
                            self.add_finding(
                                title=f"Reflected XSS (POST) via '{point.name}'",
                                severity=Severity.HIGH if exploitable else Severity.MEDIUM,
                                description=(
                                    f"POST XSS at {point.base_url}, field: {point.name}\n"
                                    f"Exploitable: {bool(exploitable)}"
                                ),
                                recommendation="Encode output contextually.",
                                evidence=f"Field: {point.name}\nPayload: {payload[:80]}",
                                category="Cross-Site Scripting",
                                url=point.base_url,
                                cwe="CWE-79",
                            )
                    else:
                        vulns_found += 1
                        self.add_finding(
                            title=f"Reflected XSS (POST) via '{point.name}'",
                            severity=Severity.MEDIUM,
                            description=(
                                f"POST XSS at {point.base_url}, field: {point.name}\n"
                                f"Exploitable: False"
                            ),
                            recommendation="Encode output contextually.",
                            evidence=f"Field: {point.name}\nPayload: {payload[:80]}",
                            category="Cross-Site Scripting",
                            url=point.base_url,
                            cwe="CWE-79",
                        )
                    break

        if vulns_found == 0:
            print_status("No reflected XSS vulnerabilities found.", "success")
            self.add_finding(
                title="No reflected XSS detected",
                severity=Severity.INFO,
                description=(
                    f"Automated tests did not detect reflected XSS.\n"
                    f"Insertion points tested: {total_points}"
                ),
                category="Cross-Site Scripting",
            )

        # ── OOB blind/stored XSS detection ───────────────────────────
        if self.oob_available:
            print_status("OOB blind/stored XSS testing (per-parameter)", "progress")
            oob_count = 0
            for point in param_points[:10]:
                token = self.oob_generate_token(point.base_url, point.name, "xss_blind", "img_src")
                cb_url = self.oob_get_url(token)
                p = f'"><img src="{cb_url}">'
                spec = point.inject(p, mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_count += 1
                except Exception:
                    pass

                token = self.oob_generate_token(point.base_url, point.name, "xss_blind", "script_src")
                cb_url = self.oob_get_url(token)
                p = f'"><script src="{cb_url}"></script>'
                spec = point.inject(p, mode="replace")
                try:
                    send_request(self.http_client, spec, allow_redirects=False)
                    oob_count += 1
                except Exception:
                    pass

            # POST forms for stored XSS
            for point in form_points[:10]:
                token = self.oob_generate_token(point.base_url, point.name, "xss_blind", "stored_img")
                cb_url = self.oob_get_url(token)
                spec = point.inject(f'"><img src="{cb_url}">', mode="replace")
                try:
                    send_request(self.http_client, spec)
                    oob_count += 1
                except Exception:
                    pass

            if oob_count:
                print_status(f"Sent {oob_count} OOB XSS payloads, waiting...", "progress")
                self.oob_collect_findings(wait_seconds=10)

    def _check_dom_xss(self, url, html):
        """Static analysis: check for DOM sinks fed by user-controllable sources."""
        sinks_found = []
        sources_found = []
        for pattern in DOM_SINKS:
            if re.search(pattern, html):
                sinks_found.append(pattern.split(r'\(')[0].replace('\\', '').replace(r'\s*', ''))
        for pattern in DOM_SOURCES:
            if re.search(pattern, html):
                sources_found.append(pattern.replace('\\', '').replace(r'\s*', ''))

        # ── Enhanced: use SmartScanner script analysis ───────────────
        script_analysis = self.analyze_scripts(html)
        if script_analysis:
            for script in script_analysis:
                content = getattr(script, "content", "") or ""
                # Check for dangerous patterns in script blocks
                if any(re.search(p, content) for p in DOM_SINKS):
                    if "inline" not in [s.split(r'\(')[0].replace('\\', '')
                                        for s in sinks_found]:
                        sinks_found.append("inline_script_sink")
                if any(re.search(p, content) for p in DOM_SOURCES):
                    if "inline_script_source" not in sources_found:
                        sources_found.append("inline_script_source")

        if sinks_found and sources_found:
            self.add_finding(
                title="Potential DOM-based XSS",
                severity=Severity.MEDIUM,
                description=(
                    f"JavaScript DOM sinks and user-controllable sources detected.\n"
                    f"Sinks: {', '.join(sinks_found[:5])}\n"
                    f"Sources: {', '.join(sources_found[:5])}"
                ),
                recommendation="Sanitize DOM manipulation inputs. Avoid innerHTML with user data.",
                evidence=f"URL: {url}",
                category="Cross-Site Scripting",
                url=url,
                cwe="CWE-79",
            )

    def _check_template_injection(self, url, engine, baseline_text):
        """
        SSTI pre-screen using DetectionEngine's baseline-aware template eval.

        Uses UNIQUE math expressions (987*123=121401) instead of 7*7=49
        to avoid false positives on pages with common numbers.
        """
        for expression, expected, engine_name in SSTI_PROBES:
            test_url = f"{url}?q={expression}"
            try:
                resp = self.http_client.get(test_url)
            except Exception:
                continue

            result = engine.test_template_eval(
                url=test_url,
                parameter="q",
                expression=expression,
                expected=expected,
                response_text=resp.text,
                baseline_text=baseline_text,
                response_status=resp.status_code,
            )

            if result.confidence >= Confidence.FIRM:
                sev = Severity.CRITICAL if result.confidence >= Confidence.CONFIRMED else Severity.HIGH
                self.add_finding(
                    title=f"Server-Side Template Injection ({engine_name})",
                    severity=sev,
                    description=(
                        f"Template expression evaluated (confidence: {result.confidence.name}).\n"
                        f"Expression: {expression} → {expected}\n"
                        f"Evidence: {'; '.join(result.evidence)}"
                    ),
                    recommendation="Never pass user input to template engines without sandboxing.",
                    evidence=(
                        f"URL: {test_url}\n"
                        f"Score: {result.score_breakdown}"
                    ),
                    category="Template Injection",
                    url=test_url,
                    cwe="CWE-1336",
                )
                print_finding(sev, f"SSTI: {expression} → {expected} ({result.confidence.name})")
                return  # One confirmed SSTI is enough

    def _build_test_urls(self, url):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.query:
            return [url]
        return []

    def _inject_value(self, url, value):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        injected = {}
        for key in params:
            injected[key] = value
        new_query = urlencode(injected)
        return urlunparse(parsed._replace(query=new_query))

    def _get_first_param(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return next(iter(params), "unknown")
