"""
HTTP Parameter Pollution Scanner — InsertionPoint-based (CWE-235).

Architecture:
  Phase 1: Server-side HPP (duplicate params, array notation, encoded dupes)
  Phase 2: POST form HPP (body param duplication)
  Phase 3: Backend-specific param merging (PHP last-wins, Node first, etc.)
  Phase 4: Encoding-based HPP (semicolons, null bytes, charset tricks)
  Phase 5: WAF bypass via parameter pollution (duplicate to evade filters)
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

from secprobe.config import Severity
from secprobe.core.insertion_points import (
    InsertionPointDiscovery, InsertionType, send_request,
)
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# Backend param handling strategies
BACKEND_STRATEGIES = [
    # (query_template, description, backend)
    ("{name}={safe}&{name}={attack}", "Last-wins (PHP/Apache)", "php"),
    ("{name}={attack}&{name}={safe}", "First-wins (Node.js/Express)", "node"),
    ("{name}={safe},{attack}", "Comma-concat (Apache/CGI)", "apache"),
    ("{name}[]={safe}&{name}[]={attack}", "Array merge (PHP array)", "php_array"),
    ("{name}[0]={safe}&{name}[1]={attack}", "Array index (Rails/Node)", "array_idx"),
    ("{name}={safe}&{name}={attack}",
     "Both-used (ASP.NET concat)", "aspnet"),
]

# Encoding tricks to bypass param parsing
ENCODING_HPP = [
    ("{name}={safe}%26{name}%3D{attack}", "URL-encoded & and ="),
    ("{name}={safe}%00&{name}={attack}", "Null byte separator"),
    ("{name}={safe};{name}={attack}", "Semicolon separator"),
    ("{name}={safe}%3B{name}%3D{attack}", "Encoded semicolon"),
    ("{name}={safe}%23%0a{name}={attack}", "Fragment + newline"),
    ("{name}={safe}&%00{name}={attack}", "Null prefix on key"),
]

# SQLi/XSS payloads that can bypass WAF via HPP splitting
WAF_BYPASS_PAIRS = [
    # Split a SQLi payload across duplicates
    ("SE", "LECT 1", "SQL keyword split"),
    ("' OR '", "1'='1", "SQL boolean split"),
    ("<scr", "ipt>alert(1)</script>", "XSS tag split"),
    ("java", "script:alert(1)", "JS protocol split"),
]


class HPPScanner(SmartScanner):
    name = "HPP Scanner"
    description = "Test for HTTP Parameter Pollution (CWE-235)"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Testing HTTP Parameter Pollution on {url}", "progress")

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
            include_cookies=False,
            include_paths=False,
        )
        points = discovery.discover(url, response=baseline)
        query_points = [p for p in points if p.type == InsertionType.QUERY_PARAM]

        # Also from context
        if self.context:
            for u in self.context.get_injection_urls():
                if u != url:
                    ctx_pts = discovery.discover(u)
                    query_points.extend(
                        pt for pt in ctx_pts
                        if pt.type == InsertionType.QUERY_PARAM
                        and pt.name not in {p.name for p in query_points}
                    )

        if not query_points:
            print_status("No parameterised URLs to test for HPP.", "info")
            self.add_finding(
                title="No HPP targets",
                severity=Severity.INFO,
                description="No parameterised endpoints found for HPP testing.",
                category="Parameter Pollution",
            )
            return

        # ── Phase 1: Server-side HPP per-param ──────────────────────
        self._test_server_side_hpp(url, query_points, baseline_text, found_vulns)

        # ── Phase 2: POST form HPP ──────────────────────────────────
        forms = self.context.get_injectable_forms() if self.context else []
        self._test_form_hpp(url, forms, baseline_text, found_vulns)

        # ── Phase 3: Backend-specific strategies ────────────────────
        self._test_backend_strategies(url, query_points, baseline_text, found_vulns)

        # ── Phase 4: Encoding-based HPP ─────────────────────────────
        self._test_encoding_hpp(url, query_points, baseline_text, found_vulns)

        # ── Phase 5: WAF bypass via param splitting ─────────────────
        self._test_waf_bypass_hpp(url, query_points, baseline_text, found_vulns)

        if not found_vulns:
            self.add_finding(
                title="No HPP detected",
                severity=Severity.INFO,
                description="Automated tests did not detect parameter pollution.",
                category="Parameter Pollution",
            )

    def _test_server_side_hpp(self, url, query_points, baseline_text, found_vulns):
        """Phase 1: Server-side HPP — one param at a time."""
        print_status("Phase 1: Server-side HPP testing", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            spec = point.inject("")
            parsed = urlparse(spec.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            original_value = params.get(point.name, ["test"])[0]

            hpp_payloads = [
                (f"{point.name}={original_value}&{point.name}=SECPROBE_HPP", "Duplicate param"),
                (f"{point.name}[]={original_value}&{point.name}[]=SECPROBE_HPP", "Array notation"),
                (f"{point.name}={original_value}%26{point.name}%3DSECPROBE_HPP", "Encoded duplicate"),
            ]

            for hpp_query, desc in hpp_payloads:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                other_params = {k: v[0] for k, v in params.items() if k != point.name}
                other_query = urlencode(other_params) if other_params else ""
                full_query = f"{other_query}&{hpp_query}" if other_query else hpp_query
                test_url = urlunparse(parsed._replace(query=full_query))

                try:
                    resp = self.http_client.get(test_url, allow_redirects=False)
                except Exception:
                    continue

                if "SECPROBE_HPP" in resp.text and "SECPROBE_HPP" not in baseline_text:
                    found_vulns.add((test_url, point.name))
                    self.add_finding(
                        title=f"Server-side HPP - {point.name} ({desc})",
                        severity=Severity.MEDIUM,
                        description=f"Server uses polluted value via {point.display_name}.",
                        recommendation="Use only the first occurrence of each parameter.",
                        evidence=f"URL: {test_url}\nParam: {point.name}",
                        category="Parameter Pollution", url=test_url, cwe="CWE-235",
                    )
                    print_finding(Severity.MEDIUM, f"HPP: {point.name} ({desc})")
                    break

                size_diff = abs(len(resp.text) - len(baseline_text))
                if size_diff > len(baseline_text) * 0.3 and size_diff > 200:
                    found_vulns.add((test_url, point.name))
                    self.add_finding(
                        title=f"Potential HPP - Response anomaly for '{point.name}'",
                        severity=Severity.LOW,
                        description=f"Duplicate param via {point.display_name} causes significant change.",
                        recommendation="Investigate parameter handling for duplicates.",
                        evidence=f"Baseline: {len(baseline_text)}B, HPP: {len(resp.text)}B",
                        category="Parameter Pollution", url=test_url, cwe="CWE-235",
                    )
                    break

    def _test_form_hpp(self, url, forms, baseline_text, found_vulns):
        """Phase 2: POST form HPP."""
        print_status("Phase 2: POST form HPP", "progress")

        for form in forms:
            action = form.get("action", url)
            fields = form.get("fields", {})

            for param_name in fields:
                if (action, param_name) in found_vulns:
                    continue

                post_data = dict(fields)
                raw_body = "&".join(f"{k}={v}" for k, v in post_data.items())
                raw_body += f"&{param_name}=SECPROBE_HPP"
                try:
                    resp = self.http_client.post(
                        action, data=raw_body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    if "SECPROBE_HPP" in resp.text and "SECPROBE_HPP" not in baseline_text:
                        found_vulns.add((action, param_name))
                        self.add_finding(
                            title=f"POST HPP - {param_name}",
                            severity=Severity.MEDIUM,
                            description=f"POST form parameter pollution in '{param_name}'.",
                            recommendation="Handle duplicate POST parameters correctly.",
                            evidence=f"URL: {action}\nParam: {param_name}",
                            category="Parameter Pollution", url=action, cwe="CWE-235",
                        )
                        break
                except Exception:
                    continue

    def _test_backend_strategies(self, url, query_points, baseline_text, found_vulns):
        """Phase 3: Backend-specific param merging detection."""
        print_status("Phase 3: Backend-specific HPP strategies", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            spec = point.inject("")
            parsed = urlparse(spec.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            original_value = params.get(point.name, ["test"])[0]

            for template, desc, backend in BACKEND_STRATEGIES:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                query_fragment = template.format(
                    name=point.name, safe=original_value, attack="SECPROBE_HPP",
                )
                other_params = {k: v[0] for k, v in params.items() if k != point.name}
                other_query = urlencode(other_params) if other_params else ""
                full_query = f"{other_query}&{query_fragment}" if other_query else query_fragment
                test_url = urlunparse(parsed._replace(query=full_query))

                try:
                    resp = self.http_client.get(test_url, allow_redirects=False)
                except Exception:
                    continue

                if "SECPROBE_HPP" in resp.text and "SECPROBE_HPP" not in baseline_text:
                    found_vulns.add((test_url, point.name))
                    self.add_finding(
                        title=f"HPP via {desc} — '{point.name}'",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Backend uses {backend} param merging strategy.\n"
                            f"Duplicate parameter '{point.name}' processed as "
                            f"attacker-controlled value."
                        ),
                        recommendation=(
                            "Normalize parameter handling. Reject duplicates or "
                            "use only the first occurrence."
                        ),
                        evidence=f"URL: {test_url}\nStrategy: {desc}\nBackend: {backend}",
                        category="Parameter Pollution", url=test_url, cwe="CWE-235",
                    )
                    print_finding(Severity.MEDIUM, f"HPP ({backend}): {point.name}")
                    break

    def _test_encoding_hpp(self, url, query_points, baseline_text, found_vulns):
        """Phase 4: Encoding tricks to bypass parameter parsers."""
        print_status("Phase 4: Encoding-based HPP", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            spec = point.inject("")
            parsed = urlparse(spec.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            original_value = params.get(point.name, ["test"])[0]

            for template, desc in ENCODING_HPP:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                query_fragment = template.format(
                    name=point.name, safe=original_value, attack="SECPROBE_HPP",
                )
                other_params = {k: v[0] for k, v in params.items() if k != point.name}
                other_query = urlencode(other_params) if other_params else ""
                full_query = f"{other_query}&{query_fragment}" if other_query else query_fragment
                test_url = urlunparse(parsed._replace(query=full_query))

                try:
                    resp = self.http_client.get(test_url, allow_redirects=False)
                except Exception:
                    continue

                if "SECPROBE_HPP" in resp.text and "SECPROBE_HPP" not in baseline_text:
                    found_vulns.add((test_url, point.name))
                    self.add_finding(
                        title=f"HPP via encoding bypass — '{point.name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"Parser bypass via {desc} allows parameter injection.\n"
                            f"This indicates the server decodes parameters in a way "
                            f"that can be exploited to override values."
                        ),
                        recommendation=(
                            "Normalise URL-decoded input before parameter parsing. "
                            "Use a single canonical parsing pass."
                        ),
                        evidence=f"URL: {test_url}\nEncoding: {desc}",
                        category="Parameter Pollution", url=test_url, cwe="CWE-235",
                    )
                    print_finding(Severity.HIGH, f"HPP encoding bypass: {point.name}")
                    break

    def _test_waf_bypass_hpp(self, url, query_points, baseline_text, found_vulns):
        """Phase 5: WAF bypass via param splitting — split malicious payload across duplicates."""
        print_status("Phase 5: WAF bypass via HPP splitting", "progress")

        for point in query_points:
            if point.name in {v[1] for v in found_vulns}:
                continue

            spec = point.inject("")
            parsed = urlparse(spec.url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for part1, part2, desc in WAF_BYPASS_PAIRS:
                if self.config.rate_limit:
                    time.sleep(self.config.rate_limit)

                # Send part1 in first param, part2 in duplicate
                query_fragment = f"{point.name}={quote(part1)}&{point.name}={quote(part2)}"
                other_params = {k: v[0] for k, v in params.items() if k != point.name}
                other_query = urlencode(other_params) if other_params else ""
                full_query = f"{other_query}&{query_fragment}" if other_query else query_fragment
                test_url = urlunparse(parsed._replace(query=full_query))

                try:
                    resp = self.http_client.get(test_url, allow_redirects=False)
                except Exception:
                    continue

                full_payload = part1 + part2
                if full_payload.lower() in resp.text.lower() and \
                        full_payload.lower() not in baseline_text.lower():
                    found_vulns.add((test_url, point.name))
                    self.add_finding(
                        title=f"WAF bypass via HPP — {desc}",
                        severity=Severity.HIGH,
                        description=(
                            f"Split payload '{part1}' + '{part2}' is concatenated "
                            f"server-side, bypassing WAF keyword detection.\n"
                            f"Parameter: {point.name}"
                        ),
                        recommendation=(
                            "WAF should inspect concatenated parameter values. "
                            "Application should reject duplicate parameters."
                        ),
                        evidence=f"URL: {test_url}\nSplit: {part1} | {part2}",
                        category="Parameter Pollution", url=test_url, cwe="CWE-235",
                    )
                    print_finding(Severity.HIGH, f"WAF bypass HPP: {desc}")
                    break
