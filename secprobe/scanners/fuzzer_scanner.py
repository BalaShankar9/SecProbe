"""
Smart Fuzzer Engine.

Mutation-based fuzzing with intelligent payload generation:
  - Boundary value testing (integer overflow, underflow, zero)
  - Format string exploitation (%s, %n, %x)
  - Buffer overflow patterns (long strings, null bytes)
  - Type confusion (string↔int↔array↔object)
  - Unicode abuse (homoglyphs, RTL override, null widths)
  - Encoding variations (double URL, base64, hex, Unicode escapes)
  - Crash detection and anomaly classification
"""

import re
import time
import hashlib
from urllib.parse import urljoin, urlencode, quote

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# ── Fuzz payload categories ───────────────────────────────────────
BOUNDARY_PAYLOADS = [
    ("0", "Zero"),
    ("-1", "Negative one"),
    ("-2147483648", "Int32 min"),
    ("2147483647", "Int32 max"),
    ("4294967295", "Uint32 max"),
    ("9999999999999999999", "Large number"),
    ("1e308", "Float max"),
    ("-1e308", "Float min"),
    ("NaN", "Not a Number"),
    ("Infinity", "Infinity"),
    ("-Infinity", "Negative Infinity"),
    ("null", "Null string"),
    ("undefined", "Undefined string"),
    ("true", "Boolean true"),
    ("false", "Boolean false"),
    ("[]", "Empty array"),
    ("{}", "Empty object"),
    ("0x0", "Hex zero"),
    ("0.0", "Float zero"),
    ("1/0", "Division by zero"),
]

FORMAT_STRING_PAYLOADS = [
    ("%s%s%s%s%s%s%s%s%s%s", "Format string %s"),
    ("%n%n%n%n%n%n%n%n%n%n", "Format string %n (write)"),
    ("%x%x%x%x%x%x%x%x%x%x", "Format string %x (hex dump)"),
    ("%d%d%d%d%d%d%d%d%d%d", "Format string %d"),
    ("%p%p%p%p%p%p%p%p%p%p", "Format string %p (pointer)"),
    ("{0}{1}{2}{3}{4}", "Python format string"),
    ("${7*7}", "Expression injection"),
    ("#{7*7}", "Ruby expression"),
]

OVERFLOW_PAYLOADS = [
    ("A" * 256, "256-byte string"),
    ("A" * 1024, "1KB string"),
    ("A" * 10240, "10KB string"),
    ("A" * 65536, "64KB string"),
    ("\x00" * 16, "Null bytes"),
    ("A" * 100 + "\x00" + "B" * 100, "Null byte in middle"),
    ("%00" * 50, "URL-encoded nulls"),
]

TYPE_CONFUSION_PAYLOADS = [
    ({"toString": "pwned"}, "Object with toString"),
    ({"__proto__": {"polluted": True}}, "Proto pollution"),
    ([1, 2, 3], "Array instead of string"),
    (True, "Boolean instead of string"),
    (None, "None/null"),
    ({"$gt": ""}, "MongoDB operator injection"),
    ({"$regex": ".*"}, "MongoDB regex injection"),
]

UNICODE_PAYLOADS = [
    ("\u200b" * 10 + "admin", "Zero-width space prefix"),
    ("admin\u200b", "Zero-width space suffix"),
    ("\u202e\u0041\u0042\u0043", "RTL override"),
    ("\ufeff" + "test", "BOM prefix"),
    ("ℯ𝓋ⅈ𝓵", "Unicode math symbols"),
    ("аdmin", "Cyrillic 'а' homoglyph"),  # The 'а' is Cyrillic
    ("＜script＞", "Fullwidth angle brackets"),
    ("%c0%ae%c0%ae/etc/passwd", "Overlong UTF-8"),
]


class FuzzerScanner(SmartScanner):
    name = "Smart Fuzzer"
    description = "Mutation-based fuzzing with boundary testing, format strings, type confusion, and Unicode abuse"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Smart fuzzing on {url}", "progress")

        # ── Phase 1: Discover fuzzable parameters ─────────────────
        print_status("Phase 1: Parameter discovery", "progress")
        targets = self._discover_targets(url)
        print_status(f"Found {len(targets)} fuzzable target(s)", "info")

        if not targets:
            self.add_finding(
                title="No fuzzable parameters discovered",
                severity=Severity.INFO,
                description="No URL parameters, form fields, or API endpoints found to fuzz.",
                category="Fuzzing",
            )
            return

        # ── Phase 2: Baseline profiling ───────────────────────────
        print_status("Phase 2: Baseline response profiling", "progress")
        baselines = self._profile_baselines(targets)

        # ── Phase 3: Boundary value fuzzing ───────────────────────
        print_status("Phase 3: Boundary value fuzzing", "progress")
        self._fuzz_category(targets, baselines, BOUNDARY_PAYLOADS, "Boundary", url)

        # ── Phase 4: Format string fuzzing ────────────────────────
        print_status("Phase 4: Format string fuzzing", "progress")
        self._fuzz_category(targets, baselines, FORMAT_STRING_PAYLOADS, "Format String", url)

        # ── Phase 5: Overflow fuzzing ─────────────────────────────
        print_status("Phase 5: Buffer overflow fuzzing", "progress")
        self._fuzz_category(targets, baselines, OVERFLOW_PAYLOADS, "Overflow", url)

        # ── Phase 6: Unicode abuse ────────────────────────────────
        print_status("Phase 6: Unicode abuse fuzzing", "progress")
        self._fuzz_unicode(targets, baselines, url)

        # ── Phase 7: Type confusion (JSON APIs) ──────────────────
        print_status("Phase 7: Type confusion fuzzing", "progress")
        self._fuzz_type_confusion(targets, url)

    def _discover_targets(self, url):
        """Discover parameters and endpoints to fuzz."""
        targets = []

        # URL parameters from the target
        if "?" in url:
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                targets.append({
                    "type": "query",
                    "url": url,
                    "param": param,
                    "original_value": params[param][0],
                })

        # Discover from crawled URLs
        crawled = self.context.get_crawled_urls() if hasattr(self.context, 'get_crawled_urls') else []
        for crawled_url in crawled[:20]:
            if "?" in crawled_url:
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(crawled_url)
                params = parse_qs(parsed.query)
                for param in params:
                    targets.append({
                        "type": "query",
                        "url": crawled_url,
                        "param": param,
                        "original_value": params[param][0],
                    })

        # Discover form parameters from the page
        try:
            resp = self.http_client.get(url, timeout=10)
            forms = re.findall(
                r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](\w+)["\'][^>]*>(.*?)</form>',
                resp.text, re.I | re.S
            )
            for action, method, body in forms:
                form_url = urljoin(url, action) if action else url
                inputs = re.findall(
                    r'<input[^>]+name=["\']([^"\']+)["\'](?:[^>]+value=["\']([^"\']*)["\'])?',
                    body, re.I
                )
                for name, value in inputs:
                    targets.append({
                        "type": "form",
                        "url": form_url,
                        "method": method.upper(),
                        "param": name,
                        "original_value": value or "test",
                    })

            # Search for links with parameters
            links = re.findall(r'href=["\']([^"\']*\?[^"\']+)', resp.text)
            for link in links[:20]:
                full_url = urljoin(url, link)
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(full_url)
                if parsed.hostname and parsed.hostname in url:
                    params = parse_qs(parsed.query)
                    for param in params:
                        targets.append({
                            "type": "query",
                            "url": full_url,
                            "param": param,
                            "original_value": params[param][0],
                        })
        except Exception:
            pass

        # Also fuzz common parameters on the base URL
        common_params = ["q", "search", "id", "page", "name", "user", "input", "data", "value", "file", "path"]
        for param in common_params:
            targets.append({
                "type": "query",
                "url": url,
                "param": param,
                "original_value": "test",
            })

        # Deduplicate
        seen = set()
        unique = []
        for t in targets:
            key = (t["url"], t["param"])
            if key not in seen:
                seen.add(key)
                unique.append(t)

        return unique[:30]  # Limit

    def _profile_baselines(self, targets):
        """Get baseline responses for comparison."""
        baselines = {}
        for target in targets:
            key = (target["url"], target["param"])
            if key in baselines:
                continue

            try:
                if target["type"] == "query":
                    resp = self.http_client.get(target["url"], timeout=10)
                else:
                    resp = self.http_client.post(
                        target["url"],
                        data={target["param"]: target["original_value"]},
                        timeout=10,
                    )
                baselines[key] = {
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "hash": hashlib.md5(resp.text.encode()).hexdigest(),
                    "time": 0,
                }
            except Exception:
                baselines[key] = {"status": 0, "length": 0, "hash": "", "time": 0}

        return baselines

    def _fuzz_category(self, targets, baselines, payloads, category, url):
        """Fuzz targets with a category of payloads."""
        for target in targets[:10]:
            key = (target["url"], target["param"])
            baseline = baselines.get(key, {"status": 200, "length": 0})

            for payload, desc in payloads[:8]:
                if isinstance(payload, (dict, list, bool, type(None))):
                    continue  # Skip non-string payloads for URL/form

                try:
                    start = time.time()
                    if target["type"] == "query":
                        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                        parsed = urlparse(target["url"])
                        params = parse_qs(parsed.query, keep_blank_values=True)
                        params[target["param"]] = [str(payload)]
                        new_query = urlencode(params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        resp = self.http_client.get(test_url, timeout=10)
                    else:
                        resp = self.http_client.post(
                            target["url"],
                            data={target["param"]: str(payload)},
                            timeout=10,
                        )
                    elapsed = time.time() - start

                    # Analyze response
                    anomaly = self._detect_anomaly(resp, elapsed, baseline, payload, desc)
                    if anomaly:
                        self.add_finding(
                            title=f"Fuzz anomaly [{category}]: {target['param']} — {desc}",
                            severity=anomaly["severity"],
                            description=(
                                f"Fuzzing parameter '{target['param']}' with {desc} "
                                f"caused an anomalous response.\n"
                                f"Anomaly: {anomaly['type']}\n"
                                f"Baseline: {baseline['status']} ({baseline['length']} bytes)\n"
                                f"Fuzzed: {resp.status_code} ({len(resp.text)} bytes)\n"
                                f"Response time: {elapsed:.2f}s"
                            ),
                            recommendation=f"Investigate how the application handles {desc} input.",
                            evidence=f"URL: {target['url']}\nParam: {target['param']}\nPayload: {str(payload)[:200]}\nAnomaly: {anomaly['type']}",
                            category="Fuzzing",
                            url=target["url"],
                            cwe=anomaly.get("cwe", "CWE-20"),
                        )
                        print_finding(anomaly["severity"], f"Fuzz [{category}]: {target['param']} {desc}")

                except Exception:
                    continue

    def _fuzz_unicode(self, targets, baselines, url):
        """Fuzz with Unicode abuse payloads."""
        for target in targets[:5]:
            key = (target["url"], target["param"])
            baseline = baselines.get(key, {"status": 200, "length": 0})

            for payload, desc in UNICODE_PAYLOADS:
                try:
                    if target["type"] == "query":
                        test_url = f"{target['url']}{'&' if '?' in target['url'] else '?'}{target['param']}={quote(payload)}"
                        resp = self.http_client.get(test_url, timeout=10)
                    else:
                        resp = self.http_client.post(
                            target["url"],
                            data={target["param"]: payload},
                            timeout=10,
                        )

                    anomaly = self._detect_anomaly(resp, 0, baseline, payload, desc)
                    if anomaly:
                        self.add_finding(
                            title=f"Unicode fuzz anomaly: {target['param']} — {desc}",
                            severity=anomaly["severity"],
                            description=f"Unicode payload '{desc}' caused anomalous response.",
                            recommendation="Normalize and validate Unicode input before processing.",
                            evidence=f"Param: {target['param']}\nPayload type: {desc}\nAnomaly: {anomaly['type']}",
                            category="Fuzzing",
                            url=target["url"],
                            cwe="CWE-176",
                        )
                        print_finding(anomaly["severity"], f"Unicode fuzz: {target['param']} {desc}")

                except Exception:
                    continue

    def _fuzz_type_confusion(self, targets, url):
        """Test API endpoints with type-confused JSON payloads."""
        api_endpoints = [t for t in targets if "api" in t["url"].lower()]
        if not api_endpoints:
            # Try common API paths
            for path in ["/api/v1", "/api/v2", "/api", "/graphql"]:
                api_endpoints.append({
                    "type": "json",
                    "url": urljoin(url, path),
                    "param": "input",
                    "original_value": "test",
                })

        for target in api_endpoints[:5]:
            for payload, desc in TYPE_CONFUSION_PAYLOADS:
                try:
                    resp = self.http_client.post(
                        target["url"],
                        json={target["param"]: payload},
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                    )

                    if resp.status_code == 500:
                        self.add_finding(
                            title=f"Type confusion crash: {target['param']} — {desc}",
                            severity=Severity.HIGH,
                            description=f"Sending {desc} caused a 500 Internal Server Error.",
                            recommendation="Implement strict type validation for all API inputs.",
                            evidence=f"URL: {target['url']}\nPayload type: {desc}\nStatus: 500",
                            category="Fuzzing",
                            url=target["url"],
                            cwe="CWE-843",
                        )
                        print_finding(Severity.HIGH, f"Type confusion: {desc} → 500")

                except Exception:
                    continue

    def _detect_anomaly(self, resp, elapsed, baseline, payload, desc):
        """Detect if a fuzzed response is anomalous compared to baseline."""
        # Server error
        if resp.status_code == 500:
            return {
                "type": "Server Error (500)",
                "severity": Severity.HIGH,
                "cwe": "CWE-20",
            }

        # Significant size difference (more than 3x or less than 1/3)
        if baseline["length"] > 0:
            ratio = len(resp.text) / baseline["length"]
            if ratio > 5 or (ratio < 0.1 and baseline["length"] > 100):
                return {
                    "type": f"Size anomaly ({baseline['length']}→{len(resp.text)} bytes)",
                    "severity": Severity.MEDIUM,
                    "cwe": "CWE-20",
                }

        # Status code change from 200 to error
        if baseline["status"] == 200 and resp.status_code >= 400:
            if resp.status_code not in (403, 404, 405):  # Expected rejection is OK
                return {
                    "type": f"Status change ({baseline['status']}→{resp.status_code})",
                    "severity": Severity.MEDIUM,
                    "cwe": "CWE-20",
                }

        # Error messages in response
        error_patterns = [
            (r'(?:fatal|critical)\s*error', Severity.HIGH, "CWE-209"),
            (r'stack\s*trace', Severity.HIGH, "CWE-209"),
            (r'traceback\s*\(most recent', Severity.HIGH, "CWE-209"),
            (r'exception\s+in\s+thread', Severity.HIGH, "CWE-209"),
            (r'segmentation\s*fault', Severity.CRITICAL, "CWE-787"),
            (r'buffer\s*overflow', Severity.CRITICAL, "CWE-120"),
            (r'out\s*of\s*memory', Severity.HIGH, "CWE-400"),
            (r'divide\s*by\s*zero', Severity.MEDIUM, "CWE-369"),
        ]

        for pattern, severity, cwe in error_patterns:
            if re.search(pattern, resp.text, re.I):
                return {
                    "type": f"Error pattern: {pattern}",
                    "severity": severity,
                    "cwe": cwe,
                }

        # Timeout / slow response
        if elapsed > 10:
            return {
                "type": f"Slow response ({elapsed:.1f}s)",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-400",
            }

        return None
