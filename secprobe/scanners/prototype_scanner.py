"""
Prototype Pollution Scanner.

Detects JavaScript prototype pollution vulnerabilities:
  - Client-side prototype pollution via URL parameters
  - Server-side prototype pollution via JSON body
  - __proto__ injection in query strings and JSON
  - constructor.prototype manipulation
  - Object.assign merge pollution
  - Lodash/jQuery deep merge exploitation
"""

import re
import json
from urllib.parse import urljoin, urlencode, quote

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# ── Client-side prototype pollution payloads ──────────────────────
CLIENT_PAYLOADS = [
    # Query string __proto__
    ("__proto__[polluted]=true", "Query string __proto__"),
    ("__proto__.polluted=true", "Dot notation __proto__"),
    ("constructor[prototype][polluted]=true", "constructor.prototype"),
    ("constructor.prototype.polluted=true", "constructor.prototype dot"),

    # Hash-based
    ("#__proto__[polluted]=true", "Hash __proto__"),
    ("#constructor[prototype][polluted]=true", "Hash constructor.prototype"),

    # Nested
    ("__proto__[toString]=polluted", "toString override"),
    ("__proto__[valueOf]=polluted", "valueOf override"),
    ("__proto__[hasOwnProperty]=polluted", "hasOwnProperty override"),
]

# ── Server-side prototype pollution payloads ──────────────────────
SERVER_PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"status": 200}},
    {"__proto__": {"toString": "polluted"}},
]

# ── Known vulnerable merge patterns ──────────────────────────────
VULNERABLE_PATTERNS = [
    (r'Object\.assign\s*\(\s*\{\}', "Object.assign merge"),
    (r'_\.merge\s*\(', "Lodash _.merge"),
    (r'_\.extend\s*\(', "Lodash _.extend"),
    (r'_\.defaultsDeep\s*\(', "Lodash _.defaultsDeep"),
    (r'\$\.extend\s*\(\s*true', "jQuery deep extend"),
    (r'deepmerge\s*\(', "deepmerge library"),
    (r'merge\s*\(\s*\{\}', "Generic deep merge"),
    (r'JSON\.parse\s*\(.*?(?:body|params|query|input|data)', "JSON.parse of user input"),
    (r'Object\.create\s*\(\s*null\)', "Safe — Object.create(null)"),  # This is actually safe
]


class PrototypePollutionScanner(SmartScanner):
    name = "Prototype Pollution Scanner"
    description = "Detect client-side and server-side prototype pollution vulnerabilities"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Prototype pollution analysis on {url}", "progress")

        # ── Phase 1: Client-side active testing ───────────────────
        print_status("Phase 1: Client-side prototype pollution testing", "progress")
        self._test_client_side(url)

        # ── Phase 2: Server-side JSON testing ─────────────────────
        print_status("Phase 2: Server-side prototype pollution testing", "progress")
        self._test_server_side(url)

        # ── Phase 3: Static analysis of JavaScript ────────────────
        print_status("Phase 3: Static analysis for vulnerable patterns", "progress")
        self._static_analysis(url)

        # ── Phase 4: URL parameter pollution ──────────────────────
        print_status("Phase 4: URL parameter prototype injection", "progress")
        self._test_url_params(url)

    def _test_client_side(self, url):
        """Test for client-side prototype pollution via URL parameters."""
        try:
            # Get baseline response
            baseline = self.http_client.get(url, timeout=10)
            baseline_length = len(baseline.text)
        except Exception as e:
            self.result.error = str(e)
            return

        for payload, description in CLIENT_PAYLOADS:
            if payload.startswith("#"):
                test_url = f"{url}{payload}"
            else:
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{payload}"

            try:
                resp = self.http_client.get(test_url, timeout=10)

                # Check for signs of pollution
                if resp.status_code == 500:
                    self.add_finding(
                        title=f"Prototype pollution causes server error: {description}",
                        severity=Severity.HIGH,
                        description=(
                            f"Sending prototype pollution payload via {description} "
                            f"caused a 500 Internal Server Error, suggesting the server-side "
                            f"JavaScript is vulnerable to prototype pollution."
                        ),
                        recommendation="Use Object.create(null) for option objects, freeze prototypes, or validate input keys.",
                        evidence=f"URL: {test_url}\nPayload: {payload}\nStatus: 500",
                        category="Prototype Pollution",
                        url=test_url,
                        cwe="CWE-1321",
                    )
                    print_finding(Severity.HIGH, f"Prototype pollution 500: {description}")

                # Check if response differs significantly
                length_diff = abs(len(resp.text) - baseline_length)
                if length_diff > 100 and resp.status_code == 200:
                    # Might have affected rendering
                    if "polluted" in resp.text or "true" in resp.text.lower():
                        self.add_finding(
                            title=f"Possible prototype pollution reflection: {description}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Prototype pollution payload via {description} caused a "
                                f"different response ({length_diff} bytes difference)."
                            ),
                            recommendation="Validate and sanitize all object keys from user input.",
                            evidence=f"URL: {test_url}\nBaseline: {baseline_length} bytes\nPolluted: {len(resp.text)} bytes",
                            category="Prototype Pollution",
                            url=test_url,
                            cwe="CWE-1321",
                        )

            except Exception:
                continue

    def _test_server_side(self, url):
        """Test for server-side prototype pollution via JSON body."""
        # Find API endpoints that accept JSON
        api_endpoints = [url]

        # Check common API paths
        api_paths = [
            "/api/v1/user", "/api/v1/settings", "/api/v1/profile",
            "/api/v2/user", "/api/settings", "/api/profile",
            "/graphql", "/api/data",
        ]

        for path in api_paths:
            test_url = urljoin(url, path)
            api_endpoints.append(test_url)

        for endpoint in api_endpoints[:10]:
            for payload in SERVER_PAYLOADS[:3]:
                try:
                    resp = self.http_client.post(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                    )

                    if resp.status_code == 500:
                        self.add_finding(
                            title=f"Server-side prototype pollution: {endpoint}",
                            severity=Severity.HIGH,
                            description=(
                                f"Sending __proto__ in JSON body to {endpoint} "
                                f"caused a 500 error, indicating prototype pollution."
                            ),
                            recommendation=(
                                "Sanitize JSON input by:\n"
                                "1. Stripping __proto__ and constructor keys\n"
                                "2. Using Object.create(null) for merge targets\n"
                                "3. Freezing Object.prototype\n"
                                "4. Using Map instead of plain objects"
                            ),
                            evidence=f"URL: {endpoint}\nPayload: {json.dumps(payload)}\nStatus: 500",
                            category="Prototype Pollution",
                            url=endpoint,
                            cwe="CWE-1321",
                        )
                        print_finding(Severity.HIGH, f"Server prototype pollution: {endpoint}")
                        break

                    # Check if __proto__ values appear in response
                    if resp.status_code == 200:
                        try:
                            resp_json = resp.json()
                            resp_str = json.dumps(resp_json)
                            if "polluted" in resp_str or '"isAdmin": true' in resp_str:
                                self.add_finding(
                                    title=f"Prototype pollution reflected in API response",
                                    severity=Severity.CRITICAL,
                                    description=f"The __proto__ values were merged into the response object at {endpoint}.",
                                    recommendation="Implement input sanitization to strip prototype keys.",
                                    evidence=f"URL: {endpoint}\nResponse contains polluted values",
                                    category="Prototype Pollution",
                                    url=endpoint,
                                    cwe="CWE-1321",
                                )
                                print_finding(Severity.CRITICAL, f"Proto pollution reflected: {endpoint}")
                                break
                        except Exception:
                            pass

                except Exception:
                    continue

    def _static_analysis(self, url):
        """Analyze JavaScript for vulnerable merge/assign patterns."""
        try:
            resp = self.http_client.get(url, timeout=10)
        except Exception:
            return

        # Collect all JS
        js_sources = {}

        # Inline scripts
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.I | re.S)
        for i, script in enumerate(scripts):
            if script.strip():
                js_sources[f"inline-{i}"] = script

        # External scripts
        src_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)', resp.text, re.I)
        for src in src_tags[:15]:
            full_url = urljoin(url, src)
            try:
                js_resp = self.http_client.get(full_url, timeout=10)
                if js_resp.status_code == 200 and len(js_resp.text) < 2_000_000:
                    js_sources[full_url] = js_resp.text
            except Exception:
                pass

        # Analyze each source
        for source_name, js_code in js_sources.items():
            for pattern, desc in VULNERABLE_PATTERNS:
                if "Safe" in desc:
                    continue  # Skip safe patterns

                matches = list(re.finditer(pattern, js_code, re.I))
                for match in matches[:3]:
                    # Get context
                    start = max(0, match.start() - 100)
                    end = min(len(js_code), match.end() + 100)
                    context = js_code[start:end].strip()

                    # Check if it's processing user input
                    has_user_input = bool(re.search(
                        r'(?:req\.body|req\.query|req\.params|location|window|document|input|data|params)',
                        context, re.I
                    ))

                    if has_user_input:
                        self.add_finding(
                            title=f"Vulnerable merge pattern: {desc}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Found {desc} in {source_name} that may process user input, "
                                f"creating a prototype pollution vector."
                            ),
                            recommendation="Use safe merge functions that skip __proto__ and constructor keys.",
                            evidence=f"Source: {source_name}\nPattern: {desc}\nContext:\n{context[:300]}",
                            category="Prototype Pollution",
                            url=url,
                            cwe="CWE-1321",
                        )
                        print_finding(Severity.MEDIUM, f"Vulnerable pattern: {desc} in {source_name}")

    def _test_url_params(self, url):
        """Test for prototype pollution via URL parameters with various encodings."""
        encodings = [
            # Standard
            ("?__proto__[test]=polluted", "Standard __proto__ bracket"),
            # URL encoded
            ("?__proto__%5Btest%5D=polluted", "URL-encoded brackets"),
            # Double encoded
            ("?__proto__%255Btest%255D=polluted", "Double URL-encoded"),
            # Unicode
            ("?__pro\u200Bto__[test]=polluted", "Zero-width space bypass"),
            # JSON in query
            ('?json={"__proto__":{"test":"polluted"}}', "JSON in query string"),
        ]

        for payload, desc in encodings:
            test_url = f"{url}{payload}"
            try:
                resp = self.http_client.get(test_url, timeout=10)
                if resp.status_code == 500:
                    self.add_finding(
                        title=f"Prototype pollution via {desc}",
                        severity=Severity.HIGH,
                        description=f"Server error triggered by {desc} prototype pollution payload.",
                        recommendation="Sanitize all input keys, especially __proto__ and constructor.",
                        evidence=f"URL: {test_url}\nStatus: 500",
                        category="Prototype Pollution",
                        url=test_url,
                        cwe="CWE-1321",
                    )
                    print_finding(Severity.HIGH, f"Proto pollution: {desc}")
                    break
            except Exception:
                continue
