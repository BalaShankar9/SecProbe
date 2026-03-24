"""
DOM-based XSS Scanner.

Tracks taint flow from user-controlled sources to dangerous sinks in JavaScript:
  - Sources: location.hash, location.search, document.URL, document.referrer,
             window.name, postMessage data, localStorage, sessionStorage
  - Sinks: innerHTML, outerHTML, document.write, eval(), setTimeout(),
            setInterval(), Function(), $.html(), v-html, dangerouslySetInnerHTML
  - Intermediate: string concatenation, template literals, JSON.parse
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs, quote

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# ── DOM XSS Sources (user-controlled input) ──────────────────────
DOM_SOURCES = [
    ("location.hash", r'location\.hash', "URL fragment"),
    ("location.search", r'location\.search', "URL query string"),
    ("location.href", r'location\.href', "Full URL"),
    ("document.URL", r'document\.URL', "Document URL"),
    ("document.documentURI", r'document\.documentURI', "Document URI"),
    ("document.referrer", r'document\.referrer', "Referrer header"),
    ("document.cookie", r'document\.cookie', "Cookies"),
    ("window.name", r'window\.name', "Window name"),
    ("window.location", r'window\.location(?!\.(?:replace|assign|reload))', "Window location"),
    ("postMessage", r'addEventListener\s*\(\s*["\']message["\']', "postMessage listener"),
    ("URLSearchParams", r'URLSearchParams\s*\(', "URL parameters"),
    ("localStorage.getItem", r'localStorage\.getItem\s*\(', "Local storage"),
    ("sessionStorage.getItem", r'sessionStorage\.getItem\s*\(', "Session storage"),
    ("history.pushState", r'history\.(?:push|replace)State', "History API"),
]

# ── DOM XSS Sinks (dangerous output) ─────────────────────────────
DOM_SINKS = [
    ("innerHTML", r'\.innerHTML\s*[+]?=', "Direct HTML injection", Severity.HIGH),
    ("outerHTML", r'\.outerHTML\s*[+]?=', "Direct HTML injection", Severity.HIGH),
    ("document.write", r'document\.write(?:ln)?\s*\(', "Document write injection", Severity.HIGH),
    ("eval()", r'eval\s*\(', "JavaScript code execution", Severity.CRITICAL),
    ("setTimeout(string)", r'setTimeout\s*\(\s*["\']', "Delayed code execution", Severity.HIGH),
    ("setInterval(string)", r'setInterval\s*\(\s*["\']', "Repeated code execution", Severity.HIGH),
    ("Function()", r'new\s+Function\s*\(', "Dynamic function creation", Severity.CRITICAL),
    ("$.html()", r'\.\s*html\s*\(\s*[^)]*(?:location|document|window|url|hash|search|param)', "jQuery HTML injection", Severity.HIGH),
    ("$.append()", r'\.\s*append\s*\(\s*[^)]*(?:location|document|window|url|hash|search)', "jQuery append injection", Severity.HIGH),
    ("v-html", r'v-html\s*=', "Vue.js HTML binding", Severity.MEDIUM),
    ("dangerouslySetInnerHTML", r'dangerouslySetInnerHTML', "React HTML injection", Severity.MEDIUM),
    ("[href]=", r'\[href\]\s*=\s*[^"\']*(?:location|document|window)', "Angular href binding", Severity.MEDIUM),
    ("insertAdjacentHTML", r'insertAdjacentHTML\s*\(', "Adjacent HTML injection", Severity.HIGH),
    ("document.domain", r'document\.domain\s*=', "Domain relaxation", Severity.HIGH),
    ("location.assign", r'location\.(?:assign|replace)\s*\(', "Open redirect sink", Severity.MEDIUM),
    ("src/href assignment", r'\.(?:src|href|action)\s*=\s*[^"\']*(?:location|document|window|url|hash|search)', "Attribute injection", Severity.HIGH),
]

# ── DOM XSS canary payloads for active testing ────────────────────
DOM_XSS_PAYLOADS = [
    # Hash-based
    "#<img src=x onerror=alert(1)>",
    "#\"><img src=x onerror=alert(1)>",
    "#javascript:alert(1)",
    "#'-alert(1)-'",

    # Search-based
    "?q=<img src=x onerror=alert(1)>",
    "?search=\"><script>alert(1)</script>",
    "?redirect=javascript:alert(1)",
    "?url=data:text/html,<script>alert(1)</script>",
    "?callback=alert",

    # Template literal injection
    "?name=${alert(1)}",
    "?input={{constructor.constructor('alert(1)')()}}",
]


class DOMXSSScanner(SmartScanner):
    name = "DOM XSS Scanner"
    description = "Detect DOM-based cross-site scripting via source-to-sink analysis"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"DOM XSS analysis on {url}", "progress")

        try:
            resp = self.http_client.get(url)
        except Exception as e:
            self.result.error = str(e)
            return

        # ── Phase 1: Collect all JavaScript ───────────────────────
        print_status("Phase 1: JavaScript collection", "progress")
        js_sources = self._collect_js(url, resp.text)
        print_status(f"Collected {len(js_sources)} JavaScript source(s)", "info")

        # ── Phase 2: Static taint analysis ────────────────────────
        print_status("Phase 2: Static source→sink analysis", "progress")
        taint_count = 0
        for source_name, js_code in js_sources.items():
            taint_count += self._analyze_taint(source_name, js_code, url)

        # ── Phase 3: Active DOM XSS testing ───────────────────────
        print_status("Phase 3: Active DOM XSS probing", "progress")
        self._active_probe(url)

        # ── Phase 4: Framework-specific checks ────────────────────
        print_status("Phase 4: Framework-specific DOM XSS checks", "progress")
        self._check_frameworks(resp.text, url)

        # ── Phase 5: PostMessage analysis ─────────────────────────
        print_status("Phase 5: postMessage security analysis", "progress")
        for source_name, js_code in js_sources.items():
            self._check_postmessage(js_code, source_name, url)

        print_status(f"DOM XSS analysis complete: {taint_count} taint flow(s) found", "info")

    def _collect_js(self, url, html):
        """Collect all JavaScript from inline scripts and external files."""
        js_sources = {}

        # Inline scripts
        inline_scripts = re.findall(
            r'<script(?:\s[^>]*)?>([^<]+)</script>',
            html, re.I | re.S,
        )
        for i, script in enumerate(inline_scripts):
            if script.strip():
                js_sources[f"inline-{i}"] = script

        # External scripts
        src_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)
        for src in src_tags[:30]:  # Limit to 30 files
            full_url = urljoin(url, src)
            try:
                resp = self.http_client.get(full_url, timeout=10)
                if resp.status_code == 200 and len(resp.text) < 2_000_000:
                    js_sources[full_url] = resp.text
            except Exception:
                pass

        return js_sources

    def _analyze_taint(self, source_name, js_code, url):
        """Analyze JavaScript for source→sink taint flows."""
        found_sources = []
        found_sinks = []

        # Find sources
        for src_name, src_pattern, src_desc in DOM_SOURCES:
            matches = list(re.finditer(src_pattern, js_code))
            if matches:
                found_sources.append((src_name, src_desc, matches))

        # Find sinks
        for sink_name, sink_pattern, sink_desc, sink_sev in DOM_SINKS:
            matches = list(re.finditer(sink_pattern, js_code))
            if matches:
                found_sinks.append((sink_name, sink_desc, sink_sev, matches))

        # Report source→sink combinations where they appear in proximity
        taint_count = 0
        for src_name, src_desc, src_matches in found_sources:
            for sink_name, sink_desc, sink_sev, sink_matches in found_sinks:
                # Check if source and sink appear within 500 chars of each other
                for src_match in src_matches:
                    for sink_match in sink_matches:
                        distance = abs(sink_match.start() - src_match.start())
                        if distance < 500:
                            # Extract context
                            start = max(0, min(src_match.start(), sink_match.start()) - 50)
                            end = min(len(js_code), max(src_match.end(), sink_match.end()) + 50)
                            context = js_code[start:end].strip()

                            # Check if there's sanitization between them
                            between_start = min(src_match.end(), sink_match.start())
                            between_end = max(src_match.start(), sink_match.end())
                            between = js_code[between_start:between_end]
                            sanitized = self._has_sanitization(between)

                            if sanitized:
                                severity = Severity.LOW
                            else:
                                severity = sink_sev

                            self.add_finding(
                                title=f"DOM XSS: {src_name} → {sink_name}" + (" (sanitized?)" if sanitized else ""),
                                severity=severity,
                                description=(
                                    f"Potential DOM-based XSS found in {source_name}.\n"
                                    f"Source: {src_name} ({src_desc})\n"
                                    f"Sink: {sink_name} ({sink_desc})\n"
                                    f"Distance: {distance} characters apart\n"
                                    f"{'Possible sanitization detected between source and sink.' if sanitized else 'No sanitization detected between source and sink.'}"
                                ),
                                recommendation=(
                                    "Sanitize all user-controlled input before passing to DOM sinks. "
                                    "Use DOMPurify, textContent instead of innerHTML, or framework-specific "
                                    "safe binding mechanisms."
                                ),
                                evidence=f"Source: {source_name}\nContext:\n{context[:500]}",
                                category="DOM XSS",
                                url=url,
                                cwe="CWE-79",
                            )
                            print_finding(severity, f"DOM XSS: {src_name} → {sink_name}")
                            taint_count += 1
                            break  # One finding per source/sink pair
                    else:
                        continue
                    break

        return taint_count

    def _has_sanitization(self, code):
        """Check if code contains common sanitization patterns."""
        sanitizers = [
            r'DOMPurify', r'sanitize', r'escape', r'encode',
            r'encodeURIComponent', r'encodeURI', r'textContent',
            r'createTextNode', r'innerText', r'htmlspecialchars',
            r'strip_tags', r'xss', r'purify', r'bleach',
        ]
        for pattern in sanitizers:
            if re.search(pattern, code, re.I):
                return True
        return False

    def _active_probe(self, url):
        """Actively test for DOM XSS with canary payloads."""
        parsed = urlparse(url)

        # Test hash-based payloads
        for payload in DOM_XSS_PAYLOADS:
            if payload.startswith("#"):
                test_url = f"{url}{payload}"
            elif payload.startswith("?"):
                test_url = f"{url}{payload}"
            else:
                continue

            try:
                resp = self.http_client.get(test_url, timeout=10)
                # Check if payload is reflected without encoding
                clean_payload = payload.lstrip("#?").split("=", 1)[-1] if "=" in payload else payload.lstrip("#?")
                if clean_payload in resp.text:
                    # Check if it's in a dangerous context
                    if self._in_script_context(resp.text, clean_payload):
                        self.add_finding(
                            title=f"DOM XSS: payload reflected in script context",
                            severity=Severity.HIGH,
                            description=(
                                f"A DOM XSS test payload was reflected in the page "
                                f"within a script context without proper encoding."
                            ),
                            recommendation="Sanitize user input before inserting into the DOM.",
                            evidence=f"URL: {test_url}\nPayload reflected in script context",
                            category="DOM XSS",
                            url=test_url,
                            cwe="CWE-79",
                        )
                        print_finding(Severity.HIGH, f"DOM XSS: payload reflected in script context")
                        return  # One finding is enough for active probe
            except Exception:
                pass

    def _in_script_context(self, html, payload):
        """Check if a payload appears within a script tag or event handler."""
        # In script block
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)
        for script in scripts:
            if payload in script:
                return True

        # In event handler
        handlers = re.findall(r'on\w+=["\']([^"\']*)', html, re.I)
        for handler in handlers:
            if payload in handler:
                return True

        return False

    def _check_frameworks(self, html, url):
        """Check for framework-specific DOM XSS patterns."""
        # Angular: ng-bind-html without $sce
        if re.search(r'ng-bind-html', html):
            if not re.search(r'\$sce\.trustAsHtml', html):
                self.add_finding(
                    title="Angular ng-bind-html without $sce sanitization",
                    severity=Severity.MEDIUM,
                    description="Found ng-bind-html directive which may render unsanitized HTML.",
                    recommendation="Use $sce.trustAsHtml() with proper sanitization.",
                    evidence="ng-bind-html found in page source",
                    category="DOM XSS",
                    url=url,
                    cwe="CWE-79",
                )

        # Vue: v-html usage
        vhtml_matches = re.findall(r'v-html\s*=\s*["\']([^"\']+)', html)
        if vhtml_matches:
            for match in vhtml_matches[:3]:
                self.add_finding(
                    title=f"Vue v-html directive: {match}",
                    severity=Severity.MEDIUM,
                    description=f"Vue v-html renders raw HTML. If '{match}' contains user input, XSS is possible.",
                    recommendation="Use v-text or {{ }} interpolation instead of v-html.",
                    evidence=f"v-html=\"{match}\"",
                    category="DOM XSS",
                    url=url,
                    cwe="CWE-79",
                )

        # React: dangerouslySetInnerHTML
        if "dangerouslySetInnerHTML" in html:
            self.add_finding(
                title="React dangerouslySetInnerHTML usage",
                severity=Severity.MEDIUM,
                description="React's dangerouslySetInnerHTML bypasses XSS protections.",
                recommendation="Avoid dangerouslySetInnerHTML or use DOMPurify to sanitize input.",
                evidence="dangerouslySetInnerHTML found in page source",
                category="DOM XSS",
                url=url,
                cwe="CWE-79",
            )

    def _check_postmessage(self, js_code, source_name, url):
        """Analyze postMessage handlers for missing origin checks."""
        # Find message event listeners
        listeners = list(re.finditer(
            r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(?:function\s*\((\w+)\)|(\w+)\s*=>|(\w+))',
            js_code
        ))

        for listener in listeners:
            # Get context around the listener
            start = listener.start()
            end = min(len(js_code), start + 1000)
            context = js_code[start:end]

            # Check for origin validation
            has_origin_check = bool(re.search(
                r'(?:event|e|evt|msg)\.origin\s*(?:===|==|!==|!=)',
                context, re.I
            ))

            if not has_origin_check:
                self.add_finding(
                    title="postMessage handler without origin validation",
                    severity=Severity.HIGH,
                    description=(
                        f"A postMessage event listener in {source_name} does not validate "
                        f"the origin of incoming messages. An attacker could send malicious "
                        f"messages from any origin."
                    ),
                    recommendation=(
                        "Always validate event.origin against an allowlist before "
                        "processing postMessage data."
                    ),
                    evidence=f"Source: {source_name}\nContext:\n{context[:300]}",
                    category="DOM XSS",
                    url=url,
                    cwe="CWE-346",
                )
                print_finding(Severity.HIGH, f"postMessage without origin check in {source_name}")
