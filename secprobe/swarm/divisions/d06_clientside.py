"""
Division 6: Client-Side Attacks — 35 agents.

Covers DOM-based attacks, prototype pollution, service workers, clickjacking,
CORS exploitation, JavaScript analysis, CSP/SRI, caching/MIME, subdomain
takeover, and miscellaneous client-side vectors.
"""
from __future__ import annotations

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


def agents() -> list[AgentSpec]:
    return [
        # ── DOM Attacks (5) ───────────────────────────────────────────
        _s(
            "cs-dom-xss-source", "DOM XSS Source Tracer", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.PAYLOAD_INJECTION},
            description="Traces DOM XSS sources (location.hash, location.search, referrer) "
                        "through JavaScript data flow to identify taint propagation paths",
            attack_types=("dom-xss",),
            cwe_ids=("CWE-79",),
            detection_patterns=(
                r"location\.(hash|search|href)",
                r"window\.name",
                r"postMessage\s*\(",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("xss", "dom", "taint-analysis"),
        ),
        _s(
            "cs-dom-xss-sink", "DOM XSS Sink Detector", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.PATTERN_MATCHING},
            description="Identifies dangerous DOM sinks including innerHTML sink, "
                        "outerHTML assignment, and DOM write sink patterns in JS code",
            attack_types=("dom-xss",),
            cwe_ids=("CWE-79",),
            detection_patterns=(
                r"\.innerHTML\s*=",
                r"setTimeout\s*\(\s*['\"]",
                r"\.outerHTML\s*=",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("xss", "dom", "sink-analysis"),
        ),
        _s(
            "cs-dom-clobbering", "DOM Clobbering Specialist", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.PAYLOAD_INJECTION},
            description="Tests for DOM clobbering attacks where named HTML elements "
                        "override JavaScript variables and built-in APIs",
            attack_types=("dom-clobbering",),
            cwe_ids=("CWE-79",),
            detection_patterns=(
                r"getElementById\s*\(",
                r"getElementsByName\s*\(",
                r'<form\s+[^>]*name=',
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("dom", "clobbering"),
        ),
        _s(
            "cs-dom-open-redirect", "DOM Open Redirect Analyst", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.HTTP_PROBE},
            description="Detects client-side open redirects via location assignment, "
                        "meta refresh injection, and window.open with user-controlled URLs",
            attack_types=("open-redirect",),
            cwe_ids=("CWE-601",),
            detection_patterns=(
                r"location\s*=",
                r"location\.replace\s*\(",
                r"window\.open\s*\(",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("redirect", "dom"),
        ),
        _s(
            "cs-dom-postmessage", "postMessage Security Auditor", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.PATTERN_MATCHING},
            description="Audits postMessage handlers for missing origin validation, "
                        "unsafe deserialization of message data, and cross-origin data leakage",
            attack_types=("postmessage-xss", "dom-xss"),
            cwe_ids=("CWE-345", "CWE-79"),
            detection_patterns=(
                r"addEventListener\s*\(\s*['\"]message['\"]",
                r"\.origin\s*[!=]==?\s*",
                r"postMessage\s*\(",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("postmessage", "origin-validation"),
        ),

        # ── Prototype Pollution (3) ──────────────────────────────────
        _s(
            "cs-proto-pollution-param", "Prototype Pollution Parameter Tester", 6,
            {Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE, Cap.JS_ANALYSIS},
            description="Tests for server-side and client-side prototype pollution via "
                        "__proto__, constructor.prototype, and Object.assign merge paths",
            attack_types=("prototype-pollution",),
            cwe_ids=("CWE-1321",),
            detection_patterns=(
                r"__proto__",
                r"constructor\[",
                r"Object\.assign\s*\(",
                r"merge\s*\(",
            ),
            payloads=("proto_pollution.txt",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("prototype-pollution", "javascript"),
        ),
        _s(
            "cs-proto-pollution-json", "JSON Merge Pollution Specialist", 6,
            {Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE, Cap.JS_ANALYSIS},
            description="Exploits prototype pollution via JSON body parsing in frameworks "
                        "using recursive merge (lodash.merge, jQuery.extend deep)",
            attack_types=("prototype-pollution",),
            cwe_ids=("CWE-1321",),
            detection_patterns=(
                r"lodash",
                r"jQuery\.extend\s*\(\s*true",
                r"deepmerge",
            ),
            payloads=("proto_pollution_json.txt",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("prototype-pollution", "json-merge"),
        ),
        _s(
            "cs-proto-pollution-gadget", "Prototype Pollution Gadget Finder", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.CHAIN_BUILDING},
            description="Discovers exploitable gadgets after prototype pollution: "
                        "script gadgets for XSS, authorization bypasses, RCE via child_process",
            attack_types=("prototype-pollution",),
            cwe_ids=("CWE-1321", "CWE-94"),
            detection_patterns=(
                r"child_process",
                r"require\s*\(",
                r"Function\s*\(",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.REDTEAM,
            tags=("prototype-pollution", "gadget-chain"),
        ),

        # ── Service Workers / Storage (3) ────────────────────────────
        _s(
            "cs-service-worker", "Service Worker Security Auditor", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.HTTP_PROBE},
            description="Audits service worker registration scope, update mechanisms, "
                        "and cache poisoning vectors via SW fetch event handlers",
            attack_types=("service-worker-abuse",),
            cwe_ids=("CWE-349",),
            detection_patterns=(
                r"navigator\.serviceWorker\.register",
                r"self\.addEventListener\s*\(\s*['\"]fetch['\"]",
                r"caches\.open\s*\(",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("service-worker", "cache"),
        ),
        _s(
            "cs-localstorage-secrets", "Client Storage Secret Scanner", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.DATA_EXTRACTION},
            description="Scans localStorage, sessionStorage, and IndexedDB for tokens, "
                        "API keys, PII, and sensitive data exposed to XSS exfiltration",
            attack_types=("insecure-storage",),
            cwe_ids=("CWE-922",),
            detection_patterns=(
                r"localStorage\.(set|get)Item",
                r"sessionStorage\.(set|get)Item",
                r"indexedDB\.open\s*\(",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("storage", "secrets", "client-side"),
        ),
        _s(
            "cs-websocket-hijack", "WebSocket Hijacking Tester", 6,
            {Cap.WEBSOCKET_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Tests WebSocket endpoints for cross-site hijacking via missing "
                        "Origin validation, token leakage, and injection in WS frames",
            attack_types=("websocket-hijacking",),
            cwe_ids=("CWE-1385", "CWE-346"),
            detection_patterns=(
                r"new\s+WebSocket\s*\(",
                r"ws(s)?://",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("websocket", "hijacking"),
        ),

        # ── Clickjacking / Framing (3) ──────────────────────────────
        _s(
            "cs-clickjack-framing", "Clickjacking Frame Tester", 6,
            {Cap.HTTP_PROBE, Cap.BROWSER_AUTOMATION, Cap.HEADER_MANIPULATION},
            description="Tests if target pages can be framed by checking X-Frame-Options, "
                        "CSP frame-ancestors, and attempting iframe embedding",
            attack_types=("clickjacking",),
            cwe_ids=("CWE-1021",),
            detection_patterns=(
                r"X-Frame-Options",
                r"frame-ancestors",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("clickjacking", "framing"),
        ),
        _s(
            "cs-clickjack-drag-drop", "Drag-and-Drop Jacking Specialist", 6,
            {Cap.BROWSER_AUTOMATION, Cap.PAYLOAD_INJECTION},
            description="Tests for drag-and-drop-based UI redressing attacks "
                        "that bypass traditional clickjacking protections",
            attack_types=("clickjacking",),
            cwe_ids=("CWE-1021",),
            priority=Pri.LOW,
            min_mode=Mode.REDTEAM,
            tags=("clickjacking", "drag-drop"),
        ),
        _s(
            "cs-ui-redress", "UI Redressing Analyst", 6,
            {Cap.BROWSER_AUTOMATION, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
            description="Detects advanced UI redressing via CSS opacity tricks, "
                        "cursor manipulation, and permission prompt hijacking",
            attack_types=("ui-redressing",),
            cwe_ids=("CWE-1021",),
            detection_patterns=(
                r"opacity\s*:\s*0",
                r"pointer-events\s*:\s*none",
                r"z-index\s*:\s*-?\d+",
            ),
            priority=Pri.LOW,
            min_mode=Mode.AUDIT,
            tags=("ui-redressing", "css"),
        ),

        # ── CORS Exploitation (3) ───────────────────────────────────
        _s(
            "cs-cors-miscfg", "CORS Misconfiguration Scanner", 6,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PATTERN_MATCHING},
            description="Tests CORS policies for overly permissive Access-Control-Allow-Origin, "
                        "null origin acceptance, and credential leakage via wildcard + credentials",
            attack_types=("cors-misconfiguration",),
            cwe_ids=("CWE-942",),
            detection_patterns=(
                r"Access-Control-Allow-Origin:\s*\*",
                r"Access-Control-Allow-Credentials:\s*true",
                r"Access-Control-Allow-Origin:\s*null",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("cors", "headers"),
        ),
        _s(
            "cs-cors-origin-reflect", "CORS Origin Reflection Tester", 6,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests if the server reflects arbitrary Origin headers in "
                        "Access-Control-Allow-Origin, enabling cross-origin data theft",
            attack_types=("cors-misconfiguration",),
            cwe_ids=("CWE-942", "CWE-346"),
            detection_patterns=(
                r"Access-Control-Allow-Origin:",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("cors", "origin-reflection"),
        ),
        _s(
            "cs-cors-preflight", "CORS Preflight Bypass Specialist", 6,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.WAF_BYPASS},
            description="Attempts to bypass CORS preflight checks via simple requests, "
                        "content-type tricks, and non-standard method exploitation",
            attack_types=("cors-misconfiguration",),
            cwe_ids=("CWE-942",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("cors", "preflight"),
        ),

        # ── JavaScript Analysis (5) ─────────────────────────────────
        _s(
            "cs-js-sourcemap", "JS Source Map Extractor", 6,
            {Cap.JS_ANALYSIS, Cap.HTTP_PROBE, Cap.OSINT},
            description="Discovers and extracts JavaScript source maps (.map files) "
                        "to recover original source code, API keys, and internal paths",
            attack_types=("information-disclosure",),
            cwe_ids=("CWE-540",),
            detection_patterns=(
                r"sourceMappingURL=",
                r"\.map$",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("javascript", "source-map", "recon"),
        ),
        _s(
            "cs-js-secret-scan", "JS Embedded Secret Scanner", 6,
            {Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING, Cap.DATA_EXTRACTION},
            description="Scans JavaScript bundles for hardcoded API keys, tokens, "
                        "AWS credentials, private keys, and internal endpoint URLs",
            attack_types=("information-disclosure",),
            cwe_ids=("CWE-798", "CWE-540"),
            detection_patterns=(
                r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]",
                r"AKIA[0-9A-Z]{16}",
                r"(?:secret|token|password)\s*[:=]\s*['\"]",
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("javascript", "secrets", "credentials"),
        ),
        _s(
            "cs-js-sink-chain", "JS Sink Chain Analyzer", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.CHAIN_BUILDING},
            description="Performs interprocedural taint analysis across JavaScript bundles "
                        "to find multi-step source-to-sink vulnerability chains",
            attack_types=("dom-xss",),
            cwe_ids=("CWE-79",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("javascript", "taint-analysis", "chain"),
        ),
        _s(
            "cs-js-dependency-enum", "JS Dependency Enumerator", 6,
            {Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING, Cap.OSINT},
            description="Enumerates client-side JavaScript libraries and their versions "
                        "from script tags, webpack manifests, and known file hashes",
            attack_types=("known-cve",),
            cwe_ids=("CWE-1035",),
            detection_patterns=(
                r"jquery[.-](\d+\.\d+\.\d+)",
                r"angular[./](\d+\.\d+)",
                r"react[.-](\d+\.\d+\.\d+)",
                r"vue[./](\d+\.\d+)",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("javascript", "libraries", "version-detection"),
        ),
        _s(
            "cs-js-dynamic-analysis", "JS Dynamic Behavior Monitor", 6,
            {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.BASELINE_PROFILING},
            description="Instruments browser runtime to monitor dynamic JS behavior: "
                        "DOM mutations, network calls, DOM cookie access, and dynamic code loading",
            attack_types=("dom-xss", "information-disclosure"),
            cwe_ids=("CWE-79", "CWE-200"),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("javascript", "dynamic-analysis", "runtime"),
        ),

        # ── CSP / SRI (3) ───────────────────────────────────────────
        _s(
            "cs-csp-analyzer", "CSP Policy Analyzer", 6,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
            description="Parses and evaluates Content-Security-Policy headers for "
                        "unsafe-inline, unsafe-eval, overly broad source lists, and bypasses",
            attack_types=("csp-bypass",),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"Content-Security-Policy",
                r"unsafe-inline",
                r"unsafe-eval",
                r"\*\.googleapis\.com",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("csp", "headers", "policy"),
        ),
        _s(
            "cs-csp-bypass", "CSP Bypass Exploitation Specialist", 6,
            {Cap.PAYLOAD_INJECTION, Cap.JS_ANALYSIS, Cap.WAF_BYPASS},
            description="Exploits CSP bypasses via JSONP endpoints on whitelisted domains, "
                        "base-uri injection, script nonce prediction, and object-src abuse",
            attack_types=("csp-bypass", "xss"),
            cwe_ids=("CWE-693", "CWE-79"),
            payloads=("csp_bypass.txt",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("csp", "bypass", "xss"),
        ),
        _s(
            "cs-sri-checker", "Subresource Integrity Checker", 6,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
            description="Verifies SRI attributes on external script/link tags and "
                        "detects CDN resources loaded without integrity hashes",
            attack_types=("supply-chain",),
            cwe_ids=("CWE-353",),
            detection_patterns=(
                r'integrity="sha(256|384|512)-',
                r'<script[^>]+src=[^>]+',
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("sri", "integrity", "cdn"),
        ),

        # ── Cache / MIME / Referrer (4) ──────────────────────────────
        _s(
            "cs-cache-deception", "Web Cache Deception Tester", 6,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests for web cache deception by appending static extensions "
                        "(.css, .js, .png) to authenticated endpoints to cache sensitive responses",
            attack_types=("cache-deception",),
            cwe_ids=("CWE-524",),
            detection_patterns=(
                r"Cache-Control",
                r"X-Cache:\s*(HIT|MISS)",
                r"Age:\s*\d+",
                r"CF-Cache-Status",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("cache", "deception"),
        ),
        _s(
            "cs-mime-sniffing", "MIME Sniffing Exploitation Tester", 6,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.PAYLOAD_INJECTION},
            description="Checks for missing X-Content-Type-Options: nosniff and tests "
                        "MIME sniffing attacks to execute scripts via content type confusion",
            attack_types=("mime-sniffing",),
            cwe_ids=("CWE-430",),
            detection_patterns=(
                r"X-Content-Type-Options",
                r"Content-Type:\s*text/plain",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("mime", "headers"),
        ),
        _s(
            "cs-referrer-leak", "Referrer Leakage Analyzer", 6,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.CRAWL},
            description="Detects sensitive data leakage via HTTP Referer header when "
                        "navigating from pages with tokens/secrets in URLs to external sites",
            attack_types=("information-disclosure",),
            cwe_ids=("CWE-200",),
            detection_patterns=(
                r"Referrer-Policy",
                r"<meta\s+name=['\"]referrer['\"]",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("referrer", "leakage", "headers"),
        ),
        _s(
            "cs-cookie-security", "Cookie Security Auditor", 6,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
            description="Audits cookie attributes: missing Secure, HttpOnly, SameSite flags; "
                        "overly broad Domain/Path; and DOM cookie access exposure",
            attack_types=("insecure-cookie",),
            cwe_ids=("CWE-614", "CWE-1004"),
            detection_patterns=(
                r"Set-Cookie:",
                r"(?i)(?:secure|httponly|samesite)",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("cookie", "security", "headers"),
        ),

        # ── Subdomain Takeover (2) ──────────────────────────────────
        _s(
            "cs-subdomain-takeover", "Subdomain Takeover Scanner", 6,
            {Cap.DNS_ENUM, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Identifies dangling DNS records (CNAME, A, AAAA) pointing to "
                        "deprovisioned cloud services eligible for subdomain takeover",
            attack_types=("subdomain-takeover",),
            cwe_ids=("CWE-668",),
            detection_patterns=(
                r"NXDOMAIN",
                r"NoSuchBucket",
                r"There isn't a GitHub Pages site here",
                r"herokucdn\.com",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("subdomain", "takeover", "dns"),
        ),
        _s(
            "cs-subdomain-fingerprint", "Subdomain Service Fingerprinter", 6,
            {Cap.DNS_ENUM, Cap.HTTP_PROBE, Cap.TECH_FINGERPRINT},
            description="Fingerprints cloud services behind subdomains (S3, Azure, Heroku, "
                        "Netlify, Fastly, Shopify) to assess takeover feasibility",
            attack_types=("subdomain-takeover",),
            cwe_ids=("CWE-668",),
            detection_patterns=(
                r"\.s3\.amazonaws\.com",
                r"\.azurewebsites\.net",
                r"\.herokuapp\.com",
                r"\.netlify\.app",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("subdomain", "fingerprint", "cloud"),
        ),

        # ── Miscellaneous Client-Side (3) ────────────────────────────
        _s(
            "cs-html-injection", "HTML Injection Tester", 6,
            {Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Tests for HTML injection where user input is rendered in the page "
                        "without sanitization, enabling phishing, form injection, and content spoofing",
            attack_types=("html-injection",),
            cwe_ids=("CWE-79",),
            payloads=("html_injection.txt",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("html-injection", "content-spoofing"),
        ),
        _s(
            "cs-css-injection", "CSS Injection Specialist", 6,
            {Cap.PAYLOAD_INJECTION, Cap.BROWSER_AUTOMATION, Cap.JS_ANALYSIS},
            description="Tests for CSS injection to exfiltrate data via attribute selectors, "
                        "font-face unicode-range, and background-image URL callbacks",
            attack_types=("css-injection",),
            cwe_ids=("CWE-79",),
            payloads=("css_injection.txt",),
            priority=Pri.LOW,
            min_mode=Mode.AUDIT,
            tags=("css-injection", "data-exfiltration"),
        ),
        _s(
            "cs-dangling-markup", "Dangling Markup Injection Analyst", 6,
            {Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Detects dangling markup injection where unclosed tags capture "
                        "subsequent page content including CSRF tokens and sensitive data",
            attack_types=("dangling-markup",),
            cwe_ids=("CWE-79", "CWE-200"),
            payloads=("dangling_markup.txt",),
            priority=Pri.LOW,
            min_mode=Mode.AUDIT,
            tags=("dangling-markup", "data-exfiltration"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "cs-commander", "Division 6 Commander — Client-Side Attacks", 6,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Orchestrates all Division 6 client-side attack agents. Prioritizes "
                        "agents based on detected client-side technologies, manages consensus "
                        "on DOM XSS and CORS findings, and coordinates JS analysis pipelines",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            tags=("commander", "division-6", "client-side"),
            max_requests=0,
            timeout=600,
        ),
    ]
