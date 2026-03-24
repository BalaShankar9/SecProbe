"""
Division 13 — Evasion & Stealth Agents (35 agents).

Specializes in bypassing web application firewalls, security filters, and
detection systems through encoding tricks, protocol manipulation, payload
mutation, fingerprint evasion, and timing-based stealth techniques.
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


def agents() -> list[AgentSpec]:
    """Return all 35 Division 13 agents."""
    return [
        # ── WAF Bypass per Vendor (9) ────────────────────────────────
        _s(
            "evasion-waf-cloudflare", "Cloudflare WAF Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Bypasses Cloudflare WAF rules using chunked transfer encoding, "
                        "Unicode normalization, HTTP/2 header smuggling, and Cloudflare-"
                        "specific rule-set gaps. Detects Cloudflare via cf-ray headers "
                        "and __cfduid markers.",
            attack_types=("waf-bypass",),
            target_technologies=("cloudflare",),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"cf-ray", r"cloudflare", r"__cfduid", r"1020.*access.*denied",
            ),
            payloads=("waf_cloudflare.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "cloudflare", "bypass"),
        ),
        _s(
            "evasion-waf-akamai", "Akamai WAF Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Evades Akamai Kona Site Defender and App & API Protector using "
                        "parameter pollution, JSON content-type switching, and multipart "
                        "boundary injection techniques specific to Akamai rule engines.",
            attack_types=("waf-bypass",),
            target_technologies=("akamai",),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"akamai", r"AkamaiGHost", r"Reference.*#\d+\.\w+",
            ),
            payloads=("waf_akamai.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "akamai", "bypass"),
        ),
        _s(
            "evasion-waf-aws", "AWS WAF Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Bypasses AWS WAF managed rules and custom rule groups using "
                        "request body size limits (8KB default), regex engine limitations, "
                        "and label-based rule ordering gaps in AWS WAF v2.",
            attack_types=("waf-bypass",),
            target_technologies=("aws",),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"x-amzn-RequestId", r"403.*Forbidden", r"AWS",
            ),
            payloads=("waf_aws.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "aws", "bypass"),
        ),
        _s(
            "evasion-waf-modsec", "ModSecurity CRS Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Evades ModSecurity Core Rule Set (CRS) using paranoia-level-aware "
                        "payloads, SQL comment injection to break tokenization, and "
                        "request body processor confusion between URLENCODED and MULTIPART.",
            attack_types=("waf-bypass",),
            target_technologies=("modsecurity", "apache", "nginx"),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"ModSecurity", r"OWASP.*CRS", r"mod_security",
                r"SecRule", r"id.*949",
            ),
            payloads=("waf_modsec.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "modsecurity", "crs", "bypass"),
        ),
        _s(
            "evasion-waf-imperva", "Imperva/Incapsula WAF Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Bypasses Imperva SecureSphere and Incapsula cloud WAF using "
                        "HTTP Parameter Pollution, JSON-in-query strings, and behavioral "
                        "analysis evasion through request rate shaping.",
            attack_types=("waf-bypass",),
            target_technologies=("imperva", "incapsula"),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"incapsula", r"visid_incap", r"imperva",
                r"_incap_ses", r"robot.*detected",
            ),
            payloads=("waf_imperva.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "imperva", "incapsula", "bypass"),
        ),
        _s(
            "evasion-waf-f5", "F5 BIG-IP ASM Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Evades F5 BIG-IP Application Security Manager using evasion "
                        "techniques targeting its positive security model, parameter "
                        "meta-character restrictions, and DataGuard response filtering.",
            attack_types=("waf-bypass",),
            target_technologies=("f5", "bigip"),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"BIGipServer", r"TS[a-f0-9]{6}", r"BigIP",
                r"F5.*ASM", r"support.*id",
            ),
            payloads=("waf_f5.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "f5", "bigip", "asm", "bypass"),
        ),
        _s(
            "evasion-waf-azure", "Azure WAF Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Bypasses Azure Front Door WAF and Application Gateway WAF "
                        "using request body truncation beyond size limits, custom "
                        "rule precedence confusion, and managed ruleset version gaps.",
            attack_types=("waf-bypass",),
            target_technologies=("azure",),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"x-azure-ref", r"Azure.*WAF", r"Front.*Door",
            ),
            payloads=("waf_azure.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "azure", "frontdoor", "bypass"),
        ),
        _s(
            "evasion-waf-fortinet", "Fortinet FortiWeb Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Evades Fortinet FortiWeb and FortiGate WAF using ML-based "
                        "detection model adversarial inputs, signature database gaps, "
                        "and HTTP protocol compliance edge cases.",
            attack_types=("waf-bypass",),
            target_technologies=("fortinet", "fortiweb"),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"FortiWeb", r"FortiGate", r"FORTIWAFSID",
            ),
            payloads=("waf_fortinet.txt",),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("waf", "fortinet", "fortiweb", "bypass"),
        ),
        _s(
            "evasion-waf-generic", "Generic WAF Bypass Specialist", 13,
            {Cap.WAF_BYPASS, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Applies vendor-agnostic WAF bypass techniques: content-type "
                        "switching (application/json, multipart/form-data), HTTP method "
                        "override (X-HTTP-Method-Override), oversized request body padding, "
                        "and null-byte injection to break pattern matching.",
            attack_types=("waf-bypass",),
            cwe_ids=("CWE-693",),
            detection_patterns=(
                r"blocked", r"forbidden", r"security.*violation",
                r"request.*rejected",
            ),
            payloads=("waf_generic.txt",),
            priority=Pri.NORMAL,
            max_requests=200,
            tags=("waf", "generic", "bypass"),
        ),

        # ── Encoding Evasion (5) ────────────────────────────────────
        _s(
            "evasion-enc-url", "URL Encoding Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Evades input filters via single URL encoding, double encoding, "
                        "mixed encoding, and over-long UTF-8 sequences that decode to "
                        "malicious payloads after server-side processing.",
            attack_types=("encoding-evasion",),
            cwe_ids=("CWE-838",),
            detection_patterns=(r"%[0-9a-fA-F]{2}",),
            payloads=("evasion_url_enc.txt",),
            priority=Pri.HIGH,
            max_requests=120,
            tags=("encoding", "url", "double-encoding"),
        ),
        _s(
            "evasion-enc-unicode", "Unicode Normalization Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Exploits Unicode normalization differences (NFC, NFD, NFKC, NFKD) "
                        "between WAF/filter and application to smuggle payloads through "
                        "confusable characters, zero-width joiners, and combining marks.",
            attack_types=("encoding-evasion",),
            cwe_ids=("CWE-176",),
            detection_patterns=(r"\\u[0-9a-fA-F]{4}",),
            payloads=("evasion_unicode.txt",),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("encoding", "unicode", "normalization"),
        ),
        _s(
            "evasion-enc-html-entity", "HTML Entity Encoding Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Bypasses HTML context filters using decimal (&#60;), hexadecimal "
                        "(&#x3c;), named (&lt;), and zero-padded HTML entities with "
                        "semicolon omission to reconstruct filtered tags and attributes.",
            attack_types=("encoding-evasion",),
            cwe_ids=("CWE-838", "CWE-79"),
            detection_patterns=(r"&#\d+;", r"&#x[0-9a-fA-F]+;"),
            payloads=("evasion_html_entity.txt",),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("encoding", "html", "entity"),
        ),
        _s(
            "evasion-enc-base64-hex", "Base64/Hex Encoding Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Smuggles payloads through filters that do not decode base64, "
                        "hex, or octal representations by using atob()-decodable strings, "
                        "\\x hex escapes, and String.fromCharCode() sequences.",
            attack_types=("encoding-evasion",),
            cwe_ids=("CWE-838",),
            detection_patterns=(r"[A-Za-z0-9+/]{20,}={0,2}",),
            payloads=("evasion_base64_hex.txt",),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("encoding", "base64", "hex"),
        ),
        _s(
            "evasion-enc-charset", "Charset Mismatch Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.HEADER_MANIPULATION, Cap.HTTP_PROBE},
            description="Exploits charset declaration mismatches between Content-Type "
                        "header (UTF-7, ISO-2022-JP, Shift_JIS) and actual body encoding "
                        "to bypass filters that only inspect one encoding interpretation.",
            attack_types=("encoding-evasion",),
            cwe_ids=("CWE-838", "CWE-436"),
            detection_patterns=(r"charset=", r"UTF-7", r"ISO-2022"),
            payloads=("evasion_charset.txt",),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("encoding", "charset", "utf7"),
        ),

        # ── TLS Fingerprint (2) ─────────────────────────────────────
        _s(
            "evasion-tls-ja3", "JA3/JA4 TLS Fingerprint Evasion Specialist", 13,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE},
            description="Evades JA3 and JA4 TLS fingerprinting by mimicking browser "
                        "cipher suite orderings, TLS extension lists, and elliptic curve "
                        "preferences for Chrome, Firefox, and Safari profiles.",
            attack_types=("fingerprint-evasion",),
            cwe_ids=("CWE-693",),
            detection_patterns=(r"ja3.*hash", r"fingerprint.*blocked"),
            priority=Pri.HIGH,
            max_requests=50,
            tags=("tls", "ja3", "ja4", "fingerprint"),
        ),
        _s(
            "evasion-tls-version", "TLS Version/Protocol Evasion Specialist", 13,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE},
            description="Tests for security control gaps by downgrading TLS versions, "
                        "using deprecated cipher suites, and exploiting differences "
                        "between TLS termination at CDN vs. origin server.",
            attack_types=("fingerprint-evasion",),
            cwe_ids=("CWE-757",),
            detection_patterns=(r"ssl.*error", r"handshake.*failure"),
            priority=Pri.NORMAL,
            max_requests=40,
            tags=("tls", "downgrade", "protocol"),
        ),

        # ── HTTP Tricks (4) ─────────────────────────────────────────
        _s(
            "evasion-http-smuggling", "HTTP Request Smuggling Specialist", 13,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
            description="Exploits CL.TE and TE.CL HTTP request smuggling to bypass "
                        "front-end security controls by desynchronizing request parsing "
                        "between reverse proxy and origin server.",
            attack_types=("http-smuggling",),
            cwe_ids=("CWE-444",),
            detection_patterns=(
                r"Transfer-Encoding", r"Content-Length",
                r"HTTP.*400", r"HTTP.*501",
            ),
            payloads=("http_smuggling.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("http", "smuggling", "desync"),
        ),
        _s(
            "evasion-http-h2-smuggling", "HTTP/2 Smuggling Specialist", 13,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
            description="Exploits HTTP/2 downgrade smuggling (H2.CL, H2.TE) and "
                        "pseudo-header injection to bypass WAFs that only inspect "
                        "the HTTP/2 frame layer but not the downgraded HTTP/1.1 request.",
            attack_types=("http-smuggling", "h2"),
            cwe_ids=("CWE-444",),
            detection_patterns=(
                r":method", r":path", r"SETTINGS",
            ),
            payloads=("http2_smuggling.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("http2", "smuggling", "downgrade"),
        ),
        _s(
            "evasion-http-method-override", "HTTP Method Override Specialist", 13,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
            description="Bypasses method-based security controls using X-HTTP-Method-Override, "
                        "X-Method-Override, and _method parameter to change request "
                        "semantics post-WAF inspection.",
            attack_types=("method-override",),
            cwe_ids=("CWE-650",),
            detection_patterns=(
                r"X-HTTP-Method", r"Method.*Not.*Allowed",
            ),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("http", "method", "override"),
        ),
        _s(
            "evasion-http-header-inject", "HTTP Header Injection Specialist", 13,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Injects CRLF sequences into header values to add arbitrary "
                        "headers, split responses, poison caches, and bypass security "
                        "headers by injecting after the WAF inspection point.",
            attack_types=("header-injection", "crlf"),
            cwe_ids=("CWE-113",),
            detection_patterns=(
                r"\\r\\n", r"%0d%0a", r"Set-Cookie",
            ),
            payloads=("crlf_injection.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("http", "crlf", "header", "injection"),
        ),

        # ── Comment / Case / Whitespace (4) ─────────────────────────
        _s(
            "evasion-sql-comment", "SQL Comment Obfuscation Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Evades SQL injection filters using inline comments (/**/), "
                        "MySQL-specific comments (/*!50000*/), nested comments, "
                        "and comment-based keyword splitting (UN/**/ION SE/**/LECT).",
            attack_types=("sql-evasion",),
            cwe_ids=("CWE-89",),
            detection_patterns=(r"/\*.*\*/", r"UNION.*SELECT"),
            payloads=("evasion_sql_comment.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("sql", "comment", "obfuscation"),
        ),
        _s(
            "evasion-case-mutation", "Case Mutation Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Bypasses case-sensitive filters by randomizing keyword casing "
                        "(sElEcT, ScRiPt), using SQL function case variations, "
                        "and exploiting locale-dependent case folding rules.",
            attack_types=("case-evasion",),
            cwe_ids=("CWE-178",),
            detection_patterns=(r"[a-zA-Z]{3,}",),
            payloads=("evasion_case.txt",),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("case", "mutation", "evasion"),
        ),
        _s(
            "evasion-whitespace", "Whitespace Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Evades keyword detection by substituting standard spaces with "
                        "tabs (\\t), vertical tabs (\\v), newlines, form feeds, and "
                        "non-breaking spaces that database/interpreter still accepts "
                        "as whitespace but filters do not match.",
            attack_types=("whitespace-evasion",),
            cwe_ids=("CWE-178",),
            detection_patterns=(r"\\t", r"\\v", r"\\x0b", r"\\x0c"),
            payloads=("evasion_whitespace.txt",),
            priority=Pri.NORMAL,
            max_requests=80,
            tags=("whitespace", "tab", "evasion"),
        ),
        _s(
            "evasion-html-tag-mutation", "HTML Tag Mutation Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Bypasses XSS filters using tag mutation: self-closing tag "
                        "variations, unquoted attributes, backtick delimiters, "
                        "event handler casing (oNeRrOr), and SVG/MathML namespace "
                        "confusion to execute scripts without blocked tag names.",
            attack_types=("xss-evasion",),
            cwe_ids=("CWE-79",),
            detection_patterns=(r"<svg", r"<math", r"onerror", r"onload"),
            payloads=("evasion_html_tag.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("html", "tag", "mutation", "xss"),
        ),

        # ── IP / Path Tricks (3) ────────────────────────────────────
        _s(
            "evasion-ip-rotation", "IP Source Rotation Specialist", 13,
            {Cap.HEADER_MANIPULATION, Cap.HTTP_PROBE, Cap.RATE_ADAPTATION},
            description="Rotates source IP appearance using X-Forwarded-For header "
                        "injection, X-Real-IP spoofing, X-Originating-IP, True-Client-IP, "
                        "and CF-Connecting-IP to bypass IP-based rate limits and ACLs.",
            attack_types=("ip-evasion",),
            cwe_ids=("CWE-290",),
            detection_patterns=(
                r"X-Forwarded-For", r"rate.*limit", r"blocked.*ip",
            ),
            priority=Pri.HIGH,
            max_requests=150,
            tags=("ip", "rotation", "header", "spoofing"),
        ),
        _s(
            "evasion-path-normalization", "Path Normalization Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Bypasses path-based WAF rules using path normalization tricks: "
                        "double slashes (//admin), dot segments (/./admin), path parameters "
                        "(/admin;x=1), URL encoding of slashes, and backslash substitution.",
            attack_types=("path-evasion",),
            cwe_ids=("CWE-436",),
            detection_patterns=(r"//", r"/\./", r";", r"%2f"),
            payloads=("evasion_path.txt",),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("path", "normalization", "evasion"),
        ),
        _s(
            "evasion-dns-rebinding", "DNS Rebinding Evasion Specialist", 13,
            {Cap.DNS_ENUM, Cap.HTTP_PROBE},
            description="Uses DNS rebinding to bypass SSRF protections that validate "
                        "hostnames at resolution time by configuring short-TTL DNS "
                        "records that resolve to allowed IPs initially, then switch "
                        "to internal targets on subsequent lookups.",
            attack_types=("dns-rebinding",),
            cwe_ids=("CWE-350",),
            detection_patterns=(
                r"dns.*rebind", r"ttl.*0", r"resolve.*127",
            ),
            priority=Pri.HIGH,
            max_requests=60,
            tags=("dns", "rebinding", "ssrf", "evasion"),
        ),

        # ── Payload Mutation (3) ────────────────────────────────────
        _s(
            "evasion-payload-concat", "String Concatenation Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Evades keyword detection by splitting payloads using string "
                        "concatenation operators: SQL CONCAT(), JavaScript string addition, "
                        "PHP dot operator, and database-specific concat syntax.",
            attack_types=("payload-mutation",),
            cwe_ids=("CWE-693",),
            detection_patterns=(r"CONCAT", r"CHR\(", r"CHAR\("),
            payloads=("evasion_concat.txt",),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("payload", "concat", "evasion"),
        ),
        _s(
            "evasion-payload-alternative-syntax", "Alternative Syntax Evasion Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Replaces filtered functions and keywords with equivalent "
                        "alternatives: SUBSTR vs SUBSTRING, IF vs CASE, exec vs system, "
                        "and using JavaScript constructor chains (''['constructor']"
                        "['constructor']('code')()) to achieve same effect without "
                        "blocked keywords.",
            attack_types=("payload-mutation",),
            cwe_ids=("CWE-693",),
            detection_patterns=(r"constructor", r"CASE.*WHEN", r"SUBSTR"),
            payloads=("evasion_alt_syntax.txt",),
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("payload", "alternative", "syntax"),
        ),
        _s(
            "evasion-payload-polyglot", "Polyglot Payload Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Generates polyglot payloads that are simultaneously valid in "
                        "multiple injection contexts (SQL + XSS + template), maximizing "
                        "detection surface while minimizing request count.",
            attack_types=("payload-mutation", "polyglot"),
            cwe_ids=("CWE-693",),
            detection_patterns=(r"jaVasCript:", r"'-\"", r"{{.*}}"),
            payloads=("evasion_polyglot.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("polyglot", "payload", "multi-context"),
        ),

        # ── Timing / Session Stealth (3) ────────────────────────────
        _s(
            "evasion-timing-jitter", "Request Timing Jitter Specialist", 13,
            {Cap.RATE_ADAPTATION, Cap.HTTP_PROBE},
            description="Evades behavioral analysis and rate-based detection by adding "
                        "human-like timing jitter, randomizing request intervals using "
                        "Poisson distributions, and mimicking organic browsing patterns.",
            attack_types=("timing-evasion",),
            cwe_ids=("CWE-693",),
            detection_patterns=(r"rate.*limit", r"captcha", r"challenge"),
            priority=Pri.NORMAL,
            max_requests=50,
            tags=("timing", "jitter", "behavioral"),
        ),
        _s(
            "evasion-session-rotation", "Session Rotation Specialist", 13,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.RATE_ADAPTATION},
            description="Evades session-based tracking and blocking by rotating session "
                        "tokens, using anonymous/incognito request patterns, and managing "
                        "cookie jar isolation per request batch.",
            attack_types=("session-evasion",),
            cwe_ids=("CWE-693",),
            detection_patterns=(r"session.*expired", r"login.*required"),
            priority=Pri.NORMAL,
            max_requests=50,
            tags=("session", "rotation", "stealth"),
        ),
        _s(
            "evasion-useragent-rotation", "User-Agent Rotation Specialist", 13,
            {Cap.HEADER_MANIPULATION, Cap.HTTP_PROBE, Cap.TLS_IMPERSONATION},
            description="Rotates User-Agent strings with correlated TLS fingerprints, "
                        "Accept-Language headers, and platform-consistent header orderings "
                        "to avoid bot detection based on client fingerprint consistency.",
            attack_types=("fingerprint-evasion",),
            cwe_ids=("CWE-693",),
            detection_patterns=(r"bot.*detected", r"User-Agent.*blocked"),
            priority=Pri.NORMAL,
            max_requests=50,
            tags=("useragent", "rotation", "fingerprint"),
        ),

        # ── Obfuscation (1) ─────────────────────────────────────────
        _s(
            "evasion-js-obfuscation", "JavaScript Obfuscation Specialist", 13,
            {Cap.ENCODING_MUTATION, Cap.PAYLOAD_INJECTION, Cap.JS_ANALYSIS},
            description="Constructs heavily obfuscated JavaScript payloads using "
                        "JSFuck encoding, template literal abuse, Proxy-based execution, "
                        "and eval-free code execution via constructor chains to bypass "
                        "XSS filters that block script keywords.",
            attack_types=("js-obfuscation", "xss-evasion"),
            cwe_ids=("CWE-79",),
            detection_patterns=(r"\[\]", r"\+!!", r"constructor"),
            payloads=("evasion_js_obfusc.txt",),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("javascript", "obfuscation", "jsfuck"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "evasion-commander", "Division 13 Evasion & Stealth Commander", 13,
            {Cap.COORDINATION, Cap.CONSENSUS_VOTING, Cap.KNOWLEDGE_SHARING},
            description="Coordinates all Division 13 agents, identifies active WAF vendor "
                        "from response fingerprints and activates the matching bypass "
                        "specialist, manages evasion technique sharing across divisions, "
                        "and provides encoding transformation services to the entire swarm.",
            attack_types=("evasion",),
            cwe_ids=(),
            priority=Pri.CRITICAL,
            max_requests=50,
            tags=("commander", "coordinator", "evasion"),
        ),
    ]
