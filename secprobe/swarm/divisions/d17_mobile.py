"""
Division 17 — Mobile & IoT Security.

25 agents covering mobile API security, token/session management, deep link and
WebView analysis, biometric/root detection bypass, IoT protocols (MQTT/CoAP/UPnP),
IoT credentials and firmware, IoT web interfaces, and mobile data transit.
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
    return [
        # ── Mobile API Security (5) ──────────────────────────────────
        _s(
            "mob-api-auth", "Mobile API Authentication Tester", 17,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Tests mobile API endpoints for broken authentication: missing "
                        "auth on sensitive routes, bearer token acceptance without "
                        "validation, and API key exposure in client-accessible responses.",
            attack_types=("broken-auth", "api-abuse"),
            cwe_ids=("CWE-287", "CWE-306"),
            priority=Pri.HIGH,
            max_requests=100,
            tags=("mobile", "api", "authentication"),
        ),
        _s(
            "mob-api-bola", "Mobile BOLA/IDOR Detector", 17,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.BOOLEAN_INFERENCE},
            description="Detects Broken Object Level Authorization (BOLA) in mobile APIs "
                        "by manipulating object IDs, UUIDs, and sequential identifiers "
                        "across user context boundaries.",
            attack_types=("idor", "bola"),
            cwe_ids=("CWE-639", "CWE-284"),
            priority=Pri.HIGH,
            max_requests=120,
            tags=("mobile", "api", "idor", "authorization"),
        ),
        _s(
            "mob-api-rate-limit", "Mobile API Rate Limit Tester", 17,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.STATISTICAL_ANALYSIS},
            description="Probes mobile API endpoints for missing or bypassable rate "
                        "limiting by varying headers (X-Forwarded-For), rotating tokens, "
                        "and measuring throttle response curves.",
            attack_types=("rate-limit-bypass",),
            cwe_ids=("CWE-770",),
            priority=Pri.NORMAL,
            max_requests=200,
            tags=("mobile", "api", "rate-limit"),
        ),
        _s(
            "mob-api-mass-assign", "Mobile Mass Assignment Scanner", 17,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Tests mobile API endpoints for mass assignment vulnerabilities "
                        "by injecting extra fields (role, isAdmin, balance) in POST/PUT "
                        "requests and comparing response state changes.",
            attack_types=("mass-assignment",),
            cwe_ids=("CWE-915",),
            min_mode=Mode.AUDIT,
            priority=Pri.HIGH,
            max_requests=80,
            tags=("mobile", "api", "mass-assignment"),
        ),
        _s(
            "mob-api-graphql", "Mobile GraphQL Security Tester", 17,
            {Cap.GRAPHQL_INTERACTION, Cap.API_INTERACTION, Cap.PAYLOAD_INJECTION},
            description="Tests mobile GraphQL endpoints for introspection exposure, query "
                        "depth/complexity abuse, batching attacks, and field-level "
                        "authorization bypass through alias and fragment manipulation.",
            attack_types=("graphql-abuse", "introspection-leak"),
            cwe_ids=("CWE-200", "CWE-770"),
            priority=Pri.HIGH,
            max_requests=80,
            tags=("mobile", "api", "graphql"),
        ),

        # ── Token / Session (3) ──────────────────────────────────────
        _s(
            "mob-token-jwt", "Mobile JWT Security Analyzer", 17,
            {Cap.API_INTERACTION, Cap.PATTERN_MATCHING, Cap.PAYLOAD_INJECTION},
            description="Analyzes JWT tokens from mobile APIs for algorithm confusion "
                        "(none, HS256/RS256 swap), weak secrets, missing expiry, excessive "
                        "claims exposure, and JWK injection attacks.",
            attack_types=("jwt-abuse",),
            cwe_ids=("CWE-347", "CWE-327", "CWE-345"),
            priority=Pri.HIGH,
            max_requests=60,
            detection_patterns=(
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.",
                r'"alg"\s*:\s*"none"',
            ),
            tags=("mobile", "jwt", "token"),
        ),
        _s(
            "mob-token-refresh", "Mobile Refresh Token Auditor", 17,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE},
            description="Tests refresh token lifecycle: rotation enforcement, revocation "
                        "after password change, replay protection, binding to device "
                        "fingerprint, and refresh-to-access token scope escalation.",
            attack_types=("token-abuse", "session-fixation"),
            cwe_ids=("CWE-613", "CWE-384"),
            priority=Pri.NORMAL,
            max_requests=50,
            tags=("mobile", "token", "refresh", "session"),
        ),
        _s(
            "mob-session-pinning", "Mobile Session Pinning Tester", 17,
            {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
            description="Verifies that mobile sessions are bound to device context by "
                        "replaying session tokens across different user-agents, IP "
                        "addresses, and device identifiers to detect session hijacking risk.",
            attack_types=("session-hijack",),
            cwe_ids=("CWE-384", "CWE-613"),
            priority=Pri.NORMAL,
            max_requests=40,
            tags=("mobile", "session", "device-binding"),
        ),

        # ── Deep Link / WebView (3) ──────────────────────────────────
        _s(
            "mob-deeplink-hijack", "Deep Link Hijack Analyzer", 17,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.JS_ANALYSIS},
            description="Analyzes iOS Universal Links (apple-app-site-association) and "
                        "Android App Links (assetlinks.json) for misconfigured intent "
                        "filters, missing autoVerify, and deep link interception vectors.",
            attack_types=("deep-link-hijack",),
            cwe_ids=("CWE-940",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=30,
            detection_patterns=(
                r"apple-app-site-association",
                r"assetlinks\.json",
            ),
            tags=("mobile", "deep-link", "intent"),
        ),
        _s(
            "mob-webview-bridge", "WebView JavaScript Bridge Inspector", 17,
            {Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING, Cap.HTTP_PROBE},
            description="Identifies exposed JavaScript bridge interfaces in mobile "
                        "WebViews that allow cross-context invocation, file access via "
                        "file:// URIs, and native function calls from untrusted web content.",
            attack_types=("webview-rce", "js-bridge-abuse"),
            cwe_ids=("CWE-749", "CWE-927"),
            priority=Pri.HIGH,
            max_requests=40,
            detection_patterns=(
                r"addJavascriptInterface",
                r"webkit\.messageHandlers",
                r"JSContext",
            ),
            tags=("mobile", "webview", "js-bridge"),
        ),
        _s(
            "mob-custom-scheme", "Custom URL Scheme Fuzzer", 17,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
            description="Fuzzes custom URL schemes (myapp://) discovered in application "
                        "manifests and web content for parameter injection, path traversal, "
                        "and unvalidated redirect through scheme handlers.",
            attack_types=("scheme-hijack", "open-redirect"),
            cwe_ids=("CWE-939", "CWE-601"),
            min_mode=Mode.AUDIT,
            priority=Pri.NORMAL,
            max_requests=50,
            tags=("mobile", "url-scheme", "fuzzing"),
        ),

        # ── Biometric / Root Detection (2) ───────────────────────────
        _s(
            "mob-root-detect-bypass", "Root/Jailbreak Detection Auditor", 17,
            {Cap.API_INTERACTION, Cap.PATTERN_MATCHING},
            description="Assesses mobile API endpoints for root/jailbreak detection "
                        "enforcement by sending crafted device attestation payloads "
                        "(SafetyNet, DeviceCheck, App Attest) with tampered integrity verdicts.",
            attack_types=("root-bypass", "integrity-check-bypass"),
            cwe_ids=("CWE-693",),
            min_mode=Mode.AUDIT,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("mobile", "root-detect", "jailbreak", "attestation"),
        ),
        _s(
            "mob-biometric-bypass", "Biometric Authentication Bypass Tester", 17,
            {Cap.API_INTERACTION, Cap.PATTERN_MATCHING},
            description="Tests whether biometric authentication is enforced server-side "
                        "or merely client-side by replaying API calls without biometric "
                        "challenge tokens and checking for crypto-backed verification.",
            attack_types=("biometric-bypass",),
            cwe_ids=("CWE-287", "CWE-306"),
            min_mode=Mode.AUDIT,
            priority=Pri.NORMAL,
            max_requests=20,
            tags=("mobile", "biometric", "authentication"),
        ),

        # ── IoT Protocols: MQTT / CoAP / UPnP (4) ───────────────────
        _s(
            "iot-mqtt-scanner", "MQTT Broker Security Scanner", 17,
            {Cap.PORT_SCAN, Cap.API_INTERACTION, Cap.PATTERN_MATCHING},
            description="Discovers MQTT brokers on standard (1883) and TLS (8883) ports, "
                        "tests for anonymous access, wildcard topic subscription (#), "
                        "and $SYS tree information disclosure.",
            attack_types=("mqtt-abuse",),
            target_technologies=("mqtt",),
            cwe_ids=("CWE-306", "CWE-319"),
            priority=Pri.HIGH,
            max_requests=50,
            tags=("iot", "mqtt", "broker"),
        ),
        _s(
            "iot-coap-tester", "CoAP Endpoint Security Tester", 17,
            {Cap.API_INTERACTION, Cap.PATTERN_MATCHING},
            description="Probes CoAP endpoints for missing DTLS, unauthenticated resource "
                        "access, .well-known/core resource directory enumeration, and "
                        "observe notification abuse.",
            attack_types=("coap-abuse",),
            target_technologies=("coap",),
            cwe_ids=("CWE-306", "CWE-319"),
            priority=Pri.NORMAL,
            max_requests=40,
            tags=("iot", "coap", "dtls"),
        ),
        _s(
            "iot-upnp-scanner", "UPnP/SSDP Discovery Scanner", 17,
            {Cap.PORT_SCAN, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Discovers UPnP devices via SSDP M-SEARCH, retrieves device "
                        "description XML, and tests SOAP action endpoints for command "
                        "injection and unauthorized control actions.",
            attack_types=("upnp-abuse",),
            target_technologies=("upnp",),
            cwe_ids=("CWE-306", "CWE-918"),
            priority=Pri.HIGH,
            max_requests=40,
            tags=("iot", "upnp", "ssdp"),
        ),
        _s(
            "iot-protocol-downgrade", "IoT Protocol Downgrade Tester", 17,
            {Cap.API_INTERACTION, Cap.TLS_IMPERSONATION, Cap.PATTERN_MATCHING},
            description="Tests IoT protocol endpoints for TLS/DTLS downgrade attacks, "
                        "fallback to plaintext MQTT/CoAP, and negotiation of deprecated "
                        "cipher suites or protocol versions.",
            attack_types=("protocol-downgrade",),
            cwe_ids=("CWE-757", "CWE-319"),
            min_mode=Mode.AUDIT,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("iot", "downgrade", "tls", "dtls"),
        ),

        # ── IoT Credentials / Firmware (4) ───────────────────────────
        _s(
            "iot-default-creds", "IoT Default Credential Tester", 17,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.PATTERN_MATCHING},
            description="Tests discovered IoT device management interfaces against "
                        "comprehensive default credential databases (admin/admin, root/root, "
                        "vendor-specific pairs) across HTTP, Telnet, and SSH.",
            attack_types=("default-credentials",),
            cwe_ids=("CWE-798", "CWE-1392"),
            min_mode=Mode.AUDIT,
            priority=Pri.HIGH,
            max_requests=100,
            tags=("iot", "credentials", "default-password"),
        ),
        _s(
            "iot-firmware-leak", "IoT Firmware Leak Detector", 17,
            {Cap.HTTP_PROBE, Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Searches for publicly accessible firmware update files (.bin, "
                        ".img, .uf2) on target web servers and vendor sites, checking for "
                        "unencrypted firmware with extractable credentials and keys.",
            attack_types=("firmware-leak",),
            cwe_ids=("CWE-312", "CWE-321"),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=40,
            tags=("iot", "firmware", "secrets"),
        ),
        _s(
            "iot-cert-pinning", "IoT Certificate Pinning Auditor", 17,
            {Cap.API_INTERACTION, Cap.TLS_IMPERSONATION},
            description="Tests IoT device API communications for certificate pinning "
                        "enforcement, trust-on-first-use weaknesses, and acceptance of "
                        "self-signed or expired certificates.",
            attack_types=("cert-pinning-bypass",),
            cwe_ids=("CWE-295",),
            min_mode=Mode.AUDIT,
            priority=Pri.NORMAL,
            max_requests=20,
            tags=("iot", "certificate", "pinning", "tls"),
        ),
        _s(
            "iot-update-mechanism", "IoT Update Mechanism Analyzer", 17,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.API_INTERACTION},
            description="Analyzes OTA update mechanisms for unsigned firmware acceptance, "
                        "HTTP-based update channels, rollback attacks, and missing version "
                        "pinning that could allow malicious update injection.",
            attack_types=("update-hijack",),
            cwe_ids=("CWE-494", "CWE-345"),
            min_mode=Mode.AUDIT,
            priority=Pri.HIGH,
            max_requests=30,
            tags=("iot", "ota", "firmware-update"),
        ),

        # ── IoT Web Interface (2) ────────────────────────────────────
        _s(
            "iot-web-panel", "IoT Web Admin Panel Scanner", 17,
            {Cap.HTTP_PROBE, Cap.CRAWL, Cap.PATTERN_MATCHING},
            description="Discovers and scans IoT device web administration panels for "
                        "common vulnerabilities: XSS in device name fields, command "
                        "injection in network config, CSRF on reboot/reset actions.",
            attack_types=("xss", "command-injection", "csrf"),
            cwe_ids=("CWE-79", "CWE-78", "CWE-352"),
            min_mode=Mode.AUDIT,
            priority=Pri.HIGH,
            max_requests=80,
            tags=("iot", "web-panel", "admin"),
        ),
        _s(
            "iot-api-undoc", "IoT Undocumented API Finder", 17,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.CRAWL},
            description="Enumerates hidden and undocumented REST/SOAP endpoints on IoT "
                        "devices by fuzzing common paths (/api, /cgi-bin, /goform, /HNAP1) "
                        "and analyzing JavaScript for hardcoded API routes.",
            attack_types=("api-enum", "hidden-endpoint"),
            cwe_ids=("CWE-200", "CWE-912"),
            min_mode=Mode.AUDIT,
            priority=Pri.NORMAL,
            max_requests=100,
            tags=("iot", "api", "enumeration"),
        ),

        # ── Mobile Data Transit (1) ──────────────────────────────────
        _s(
            "mob-data-transit", "Mobile Data Transit Analyzer", 17,
            {Cap.HTTP_PROBE, Cap.TLS_IMPERSONATION, Cap.PATTERN_MATCHING},
            description="Analyzes mobile app network traffic patterns for sensitive data "
                        "transmitted in cleartext, PII in URL parameters, analytics "
                        "payloads leaking user data, and certificate pinning gaps.",
            attack_types=("data-exposure", "cleartext-transit"),
            cwe_ids=("CWE-319", "CWE-532"),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=40,
            tags=("mobile", "data-transit", "tls", "privacy"),
        ),

        # ── Division Commander (1) ───────────────────────────────────
        _s(
            "mob-iot-commander", "Mobile & IoT Division Commander", 17,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Coordinates all Division 17 agents, routes mobile API findings "
                        "to token/session testers, correlates IoT protocol results with "
                        "firmware analysis, and manages device-specific scanning schedules.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("commander", "coordination"),
        ),
    ]
