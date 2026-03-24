"""
Division 7: Cryptographic Attacks — 25 agents.

Covers TLS/SSL version testing, cipher/certificate analysis, known TLS attacks,
JWT cryptographic weaknesses, hash/RNG issues, timing side-channels, and
protocol downgrade vectors.
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
        # ── TLS/SSL Versions (4) ─────────────────────────────────────
        _s(
            "cr-sslv3-detect", "SSLv3 POODLE Detector", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Tests for SSLv3 support which is vulnerable to the POODLE attack "
                        "(CVE-2014-3566) allowing decryption of CBC-mode ciphertext",
            attack_types=("tls-misconfiguration",),
            cwe_ids=("CWE-326",),
            target_technologies=("ssl", "tls"),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("tls", "sslv3", "poodle"),
        ),
        _s(
            "cr-tls10-detect", "TLS 1.0 Deprecation Scanner", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE, Cap.COMPLIANCE_MAPPING},
            description="Detects TLS 1.0 support, deprecated per RFC 8996. Checks for "
                        "BEAST vulnerability (CVE-2011-3389) in CBC cipher suites",
            attack_types=("tls-misconfiguration",),
            cwe_ids=("CWE-326",),
            target_technologies=("tls",),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("tls", "tls10", "beast", "compliance"),
        ),
        _s(
            "cr-tls11-detect", "TLS 1.1 Deprecation Scanner", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE, Cap.COMPLIANCE_MAPPING},
            description="Detects TLS 1.1 support, deprecated per RFC 8996. Reports "
                        "PCI-DSS non-compliance for payment card environments",
            attack_types=("tls-misconfiguration",),
            cwe_ids=("CWE-326",),
            target_technologies=("tls",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("tls", "tls11", "pci-dss"),
        ),
        _s(
            "cr-tls13-feature", "TLS 1.3 Feature Analyzer", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE, Cap.BASELINE_PROFILING},
            description="Verifies TLS 1.3 deployment quality: 0-RTT replay risks, "
                        "supported cipher suites (only AEAD), and key share groups",
            attack_types=("tls-misconfiguration",),
            cwe_ids=("CWE-326",),
            target_technologies=("tls",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("tls", "tls13", "0-rtt"),
        ),

        # ── Cipher / Certificate Analysis (4) ───────────────────────
        _s(
            "cr-weak-cipher", "Weak Cipher Suite Detector", 7,
            {Cap.TLS_IMPERSONATION, Cap.PATTERN_MATCHING, Cap.COMPLIANCE_MAPPING},
            description="Identifies weak cipher suites: NULL ciphers, EXPORT grades, "
                        "RC4, DES, 3DES, and anonymous key exchanges (ADH/AECDH)",
            attack_types=("weak-cipher",),
            cwe_ids=("CWE-326", "CWE-327"),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("cipher", "weak-crypto", "compliance"),
        ),
        _s(
            "cr-cert-chain", "Certificate Chain Validator", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Validates X.509 certificate chains: expiration, self-signed roots, "
                        "missing intermediates, weak signature algorithms (SHA-1, MD5)",
            attack_types=("certificate-issue",),
            cwe_ids=("CWE-295", "CWE-296"),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("certificate", "x509", "chain"),
        ),
        _s(
            "cr-cert-transparency", "Certificate Transparency Monitor", 7,
            {Cap.HTTP_PROBE, Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Queries CT logs for target domain certificates, detecting "
                        "unauthorized issuance, shadow domains, and wildcard abuse",
            attack_types=("certificate-issue",),
            cwe_ids=("CWE-295",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("certificate", "ct-log", "transparency"),
        ),
        _s(
            "cr-key-strength", "Key Strength Analyzer", 7,
            {Cap.TLS_IMPERSONATION, Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING},
            description="Evaluates cryptographic key strength: RSA < 2048 bits, "
                        "ECC < 256 bits, DHE < 2048 bits, and Debian weak key detection",
            attack_types=("weak-key",),
            cwe_ids=("CWE-326",),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("key-strength", "rsa", "ecc"),
        ),

        # ── Known TLS Attacks (4) ───────────────────────────────────
        _s(
            "cr-heartbleed", "Heartbleed Vulnerability Tester", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE, Cap.DATA_EXTRACTION},
            description="Tests for OpenSSL Heartbleed (CVE-2014-0160) by sending malformed "
                        "TLS heartbeat requests and checking for memory leakage in responses",
            attack_types=("heartbleed",),
            cwe_ids=("CWE-126",),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("heartbleed", "openssl", "memory-leak"),
        ),
        _s(
            "cr-robot-attack", "ROBOT Attack Tester", 7,
            {Cap.TLS_IMPERSONATION, Cap.STATISTICAL_ANALYSIS, Cap.TIME_BASED},
            description="Tests for Return Of Bleichenbacher's Oracle Threat (ROBOT) "
                        "by detecting RSA PKCS#1 v1.5 padding oracle in TLS handshakes",
            attack_types=("robot",),
            cwe_ids=("CWE-203",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("robot", "bleichenbacher", "rsa"),
        ),
        _s(
            "cr-sweet32", "SWEET32 Birthday Attack Detector", 7,
            {Cap.TLS_IMPERSONATION, Cap.PATTERN_MATCHING},
            description="Detects 64-bit block ciphers (3DES, Blowfish) vulnerable to "
                        "SWEET32 birthday attack (CVE-2016-2183) in long-lived TLS sessions",
            attack_types=("sweet32",),
            cwe_ids=("CWE-326",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("sweet32", "3des", "birthday"),
        ),
        _s(
            "cr-renegotiation", "TLS Renegotiation Tester", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE},
            description="Tests for insecure TLS renegotiation (CVE-2009-3555) and "
                        "client-initiated renegotiation DoS vectors",
            attack_types=("tls-misconfiguration",),
            cwe_ids=("CWE-310",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("tls", "renegotiation"),
        ),

        # ── JWT Crypto (3) ──────────────────────────────────────────
        _s(
            "cr-jwt-none-alg", "JWT None Algorithm Bypass Tester", 7,
            {Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Tests for JWT 'none' algorithm acceptance (CVE-2015-9235) "
                        "by sending tokens with alg:none to bypass signature verification",
            attack_types=("jwt-bypass",),
            cwe_ids=("CWE-345", "CWE-347"),
            payloads=("jwt_none_alg.txt",),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("jwt", "none-algorithm", "auth-bypass"),
        ),
        _s(
            "cr-jwt-key-confusion", "JWT Key Confusion Attacker", 7,
            {Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Exploits JWT RS256-to-HS256 algorithm confusion where the public "
                        "RSA key is used as HMAC secret to forge arbitrary tokens",
            attack_types=("jwt-bypass",),
            cwe_ids=("CWE-327", "CWE-345"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("jwt", "key-confusion", "algorithm-switch"),
        ),
        _s(
            "cr-jwt-jku-jwks", "JWT JKU/x5u Injection Specialist", 7,
            {Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
            description="Tests JWT header injection via jku (JWK Set URL) and x5u (X.509 URL) "
                        "parameters to redirect key fetching to attacker-controlled servers",
            attack_types=("jwt-bypass",),
            cwe_ids=("CWE-345", "CWE-918"),
            priority=Pri.HIGH,
            min_mode=Mode.REDTEAM,
            tags=("jwt", "jku", "x5u", "ssrf"),
        ),

        # ── Hash / RNG Weakness (3) ─────────────────────────────────
        _s(
            "cr-weak-hash", "Weak Hashing Algorithm Detector", 7,
            {Cap.PATTERN_MATCHING, Cap.HTTP_PROBE, Cap.RESPONSE_DIFF},
            description="Identifies usage of broken hash algorithms (MD5, SHA-1) in "
                        "password storage, HMAC signatures, and integrity checks",
            attack_types=("weak-hash",),
            cwe_ids=("CWE-328", "CWE-916"),
            detection_patterns=(
                r"[a-f0-9]{32}(?![a-f0-9])",
                r"[a-f0-9]{40}(?![a-f0-9])",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("hash", "md5", "sha1"),
        ),
        _s(
            "cr-prng-weakness", "PRNG Weakness Analyzer", 7,
            {Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING, Cap.HTTP_PROBE},
            description="Detects weak pseudo-random number generation in session tokens, "
                        "CSRF tokens, and password reset links via statistical analysis",
            attack_types=("weak-random",),
            cwe_ids=("CWE-330", "CWE-338"),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("prng", "randomness", "tokens"),
        ),
        _s(
            "cr-entropy-analyzer", "Token Entropy Analyzer", 7,
            {Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING, Cap.BASELINE_PROFILING},
            description="Measures Shannon entropy and chi-squared distribution of tokens "
                        "and session IDs to identify predictable generation patterns",
            attack_types=("weak-random",),
            cwe_ids=("CWE-330",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("entropy", "statistics", "tokens"),
        ),

        # ── Timing / Side-Channel (3) ───────────────────────────────
        _s(
            "cr-timing-oracle", "Cryptographic Timing Oracle Detector", 7,
            {Cap.TIME_BASED, Cap.STATISTICAL_ANALYSIS, Cap.HTTP_PROBE},
            description="Detects timing side-channels in cryptographic comparisons "
                        "(HMAC verification, password checks) using statistical timing analysis",
            attack_types=("timing-attack",),
            cwe_ids=("CWE-208",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            max_requests=500,
            tags=("timing", "side-channel", "oracle"),
        ),
        _s(
            "cr-padding-oracle", "Padding Oracle Specialist", 7,
            {Cap.PAYLOAD_INJECTION, Cap.ERROR_ANALYSIS, Cap.TIME_BASED},
            description="Tests for CBC padding oracle vulnerabilities by manipulating "
                        "ciphertext blocks and observing error responses (CVE-2016-0778 class)",
            attack_types=("padding-oracle",),
            cwe_ids=("CWE-209", "CWE-347"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("padding-oracle", "cbc", "decryption"),
        ),
        _s(
            "cr-cache-timing", "Cache Timing Side-Channel Tester", 7,
            {Cap.TIME_BASED, Cap.STATISTICAL_ANALYSIS, Cap.BROWSER_AUTOMATION},
            description="Exploits browser cache timing to infer cross-origin resource existence "
                        "and sizes, bypassing SOP via observable timing differences",
            attack_types=("timing-attack",),
            cwe_ids=("CWE-208", "CWE-203"),
            priority=Pri.LOW,
            min_mode=Mode.AUDIT,
            tags=("cache-timing", "side-channel", "browser"),
        ),

        # ── Protocol Downgrade (3) ──────────────────────────────────
        _s(
            "cr-tls-downgrade", "TLS Downgrade Attack Tester", 7,
            {Cap.TLS_IMPERSONATION, Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
            description="Tests for TLS downgrade attacks by checking SCSV fallback "
                        "signaling and verifying resistance to MITM version rollback",
            attack_types=("protocol-downgrade",),
            cwe_ids=("CWE-757",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("downgrade", "tls", "scsv"),
        ),
        _s(
            "cr-hsts-bypass", "HSTS Bypass Analyzer", 7,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PATTERN_MATCHING},
            description="Analyzes HSTS deployment: missing headers, short max-age, "
                        "missing includeSubDomains, and preload eligibility gaps",
            attack_types=("protocol-downgrade",),
            cwe_ids=("CWE-319",),
            detection_patterns=(
                r"Strict-Transport-Security",
                r"max-age=(\d+)",
                r"includeSubDomains",
                r"preload",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("hsts", "https", "downgrade"),
        ),
        _s(
            "cr-https-stripping", "HTTPS Stripping Detector", 7,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.CRAWL},
            description="Tests for SSL stripping opportunities: HTTP-to-HTTPS redirects "
                        "without HSTS, mixed content, and insecure form action URLs",
            attack_types=("protocol-downgrade",),
            cwe_ids=("CWE-319", "CWE-311"),
            detection_patterns=(
                r'action="http://',
                r'src="http://',
                r'href="http://',
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("ssl-stripping", "mixed-content", "https"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "cr-commander", "Division 7 Commander — Cryptographic Attacks", 7,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Orchestrates all Division 7 crypto agents. Sequences TLS version "
                        "probes before cipher analysis, coordinates timing attack sample "
                        "collection, and manages JWT bypass chains across agents",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            tags=("commander", "division-7", "crypto"),
            max_requests=0,
            timeout=600,
        ),
    ]
