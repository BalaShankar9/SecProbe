"""
Division 3 — Authentication & Session Management
===================================================
35 agents specializing in login security, session management, JWT attacks,
OAuth/OIDC flows, SAML/SSO bypasses, CSRF, registration abuse, and
token analysis.
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


# ═══════════════════════════════════════════════════════════════════════
# Login & Brute-Force (5)
# ═══════════════════════════════════════════════════════════════════════

_login = [
    _s("auth-login-brute", "Credential Brute-Force Agent", 3,
       {Cap.HTTP_PROBE, Cap.RATE_ADAPTATION, Cap.PATTERN_MATCHING},
       description="Tests login endpoints for weak credentials using common username/password lists with adaptive throttling",
       attack_types=("brute-force",), cwe_ids=("CWE-307", "CWE-521"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=500, timeout=900,
       payloads=("auth/common_creds.txt",),
       detection_patterns=(r"Invalid (username|password)", r"Login failed", r"Account locked"),
       tags=("auth", "brute-force", "login")),

    _s("auth-login-spray", "Password Spray Agent", 3,
       {Cap.HTTP_PROBE, Cap.RATE_ADAPTATION, Cap.PATTERN_MATCHING},
       description="Tests a small set of common passwords against many usernames to evade per-account lockouts",
       attack_types=("password-spray",), cwe_ids=("CWE-307",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=600,
       payloads=("auth/spray_passwords.txt",),
       detection_patterns=(r"Invalid credentials", r"Too many attempts"),
       tags=("auth", "password-spray", "lockout")),

    _s("auth-login-enum", "Username Enumeration Agent", 3,
       {Cap.HTTP_PROBE, Cap.RESPONSE_DIFF, Cap.STATISTICAL_ANALYSIS},
       description="Detects username enumeration via response time, body length, and error message differences",
       attack_types=("user-enumeration",), cwe_ids=("CWE-204",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"User not found", r"No such user", r"Invalid username"),
       tags=("auth", "enumeration", "username")),

    _s("auth-login-bypass", "Authentication Bypass Agent", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.PAYLOAD_INJECTION},
       description="Tests for auth bypass via SQL injection in login, default credentials, forced browsing, and missing auth checks",
       attack_types=("auth-bypass",), cwe_ids=("CWE-287",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("auth/bypass_payloads.txt",),
       detection_patterns=(r"Welcome", r"Dashboard", r"admin"),
       tags=("auth", "bypass", "login")),

    _s("auth-login-mfa", "MFA Bypass Analyst", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.BOOLEAN_INFERENCE},
       description="Tests MFA implementation for race conditions, code reuse, brute-force, and step-skipping bypasses",
       attack_types=("mfa-bypass",), cwe_ids=("CWE-308",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"verification code", r"2FA", r"OTP"),
       tags=("auth", "mfa", "2fa", "bypass")),
]

# ═══════════════════════════════════════════════════════════════════════
# Session Management (5)
# ═══════════════════════════════════════════════════════════════════════

_session = [
    _s("auth-session-fixation", "Session Fixation Detector", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests whether session IDs are rotated after login and whether pre-auth tokens survive authentication",
       attack_types=("session-fixation",), cwe_ids=("CWE-384",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=180,
       detection_patterns=(r"Set-Cookie.*session", r"JSESSIONID", r"PHPSESSID"),
       tags=("session", "fixation")),

    _s("auth-session-hijack", "Session Hijacking Tester", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.HEADER_MANIPULATION},
       description="Validates session cookie flags (Secure, HttpOnly, SameSite) and tests for session theft vectors",
       attack_types=("session-hijack",), cwe_ids=("CWE-614", "CWE-1004"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=180,
       depends_on=("recon-header-cookie",),
       tags=("session", "hijack", "cookie")),

    _s("auth-session-timeout", "Session Timeout Validator", 3,
       {Cap.HTTP_PROBE, Cap.STATISTICAL_ANALYSIS},
       description="Measures idle and absolute session timeouts against security policy requirements",
       attack_types=("session-misconfiguration",), cwe_ids=("CWE-613",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=30, timeout=3600,
       tags=("session", "timeout", "expiry")),

    _s("auth-session-concurrent", "Concurrent Session Tester", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests whether multiple simultaneous sessions are allowed and whether old sessions are properly invalidated",
       attack_types=("session-misconfiguration",), cwe_ids=("CWE-613",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=300,
       tags=("session", "concurrent", "invalidation")),

    _s("auth-session-logout", "Logout Completeness Validator", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Verifies that logout properly destroys server-side session state and invalidates all tokens",
       attack_types=("session-misconfiguration",), cwe_ids=("CWE-613",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=30, timeout=180,
       tags=("session", "logout", "invalidation")),
]

# ═══════════════════════════════════════════════════════════════════════
# JWT Attacks (6)
# ═══════════════════════════════════════════════════════════════════════

_jwt = [
    _s("auth-jwt-none", "JWT None Algorithm Attack Agent", 3,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests JWT 'alg: none' bypass where signature verification is skipped entirely",
       attack_types=("jwt-attack",), cwe_ids=("CWE-327", "CWE-345"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=180,
       detection_patterns=(r"\"alg\":\s*\"none\"",),
       tags=("jwt", "none-alg", "bypass")),

    _s("auth-jwt-confusion", "JWT Algorithm Confusion Agent", 3,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Exploits RS256-to-HS256 key confusion where the public RSA key is used as HMAC secret",
       attack_types=("jwt-attack",), cwe_ids=("CWE-327",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=300,
       tags=("jwt", "algorithm-confusion", "rs256", "hs256")),

    _s("auth-jwt-kid", "JWT KID Injection Agent", 3,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests key ID (kid) header parameter for directory traversal, SQL injection, and command injection",
       attack_types=("jwt-attack",), cwe_ids=("CWE-22", "CWE-89"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("auth/jwt_kid.txt",),
       detection_patterns=(r"\"kid\":", r"\.\./"),
       tags=("jwt", "kid", "injection")),

    _s("auth-jwt-jwks", "JWT JWK/JWKS Spoofing Agent", 3,
       {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
       description="Tests JKU/X5U header injection to point token verification at attacker-controlled key servers",
       attack_types=("jwt-attack",), cwe_ids=("CWE-345",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=300,
       detection_patterns=(r"\"jku\":", r"\"x5u\":", r"\.well-known/jwks"),
       tags=("jwt", "jwks", "jku", "spoofing")),

    _s("auth-jwt-claims", "JWT Claims Tampering Agent", 3,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING, Cap.PRIVILEGE_ESCALATION},
       description="Modifies JWT payload claims (sub, role, admin, exp, iss) to test authorization enforcement",
       attack_types=("jwt-attack",), cwe_ids=("CWE-269", "CWE-345"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"\"role\":", r"\"admin\":", r"\"sub\":"),
       tags=("jwt", "claims", "tampering", "privilege")),

    _s("auth-jwt-crack", "JWT Secret Brute-Force Agent", 3,
       {Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
       description="Attempts offline brute-force of weak HMAC secrets used in HS256/HS384/HS512 JWT signing",
       attack_types=("jwt-attack",), cwe_ids=("CWE-326", "CWE-521"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=0, timeout=600,
       payloads=("auth/jwt_secrets.txt",),
       tags=("jwt", "brute-force", "hmac", "secret")),
]

# ═══════════════════════════════════════════════════════════════════════
# OAuth / OIDC (4)
# ═══════════════════════════════════════════════════════════════════════

_oauth = [
    _s("auth-oauth-redirect", "OAuth Redirect URI Validator", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests redirect_uri for open redirect, subdomain matching, path traversal, and parameter pollution bypasses",
       attack_types=("oauth-misconfiguration",), cwe_ids=("CWE-601",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"redirect_uri", r"code=", r"access_token="),
       tags=("oauth", "redirect", "open-redirect")),

    _s("auth-oauth-state", "OAuth State Parameter Tester", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Validates the state parameter for CSRF protection in OAuth flows and tests for state fixation",
       attack_types=("oauth-misconfiguration",), cwe_ids=("CWE-352",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=180,
       detection_patterns=(r"state=", r"csrf"),
       tags=("oauth", "state", "csrf")),

    _s("auth-oauth-scope", "OAuth Scope Escalation Agent", 3,
       {Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION, Cap.PATTERN_MATCHING},
       description="Tests for scope escalation by requesting additional scopes and testing token permissions beyond granted scope",
       attack_types=("oauth-misconfiguration",), cwe_ids=("CWE-269",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"scope=", r"insufficient_scope"),
       tags=("oauth", "scope", "escalation")),

    _s("auth-oauth-token-leak", "OAuth Token Leakage Detector", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.JS_ANALYSIS},
       description="Detects access token leakage via Referer header, browser history, and implicit flow fragment exposure",
       attack_types=("oauth-misconfiguration",), cwe_ids=("CWE-200", "CWE-598"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=180,
       detection_patterns=(r"access_token=", r"token_type=bearer"),
       tags=("oauth", "token-leak", "implicit-flow")),
]

# ═══════════════════════════════════════════════════════════════════════
# SAML / SSO (3)
# ═══════════════════════════════════════════════════════════════════════

_saml = [
    _s("auth-saml-sig", "SAML Signature Bypass Agent", 3,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests SAML signature wrapping, removal, and digest mismatch attacks on assertion verification",
       attack_types=("saml-attack",), cwe_ids=("CWE-347",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"<saml:Assertion", r"<ds:SignatureValue", r"SAMLResponse"),
       tags=("saml", "signature", "wrapping")),

    _s("auth-saml-inject", "SAML XML Injection Agent", 3,
       {Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests for XML injection in SAML assertions including XXE, comment injection, and entity expansion",
       attack_types=("saml-attack", "xxe"), cwe_ids=("CWE-611", "CWE-91"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("auth/saml_inject.txt",),
       detection_patterns=(r"<!ENTITY", r"<!DOCTYPE", r"SYSTEM"),
       tags=("saml", "xxe", "xml-injection")),

    _s("auth-saml-replay", "SAML Replay & Recipient Mismatch Agent", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests assertion replay, audience restriction bypass, and recipient/destination mismatch in SAML SSO",
       attack_types=("saml-attack",), cwe_ids=("CWE-294",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=300,
       detection_patterns=(r"NotOnOrAfter", r"Audience", r"Recipient"),
       tags=("saml", "replay", "sso")),
]

# ═══════════════════════════════════════════════════════════════════════
# CSRF (3)
# ═══════════════════════════════════════════════════════════════════════

_csrf = [
    _s("auth-csrf-token", "CSRF Token Validation Agent", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.BROWSER_AUTOMATION},
       description="Tests CSRF token presence, randomness, binding to session, and acceptance of missing/modified tokens",
       attack_types=("csrf",), cwe_ids=("CWE-352",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"csrf", r"_token", r"authenticity_token", r"__RequestVerificationToken"),
       tags=("csrf", "token", "validation")),

    _s("auth-csrf-method", "CSRF Method Override Agent", 3,
       {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
       description="Tests if CSRF protections can be bypassed via method override (X-HTTP-Method-Override, _method param)",
       attack_types=("csrf",), cwe_ids=("CWE-352",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=180,
       detection_patterns=(r"X-HTTP-Method-Override", r"_method"),
       tags=("csrf", "method-override")),

    _s("auth-csrf-samesite", "CSRF SameSite Cookie Analyzer", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Evaluates SameSite cookie attribute effectiveness and tests cross-origin submission vectors",
       attack_types=("csrf",), cwe_ids=("CWE-352", "CWE-1275"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=30, timeout=180,
       depends_on=("recon-header-cookie",),
       tags=("csrf", "samesite", "cookie")),
]

# ═══════════════════════════════════════════════════════════════════════
# Registration & Account Lockout (4)
# ═══════════════════════════════════════════════════════════════════════

_registration = [
    _s("auth-reg-abuse", "Registration Abuse Agent", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.PAYLOAD_INJECTION},
       description="Tests registration for mass sign-up abuse, duplicate accounts, input validation, and email verification bypass",
       attack_types=("registration-abuse",), cwe_ids=("CWE-799",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       tags=("registration", "abuse", "enumeration")),

    _s("auth-lockout-test", "Account Lockout Tester", 3,
       {Cap.HTTP_PROBE, Cap.RATE_ADAPTATION, Cap.STATISTICAL_ANALYSIS},
       description="Tests lockout thresholds, lockout duration, lockout bypass via header/IP rotation, and permanent lockout DoS",
       attack_types=("account-lockout",), cwe_ids=("CWE-307",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       tags=("lockout", "brute-force", "dos")),

    _s("auth-reset-flow", "Password Reset Flow Analyzer", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.BOOLEAN_INFERENCE},
       description="Tests password reset for token predictability, expiry enforcement, reuse, and host header poisoning",
       attack_types=("password-reset",), cwe_ids=("CWE-640",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"reset.*token", r"forgot.*password", r"reset_password"),
       tags=("password-reset", "token", "flow")),

    _s("auth-captcha-bypass", "CAPTCHA Bypass Agent", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests CAPTCHA implementations for reuse, missing server-side validation, and response manipulation bypasses",
       attack_types=("captcha-bypass",), cwe_ids=("CWE-804",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=180,
       detection_patterns=(r"captcha", r"recaptcha", r"hcaptcha"),
       tags=("captcha", "bypass", "bot-protection")),
]

# ═══════════════════════════════════════════════════════════════════════
# Token Analysis (4)
# ═══════════════════════════════════════════════════════════════════════

_token = [
    _s("auth-token-entropy", "Token Entropy Analyzer", 3,
       {Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Collects and statistically analyzes session tokens for insufficient randomness and predictable patterns",
       attack_types=("weak-token",), cwe_ids=("CWE-330", "CWE-331"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       tags=("token", "entropy", "randomness")),

    _s("auth-token-predict", "Token Prediction Agent", 3,
       {Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING, Cap.BOOLEAN_INFERENCE},
       description="Attempts to predict future session/reset tokens based on sequential patterns and timestamp correlation",
       attack_types=("token-prediction",), cwe_ids=("CWE-330",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=600,
       tags=("token", "prediction", "sequential")),

    _s("auth-token-storage", "Client-Side Token Storage Auditor", 3,
       {Cap.JS_ANALYSIS, Cap.BROWSER_AUTOMATION, Cap.PATTERN_MATCHING},
       description="Checks if tokens are stored in localStorage, sessionStorage, or cookies without adequate protection",
       attack_types=("token-storage",), cwe_ids=("CWE-922",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=20, timeout=180,
       detection_patterns=(r"localStorage\.setItem", r"sessionStorage", r"document\.cookie"),
       tags=("token", "storage", "client-side")),

    _s("auth-token-revocation", "Token Revocation Tester", 3,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests whether revoked/expired tokens are still accepted by the server after logout or password change",
       attack_types=("token-revocation",), cwe_ids=("CWE-613",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=300,
       tags=("token", "revocation", "expiry")),
]

# ═══════════════════════════════════════════════════════════════════════
# Commander (1)
# ═══════════════════════════════════════════════════════════════════════

_commander = [
    _s("auth-commander", "Auth Division Commander", 3,
       {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
       description="Orchestrates Division 3 agents, correlates auth findings across login/session/token layers, and prioritizes tests",
       attack_types=(),
       min_mode=Mode.AUDIT, priority=Pri.CRITICAL, max_requests=0, timeout=3600,
       tags=("commander", "coordination", "division-3")),
]


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def agents() -> list[AgentSpec]:
    """Return all 35 Division 3 (Authentication & Session) agents."""
    all_agents = _login + _session + _jwt + _oauth + _saml + _csrf + _registration + _token + _commander
    assert len(all_agents) == 35, f"Division 3 must have exactly 35 agents, got {len(all_agents)}"
    return all_agents
