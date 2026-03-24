"""
Division 4 — Authorization & Access Control
==============================================
30 agents specializing in IDOR, BOLA/BFLA, privilege escalation,
method/path bypass, role testing, multi-tenant isolation, feature
gating, and admin panel discovery.
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
# IDOR by Type (4)
# ═══════════════════════════════════════════════════════════════════════

_idor = [
    _s("authz-idor-numeric", "Numeric IDOR Specialist", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.BOOLEAN_INFERENCE},
       description="Tests sequential numeric IDs in URLs, parameters, and JSON bodies for unauthorized resource access",
       attack_types=("idor",), cwe_ids=("CWE-639",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"/users/\d+", r"\"id\":\s*\d+", r"userId=\d+"),
       tags=("idor", "numeric", "sequential")),

    _s("authz-idor-uuid", "UUID IDOR Specialist", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Harvests UUIDs from responses and tests cross-account access with swapped identifiers",
       attack_types=("idor",), cwe_ids=("CWE-639",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",),
       tags=("idor", "uuid", "guid")),

    _s("authz-idor-filename", "Filename IDOR Specialist", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.CRAWL},
       description="Tests file download/upload endpoints for path traversal and unauthorized access to other users' files",
       attack_types=("idor", "path-traversal"), cwe_ids=("CWE-639", "CWE-22"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"filename=", r"/download/", r"/upload/", r"\.\."),
       payloads=("authz/path_traversal.txt",),
       tags=("idor", "filename", "path-traversal")),

    _s("authz-idor-graphql", "GraphQL IDOR Specialist", 4,
       {Cap.GRAPHQL_INTERACTION, Cap.PATTERN_MATCHING, Cap.HTTP_PROBE},
       description="Tests GraphQL node queries and mutations for unauthorized object access via ID parameter swapping",
       attack_types=("idor",), cwe_ids=("CWE-639",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"\"node\"", r"\"id\":", r"query.*\(id:"),
       tags=("idor", "graphql", "node")),
]

# ═══════════════════════════════════════════════════════════════════════
# BOLA / BFLA (3)
# ═══════════════════════════════════════════════════════════════════════

_bola = [
    _s("authz-bola-api", "BOLA API Object Access Tester", 4,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests API endpoints for Broken Object Level Authorization by swapping resource IDs between user contexts",
       attack_types=("bola",), cwe_ids=("CWE-639",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=600,
       detection_patterns=(r"\"data\":", r"\"error\":\s*\"forbidden\""),
       tags=("bola", "api", "object-level")),

    _s("authz-bfla-func", "BFLA Function Level Access Tester", 4,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
       description="Tests Broken Function Level Authorization by calling admin-only endpoints with regular user tokens",
       attack_types=("bfla",), cwe_ids=("CWE-285",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"/admin/", r"\"role\":", r"403", r"forbidden"),
       tags=("bfla", "function-level", "admin")),

    _s("authz-bola-mass", "Mass Assignment / BOLA Property Tester", 4,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
       description="Tests for mass assignment and property-level authorization by injecting extra fields (role, admin, verified) in updates",
       attack_types=("mass-assignment", "bola"), cwe_ids=("CWE-915",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("authz/mass_assign.txt",),
       detection_patterns=(r"\"admin\":\s*true", r"\"role\":\s*\"admin\""),
       tags=("mass-assignment", "bola", "property-level")),
]

# ═══════════════════════════════════════════════════════════════════════
# Privilege Escalation (4)
# ═══════════════════════════════════════════════════════════════════════

_privesc = [
    _s("authz-privesc-horizontal", "Horizontal Privilege Escalation Agent", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.PRIVILEGE_ESCALATION},
       description="Tests access to peer-level resources by swapping user identifiers in cookies, headers, and parameters",
       attack_types=("privilege-escalation",), cwe_ids=("CWE-639",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       tags=("privesc", "horizontal", "peer-access")),

    _s("authz-privesc-vertical", "Vertical Privilege Escalation Agent", 4,
       {Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION, Cap.PATTERN_MATCHING},
       description="Tests access to higher-privilege resources and actions using lower-privilege credentials",
       attack_types=("privilege-escalation",), cwe_ids=("CWE-269",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"admin", r"superuser", r"manager", r"403"),
       tags=("privesc", "vertical", "role-escalation")),

    _s("authz-privesc-param", "Parameter-Based Privilege Escalation Agent", 4,
       {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PRIVILEGE_ESCALATION},
       description="Tests hidden parameters (isAdmin, role, group_id) that may grant elevated privileges when tampered",
       attack_types=("privilege-escalation",), cwe_ids=("CWE-269",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("authz/privesc_params.txt",),
       tags=("privesc", "parameter", "hidden-field")),

    _s("authz-privesc-chain", "Privilege Escalation Chain Builder", 4,
       {Cap.CHAIN_BUILDING, Cap.PRIVILEGE_ESCALATION, Cap.PROOF_GENERATION},
       description="Chains multiple low-severity authz flaws into complete privilege escalation paths from guest to admin",
       attack_types=("privilege-escalation",), cwe_ids=("CWE-269",),
       min_mode=Mode.REDTEAM, priority=Pri.HIGH, max_requests=100, timeout=600,
       tags=("privesc", "chain", "exploit")),
]

# ═══════════════════════════════════════════════════════════════════════
# Method & Path Bypass (4)
# ═══════════════════════════════════════════════════════════════════════

_method_path = [
    _s("authz-method-swap", "HTTP Method Tampering Agent", 4,
       {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
       description="Tests if authorization differs across HTTP methods (GET vs POST vs PUT vs DELETE vs PATCH) on the same resource",
       attack_types=("method-bypass",), cwe_ids=("CWE-650",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       tags=("method", "swap", "verb-tampering")),

    _s("authz-path-normalize", "Path Normalization Bypass Agent", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests path-based auth bypass via dot segments, double encoding, case variation, trailing slashes, and semicolons",
       attack_types=("path-bypass",), cwe_ids=("CWE-706",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("authz/path_bypass.txt",),
       detection_patterns=(r"/\.\./", r"%2e%2e", r"//"),
       tags=("path", "normalization", "bypass")),

    _s("authz-header-bypass", "Authorization Header Bypass Agent", 4,
       {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
       description="Tests X-Original-URL, X-Rewrite-URL, X-Forwarded-For, and Host header overrides to bypass front-end authorization",
       attack_types=("header-bypass",), cwe_ids=("CWE-290",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(r"X-Original-URL", r"X-Rewrite-URL", r"X-Forwarded"),
       tags=("header", "bypass", "proxy")),

    _s("authz-version-bypass", "API Version Bypass Agent", 4,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE},
       description="Tests access to resources via older/deprecated API versions that may lack authorization enforcement",
       attack_types=("version-bypass",), cwe_ids=("CWE-285",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       detection_patterns=(r"/v1/", r"/v2/", r"/api/v\d+"),
       tags=("api-version", "bypass", "deprecated")),
]

# ═══════════════════════════════════════════════════════════════════════
# Role & Scope Testing (5)
# ═══════════════════════════════════════════════════════════════════════

_role_scope = [
    _s("authz-role-matrix", "Role Permission Matrix Validator", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
       description="Systematically maps which roles can access which endpoints and flags unexpected permissions",
       attack_types=("role-misconfiguration",), cwe_ids=("CWE-285",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=500, timeout=900,
       tags=("role", "matrix", "permission")),

    _s("authz-scope-exceed", "OAuth Scope Boundary Tester", 4,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
       description="Tests whether API calls succeed beyond the granted OAuth scope on resource servers",
       attack_types=("scope-violation",), cwe_ids=("CWE-269",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"insufficient_scope", r"scope="),
       tags=("scope", "oauth", "boundary")),

    _s("authz-default-deny", "Default-Deny Policy Validator", 4,
       {Cap.HTTP_PROBE, Cap.CRAWL, Cap.PATTERN_MATCHING},
       description="Probes for resources that return 200 without authentication — testing default-deny vs default-allow policy",
       attack_types=("missing-authz",), cwe_ids=("CWE-862",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=600,
       tags=("default-deny", "unauthenticated", "missing-auth")),

    _s("authz-field-level", "Field-Level Authorization Tester", 4,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.RESPONSE_DIFF},
       description="Tests whether API responses expose fields (SSN, email, salary) that the requesting role should not see",
       attack_types=("data-exposure",), cwe_ids=("CWE-200", "CWE-639"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       detection_patterns=(r"\"ssn\":", r"\"salary\":", r"\"password\":", r"\"email\":"),
       tags=("field-level", "data-exposure", "over-sharing")),

    _s("authz-rbac-consistency", "RBAC Consistency Checker", 4,
       {Cap.HTTP_PROBE, Cap.STATISTICAL_ANALYSIS, Cap.RESPONSE_DIFF},
       description="Compares authorization responses across identical requests from different user contexts to find inconsistencies",
       attack_types=("role-misconfiguration",), cwe_ids=("CWE-285",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=300, timeout=600,
       tags=("rbac", "consistency", "comparison")),
]

# ═══════════════════════════════════════════════════════════════════════
# Multi-Tenant Isolation (3)
# ═══════════════════════════════════════════════════════════════════════

_multitenant = [
    _s("authz-tenant-cross", "Cross-Tenant Data Access Tester", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.PRIVILEGE_ESCALATION},
       description="Tests if tenant A can access tenant B resources by swapping tenant IDs, subdomains, or org headers",
       attack_types=("tenant-isolation",), cwe_ids=("CWE-639", "CWE-284"),
       min_mode=Mode.AUDIT, priority=Pri.CRITICAL, max_requests=200, timeout=300,
       detection_patterns=(r"tenant_id", r"org_id", r"X-Tenant"),
       tags=("multitenant", "cross-tenant", "isolation")),

    _s("authz-tenant-admin", "Tenant Admin Escalation Agent", 4,
       {Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION, Cap.PATTERN_MATCHING},
       description="Tests if a regular tenant member can access tenant admin functions or management APIs",
       attack_types=("privilege-escalation",), cwe_ids=("CWE-269",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       tags=("multitenant", "admin", "escalation")),

    _s("authz-tenant-leak", "Tenant Data Leakage Detector", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.RESPONSE_DIFF},
       description="Detects cross-tenant data bleed in search results, autocomplete, shared caches, and aggregation endpoints",
       attack_types=("data-leakage",), cwe_ids=("CWE-200",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       tags=("multitenant", "leakage", "shared-resource")),
]

# ═══════════════════════════════════════════════════════════════════════
# Feature & Subscription Bypass (3)
# ═══════════════════════════════════════════════════════════════════════

_feature = [
    _s("authz-paywall-bypass", "Paywall/Subscription Bypass Agent", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.API_INTERACTION},
       description="Tests access to premium features and content without valid subscription by manipulating plan/tier parameters",
       attack_types=("paywall-bypass",), cwe_ids=("CWE-284",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       detection_patterns=(r"\"plan\":", r"\"tier\":", r"subscription"),
       tags=("paywall", "subscription", "bypass")),

    _s("authz-feature-flag", "Feature Flag Bypass Agent", 4,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.API_INTERACTION},
       description="Discovers and manipulates client-side feature flags to access unreleased or restricted functionality",
       attack_types=("feature-bypass",), cwe_ids=("CWE-284",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       detection_patterns=(r"feature_flag", r"\"enabled\":", r"\"beta\":"),
       tags=("feature-flag", "bypass", "unreleased")),

    _s("authz-rate-bypass", "Rate Limit Bypass Agent", 4,
       {Cap.HTTP_PROBE, Cap.RATE_ADAPTATION, Cap.HEADER_MANIPULATION},
       description="Tests rate limit enforcement for bypass via header manipulation, API key rotation, and endpoint aliasing",
       attack_types=("rate-limit-bypass",), cwe_ids=("CWE-770",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=200, timeout=300,
       detection_patterns=(r"429", r"rate.limit", r"X-RateLimit"),
       tags=("rate-limit", "bypass", "throttling")),
]

# ═══════════════════════════════════════════════════════════════════════
# Admin Panel Discovery (3)
# ═══════════════════════════════════════════════════════════════════════

_admin = [
    _s("authz-admin-panel", "Admin Panel Discovery Agent", 4,
       {Cap.CRAWL, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Discovers hidden admin panels and management interfaces via wordlist brute-force and common path probing",
       attack_types=("admin-discovery",), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=500, timeout=600,
       payloads=("authz/admin_paths.txt",),
       detection_patterns=(r"admin", r"dashboard", r"management", r"login"),
       tags=("admin", "panel", "discovery")),

    _s("authz-admin-debug", "Debug Endpoint Discovery Agent", 4,
       {Cap.CRAWL, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Finds exposed debug endpoints (phpinfo, elmah, trace.axd, actuator, debug toolbar) with sensitive information",
       attack_types=("debug-exposure",), cwe_ids=("CWE-215",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("authz/debug_endpoints.txt",),
       detection_patterns=(r"phpinfo", r"actuator", r"trace\.axd", r"debug"),
       tags=("debug", "endpoint", "exposure")),

    _s("authz-admin-api", "Admin API Endpoint Tester", 4,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
       description="Tests discovered admin API endpoints for missing authentication and authorization using unprivileged tokens",
       attack_types=("admin-bypass",), cwe_ids=("CWE-862", "CWE-285"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       depends_on=("authz-admin-panel",),
       tags=("admin", "api", "bypass")),
]

# ═══════════════════════════════════════════════════════════════════════
# Commander (1)
# ═══════════════════════════════════════════════════════════════════════

_commander = [
    _s("authz-commander", "Authorization Division Commander", 4,
       {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
       description="Orchestrates Division 4 agents, correlates authz findings across IDOR/BOLA/role layers, and manages user contexts",
       attack_types=(),
       min_mode=Mode.AUDIT, priority=Pri.CRITICAL, max_requests=0, timeout=3600,
       tags=("commander", "coordination", "division-4")),
]


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def agents() -> list[AgentSpec]:
    """Return all 30 Division 4 (Authorization & Access Control) agents."""
    all_agents = (
        _idor + _bola + _privesc + _method_path
        + _role_scope + _multitenant + _feature + _admin + _commander
    )
    assert len(all_agents) == 30, f"Division 4 must have exactly 30 agents, got {len(all_agents)}"
    return all_agents
