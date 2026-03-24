"""
Division 5 — API Security
============================
40 agents covering REST, GraphQL, WebSocket, gRPC, SOAP/XML-RPC
testing, and API meta-security (key exposure, CORS, error handling,
batch abuse, content negotiation, SSRF webhook, schema violation,
idempotency, file upload, rate limiting, versioning).
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
# REST API Testing (10)
# ═══════════════════════════════════════════════════════════════════════

_rest = [
    _s("api-rest-enum", "REST Endpoint Enumerator", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.CRAWL},
       description="Discovers REST API endpoints from OpenAPI/Swagger specs, HTML, JavaScript, and common path brute-force",
       attack_types=("api-recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=500, timeout=600,
       payloads=("api/rest_paths.txt",),
       detection_patterns=(r"swagger", r"openapi", r"/api/v\d+"),
       tags=("rest", "enumeration", "swagger")),

    _s("api-rest-method", "REST Method Enumeration Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE},
       description="Tests each endpoint with all HTTP methods (OPTIONS, HEAD, PUT, DELETE, PATCH, TRACE) to find unintended verbs",
       attack_types=("method-enumeration",), cwe_ids=("CWE-650",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=300,
       detection_patterns=(r"Allow:", r"405", r"200"),
       tags=("rest", "method", "verb")),

    _s("api-rest-content-type", "REST Content-Type Confusion Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
       description="Tests parser confusion by sending XML to JSON endpoints and vice versa to trigger deserialization flaws",
       attack_types=("content-type-confusion",), cwe_ids=("CWE-436",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       tags=("rest", "content-type", "confusion", "deserialization")),

    _s("api-rest-pagination", "REST Pagination Abuse Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests pagination parameters for data overexposure via large page sizes, negative offsets, and filter bypasses",
       attack_types=("data-exposure",), cwe_ids=("CWE-200",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       detection_patterns=(r"\"total\":", r"\"count\":", r"page=", r"limit="),
       tags=("rest", "pagination", "data-exposure")),

    _s("api-rest-mass-assign", "REST Mass Assignment Tester", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
       description="Tests POST/PUT/PATCH endpoints for mass assignment by including extra fields (role, admin, verified, balance)",
       attack_types=("mass-assignment",), cwe_ids=("CWE-915",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("api/mass_assign_fields.txt",),
       tags=("rest", "mass-assignment", "over-posting")),

    _s("api-rest-input-validation", "REST Input Validation Tester", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
       description="Tests API input validation with boundary values, type confusion, oversized payloads, and special characters",
       attack_types=("input-validation",), cwe_ids=("CWE-20",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=300,
       payloads=("api/input_validation.txt",),
       tags=("rest", "input-validation", "boundary")),

    _s("api-rest-bola", "REST BOLA/IDOR Specialist", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
       description="Tests for Broken Object Level Authorization by swapping object IDs across user contexts to access unauthorized resources",
       attack_types=("bola", "idor"), cwe_ids=("CWE-639",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=300, timeout=300,
       detection_patterns=(r"\"id\":", r"\"user_id\":", r"forbidden", r"unauthorized"),
       tags=("rest", "bola", "idor", "authorization")),

    _s("api-rest-bfla", "REST BFLA Specialist", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
       description="Tests for Broken Function Level Authorization by invoking admin-only operations with regular user tokens",
       attack_types=("bfla",), cwe_ids=("CWE-285",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("api/admin_endpoints.txt",),
       tags=("rest", "bfla", "function-level", "authorization")),

    _s("api-rest-ssrf", "REST SSRF Specialist", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.OOB_CALLBACK},
       description="Tests URL-accepting parameters for SSRF via internal IP, cloud metadata endpoints, and DNS rebinding",
       attack_types=("ssrf",), cwe_ids=("CWE-918",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("api/ssrf_payloads.txt",),
       detection_patterns=(r"169\.254\.169\.254", r"metadata", r"localhost"),
       tags=("rest", "ssrf", "internal")),

    _s("api-rest-cache-poison", "REST Cache Poisoning Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
       description="Tests for web cache poisoning via unkeyed headers, query parameters, and cache key normalization differences",
       attack_types=("cache-poisoning",), cwe_ids=("CWE-444",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       detection_patterns=(r"X-Cache", r"CF-Cache-Status", r"Age:", r"Vary:"),
       tags=("rest", "cache", "poisoning")),
]

# ═══════════════════════════════════════════════════════════════════════
# GraphQL (6)
# ═══════════════════════════════════════════════════════════════════════

_graphql = [
    _s("api-gql-introspection", "GraphQL Introspection Agent", 5,
       {Cap.GRAPHQL_INTERACTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests for enabled introspection queries and extracts full schema including types, queries, mutations, and subscriptions",
       attack_types=("graphql-recon",), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=20, timeout=180,
       detection_patterns=(r"__schema", r"__type", r"queryType"),
       tags=("graphql", "introspection", "schema")),

    _s("api-gql-dos", "GraphQL Denial-of-Service Agent", 5,
       {Cap.GRAPHQL_INTERACTION, Cap.HTTP_PROBE},
       description="Tests for GraphQL DoS via deeply nested queries, circular fragments, alias amplification, and batch query abuse",
       attack_types=("graphql-dos",), cwe_ids=("CWE-400",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=300,
       payloads=("api/graphql_dos.txt",),
       tags=("graphql", "dos", "nested", "amplification")),

    _s("api-gql-injection", "GraphQL Injection Agent", 5,
       {Cap.GRAPHQL_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests GraphQL variables, arguments, and directives for SQLi, NoSQLi, and SSRF injection vectors",
       attack_types=("graphql-injection",), cwe_ids=("CWE-89", "CWE-943"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("api/graphql_inject.txt",),
       tags=("graphql", "injection", "variable")),

    _s("api-gql-authz", "GraphQL Authorization Tester", 5,
       {Cap.GRAPHQL_INTERACTION, Cap.HTTP_PROBE, Cap.PRIVILEGE_ESCALATION},
       description="Tests field-level and type-level authorization in GraphQL by requesting restricted fields with unprivileged tokens",
       attack_types=("graphql-authz",), cwe_ids=("CWE-285", "CWE-639"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       tags=("graphql", "authorization", "field-level")),

    _s("api-gql-batching", "GraphQL Batching Abuse Agent", 5,
       {Cap.GRAPHQL_INTERACTION, Cap.HTTP_PROBE, Cap.RATE_ADAPTATION},
       description="Tests batch query support for rate limit bypass, brute-force amplification, and data exfiltration acceleration",
       attack_types=("graphql-batching",), cwe_ids=("CWE-770",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=300,
       tags=("graphql", "batching", "rate-limit")),

    _s("api-gql-suggestion", "GraphQL Field Suggestion Harvester", 5,
       {Cap.GRAPHQL_INTERACTION, Cap.PATTERN_MATCHING},
       description="Exploits GraphQL error messages that suggest valid field names to enumerate schema without introspection",
       attack_types=("graphql-recon",), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=200, timeout=300,
       detection_patterns=(r"Did you mean", r"Cannot query field"),
       tags=("graphql", "suggestion", "enumeration")),
]

# ═══════════════════════════════════════════════════════════════════════
# WebSocket (4)
# ═══════════════════════════════════════════════════════════════════════

_websocket = [
    _s("api-ws-auth", "WebSocket Authentication Tester", 5,
       {Cap.WEBSOCKET_INTERACTION, Cap.PATTERN_MATCHING},
       description="Tests WebSocket handshake for missing authentication, token validation, and origin verification",
       attack_types=("ws-auth",), cwe_ids=("CWE-287", "CWE-346"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=50, timeout=300,
       detection_patterns=(r"Sec-WebSocket", r"Upgrade:", r"101 Switching"),
       tags=("websocket", "authentication", "handshake")),

    _s("api-ws-injection", "WebSocket Message Injection Agent", 5,
       {Cap.WEBSOCKET_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests WebSocket message handlers for injection vulnerabilities (SQLi, XSS, command injection) in JSON/text frames",
       attack_types=("ws-injection",), cwe_ids=("CWE-89", "CWE-79"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("api/ws_inject.txt",),
       tags=("websocket", "injection", "message")),

    _s("api-ws-hijack", "Cross-Site WebSocket Hijacking Agent", 5,
       {Cap.WEBSOCKET_INTERACTION, Cap.BROWSER_AUTOMATION},
       description="Tests for CSWSH by initiating WebSocket connections from attacker-controlled origins without proper origin checking",
       attack_types=("cswsh",), cwe_ids=("CWE-346",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=30, timeout=300,
       tags=("websocket", "hijack", "cswsh", "origin")),

    _s("api-ws-dos", "WebSocket DoS Agent", 5,
       {Cap.WEBSOCKET_INTERACTION, Cap.RATE_ADAPTATION},
       description="Tests WebSocket rate limiting, maximum message size enforcement, and connection flood resilience",
       attack_types=("ws-dos",), cwe_ids=("CWE-400",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=300,
       tags=("websocket", "dos", "rate-limit")),
]

# ═══════════════════════════════════════════════════════════════════════
# gRPC (4)
# ═══════════════════════════════════════════════════════════════════════

_grpc = [
    _s("api-grpc-reflect", "gRPC Reflection Agent", 5,
       {Cap.GRPC_INTERACTION, Cap.PATTERN_MATCHING},
       description="Tests for enabled gRPC server reflection to enumerate available services, methods, and message types",
       attack_types=("grpc-recon",), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=20, timeout=180,
       tags=("grpc", "reflection", "enumeration")),

    _s("api-grpc-auth", "gRPC Authentication Tester", 5,
       {Cap.GRPC_INTERACTION, Cap.PATTERN_MATCHING},
       description="Tests gRPC metadata-based authentication and per-method authorization with missing/tampered tokens",
       attack_types=("grpc-auth",), cwe_ids=("CWE-287", "CWE-285"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       tags=("grpc", "authentication", "metadata")),

    _s("api-grpc-input", "gRPC Input Validation Agent", 5,
       {Cap.GRPC_INTERACTION, Cap.PAYLOAD_INJECTION},
       description="Tests protobuf message fields for boundary values, type confusion, oversized messages, and unknown field injection",
       attack_types=("grpc-input",), cwe_ids=("CWE-20",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("api/grpc_fuzz.txt",),
       tags=("grpc", "input", "protobuf", "fuzzing")),

    _s("api-grpc-error", "gRPC Error Handling Analyzer", 5,
       {Cap.GRPC_INTERACTION, Cap.ERROR_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Analyzes gRPC status codes and error details for information disclosure including stack traces and internal paths",
       attack_types=("information-disclosure",), cwe_ids=("CWE-209",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=50, timeout=180,
       detection_patterns=(r"INTERNAL", r"UNKNOWN", r"grpc-status"),
       tags=("grpc", "error", "status-code")),
]

# ═══════════════════════════════════════════════════════════════════════
# SOAP / XML-RPC (4)
# ═══════════════════════════════════════════════════════════════════════

_soap = [
    _s("api-soap-enum", "SOAP/WSDL Enumerator", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Discovers SOAP endpoints by fetching and parsing WSDL files for operations, bindings, and message schemas",
       attack_types=("soap-recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=300,
       detection_patterns=(r"<wsdl:", r"<soap:", r"\?wsdl"),
       tags=("soap", "wsdl", "enumeration")),

    _s("api-soap-xxe", "SOAP XXE Specialist", 5,
       {Cap.API_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK},
       description="Tests SOAP XML parsing for XXE via external entity expansion, parameter entities, and OOB data exfiltration",
       attack_types=("xxe",), cwe_ids=("CWE-611",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("api/xxe_payloads.txt",),
       detection_patterns=(r"<!ENTITY", r"SYSTEM", r"<!DOCTYPE"),
       tags=("soap", "xxe", "xml", "entity")),

    _s("api-soap-injection", "SOAP Body Injection Agent", 5,
       {Cap.API_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests SOAP body parameters for SQL injection, XPath injection, and XML injection via malformed elements",
       attack_types=("soap-injection",), cwe_ids=("CWE-89", "CWE-643", "CWE-91"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=200, timeout=300,
       payloads=("api/soap_inject.txt",),
       tags=("soap", "injection", "body")),

    _s("api-xmlrpc-abuse", "XML-RPC Abuse Agent", 5,
       {Cap.API_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.PATTERN_MATCHING},
       description="Tests XML-RPC endpoints for method enumeration, XXE, SSRF via pingback, and brute-force via system.multicall",
       attack_types=("xmlrpc-abuse",), cwe_ids=("CWE-611", "CWE-918"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       detection_patterns=(r"<methodResponse>", r"xmlrpc\.php", r"system\.listMethods"),
       tags=("xmlrpc", "abuse", "pingback", "ssrf")),
]

# ═══════════════════════════════════════════════════════════════════════
# API Meta-Security (11)
# ═══════════════════════════════════════════════════════════════════════

_meta = [
    _s("api-key-exposure", "API Key Exposure Detector", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Detects API keys leaked in client-side source, HTTP responses, error messages, and public repositories",
       attack_types=("api-key-leakage",), cwe_ids=("CWE-798", "CWE-200"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(
           r"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9]{16,}",
           r"sk_live_[A-Za-z0-9]+",
           r"AKIA[A-Z0-9]{16}",
       ),
       tags=("api", "key", "exposure", "secrets")),

    _s("api-cors-audit", "API CORS Deep Auditor", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
       description="Comprehensive CORS testing: reflected origins, null origin bypass, subdomain wildcard, preflight cache abuse, credential leakage",
       attack_types=("cors-misconfiguration",), cwe_ids=("CWE-942", "CWE-346"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=80, timeout=300,
       detection_patterns=(
           r"Access-Control-Allow-Origin",
           r"Access-Control-Allow-Credentials:\s*true",
       ),
       tags=("api", "cors", "origin", "preflight")),

    _s("api-error-disclosure", "API Error Information Disclosure Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.ERROR_ANALYSIS},
       description="Triggers verbose error responses via malformed input to extract stack traces, SQL fragments, internal paths, and debug data",
       attack_types=("information-disclosure",), cwe_ids=("CWE-209", "CWE-211"),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=150, timeout=300,
       detection_patterns=(
           r"Traceback \(most recent call last\)",
           r"at .*\.(java|py|js|rb|cs):\d+",
           r"Internal Server Error",
           r"DEBUG\s*=\s*True",
       ),
       tags=("api", "error", "disclosure", "stack-trace")),

    _s("api-batch-abuse", "API Batch Request Abuse Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.RATE_ADAPTATION},
       description="Tests batch/bulk API endpoints for rate limit bypass, resource exhaustion, and authorization check skipping in batched operations",
       attack_types=("batch-abuse",), cwe_ids=("CWE-770", "CWE-799"),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=60, timeout=300,
       detection_patterns=(r"batch", r"bulk", r"\"results\":\s*\["),
       tags=("api", "batch", "bulk", "rate-limit")),

    _s("api-content-negotiation", "API Content Negotiation Tester", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION},
       description="Tests Accept and Content-Type negotiation for parser differentials, XML fallback XXE, and unexpected serialization formats",
       attack_types=("content-negotiation",), cwe_ids=("CWE-436",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=100, timeout=300,
       detection_patterns=(r"Content-Type:", r"Accept:", r"406 Not Acceptable"),
       tags=("api", "content-negotiation", "accept", "parser")),

    _s("api-ssrf-webhook", "API Webhook SSRF Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.OOB_CALLBACK},
       description="Tests webhook registration endpoints for SSRF by supplying internal URLs, cloud metadata addresses, and DNS rebinding targets",
       attack_types=("ssrf", "webhook-abuse"), cwe_ids=("CWE-918",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=80, timeout=300,
       payloads=("api/ssrf_webhook.txt",),
       detection_patterns=(r"169\.254\.169\.254", r"127\.0\.0\.1", r"callback"),
       tags=("api", "webhook", "ssrf", "callback")),

    _s("api-schema-violation", "API Schema Violation Detector", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Compares API responses against OpenAPI/JSON Schema definitions to detect undocumented fields, extra data leaks, and type mismatches",
       attack_types=("schema-violation",), cwe_ids=("CWE-200",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=200, timeout=300,
       tags=("api", "schema", "validation", "openapi")),

    _s("api-idempotency", "API Idempotency Abuse Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.STATISTICAL_ANALYSIS},
       description="Tests non-idempotent operations (payments, transfers) for replay attacks by resending requests with same/missing idempotency keys",
       attack_types=("replay-attack", "idempotency-abuse"), cwe_ids=("CWE-841",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=60, timeout=300,
       detection_patterns=(r"Idempotency-Key", r"X-Request-Id", r"duplicate"),
       tags=("api", "idempotency", "replay", "payment")),

    _s("api-file-upload", "API File Upload Security Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
       description="Tests file upload endpoints for unrestricted types, path traversal in filenames, oversized uploads, and polyglot file abuse",
       attack_types=("file-upload",), cwe_ids=("CWE-434",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=100, timeout=300,
       payloads=("api/upload_payloads.txt",),
       tags=("api", "file-upload", "unrestricted", "polyglot")),

    _s("api-rate-limit", "API Rate Limit Enforcement Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.RATE_ADAPTATION, Cap.STATISTICAL_ANALYSIS},
       description="Measures rate limiting across endpoints for consistency, tests bypass via header spoofing (X-Forwarded-For), key rotation, and distributed requests",
       attack_types=("rate-limit-bypass",), cwe_ids=("CWE-770",),
       min_mode=Mode.AUDIT, priority=Pri.HIGH, max_requests=500, timeout=600,
       detection_patterns=(r"429", r"X-RateLimit", r"Retry-After"),
       tags=("api", "rate-limit", "throttling", "bypass")),

    _s("api-versioning", "API Version Regression Agent", 5,
       {Cap.API_INTERACTION, Cap.HTTP_PROBE, Cap.RESPONSE_DIFF},
       description="Discovers all API versions and diffs security controls between them to find regressions, deprecated auth, and removed validations",
       attack_types=("version-regression",), cwe_ids=("CWE-285",),
       min_mode=Mode.AUDIT, priority=Pri.NORMAL, max_requests=200, timeout=300,
       detection_patterns=(r"/v\d+/", r"/api/v\d+", r"api-version"),
       tags=("api", "versioning", "regression", "deprecated")),
]

# ═══════════════════════════════════════════════════════════════════════
# Commander (1)
# ═══════════════════════════════════════════════════════════════════════

_commander = [
    _s("api-commander", "API Division Commander", 5,
       {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
       description="Orchestrates Division 5 agents across REST/GraphQL/WS/gRPC layers, correlates cross-protocol findings, and manages the API attack surface inventory",
       attack_types=(),
       min_mode=Mode.AUDIT, priority=Pri.CRITICAL, max_requests=0, timeout=3600,
       tags=("commander", "coordination", "division-5")),
]


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def agents() -> list[AgentSpec]:
    """Return all 40 Division 5 (API Security) agents."""
    all_agents = _rest + _graphql + _websocket + _grpc + _soap + _meta + _commander
    assert len(all_agents) == 40, f"Division 5 must have exactly 40 agents, got {len(all_agents)}"
    return all_agents
