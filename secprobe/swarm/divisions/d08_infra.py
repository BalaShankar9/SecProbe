"""
Division 8: Infrastructure & Network — 35 agents.

Covers service exposure, database exposure, container/K8s, debug/admin endpoints,
SSRF variants, HTTP smuggling/desync, cache poisoning, reverse proxy/vhost, and
miscellaneous infrastructure vectors.
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
        # ── Service Exposure (6) ─────────────────────────────────────
        _s(
            "in-port-scan", "TCP Port Scanner", 8,
            {Cap.PORT_SCAN, Cap.TECH_FINGERPRINT, Cap.BASELINE_PROFILING},
            description="Performs TCP SYN/connect scanning on common and high-value ports "
                        "to map the target's exposed service attack surface",
            attack_types=("service-exposure",),
            cwe_ids=("CWE-200",),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=500,
            tags=("port-scan", "recon", "tcp"),
        ),
        _s(
            "in-service-fingerprint", "Service Version Fingerprinter", 8,
            {Cap.PORT_SCAN, Cap.TECH_FINGERPRINT, Cap.PATTERN_MATCHING},
            description="Fingerprints service versions via banner grabbing, protocol probes, "
                        "and response signature matching against known version databases",
            attack_types=("service-exposure",),
            cwe_ids=("CWE-200",),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("fingerprint", "version", "banner"),
        ),
        _s(
            "in-smtp-exposure", "SMTP Service Auditor", 8,
            {Cap.PORT_SCAN, Cap.PATTERN_MATCHING, Cap.DATA_EXTRACTION},
            description="Tests exposed SMTP services for open relay, VRFY/EXPN user enumeration, "
                        "and misconfigured SPF/DKIM/DMARC records enabling spoofing",
            attack_types=("smtp-misconfiguration",),
            cwe_ids=("CWE-200", "CWE-287"),
            target_technologies=("smtp", "postfix", "sendmail", "exchange"),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("smtp", "email", "open-relay"),
        ),
        _s(
            "in-dns-exposure", "DNS Service Auditor", 8,
            {Cap.DNS_ENUM, Cap.PATTERN_MATCHING, Cap.DATA_EXTRACTION},
            description="Tests DNS servers for zone transfer (AXFR), cache poisoning, "
                        "open resolver abuse, and DNSSEC validation issues",
            attack_types=("dns-misconfiguration",),
            cwe_ids=("CWE-200", "CWE-350"),
            target_technologies=("dns", "bind", "dnsmasq"),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("dns", "zone-transfer", "axfr"),
        ),
        _s(
            "in-ftp-exposure", "FTP/SFTP Service Scanner", 8,
            {Cap.PORT_SCAN, Cap.PATTERN_MATCHING, Cap.HTTP_PROBE},
            description="Tests FTP services for anonymous access, directory traversal, "
                        "bounce attacks, and cleartext credential transmission",
            attack_types=("ftp-misconfiguration",),
            cwe_ids=("CWE-284", "CWE-319"),
            target_technologies=("ftp", "vsftpd", "proftpd"),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("ftp", "anonymous", "cleartext"),
        ),
        _s(
            "in-snmp-exposure", "SNMP Community String Tester", 8,
            {Cap.PORT_SCAN, Cap.PAYLOAD_INJECTION, Cap.DATA_EXTRACTION},
            description="Tests for default SNMP community strings (public/private), "
                        "SNMPv1/v2c cleartext exposure, and information leakage via MIB walks",
            attack_types=("snmp-misconfiguration",),
            cwe_ids=("CWE-798", "CWE-319"),
            target_technologies=("snmp",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("snmp", "community-string", "default-creds"),
        ),

        # ── Database Exposure (4) ────────────────────────────────────
        _s(
            "in-mysql-exposure", "MySQL/MariaDB Exposure Scanner", 8,
            {Cap.PORT_SCAN, Cap.PATTERN_MATCHING, Cap.DATA_EXTRACTION},
            description="Detects exposed MySQL/MariaDB instances: default ports, "
                        "anonymous login, weak root passwords, and version disclosure",
            attack_types=("database-exposure",),
            cwe_ids=("CWE-284", "CWE-798"),
            target_technologies=("mysql", "mariadb"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("mysql", "database", "exposure"),
        ),
        _s(
            "in-postgres-exposure", "PostgreSQL Exposure Scanner", 8,
            {Cap.PORT_SCAN, Cap.PATTERN_MATCHING, Cap.DATA_EXTRACTION},
            description="Detects exposed PostgreSQL instances: trust authentication, "
                        "pg_hba.conf misconfigurations, and default credential testing",
            attack_types=("database-exposure",),
            cwe_ids=("CWE-284", "CWE-798"),
            target_technologies=("postgresql", "postgres"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("postgresql", "database", "exposure"),
        ),
        _s(
            "in-redis-exposure", "Redis Exposure Scanner", 8,
            {Cap.PORT_SCAN, Cap.PAYLOAD_INJECTION, Cap.DATA_EXTRACTION},
            description="Detects unauthenticated Redis instances and tests for CONFIG "
                        "write exploitation, Lua sandbox escape, and key exfiltration",
            attack_types=("database-exposure",),
            cwe_ids=("CWE-284", "CWE-306"),
            target_technologies=("redis",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("redis", "nosql", "unauthenticated"),
        ),
        _s(
            "in-mongo-exposure", "MongoDB Exposure Scanner", 8,
            {Cap.PORT_SCAN, Cap.PATTERN_MATCHING, Cap.DATA_EXTRACTION},
            description="Detects exposed MongoDB instances without authentication, "
                        "tests for SCRAM bypass, and enumerates databases and collections",
            attack_types=("database-exposure",),
            cwe_ids=("CWE-284", "CWE-306"),
            target_technologies=("mongodb", "mongo"),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("mongodb", "nosql", "unauthenticated"),
        ),

        # ── Container / K8s (3) ──────────────────────────────────────
        _s(
            "in-docker-api", "Docker API Exposure Scanner", 8,
            {Cap.HTTP_PROBE, Cap.PORT_SCAN, Cap.PRIVILEGE_ESCALATION},
            description="Detects exposed Docker daemon APIs (/v1.24/containers/json) "
                        "enabling container escape, host mount, and remote code execution",
            attack_types=("container-escape",),
            cwe_ids=("CWE-284", "CWE-250"),
            target_technologies=("docker",),
            detection_patterns=(
                r"/v\d+\.\d+/containers",
                r"Docker-Content-Digest",
            ),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("docker", "api", "container-escape"),
        ),
        _s(
            "in-k8s-api", "Kubernetes API Server Scanner", 8,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.PRIVILEGE_ESCALATION},
            description="Tests Kubernetes API server exposure: anonymous auth, "
                        "unauthenticated /api /version endpoints, and RBAC misconfigurations",
            attack_types=("k8s-misconfiguration",),
            cwe_ids=("CWE-284", "CWE-306"),
            target_technologies=("kubernetes", "k8s"),
            detection_patterns=(
                r'"kind"\s*:\s*"(Pod|Service|Deployment)"',
                r"/api/v1/namespaces",
            ),
            priority=Pri.CRITICAL,
            min_mode=Mode.AUDIT,
            tags=("kubernetes", "api", "rbac"),
        ),
        _s(
            "in-k8s-dashboard", "Kubernetes Dashboard Scanner", 8,
            {Cap.HTTP_PROBE, Cap.BROWSER_AUTOMATION, Cap.PATTERN_MATCHING},
            description="Detects exposed Kubernetes dashboards with skip-login enabled "
                        "or default service account tokens providing cluster-admin access",
            attack_types=("k8s-misconfiguration",),
            cwe_ids=("CWE-306",),
            target_technologies=("kubernetes", "k8s"),
            detection_patterns=(
                r"Kubernetes Dashboard",
                r"kubernetes-dashboard",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("kubernetes", "dashboard", "unauthenticated"),
        ),

        # ── Debug / Admin Endpoints (3) ─────────────────────────────
        _s(
            "in-debug-endpoint", "Debug Endpoint Discovery Agent", 8,
            {Cap.HTTP_PROBE, Cap.CRAWL, Cap.PATTERN_MATCHING},
            description="Discovers exposed debug endpoints: /debug/pprof, /actuator, "
                        "/__debug__, /trace, /phpinfo, /server-status, and stack traces",
            attack_types=("information-disclosure",),
            cwe_ids=("CWE-215", "CWE-200"),
            detection_patterns=(
                r"/debug/pprof",
                r"/actuator",
                r"phpinfo\(\)",
                r"/server-status",
                r"/__debug__",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("debug", "admin", "information-disclosure"),
        ),
        _s(
            "in-admin-panel", "Admin Panel Discovery Agent", 8,
            {Cap.HTTP_PROBE, Cap.CRAWL, Cap.TECH_FINGERPRINT},
            description="Discovers exposed admin panels: /admin, /wp-admin, /manager, "
                        "/console, /adminer, and framework-specific admin interfaces",
            attack_types=("admin-exposure",),
            cwe_ids=("CWE-284",),
            detection_patterns=(
                r"/admin",
                r"/wp-admin",
                r"/manager/html",
                r"/console",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("admin", "panel", "discovery"),
        ),
        _s(
            "in-error-disclosure", "Error Message Information Leakage Detector", 8,
            {Cap.HTTP_PROBE, Cap.ERROR_ANALYSIS, Cap.PATTERN_MATCHING},
            description="Triggers and analyzes verbose error messages that disclose "
                        "stack traces, database schemas, internal paths, and framework versions",
            attack_types=("information-disclosure",),
            cwe_ids=("CWE-209", "CWE-200"),
            detection_patterns=(
                r"Traceback \(most recent call last\)",
                r"at [\w\.]+\([\w\.]+:\d+\)",
                r"Stack Trace:",
                r"SQLSTATE\[",
            ),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("error", "stack-trace", "disclosure"),
        ),

        # ── SSRF Variants (4) ───────────────────────────────────────
        _s(
            "in-ssrf-basic", "Basic SSRF Tester", 8,
            {Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK, Cap.HTTP_PROBE},
            description="Tests for server-side request forgery by injecting internal URLs "
                        "(127.0.0.1, 169.254.169.254, localhost) in URL-accepting parameters",
            attack_types=("ssrf",),
            cwe_ids=("CWE-918",),
            payloads=("ssrf_basic.txt",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("ssrf", "internal", "metadata"),
        ),
        _s(
            "in-ssrf-blind", "Blind SSRF Detector", 8,
            {Cap.PAYLOAD_INJECTION, Cap.OOB_CALLBACK, Cap.TIME_BASED},
            description="Detects blind SSRF via out-of-band callbacks (DNS, HTTP) to "
                        "attacker-controlled servers when direct response is not visible",
            attack_types=("ssrf",),
            cwe_ids=("CWE-918",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("ssrf", "blind", "oob"),
        ),
        _s(
            "in-ssrf-protocol", "SSRF Protocol Smuggling Specialist", 8,
            {Cap.PAYLOAD_INJECTION, Cap.ENCODING_MUTATION, Cap.HTTP_PROBE},
            description="Exploits SSRF via protocol smuggling: gopher://, dict://, file://, "
                        "and URL parser differential exploitation across libraries",
            attack_types=("ssrf",),
            cwe_ids=("CWE-918",),
            payloads=("ssrf_protocols.txt",),
            priority=Pri.NORMAL,
            min_mode=Mode.REDTEAM,
            tags=("ssrf", "gopher", "protocol-smuggling"),
        ),
        _s(
            "in-ssrf-filter-bypass", "SSRF Filter Bypass Specialist", 8,
            {Cap.PAYLOAD_INJECTION, Cap.ENCODING_MUTATION, Cap.WAF_BYPASS},
            description="Bypasses SSRF filters using IP encoding tricks (decimal, hex, "
                        "IPv6 mapping), DNS rebinding, URL parser inconsistencies, and redirects",
            attack_types=("ssrf",),
            cwe_ids=("CWE-918",),
            payloads=("ssrf_bypass.txt",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("ssrf", "bypass", "filter-evasion"),
        ),

        # ── HTTP Smuggling / Desync (3) ─────────────────────────────
        _s(
            "in-http-smuggle-clte", "HTTP Smuggling CL.TE Tester", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests for CL.TE HTTP request smuggling where the front-end "
                        "uses Content-Length and back-end uses Transfer-Encoding",
            attack_types=("http-smuggling",),
            cwe_ids=("CWE-444",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("smuggling", "clte", "desync"),
        ),
        _s(
            "in-http-smuggle-tecl", "HTTP Smuggling TE.CL Tester", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests for TE.CL HTTP request smuggling where the front-end "
                        "uses Transfer-Encoding and back-end uses Content-Length",
            attack_types=("http-smuggling",),
            cwe_ids=("CWE-444",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("smuggling", "tecl", "desync"),
        ),
        _s(
            "in-http2-smuggle", "HTTP/2 Desync Specialist", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests for HTTP/2 request smuggling via H2.CL and H2.TE desync, "
                        "CRLF injection in HTTP/2 pseudo-headers, and WebSocket smuggling",
            attack_types=("http-smuggling",),
            cwe_ids=("CWE-444",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("smuggling", "http2", "h2c"),
        ),

        # ── Cache Poisoning / Host Header (3) ───────────────────────
        _s(
            "in-cache-poison", "Web Cache Poisoning Specialist", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests for web cache poisoning via unkeyed headers (X-Forwarded-Host, "
                        "X-Original-URL) that inject malicious content into cached responses",
            attack_types=("cache-poisoning",),
            cwe_ids=("CWE-444",),
            detection_patterns=(
                r"X-Cache:\s*HIT",
                r"Age:\s*\d+",
                r"CF-Cache-Status",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("cache-poisoning", "headers"),
        ),
        _s(
            "in-host-header", "Host Header Injection Tester", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PAYLOAD_INJECTION},
            description="Tests for host header attacks: password reset poisoning, "
                        "web cache poisoning, server-side routing manipulation, and SSRF via Host",
            attack_types=("host-header-injection",),
            cwe_ids=("CWE-644",),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("host-header", "injection", "password-reset"),
        ),
        _s(
            "in-request-splitting", "HTTP Response Splitting Detector", 8,
            {Cap.PAYLOAD_INJECTION, Cap.HEADER_MANIPULATION, Cap.HTTP_PROBE},
            description="Tests for HTTP response splitting via CRLF injection in response "
                        "headers, enabling cache poisoning and XSS via injected headers",
            attack_types=("response-splitting",),
            cwe_ids=("CWE-113",),
            payloads=("crlf_injection.txt",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("crlf", "response-splitting", "header-injection"),
        ),

        # ── Reverse Proxy / VHost (3) ───────────────────────────────
        _s(
            "in-vhost-enum", "Virtual Host Enumerator", 8,
            {Cap.HTTP_PROBE, Cap.DNS_ENUM, Cap.HEADER_MANIPULATION},
            description="Enumerates virtual hosts by brute-forcing Host header values "
                        "to discover hidden applications, internal tools, and staging sites",
            attack_types=("vhost-discovery",),
            cwe_ids=("CWE-200",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            max_requests=500,
            tags=("vhost", "enumeration", "host-header"),
        ),
        _s(
            "in-proxy-miscfg", "Reverse Proxy Misconfiguration Scanner", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PATTERN_MATCHING},
            description="Tests for reverse proxy misconfigurations: path traversal via "
                        "path normalization differences, ACL bypass, and backend exposure",
            attack_types=("proxy-misconfiguration",),
            cwe_ids=("CWE-441",),
            detection_patterns=(
                r"X-Forwarded-For",
                r"X-Real-IP",
                r"Via:\s",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.AUDIT,
            tags=("proxy", "nginx", "path-traversal"),
        ),
        _s(
            "in-lb-bypass", "Load Balancer Bypass Tester", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PORT_SCAN},
            description="Attempts to bypass load balancers and WAFs by discovering direct "
                        "backend IPs via DNS history, error messages, and header leakage",
            attack_types=("waf-bypass",),
            cwe_ids=("CWE-693",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("load-balancer", "bypass", "direct-ip"),
        ),

        # ── Misc Infrastructure (5) ─────────────────────────────────
        _s(
            "in-cors-internal", "Internal CORS Exposure Detector", 8,
            {Cap.HTTP_PROBE, Cap.HEADER_MANIPULATION, Cap.PATTERN_MATCHING},
            description="Detects CORS configurations that accidentally expose internal "
                        "API endpoints to external origins via misconfigured allow-origin",
            attack_types=("cors-misconfiguration",),
            cwe_ids=("CWE-942",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("cors", "internal", "api"),
        ),
        _s(
            "in-graphql-introspection", "GraphQL Introspection Scanner", 8,
            {Cap.GRAPHQL_INTERACTION, Cap.HTTP_PROBE, Cap.DATA_EXTRACTION},
            description="Exploits enabled GraphQL introspection to enumerate full schema "
                        "including types, queries, mutations, and internal field descriptions",
            attack_types=("graphql-misconfiguration",),
            cwe_ids=("CWE-200",),
            target_technologies=("graphql",),
            detection_patterns=(
                r"__schema",
                r"__type",
                r"graphql",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("graphql", "introspection", "schema"),
        ),
        _s(
            "in-grpc-reflection", "gRPC Reflection Scanner", 8,
            {Cap.GRPC_INTERACTION, Cap.PORT_SCAN, Cap.DATA_EXTRACTION},
            description="Detects gRPC server reflection services that expose protobuf "
                        "service definitions, method signatures, and message types",
            attack_types=("grpc-misconfiguration",),
            cwe_ids=("CWE-200",),
            target_technologies=("grpc",),
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            tags=("grpc", "reflection", "protobuf"),
        ),
        _s(
            "in-websocket-abuse", "WebSocket Infrastructure Tester", 8,
            {Cap.WEBSOCKET_INTERACTION, Cap.PAYLOAD_INJECTION, Cap.HTTP_PROBE},
            description="Tests WebSocket infrastructure for missing rate limiting, "
                        "origin validation bypass, and tunneling for firewall evasion",
            attack_types=("websocket-abuse",),
            cwe_ids=("CWE-346",),
            priority=Pri.NORMAL,
            min_mode=Mode.AUDIT,
            tags=("websocket", "infrastructure", "tunneling"),
        ),
        _s(
            "in-git-svn-exposure", "Git/SVN Repository Exposure Scanner", 8,
            {Cap.HTTP_PROBE, Cap.CRAWL, Cap.DATA_EXTRACTION},
            description="Detects exposed version control directories (.git, .svn, .hg) "
                        "that allow full source code reconstruction and secret extraction",
            attack_types=("information-disclosure",),
            cwe_ids=("CWE-538",),
            detection_patterns=(
                r"\.git/HEAD",
                r"\.git/config",
                r"\.svn/entries",
            ),
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            tags=("git", "svn", "source-exposure"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "in-commander", "Division 8 Commander — Infrastructure & Network", 8,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Orchestrates all Division 8 infrastructure agents. Sequences port "
                        "scanning before service-specific probes, coordinates SSRF and smuggling "
                        "chains, and manages database exposure consensus findings",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            tags=("commander", "division-8", "infrastructure"),
            max_requests=0,
            timeout=600,
        ),
    ]
