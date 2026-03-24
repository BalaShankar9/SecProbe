"""
Division 15 — Persistence & Lateral Movement Agents (20 agents).

ALL agents in this division require REDTEAM mode. Covers web shell/backdoor
deployment, token/credential persistence, command-and-control channels,
lateral movement across infrastructure, data staging for exfiltration,
and anti-forensics techniques.
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
    """Return all 20 Division 15 agents — all REDTEAM only."""
    return [
        # ── Web Shell / Backdoor (4) ────────────────────────────────
        _s(
            "persist-webshell-php", "PHP Web Shell Persistence Specialist", 15,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PROOF_GENERATION},
            description="Deploys minimal PHP web shells through file upload, LFI log "
                        "poisoning, and CMS plugin injection vectors. Uses obfuscated "
                        "evaluation constructs, .htaccess handler overrides, and "
                        "auto_prepend_file techniques to maintain server-side execution.",
            attack_types=("webshell", "persistence", "php"),
            target_technologies=("php", "wordpress", "laravel", "drupal"),
            cwe_ids=("CWE-506", "CWE-94"),
            detection_patterns=(
                r"uid=\d+", r"www-data", r"<\?php",
            ),
            min_mode=Mode.REDTEAM,
            payloads=("persist_webshell_php.txt",),
            priority=Pri.HIGH,
            max_requests=60,
            tags=("webshell", "php", "persistence"),
        ),
        _s(
            "persist-webshell-aspx", "ASP.NET Web Shell Persistence Specialist", 15,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PROOF_GENERATION},
            description="Deploys ASPX web shells via file upload and deserialization "
                        "vectors. Uses Assembly.Load for in-memory code execution, "
                        "web.config handler registration, and IIS module injection "
                        "for persistent backdoor access on Windows/IIS targets.",
            attack_types=("webshell", "persistence", "aspnet"),
            target_technologies=("aspnet", "iis", "dotnet"),
            cwe_ids=("CWE-506", "CWE-94"),
            detection_patterns=(
                r"COMPUTERNAME", r"NT AUTHORITY", r"<%@",
                r"Assembly\.Load",
            ),
            min_mode=Mode.REDTEAM,
            payloads=("persist_webshell_aspx.txt",),
            priority=Pri.HIGH,
            max_requests=60,
            tags=("webshell", "aspx", "iis", "persistence"),
        ),
        _s(
            "persist-webshell-jsp", "JSP Web Shell Persistence Specialist", 15,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PROOF_GENERATION},
            description="Deploys JSP web shells on Java application servers via file "
                        "upload, WAR deployment, and expression language injection. "
                        "Uses Runtime.getRuntime wrappers and ClassLoader techniques "
                        "for stealthy execution on Tomcat, JBoss, and WebLogic.",
            attack_types=("webshell", "persistence", "java"),
            target_technologies=("java", "tomcat", "jboss", "weblogic"),
            cwe_ids=("CWE-506", "CWE-94"),
            detection_patterns=(
                r"Runtime\.getRuntime", r"ProcessBuilder",
                r"<%@.*page", r"ClassLoader",
            ),
            min_mode=Mode.REDTEAM,
            payloads=("persist_webshell_jsp.txt",),
            priority=Pri.HIGH,
            max_requests=60,
            tags=("webshell", "jsp", "java", "persistence"),
        ),
        _s(
            "persist-backdoor-cron", "Cron/Scheduled Task Backdoor Specialist", 15,
            {Cap.HTTP_PROBE, Cap.PROOF_GENERATION, Cap.PRIVILEGE_ESCALATION},
            description="Establishes persistence through scheduled task mechanisms: "
                        "crontab entries on Linux, Windows Task Scheduler via schtasks, "
                        "systemd timers, and at jobs. Installs recurring callback scripts "
                        "through confirmed RCE vectors.",
            attack_types=("backdoor", "persistence", "scheduled-task"),
            cwe_ids=("CWE-506",),
            detection_patterns=(
                r"crontab", r"schtasks", r"systemd.*timer",
                r"\* \* \* \*",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=40,
            tags=("backdoor", "cron", "scheduled", "persistence"),
        ),

        # ── Token / Credential Persistence (3) ──────────────────────
        _s(
            "persist-token-theft", "Session Token Persistence Specialist", 15,
            {Cap.DATA_EXTRACTION, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Maintains access by harvesting and replaying long-lived session "
                        "tokens, refresh tokens, API keys, and remember-me identifiers. "
                        "Tests token expiration enforcement and monitors for token "
                        "rotation that would invalidate stolen credentials.",
            attack_types=("token-persistence",),
            cwe_ids=("CWE-613", "CWE-384"),
            detection_patterns=(
                r"refresh_token", r"remember_me", r"api[_-]?key",
                r"expires_in", r"token_type",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=60,
            tags=("token", "session", "persistence"),
        ),
        _s(
            "persist-oauth-grant", "OAuth Persistent Grant Specialist", 15,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.DATA_EXTRACTION},
            description="Maintains persistent access through OAuth by registering "
                        "malicious OAuth applications, stealing authorization codes, "
                        "abusing offline_access scopes, and manipulating refresh token "
                        "flows to maintain indefinite API access.",
            attack_types=("oauth-persistence",),
            cwe_ids=("CWE-863", "CWE-613"),
            detection_patterns=(
                r"access_token", r"refresh_token", r"authorization_code",
                r"offline_access", r"grant_type",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=60,
            tags=("oauth", "grant", "persistence"),
        ),
        _s(
            "persist-account-creation", "Backdoor Account Creation Specialist", 15,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION, Cap.PRIVILEGE_ESCALATION},
            description="Creates hidden administrative accounts through SQL injection "
                        "INSERT statements, mass assignment with admin role fields, "
                        "and invitation system abuse to establish persistent access "
                        "independent of the initial exploit vector.",
            attack_types=("account-creation", "persistence"),
            cwe_ids=("CWE-284",),
            detection_patterns=(
                r"user.*created", r"account.*registered", r"role.*admin",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=40,
            tags=("account", "backdoor", "admin", "persistence"),
        ),

        # ── C2 Channels (3) ─────────────────────────────────────────
        _s(
            "persist-c2-http", "HTTP-Based C2 Channel Specialist", 15,
            {Cap.HTTP_PROBE, Cap.OOB_CALLBACK, Cap.PROOF_GENERATION},
            description="Establishes command-and-control communication over HTTP/HTTPS "
                        "using domain fronting, legitimate cloud service APIs (Slack, "
                        "Teams, Pastebin), and CDN-based callback channels that blend "
                        "with normal web traffic.",
            attack_types=("c2", "http"),
            cwe_ids=("CWE-506",),
            detection_patterns=(
                r"callback.*received", r"beacon", r"check-in",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=40,
            tags=("c2", "http", "domain-fronting"),
        ),
        _s(
            "persist-c2-dns", "DNS-Based C2 Channel Specialist", 15,
            {Cap.DNS_ENUM, Cap.OOB_CALLBACK, Cap.PROOF_GENERATION},
            description="Establishes covert C2 channels over DNS using TXT record "
                        "queries for command retrieval, CNAME-based data exfiltration, "
                        "and DNS-over-HTTPS tunneling to bypass network monitoring.",
            attack_types=("c2", "dns"),
            cwe_ids=("CWE-506",),
            detection_patterns=(
                r"dns.*query", r"TXT.*record", r"nslookup",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=40,
            tags=("c2", "dns", "tunnel", "covert"),
        ),
        _s(
            "persist-c2-websocket", "WebSocket C2 Channel Specialist", 15,
            {Cap.WEBSOCKET_INTERACTION, Cap.OOB_CALLBACK, Cap.PROOF_GENERATION},
            description="Establishes persistent C2 via WebSocket connections that "
                        "maintain bidirectional communication, evade HTTP-focused "
                        "monitoring, and leverage legitimate WebSocket endpoints "
                        "for command relay through protocol upgrade abuse.",
            attack_types=("c2", "websocket"),
            cwe_ids=("CWE-506",),
            detection_patterns=(
                r"websocket", r"Upgrade.*websocket", r"ws://",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("c2", "websocket", "persistent"),
        ),

        # ── Lateral Movement (5) ────────────────────────────────────
        _s(
            "persist-lateral-ssrf-pivot", "SSRF-Based Lateral Movement Specialist", 15,
            {Cap.HTTP_PROBE, Cap.LATERAL_MOVEMENT, Cap.PAYLOAD_INJECTION},
            description="Uses SSRF as a pivot point to reach internal services: Redis "
                        "command injection via CRLF, internal API abuse, Elasticsearch "
                        "queries, and internal admin panel access from the compromised "
                        "server network position.",
            attack_types=("lateral-movement", "ssrf"),
            cwe_ids=("CWE-918",),
            detection_patterns=(
                r"redis.*OK", r"elasticsearch", r"internal.*api",
                r"admin.*panel",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=80,
            tags=("lateral", "ssrf", "pivot", "internal"),
        ),
        _s(
            "persist-lateral-k8s", "Kubernetes Lateral Movement Specialist", 15,
            {Cap.HTTP_PROBE, Cap.LATERAL_MOVEMENT, Cap.API_INTERACTION},
            description="Moves laterally within Kubernetes clusters by abusing service "
                        "account tokens, accessing the kubelet API, listing pods and "
                        "secrets, and exploiting misconfigured RBAC to reach other "
                        "namespaces and workloads.",
            attack_types=("lateral-movement", "kubernetes"),
            target_technologies=("kubernetes", "docker"),
            cwe_ids=("CWE-269",),
            detection_patterns=(
                r"kubelet", r"serviceaccount", r"namespace",
                r"kube-system", r"ClusterRole",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=60,
            tags=("lateral", "kubernetes", "rbac", "pods"),
        ),
        _s(
            "persist-lateral-cloud-role", "Cloud IAM Role Chaining Specialist", 15,
            {Cap.HTTP_PROBE, Cap.LATERAL_MOVEMENT, Cap.PRIVILEGE_ESCALATION},
            description="Chains cloud IAM role assumptions to escalate access across "
                        "accounts and services: AWS AssumeRole chains, GCP service "
                        "account impersonation, and Azure managed identity pivots "
                        "to reach higher-privilege resources.",
            attack_types=("lateral-movement", "cloud-iam"),
            target_technologies=("aws", "gcp", "azure"),
            cwe_ids=("CWE-269",),
            detection_patterns=(
                r"AssumeRole", r"sts\.amazonaws", r"impersonate",
                r"managed.*identity",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=60,
            tags=("lateral", "cloud", "iam", "role-chain"),
        ),
        _s(
            "persist-lateral-db-link", "Database Link Lateral Movement Specialist", 15,
            {Cap.PAYLOAD_INJECTION, Cap.LATERAL_MOVEMENT, Cap.DATA_EXTRACTION},
            description="Moves laterally through database links and federation: SQL "
                        "Server linked servers (OPENROWSET, OPENQUERY), Oracle database "
                        "links, PostgreSQL dblink/foreign data wrappers, and MySQL "
                        "federated tables to access connected databases.",
            attack_types=("lateral-movement", "database"),
            cwe_ids=("CWE-89",),
            detection_patterns=(
                r"OPENROWSET", r"OPENQUERY", r"dblink",
                r"db_link", r"federated",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.NORMAL,
            max_requests=60,
            tags=("lateral", "database", "link", "federation"),
        ),
        _s(
            "persist-lateral-shared-creds", "Shared Credential Lateral Movement Specialist", 15,
            {Cap.HTTP_PROBE, Cap.LATERAL_MOVEMENT, Cap.PATTERN_MATCHING},
            description="Tests harvested credentials against other application endpoints, "
                        "APIs, admin panels, and associated services to identify password "
                        "reuse and shared service account credentials across the target "
                        "infrastructure.",
            attack_types=("lateral-movement", "credential-reuse"),
            cwe_ids=("CWE-798", "CWE-521"),
            detection_patterns=(
                r"login.*success", r"authenticated", r"welcome.*admin",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=80,
            tags=("lateral", "credentials", "reuse", "spray"),
        ),

        # ── Data Staging (2) ────────────────────────────────────────
        _s(
            "persist-staging-compress", "Data Staging & Compression Specialist", 15,
            {Cap.DATA_EXTRACTION, Cap.PROOF_GENERATION},
            description="Prepares extracted data for exfiltration by compressing, "
                        "encrypting, chunking into protocol-appropriate sizes, and "
                        "staging in temporary locations accessible to C2 channels.",
            attack_types=("data-staging",),
            cwe_ids=("CWE-200",),
            detection_patterns=(
                r"archive.*created", r"compressed", r"chunk",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("staging", "compression", "exfiltration"),
        ),
        _s(
            "persist-staging-steganography", "Steganographic Data Staging Specialist", 15,
            {Cap.DATA_EXTRACTION, Cap.ENCODING_MUTATION},
            description="Embeds exfiltrated data within innocent-looking carriers: image "
                        "steganography in uploaded/downloaded images, data hidden in HTTP "
                        "response headers, and encoding within legitimate API response "
                        "fields to avoid DLP detection.",
            attack_types=("data-staging", "steganography"),
            cwe_ids=("CWE-200",),
            detection_patterns=(
                r"image.*upload", r"download", r"attachment",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("staging", "steganography", "covert"),
        ),

        # ── Anti-Forensics (2) ──────────────────────────────────────
        _s(
            "persist-antiforensic-log-tamper", "Log Tampering Anti-Forensics Specialist", 15,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Covers tracks by injecting log-clearing commands via RCE, "
                        "manipulating application audit logs through parameter injection, "
                        "and creating false log entries to misdirect incident response. "
                        "Also tests for log injection vulnerabilities (CWE-117).",
            attack_types=("anti-forensics", "log-tampering"),
            cwe_ids=("CWE-117",),
            detection_patterns=(
                r"log.*cleared", r"audit.*deleted", r"history.*truncated",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("anti-forensics", "logs", "tampering"),
        ),
        _s(
            "persist-antiforensic-timestamp", "Timestamp Manipulation Specialist", 15,
            {Cap.HTTP_PROBE, Cap.PAYLOAD_INJECTION},
            description="Manipulates file timestamps and database record timestamps "
                        "to hide evidence of backdoor deployment, using touch commands "
                        "via RCE, SQL UPDATE on audit columns, and header injection to "
                        "alter cache timestamps.",
            attack_types=("anti-forensics", "timestamp-manipulation"),
            cwe_ids=("CWE-117",),
            detection_patterns=(
                r"timestamp.*modified", r"touch.*-t", r"updated_at",
            ),
            min_mode=Mode.REDTEAM,
            priority=Pri.LOW,
            max_requests=20,
            tags=("anti-forensics", "timestamp", "cover-tracks"),
        ),

        # ── Commander (1) ────────────────────────────────────────────
        _s(
            "persist-commander", "Division 15 Persistence & Lateral Movement Commander", 15,
            {Cap.COORDINATION, Cap.CONSENSUS_VOTING, Cap.KNOWLEDGE_SHARING, Cap.LATERAL_MOVEMENT},
            description="Coordinates all Division 15 red team agents, sequences "
                        "persistence establishment after confirmed exploitation, manages "
                        "lateral movement campaigns, and ensures operational security "
                        "throughout the persistence and pivot lifecycle.",
            attack_types=("persistence", "lateral-movement"),
            cwe_ids=(),
            min_mode=Mode.REDTEAM,
            priority=Pri.CRITICAL,
            max_requests=50,
            tags=("commander", "coordinator", "persistence", "redteam"),
        ),
    ]
