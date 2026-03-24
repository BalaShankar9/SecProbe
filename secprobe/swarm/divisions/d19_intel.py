"""
Division 19 — Intelligence & Analysis.

25 agents covering deduplication, attack chain correlation, threat modeling,
false positive elimination, pattern recognition, severity scoring, coverage
tracking, anomaly detection, learning, knowledge graph, report generation
(HTML/JSON/PDF/SARIF/JUnit), diff reports, API feed, and notifications.
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
        # ── Dedup Engine (1) ─────────────────────────────────────────
        _s(
            "intel-dedup", "Finding Deduplication Engine", 19,
            {Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
            description="Deduplicates findings from all 600 agents using content-based "
                        "fingerprinting, URL normalization, CWE equivalence classes, and "
                        "fuzzy matching on evidence payloads to eliminate redundant reports.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.CRITICAL,
            max_requests=10,
            tags=("intel", "dedup", "normalization"),
        ),

        # ── Attack Chain Correlator (1) ──────────────────────────────
        _s(
            "intel-chain-correlator", "Attack Chain Correlator", 19,
            {Cap.CHAIN_BUILDING, Cap.PATTERN_MATCHING, Cap.KNOWLEDGE_SHARING},
            description="Identifies multi-step attack chains by correlating individual "
                        "findings across divisions (e.g., SSRF + cloud metadata = RCE, "
                        "XSS + CSRF + privilege escalation) and computes composite severity.",
            attack_types=("analysis", "chain-detection"),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("intel", "attack-chain", "correlation"),
        ),

        # ── Threat Modeler (1) ───────────────────────────────────────
        _s(
            "intel-threat-modeler", "STRIDE Threat Modeler", 19,
            {Cap.PATTERN_MATCHING, Cap.KNOWLEDGE_SHARING},
            description="Constructs a STRIDE-based threat model from discovered attack "
                        "surface, mapping findings to Spoofing, Tampering, Repudiation, "
                        "Information Disclosure, Denial of Service, and Elevation of "
                        "Privilege categories with data flow diagrams.",
            attack_types=("threat-modeling",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "threat-model", "stride"),
        ),

        # ── FP Eliminator (1) ────────────────────────────────────────
        _s(
            "intel-fp-eliminator", "False Positive Eliminator", 19,
            {Cap.STATISTICAL_ANALYSIS, Cap.CONSENSUS_VOTING, Cap.PATTERN_MATCHING},
            description="Applies multi-signal false positive detection using response "
                        "diffing against baseline, WAF reflection detection, payload echo "
                        "analysis, statistical outlier tests, and multi-agent consensus "
                        "to eliminate spurious findings.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.CRITICAL,
            max_requests=10,
            tags=("intel", "false-positive", "validation"),
        ),

        # ── Pattern Recognition (2) ──────────────────────────────────
        _s(
            "intel-pattern-vuln", "Vulnerability Pattern Recognizer", 19,
            {Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
            description="Identifies recurring vulnerability patterns across the target "
                        "such as consistent input validation failures, systematic "
                        "authorization gaps, and repeated cryptographic weaknesses that "
                        "indicate systemic security deficiencies.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "pattern", "systemic"),
        ),
        _s(
            "intel-pattern-defense", "Defense Pattern Analyzer", 19,
            {Cap.PATTERN_MATCHING, Cap.RESPONSE_DIFF, Cap.BASELINE_PROFILING},
            description="Profiles the target's defensive patterns including WAF signatures, "
                        "rate limiting behavior, input sanitization consistency, and CSP "
                        "deployment to identify gaps and inform evasion strategies.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "pattern", "defense", "waf"),
        ),

        # ── Severity / Risk Scoring (3) ──────────────────────────────
        _s(
            "intel-severity-auto", "Automated Severity Classifier", 19,
            {Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING},
            description="Assigns severity ratings (Critical/High/Medium/Low/Info) to "
                        "findings using exploit complexity, data impact, authentication "
                        "requirements, and network exposure as weighted factors with "
                        "ML-assisted classification.",
            attack_types=("scoring",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("intel", "severity", "classification"),
        ),
        _s(
            "intel-business-impact", "Business Impact Scorer", 19,
            {Cap.STATISTICAL_ANALYSIS, Cap.KNOWLEDGE_SHARING},
            description="Augments technical severity with business impact assessment "
                        "considering data classification, regulatory exposure, brand "
                        "damage potential, and estimated financial impact based on "
                        "industry breach cost models.",
            attack_types=("scoring",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "business-impact", "risk"),
        ),
        _s(
            "intel-exploitability", "Exploitability Assessor", 19,
            {Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING},
            description="Evaluates real-world exploitability of findings by checking for "
                        "public exploit availability, Metasploit module existence, required "
                        "attacker skill level, and environmental factors that affect "
                        "weaponization feasibility.",
            attack_types=("scoring",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=20,
            tags=("intel", "exploitability", "weaponization"),
        ),

        # ── Coverage Tracking (2) ────────────────────────────────────
        _s(
            "intel-coverage-endpoint", "Endpoint Coverage Tracker", 19,
            {Cap.PATTERN_MATCHING, Cap.KNOWLEDGE_SHARING},
            description="Tracks which discovered endpoints, parameters, and functionality "
                        "have been tested by which agents, identifying untested attack "
                        "surface areas and recommending additional scan focus.",
            attack_types=("coverage",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "coverage", "endpoint"),
        ),
        _s(
            "intel-coverage-technique", "Technique Coverage Tracker", 19,
            {Cap.PATTERN_MATCHING, Cap.KNOWLEDGE_SHARING},
            description="Maps tested attack techniques against the full MITRE ATT&CK "
                        "web matrix and CWE taxonomy, reporting percentage coverage and "
                        "identifying untested technique categories.",
            attack_types=("coverage",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "coverage", "mitre-attack"),
        ),

        # ── Anomaly Detection (1) ────────────────────────────────────
        _s(
            "intel-anomaly", "Response Anomaly Detector", 19,
            {Cap.STATISTICAL_ANALYSIS, Cap.RESPONSE_DIFF, Cap.BASELINE_PROFILING},
            description="Detects anomalous server responses by establishing behavioral "
                        "baselines (response times, sizes, status codes) and flagging "
                        "statistical outliers that may indicate hidden vulnerabilities, "
                        "debug modes, or backend errors.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "anomaly", "baseline"),
        ),

        # ── Learning Engine (1) ──────────────────────────────────────
        _s(
            "intel-learning", "Adaptive Learning Engine", 19,
            {Cap.SELF_IMPROVEMENT, Cap.STATISTICAL_ANALYSIS, Cap.KNOWLEDGE_SHARING},
            description="Aggregates scan results across sessions to improve detection "
                        "accuracy: tracks false positive rates per agent, successful "
                        "payload patterns, and WAF bypass effectiveness to tune future "
                        "scan strategies.",
            attack_types=("learning",),
            min_mode=Mode.RECON,
            priority=Pri.BACKGROUND,
            max_requests=10,
            tags=("intel", "learning", "ml", "adaptation"),
        ),

        # ── Knowledge Graph (1) ──────────────────────────────────────
        _s(
            "intel-knowledge-graph", "Security Knowledge Graph Builder", 19,
            {Cap.KNOWLEDGE_SHARING, Cap.PATTERN_MATCHING},
            description="Constructs a knowledge graph linking targets, technologies, "
                        "vulnerabilities, attack chains, and remediation actions as "
                        "interconnected nodes for traversal queries and relationship "
                        "discovery across the entire scan corpus.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "knowledge-graph", "ontology"),
        ),

        # ── Report Generators (5) ────────────────────────────────────
        _s(
            "intel-report-html", "HTML Report Generator", 19,
            {Cap.KNOWLEDGE_SHARING},
            description="Generates interactive HTML security reports with severity "
                        "distribution charts, finding detail pages, evidence screenshots, "
                        "compliance matrices, and filterable/sortable finding tables "
                        "for stakeholder review.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("reporting", "html", "interactive"),
        ),
        _s(
            "intel-report-json", "JSON Report Generator", 19,
            {Cap.KNOWLEDGE_SHARING, Cap.API_INTERACTION},
            description="Serializes complete scan results into structured JSON format "
                        "with schema versioning, finding arrays, evidence references, "
                        "metadata, and compliance mappings for programmatic consumption "
                        "and downstream integration.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("reporting", "json", "api"),
        ),
        _s(
            "intel-report-pdf", "PDF Report Generator", 19,
            {Cap.KNOWLEDGE_SHARING},
            description="Produces professionally formatted PDF reports with cover page, "
                        "table of contents, executive summary, detailed findings with "
                        "evidence, remediation guidance, compliance appendices, and "
                        "severity trend graphs.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("reporting", "pdf", "professional"),
        ),
        _s(
            "intel-report-sarif", "SARIF Report Generator", 19,
            {Cap.KNOWLEDGE_SHARING},
            description="Generates SARIF v2.1.0 output for integration with GitHub "
                        "Advanced Security, Azure DevOps, and IDE SARIF viewers with "
                        "full taxonomy references, fix suggestions, and thread flow "
                        "locations for attack path visualization.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("reporting", "sarif", "github", "devops"),
        ),
        _s(
            "intel-report-junit", "JUnit XML Report Generator", 19,
            {Cap.KNOWLEDGE_SHARING},
            description="Converts security findings into JUnit XML format where each "
                        "finding becomes a test case (pass/fail), enabling integration "
                        "with CI/CD pipelines (Jenkins, GitLab CI, GitHub Actions) as "
                        "quality gate checks.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("reporting", "junit", "ci-cd", "quality-gate"),
        ),

        # ── Diff Report (1) ──────────────────────────────────────────
        _s(
            "intel-diff-report", "Differential Report Generator", 19,
            {Cap.KNOWLEDGE_SHARING, Cap.RESPONSE_DIFF},
            description="Compares current scan results against previous baselines to "
                        "produce delta reports showing new findings, resolved findings, "
                        "severity changes, and regression tracking across scan iterations.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("reporting", "diff", "regression", "trending"),
        ),

        # ── API Feed (1) ─────────────────────────────────────────────
        _s(
            "intel-api-feed", "Real-Time API Feed Publisher", 19,
            {Cap.API_INTERACTION, Cap.KNOWLEDGE_SHARING},
            description="Publishes findings and scan progress as a real-time event stream "
                        "(SSE/WebSocket) and REST API for integration with SIEM, SOAR, "
                        "ticketing systems (Jira, ServiceNow), and custom dashboards.",
            attack_types=("integration",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("integration", "api", "siem", "soar"),
        ),

        # ── Notification (1) ─────────────────────────────────────────
        _s(
            "intel-notification", "Alert Notification Dispatcher", 19,
            {Cap.API_INTERACTION, Cap.KNOWLEDGE_SHARING},
            description="Dispatches real-time alerts for critical/high findings via "
                        "configured channels: Slack webhooks, Microsoft Teams, email, "
                        "PagerDuty, and custom HTTP callbacks with severity-based "
                        "routing and deduplication.",
            attack_types=("notification",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=50,
            tags=("notification", "slack", "teams", "email"),
        ),

        # ── Trend Analyzer (1) ────────────────────────────────────────
        _s(
            "intel-trend-analyzer", "Historical Trend Analyzer", 19,
            {Cap.STATISTICAL_ANALYSIS, Cap.KNOWLEDGE_SHARING},
            description="Analyzes finding trends across multiple scan sessions to identify "
                        "improving or degrading security posture, recurring vulnerability "
                        "classes, mean-time-to-remediate metrics, and seasonal patterns "
                        "in vulnerability introduction.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "trend", "historical", "metrics"),
        ),

        # ── Attack Surface Quantifier (1) ────────────────────────────
        _s(
            "intel-attack-surface", "Attack Surface Quantifier", 19,
            {Cap.STATISTICAL_ANALYSIS, Cap.PATTERN_MATCHING, Cap.KNOWLEDGE_SHARING},
            description="Quantifies the total attack surface by enumerating exposed "
                        "endpoints, input vectors, authentication boundaries, and "
                        "technology components, producing a numerical attack surface "
                        "score with component-level breakdown.",
            attack_types=("analysis",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("intel", "attack-surface", "quantification"),
        ),

        # ── Division Commander (1) ───────────────────────────────────
        _s(
            "intel-commander", "Intelligence & Analysis Division Commander", 19,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Coordinates all Division 19 agents, ensures deduplication runs "
                        "before analysis, triggers report generation after all findings "
                        "are scored and classified, and manages the intelligence pipeline "
                        "from raw findings to actionable reports.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("commander", "coordination"),
        ),
    ]
