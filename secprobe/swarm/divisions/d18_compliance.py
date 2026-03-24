"""
Division 18 — Compliance & Standards.

20 agents covering OWASP mapping, PCI DSS, NIST, ISO 27001, HIPAA, SOC 2, GDPR,
CIS benchmarks, SANS/CWE Top 25, CVSS 3.1/4.0 scoring, EPSS, risk matrix,
remediation priority, executive summary, SARIF output, and coordination.
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
        # ── OWASP Mappers (3) ────────────────────────────────────────
        _s(
            "comp-owasp-top10-web", "OWASP Top 10 Web Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps all discovered findings to the OWASP Top 10 2021 categories "
                        "(A01-A10), including injection, broken access control, crypto "
                        "failures, and SSRF, with category-specific remediation guidance.",
            attack_types=("compliance-mapping",),
            cwe_ids=("CWE-1344",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("compliance", "owasp", "top10", "web"),
        ),
        _s(
            "comp-owasp-api-top10", "OWASP API Top 10 Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps API-related findings to OWASP API Security Top 10 2023 "
                        "categories (API1-API10): BOLA, broken authentication, object "
                        "property level authorization, SSRF, and security misconfiguration.",
            attack_types=("compliance-mapping",),
            cwe_ids=("CWE-1344",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("compliance", "owasp", "api", "top10"),
        ),
        _s(
            "comp-owasp-mobile-top10", "OWASP Mobile Top 10 Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps mobile findings to OWASP Mobile Top 10 2024 categories "
                        "(M1-M10): improper credential usage, inadequate supply chain, "
                        "insecure authentication, and insufficient cryptography.",
            attack_types=("compliance-mapping",),
            cwe_ids=("CWE-1344",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("compliance", "owasp", "mobile", "top10"),
        ),

        # ── Regulatory Frameworks (7) ────────────────────────────────
        _s(
            "comp-pci-dss", "PCI DSS 4.0 Compliance Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps findings to PCI DSS 4.0 requirements covering network "
                        "security (Req 1-2), data protection (Req 3-4), vulnerability "
                        "management (Req 5-6), access control (Req 7-8), monitoring "
                        "(Req 10), and testing (Req 11).",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("compliance", "pci-dss", "payment"),
        ),
        _s(
            "comp-nist", "NIST SP 800-53 / CSF Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps findings to NIST SP 800-53 Rev 5 control families (AC, AU, "
                        "CA, CM, IA, SC, SI) and NIST Cybersecurity Framework 2.0 functions "
                        "(Identify, Protect, Detect, Respond, Recover, Govern).",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("compliance", "nist", "800-53", "csf"),
        ),
        _s(
            "comp-iso27001", "ISO 27001:2022 Controls Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps findings to ISO 27001:2022 Annex A controls across "
                        "organizational (A.5), people (A.6), physical (A.7), and "
                        "technological (A.8) control categories with SoA references.",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("compliance", "iso27001", "isms"),
        ),
        _s(
            "comp-hipaa", "HIPAA Security Rule Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps findings to HIPAA Security Rule safeguards: administrative "
                        "(164.308), physical (164.310), and technical (164.312) including "
                        "access control, audit controls, integrity, and transmission security.",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("compliance", "hipaa", "healthcare"),
        ),
        _s(
            "comp-soc2", "SOC 2 Trust Service Criteria Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps findings to SOC 2 Type II Trust Service Criteria: security "
                        "(CC1-CC9), availability (A1), processing integrity (PI1), "
                        "confidentiality (C1), and privacy (P1-P8) with control references.",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("compliance", "soc2", "audit"),
        ),
        _s(
            "comp-gdpr", "GDPR Technical Compliance Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps findings to GDPR Articles 25 (data protection by design), "
                        "32 (security of processing), 33-34 (breach notification), and "
                        "assesses technical measures for data minimization and pseudonymization.",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("compliance", "gdpr", "privacy", "eu"),
        ),
        _s(
            "comp-cis-benchmark", "CIS Benchmark Mapper", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Maps web server and application findings to CIS Benchmarks for "
                        "Apache, Nginx, IIS, and application-level controls including TLS "
                        "configuration, header security, and access restrictions.",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("compliance", "cis", "benchmark", "hardening"),
        ),

        # ── Vulnerability Taxonomy (1) ───────────────────────────────
        _s(
            "comp-sans-cwe-top25", "SANS/CWE Top 25 Classifier", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
            description="Classifies all findings against the CWE Top 25 Most Dangerous "
                        "Software Weaknesses list, tracking coverage across out-of-bounds "
                        "write, XSS, SQL injection, use-after-free, command injection, "
                        "and path traversal categories.",
            attack_types=("compliance-mapping",),
            cwe_ids=("CWE-1350",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("compliance", "cwe", "sans", "top25"),
        ),

        # ── Scoring Engines (3) ──────────────────────────────────────
        _s(
            "comp-cvss31-scorer", "CVSS 3.1 Scoring Engine", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.STATISTICAL_ANALYSIS},
            description="Calculates CVSS 3.1 base, temporal, and environmental scores for "
                        "each finding using attack vector, complexity, privileges required, "
                        "user interaction, scope, and CIA impact metrics.",
            attack_types=("scoring",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("scoring", "cvss", "3.1"),
        ),
        _s(
            "comp-cvss40-scorer", "CVSS 4.0 Scoring Engine", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.STATISTICAL_ANALYSIS},
            description="Calculates CVSS 4.0 scores incorporating the new supplemental "
                        "metrics group (Automatable, Recovery, Value Density, Provider "
                        "Urgency) alongside base, threat, and environmental metric groups.",
            attack_types=("scoring",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("scoring", "cvss", "4.0"),
        ),
        _s(
            "comp-epss-scorer", "EPSS Probability Scorer", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.STATISTICAL_ANALYSIS, Cap.API_INTERACTION},
            description="Enriches findings with Exploit Prediction Scoring System (EPSS) "
                        "probability and percentile data by correlating CWE/CVE identifiers "
                        "with the FIRST EPSS model for exploitation likelihood assessment.",
            attack_types=("scoring",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=20,
            tags=("scoring", "epss", "exploit-prediction"),
        ),

        # ── Risk & Remediation (2) ───────────────────────────────────
        _s(
            "comp-risk-matrix", "Risk Matrix Calculator", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.STATISTICAL_ANALYSIS},
            description="Computes organizational risk scores by combining CVSS base scores, "
                        "EPSS exploitation probability, asset criticality, data sensitivity, "
                        "and exposure context into a 5x5 likelihood-impact risk matrix.",
            attack_types=("risk-assessment",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            tags=("risk", "matrix", "prioritization"),
        ),
        _s(
            "comp-remediation-priority", "Remediation Priority Engine", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.KNOWLEDGE_SHARING},
            description="Generates prioritized remediation roadmaps by ranking findings "
                        "using risk scores, fix complexity estimates, dependency chains, "
                        "and quick-win identification for maximum risk reduction.",
            attack_types=("remediation",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=10,
            depends_on=("comp-risk-matrix",),
            tags=("remediation", "priority", "roadmap"),
        ),

        # ── Reporting (2) ────────────────────────────────────────────
        _s(
            "comp-executive-summary", "Executive Summary Generator", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.KNOWLEDGE_SHARING},
            description="Produces a non-technical executive summary with overall security "
                        "posture grade (A-F), top risk areas, trend comparison with previous "
                        "scans, compliance gap highlights, and strategic recommendations.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            depends_on=("comp-risk-matrix", "comp-remediation-priority"),
            tags=("reporting", "executive", "summary"),
        ),
        _s(
            "comp-sarif-output", "SARIF Output Generator", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.KNOWLEDGE_SHARING},
            description="Serializes all findings into SARIF v2.1.0 format with tool "
                        "metadata, taxonomies (CWE, OWASP), threadFlowLocations for "
                        "attack chains, and CodeQL-compatible result structures for "
                        "IDE and CI/CD integration.",
            attack_types=("reporting",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            tags=("reporting", "sarif", "ci-cd"),
        ),

        # ── Compliance Gap Analysis (1) ──────────────────────────────
        _s(
            "comp-gap-analyzer", "Compliance Coverage Gap Analyzer", 18,
            {Cap.COMPLIANCE_MAPPING, Cap.KNOWLEDGE_SHARING, Cap.STATISTICAL_ANALYSIS},
            description="Identifies gaps in compliance coverage by cross-referencing "
                        "tested controls against each framework's full requirements list, "
                        "producing a heatmap of untested or partially validated controls "
                        "with recommendations for additional assessment.",
            attack_types=("compliance-mapping",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=10,
            depends_on=("comp-pci-dss", "comp-nist", "comp-iso27001"),
            tags=("compliance", "gap-analysis", "coverage"),
        ),

        # ── Division Commander (1) ───────────────────────────────────
        _s(
            "comp-commander", "Compliance & Standards Division Commander", 18,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Coordinates all Division 18 agents, ensures findings are mapped "
                        "to all applicable frameworks before reporting, triggers scoring "
                        "engines after finding consolidation, and orchestrates report "
                        "generation sequence.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("commander", "coordination"),
        ),
    ]
