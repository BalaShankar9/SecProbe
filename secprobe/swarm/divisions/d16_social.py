"""
Division 16 — Social Engineering Vectors.

20 agents covering email security (SPF/DKIM/DMARC/MTA-STS/BIMI), phishing detection,
credential leak / OSINT, password spray, organization reconnaissance, and watering hole.
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
        # ── Email Security: SPF / DKIM / DMARC / MTA-STS / BIMI (6) ──
        _s(
            "se-spf-validator", "SPF Record Validator", 16,
            {Cap.DNS_ENUM, Cap.PATTERN_MATCHING},
            description="Queries and validates SPF TXT records for overly permissive "
                        "mechanisms (+all, ?all), nested includes exceeding 10-lookup limit, "
                        "and missing records that allow spoofing.",
            attack_types=("email-spoofing",),
            cwe_ids=("CWE-290",),
            detection_patterns=(
                r"v=spf1\s.*\+all",
                r"v=spf1\s.*\?all",
            ),
            priority=Pri.HIGH,
            max_requests=20,
            tags=("email", "spf", "dns"),
        ),
        _s(
            "se-dkim-analyzer", "DKIM Selector Analyzer", 16,
            {Cap.DNS_ENUM, Cap.PATTERN_MATCHING},
            description="Enumerates common DKIM selectors (default, google, selector1/2, "
                        "k1/k2) and checks for weak key lengths (<1024-bit RSA), missing "
                        "selectors, and testing mode (t=y).",
            attack_types=("email-spoofing",),
            cwe_ids=("CWE-290", "CWE-326"),
            detection_patterns=(r"p=([A-Za-z0-9+/=]{80,})",),
            priority=Pri.HIGH,
            max_requests=50,
            tags=("email", "dkim", "dns", "cryptography"),
        ),
        _s(
            "se-dmarc-auditor", "DMARC Policy Auditor", 16,
            {Cap.DNS_ENUM, Cap.PATTERN_MATCHING},
            description="Validates DMARC records for policy strength (p=none vs p=reject), "
                        "subdomain policy (sp=), reporting URIs (rua/ruf), and percentage "
                        "deployment (pct<100).",
            attack_types=("email-spoofing",),
            cwe_ids=("CWE-290",),
            detection_patterns=(
                r"v=DMARC1;\s*p=none",
                r"v=DMARC1;\s*p=quarantine.*pct=\d{1,2}[^0]",
            ),
            priority=Pri.HIGH,
            max_requests=10,
            tags=("email", "dmarc", "dns"),
        ),
        _s(
            "se-mta-sts-checker", "MTA-STS Policy Checker", 16,
            {Cap.HTTP_PROBE, Cap.DNS_ENUM},
            description="Verifies MTA-STS DNS records (_mta-sts TXT), retrieves the "
                        "well-known policy file, and checks for enforce mode, valid max_age, "
                        "and correct MX alignment.",
            attack_types=("email-downgrade",),
            cwe_ids=("CWE-319",),
            detection_patterns=(r"mode:\s*testing",),
            priority=Pri.NORMAL,
            max_requests=15,
            tags=("email", "mta-sts", "tls"),
        ),
        _s(
            "se-bimi-inspector", "BIMI Record Inspector", 16,
            {Cap.DNS_ENUM, Cap.HTTP_PROBE},
            description="Checks for BIMI DNS records (default._bimi), validates SVG logo "
                        "accessibility, and verifies VMC certificate presence for brand "
                        "indicator display in email clients.",
            attack_types=("brand-impersonation",),
            cwe_ids=("CWE-290",),
            detection_patterns=(r"v=BIMI1",),
            priority=Pri.LOW,
            max_requests=10,
            tags=("email", "bimi", "brand"),
        ),
        _s(
            "se-email-header-analyzer", "Email Header Security Analyzer", 16,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
            description="Inspects mail-related HTTP headers and DNS for DANE TLSA records, "
                        "SMTP TLS reporting (TLS-RPT), and ARC seal chains to detect email "
                        "authentication gaps.",
            attack_types=("email-spoofing", "email-downgrade"),
            cwe_ids=("CWE-290", "CWE-319"),
            detection_patterns=(r"_smtp._tls",),
            priority=Pri.NORMAL,
            max_requests=20,
            tags=("email", "dane", "tls-rpt", "arc"),
        ),

        # ── Phishing / Branding (3) ──────────────────────────────────
        _s(
            "se-phish-similarity", "Phishing Domain Similarity Scanner", 16,
            {Cap.DNS_ENUM, Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Generates and probes typosquatted, homoglyph, and bitsquatted "
                        "domain variants to identify potential phishing infrastructure "
                        "targeting the organization.",
            attack_types=("phishing", "typosquatting"),
            cwe_ids=("CWE-451",),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=200,
            tags=("phishing", "domain", "typosquat"),
        ),
        _s(
            "se-brand-impersonation", "Brand Impersonation Detector", 16,
            {Cap.HTTP_PROBE, Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Searches certificate transparency logs, WHOIS, and web content "
                        "for unauthorized use of organization logos, names, and trademarks "
                        "on third-party sites.",
            attack_types=("brand-impersonation",),
            cwe_ids=("CWE-451",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=50,
            tags=("phishing", "brand", "ct-logs"),
        ),
        _s(
            "se-login-clone-detector", "Login Page Clone Detector", 16,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.BROWSER_AUTOMATION},
            description="Compares visual and DOM structure of discovered phishing pages "
                        "against the organization's legitimate login portal to detect "
                        "credential-harvesting clones.",
            attack_types=("phishing", "credential-theft"),
            cwe_ids=("CWE-451",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("phishing", "credential-harvest", "visual-diff"),
        ),

        # ── Credential Leak / OSINT (4) ──────────────────────────────
        _s(
            "se-credential-leak", "Credential Leak Monitor", 16,
            {Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Queries breach databases, paste sites, and dark web indexes for "
                        "exposed credentials associated with the target organization's "
                        "email domains and known employee identifiers.",
            attack_types=("credential-leak",),
            cwe_ids=("CWE-521", "CWE-522"),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=30,
            tags=("osint", "breach", "credentials"),
        ),
        _s(
            "se-github-secret-scanner", "GitHub Secret Scanner", 16,
            {Cap.OSINT, Cap.PATTERN_MATCHING, Cap.API_INTERACTION},
            description="Searches public GitHub repositories, gists, and commit history "
                        "for exposed API keys, tokens, passwords, and connection strings "
                        "linked to the target organization.",
            attack_types=("secret-exposure",),
            cwe_ids=("CWE-798", "CWE-540"),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=60,
            tags=("osint", "github", "secrets", "api-keys"),
        ),
        _s(
            "se-employee-enum", "Employee Enumeration Agent", 16,
            {Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Harvests employee names and email addresses from LinkedIn, "
                        "social media, company pages, and public filings to build a "
                        "target list for credential-based attacks.",
            attack_types=("osint-enum",),
            cwe_ids=("CWE-200",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=40,
            tags=("osint", "employee", "enumeration"),
        ),
        _s(
            "se-metadata-harvester", "Document Metadata Harvester", 16,
            {Cap.HTTP_PROBE, Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Downloads and analyzes publicly available documents (PDF, DOCX, "
                        "XLSX) for embedded metadata revealing internal usernames, software "
                        "versions, file paths, and printer names.",
            attack_types=("metadata-leak",),
            cwe_ids=("CWE-200", "CWE-538"),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=40,
            tags=("osint", "metadata", "documents"),
        ),

        # ── Password Spray (2) ───────────────────────────────────────
        _s(
            "se-password-spray", "Password Spray Engine", 16,
            {Cap.HTTP_PROBE, Cap.API_INTERACTION, Cap.RATE_ADAPTATION},
            description="Executes low-and-slow password spray attacks against discovered "
                        "authentication endpoints using common/seasonal passwords while "
                        "respecting lockout thresholds.",
            attack_types=("password-spray", "brute-force"),
            cwe_ids=("CWE-307", "CWE-521"),
            min_mode=Mode.REDTEAM,
            priority=Pri.HIGH,
            max_requests=200,
            timeout=600,
            tags=("auth", "password-spray", "brute-force"),
        ),
        _s(
            "se-lockout-detector", "Account Lockout Policy Detector", 16,
            {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.STATISTICAL_ANALYSIS},
            description="Probes authentication endpoints with controlled failed attempts "
                        "to map lockout thresholds, timing windows, and bypass conditions "
                        "before spray campaigns begin.",
            attack_types=("lockout-detection",),
            cwe_ids=("CWE-307",),
            min_mode=Mode.AUDIT,
            priority=Pri.NORMAL,
            max_requests=30,
            depends_on=("se-password-spray",),
            tags=("auth", "lockout", "rate-limit"),
        ),

        # ── Organization Recon (3) ───────────────────────────────────
        _s(
            "se-org-structure-mapper", "Organization Structure Mapper", 16,
            {Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Maps organizational hierarchy, department structure, and key "
                        "personnel from public sources to identify high-value targets "
                        "for social engineering campaigns.",
            attack_types=("osint-enum",),
            cwe_ids=("CWE-200",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=30,
            tags=("osint", "org-chart", "recon"),
        ),
        _s(
            "se-tech-job-posting-analyzer", "Technology Stack Job Posting Analyzer", 16,
            {Cap.OSINT, Cap.PATTERN_MATCHING},
            description="Analyzes job postings on careers pages and job boards to infer "
                        "internal technology stacks, security tools, cloud providers, and "
                        "development practices.",
            attack_types=("osint-enum",),
            cwe_ids=("CWE-200",),
            min_mode=Mode.RECON,
            priority=Pri.LOW,
            max_requests=20,
            tags=("osint", "tech-stack", "job-postings"),
        ),
        _s(
            "se-supply-chain-mapper", "Supply Chain Relationship Mapper", 16,
            {Cap.OSINT, Cap.DNS_ENUM, Cap.PATTERN_MATCHING},
            description="Identifies third-party vendors, SaaS providers, and partner "
                        "integrations through DNS records, JavaScript includes, and public "
                        "filings to map the supply chain attack surface.",
            attack_types=("supply-chain",),
            cwe_ids=("CWE-1357",),
            min_mode=Mode.RECON,
            priority=Pri.NORMAL,
            max_requests=40,
            tags=("osint", "supply-chain", "third-party"),
        ),

        # ── Watering Hole (1) ────────────────────────────────────────
        _s(
            "se-watering-hole-scanner", "Watering Hole Vector Scanner", 16,
            {Cap.HTTP_PROBE, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
            description="Analyzes third-party resources loaded by the target site "
                        "(CDN scripts, analytics, ad networks) for signs of compromise "
                        "or injection that could turn them into watering hole vectors.",
            attack_types=("watering-hole", "supply-chain"),
            cwe_ids=("CWE-829", "CWE-506"),
            min_mode=Mode.RECON,
            priority=Pri.HIGH,
            max_requests=50,
            tags=("watering-hole", "supply-chain", "third-party-js"),
        ),

        # ── Division Commander (1) ───────────────────────────────────
        _s(
            "se-commander", "Social Engineering Division Commander", 16,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
            description="Coordinates all Division 16 agents, prioritizes email security "
                        "checks before offensive social engineering operations, aggregates "
                        "OSINT findings, and enforces mode restrictions for spray/phishing.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("commander", "coordination"),
        ),
    ]
