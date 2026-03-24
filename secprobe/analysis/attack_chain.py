"""
Attack Chain Analyzer — SecProbe's KEY differentiator.

Correlates individual findings across scanners to identify multi-step
exploitation paths that no single scanner would detect alone.

Examples:
  - Open admin port + default credentials + SQLi = Full DB compromise
  - XSS + missing HttpOnly + session fixation = Account takeover
  - CORS misconfiguration + sensitive API + no auth = Data exfiltration
  - Open redirect + XSS + OAuth flow = Token theft
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Optional

from secprobe.models import Finding


# ─────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────

@dataclass
class AttackStep:
    """Single step in an attack chain."""
    order: int
    finding: Finding
    role: str  # "entry", "pivot", "escalation", "objective"
    description: str


@dataclass
class AttackChain:
    """Multi-step exploitation path built from correlated findings."""
    chain_id: str
    name: str
    description: str
    steps: list[AttackStep] = field(default_factory=list)
    impact: str = ""
    likelihood: str = "Medium"
    overall_severity: str = "Critical"
    remediation: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        """Compute composite risk score (0-100) from chain properties."""
        severity_scores = {
            "Critical": 95, "High": 75, "Medium": 50, "Low": 25, "Info": 5
        }
        likelihood_scores = {
            "Very High": 1.0, "High": 0.8, "Medium": 0.6, "Low": 0.4, "Very Low": 0.2
        }
        base = severity_scores.get(self.overall_severity, 50)
        mult = likelihood_scores.get(self.likelihood, 0.6)
        chain_bonus = min(len(self.steps) * 5, 20)  # longer chains = higher risk
        return min(base * mult + chain_bonus, 100)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "steps": [
                {
                    "order": s.order,
                    "role": s.role,
                    "description": s.description,
                    "finding_title": s.finding.title,
                    "finding_severity": s.finding.severity,
                    "scanner": s.finding.scanner,
                }
                for s in self.steps
            ],
            "impact": self.impact,
            "likelihood": self.likelihood,
            "overall_severity": self.overall_severity,
            "risk_score": self.risk_score,
            "remediation": self.remediation,
            "mitre_attack": self.mitre_attack,
            "tags": self.tags,
        }


# ─────────────────────────────────────────────────────────────────
# Chain Rules — define how findings correlate into attack paths
# ─────────────────────────────────────────────────────────────────

@dataclass
class ChainRule:
    """A rule that matches a set of finding patterns into an attack chain."""
    rule_id: str
    name: str
    description: str
    required_patterns: list[FindingPattern]
    optional_patterns: list[FindingPattern] = field(default_factory=list)
    impact: str = ""
    likelihood: str = "Medium"
    severity: str = "Critical"
    remediation: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class FindingPattern:
    """Pattern to match a finding for chain correlation."""
    scanner: Optional[str] = None          # scanner name or None for any
    title_contains: Optional[str] = None   # substring match on title
    title_regex: Optional[str] = None      # regex match on title
    severity_in: Optional[list[str]] = None  # ["Critical", "High"]
    detail_contains: Optional[str] = None  # substring in details
    role: str = "pivot"                    # role in the chain
    step_description: str = ""


# ─────────────────────────────────────────────────────────────────
# Built-in Chain Rules
# ─────────────────────────────────────────────────────────────────

CHAIN_RULES: list[ChainRule] = [
    # ── Chain 1: Full Database Compromise ────────────────────────
    ChainRule(
        rule_id="CHAIN-001",
        name="Full Database Compromise",
        description=(
            "SQL injection combined with exposed database ports and weak "
            "credentials enables complete database takeover."
        ),
        required_patterns=[
            FindingPattern(
                scanner="sqli",
                title_contains="SQL Injection",
                role="entry",
                step_description="SQL injection vulnerability allows arbitrary query execution",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="port",
                detail_contains="3306",
                role="escalation",
                step_description="MySQL port (3306) is publicly accessible",
            ),
            FindingPattern(
                scanner="port",
                detail_contains="5432",
                role="escalation",
                step_description="PostgreSQL port (5432) is publicly accessible",
            ),
            FindingPattern(
                scanner="port",
                detail_contains="1433",
                role="escalation",
                step_description="MSSQL port (1433) is publicly accessible",
            ),
            FindingPattern(
                scanner="header",
                title_contains="Server Version",
                role="pivot",
                step_description="Server version disclosure aids exploitation",
            ),
        ],
        impact="Complete database access — read, modify, delete all data. Potential OS command execution via SQLi.",
        likelihood="High",
        severity="Critical",
        remediation="1) Fix all SQL injection points with parameterized queries. 2) Block database ports from public access. 3) Use least-privilege DB accounts.",
        mitre_attack=["T1190", "T1059.004", "T1005"],
        tags=["database", "sqli", "data-breach"],
    ),

    # ── Chain 2: Account Takeover via XSS ────────────────────────
    ChainRule(
        rule_id="CHAIN-002",
        name="Account Takeover via XSS + Cookie Theft",
        description=(
            "Cross-site scripting combined with missing cookie security "
            "flags enables session hijacking and account takeover."
        ),
        required_patterns=[
            FindingPattern(
                scanner="xss",
                title_contains="XSS",
                role="entry",
                step_description="XSS vulnerability allows JavaScript execution in victim's browser",
            ),
            FindingPattern(
                scanner="cookie",
                title_contains="HttpOnly",
                role="pivot",
                step_description="Session cookies accessible to JavaScript (missing HttpOnly flag)",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="cookie",
                title_contains="Secure",
                role="escalation",
                step_description="Cookies transmitted over unencrypted HTTP",
            ),
            FindingPattern(
                scanner="cookie",
                title_contains="SameSite",
                role="escalation",
                step_description="Missing SameSite flag enables cross-origin cookie sending",
            ),
            FindingPattern(
                scanner="header",
                title_contains="Content-Security-Policy",
                role="pivot",
                step_description="Missing CSP allows unrestricted script execution",
            ),
        ],
        impact="Full account takeover — attacker steals session cookies via XSS, impersonates any user.",
        likelihood="High",
        severity="Critical",
        remediation="1) Fix all XSS vulnerabilities with proper output encoding. 2) Set HttpOnly, Secure, and SameSite flags on all session cookies. 3) Implement Content-Security-Policy header.",
        mitre_attack=["T1189", "T1539", "T1550.004"],
        tags=["xss", "session-hijack", "account-takeover"],
    ),

    # ── Chain 3: Data Exfiltration via CORS ──────────────────────
    ChainRule(
        rule_id="CHAIN-003",
        name="Data Exfiltration via CORS Misconfiguration",
        description=(
            "CORS misconfiguration combined with authenticated API endpoints "
            "enables cross-origin data theft."
        ),
        required_patterns=[
            FindingPattern(
                scanner="cors",
                title_contains="CORS",
                role="entry",
                step_description="CORS policy allows arbitrary origins to read responses",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="cors",
                title_contains="credentials",
                role="escalation",
                step_description="CORS allows credentials — cookies sent with cross-origin requests",
            ),
            FindingPattern(
                scanner="header",
                title_contains="X-Frame-Options",
                role="pivot",
                step_description="Missing X-Frame-Options allows clickjacking to trigger requests",
            ),
            FindingPattern(
                scanner="cookie",
                title_contains="SameSite",
                role="pivot",
                step_description="Missing SameSite allows cross-origin cookie attachment",
            ),
        ],
        impact="Sensitive data exfiltration — attacker's site reads API responses authenticated as the victim.",
        likelihood="Medium",
        severity="High",
        remediation="1) Restrict Access-Control-Allow-Origin to specific trusted domains. 2) Never reflect arbitrary Origin headers. 3) Set SameSite=Strict on sensitive cookies.",
        mitre_attack=["T1557", "T1185"],
        tags=["cors", "data-exfiltration", "cross-origin"],
    ),

    # ── Chain 4: SSL/TLS Downgrade + Session Hijack ──────────────
    ChainRule(
        rule_id="CHAIN-004",
        name="SSL/TLS Downgrade to Session Hijack",
        description=(
            "Weak SSL/TLS combined with missing HSTS and insecure cookies "
            "enables man-in-the-middle session hijacking."
        ),
        required_patterns=[
            FindingPattern(
                scanner="ssl",
                severity_in=["Critical", "High"],
                role="entry",
                step_description="Weak SSL/TLS configuration enables protocol downgrade",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="header",
                title_contains="Strict-Transport-Security",
                role="pivot",
                step_description="Missing HSTS allows HTTP downgrade attacks",
            ),
            FindingPattern(
                scanner="cookie",
                title_contains="Secure",
                role="escalation",
                step_description="Cookies transmitted over unencrypted connections",
            ),
        ],
        impact="Man-in-the-middle attack — attacker intercepts traffic, steals sessions, injects content.",
        likelihood="Medium",
        severity="High",
        remediation="1) Enforce TLS 1.2+ only. 2) Deploy HSTS with long max-age. 3) Set Secure flag on all cookies. 4) Disable weak cipher suites.",
        mitre_attack=["T1557.002", "T1040"],
        tags=["ssl", "mitm", "session-hijack"],
    ),

    # ── Chain 5: Sensitive Admin Panel Exposure ──────────────────
    ChainRule(
        rule_id="CHAIN-005",
        name="Exposed Admin Panel with Information Leakage",
        description=(
            "Discoverable admin panel combined with server information "
            "leakage and technology fingerprints aids targeted attacks."
        ),
        required_patterns=[
            FindingPattern(
                scanner="directory",
                title_contains="admin",
                role="entry",
                step_description="Admin panel or management interface is publicly accessible",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="header",
                title_contains="Server",
                role="pivot",
                step_description="Server version disclosed — enables version-specific exploits",
            ),
            FindingPattern(
                scanner="header",
                title_contains="X-Powered-By",
                role="pivot",
                step_description="Technology stack disclosed via headers",
            ),
            FindingPattern(
                scanner="tech",
                role="pivot",
                step_description="Detailed technology fingerprint identified",
            ),
        ],
        impact="Admin panel brute-force or exploitation with known CVEs for the identified technology stack.",
        likelihood="Medium",
        severity="High",
        remediation="1) Restrict admin panel to VPN/internal network. 2) Remove version headers. 3) Implement multi-factor authentication. 4) Use IP allowlisting.",
        mitre_attack=["T1190", "T1078"],
        tags=["admin-panel", "information-disclosure", "brute-force"],
    ),

    # ── Chain 6: DNS + Subdomain Takeover ────────────────────────
    ChainRule(
        rule_id="CHAIN-006",
        name="Subdomain Takeover Risk",
        description=(
            "Dangling DNS records or missing SPF/DMARC create risks of "
            "subdomain takeover and email spoofing."
        ),
        required_patterns=[
            FindingPattern(
                scanner="dns",
                title_contains="CNAME",
                role="entry",
                step_description="CNAME records point to potentially claimable external services",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="dns",
                title_contains="SPF",
                role="pivot",
                step_description="Missing/weak SPF enables email spoofing from this domain",
            ),
            FindingPattern(
                scanner="dns",
                title_contains="DMARC",
                role="pivot",
                step_description="Missing DMARC allows spoofed emails to be delivered",
            ),
            FindingPattern(
                scanner="ssl",
                title_contains="certificate",
                role="escalation",
                step_description="SSL certificate issues on subdomains",
            ),
        ],
        impact="Subdomain takeover enables phishing, cookie theft, and CSP bypass. Email spoofing enables social engineering.",
        likelihood="Medium",
        severity="High",
        remediation="1) Audit all CNAME records and remove dangling entries. 2) Configure strict SPF and DMARC policies. 3) Monitor subdomains for takeover.",
        mitre_attack=["T1584.001", "T1566.002"],
        tags=["dns", "subdomain-takeover", "email-spoofing"],
    ),

    # ── Chain 7: SSRF / Internal Network Pivot ───────────────────
    ChainRule(
        rule_id="CHAIN-007",
        name="Server-Side Request Forgery to Internal Access",
        description=(
            "Template injection or SSRF combined with exposed internal "
            "services enables pivoting into the internal network."
        ),
        required_patterns=[
            FindingPattern(
                scanner="xss",
                title_contains="SSTI",
                role="entry",
                step_description="Server-Side Template Injection enables server-side code execution",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="port",
                detail_contains="6379",
                role="escalation",
                step_description="Redis port exposed — potential data access via SSRF",
            ),
            FindingPattern(
                scanner="port",
                detail_contains="27017",
                role="escalation",
                step_description="MongoDB port exposed — potential data access via SSRF",
            ),
            FindingPattern(
                scanner="port",
                detail_contains="9200",
                role="escalation",
                step_description="Elasticsearch port exposed — potential data access via SSRF",
            ),
            FindingPattern(
                scanner="header",
                detail_contains="internal",
                role="pivot",
                step_description="Internal IP addresses leaked in headers",
            ),
        ],
        impact="Pivot from web application into internal network — access databases, caches, internal services.",
        likelihood="Medium",
        severity="Critical",
        remediation="1) Fix SSTI/SSRF vulnerabilities. 2) Block outbound connections from web servers. 3) Segment internal services. 4) Remove internal IPs from responses.",
        mitre_attack=["T1190", "T1210", "T1046"],
        tags=["ssrf", "ssti", "internal-pivot", "network-segmentation"],
    ),

    # ── Chain 8: Sensitive File Exposure ─────────────────────────
    ChainRule(
        rule_id="CHAIN-008",
        name="Source Code / Configuration Exposure",
        description=(
            "Exposed version control, configuration files, or backup "
            "archives leak credentials and application secrets."
        ),
        required_patterns=[
            FindingPattern(
                scanner="directory",
                title_contains="sensitive",
                role="entry",
                step_description="Sensitive file or directory exposed publicly",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="directory",
                detail_contains=".git",
                role="escalation",
                step_description=".git directory exposed — full source code recoverable",
            ),
            FindingPattern(
                scanner="directory",
                detail_contains=".env",
                role="escalation",
                step_description="Environment file exposed — API keys, database credentials",
            ),
            FindingPattern(
                scanner="directory",
                detail_contains="backup",
                role="escalation",
                step_description="Backup files exposed — may contain database dumps",
            ),
            FindingPattern(
                scanner="directory",
                detail_contains="config",
                role="escalation",
                step_description="Configuration files exposed — infrastructure secrets",
            ),
        ],
        impact="Full source code access, leaked credentials, API keys, database passwords.",
        likelihood="High",
        severity="Critical",
        remediation="1) Block access to .git, .env, and backup files via web server config. 2) Move sensitive files outside web root. 3) Rotate all exposed credentials.",
        mitre_attack=["T1213", "T1552.001"],
        tags=["source-code", "credentials", "information-disclosure"],
    ),

    # ── Chain 9: Open Redirect + Phishing ────────────────────────
    ChainRule(
        rule_id="CHAIN-009",
        name="Open Redirect to Credential Phishing",
        description=(
            "Open redirect combined with lack of security headers enables "
            "convincing phishing attacks using the trusted domain."
        ),
        required_patterns=[
            FindingPattern(
                scanner="directory",
                detail_contains="redirect",
                role="entry",
                step_description="Open redirect endpoint found on trusted domain",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="header",
                title_contains="Content-Security-Policy",
                role="pivot",
                step_description="Missing CSP allows framing and redirection",
            ),
            FindingPattern(
                scanner="header",
                title_contains="X-Frame-Options",
                role="pivot",
                step_description="Missing X-Frame-Options enables clickjacking",
            ),
            FindingPattern(
                scanner="ssl",
                title_contains="certificate",
                role="pivot",
                step_description="SSL certificate issues reduce trust indicators",
            ),
        ],
        impact="Phishing attacks using the organization's trusted domain — high click-through rate, credential theft.",
        likelihood="High",
        severity="High",
        remediation="1) Validate and whitelist redirect targets. 2) Implement CSP frame-ancestors. 3) Deploy X-Frame-Options DENY.",
        mitre_attack=["T1566.002", "T1204.001"],
        tags=["open-redirect", "phishing", "social-engineering"],
    ),

    # ── Chain 10: Complete Infrastructure Mapping ────────────────
    ChainRule(
        rule_id="CHAIN-010",
        name="Comprehensive Attack Surface Exposure",
        description=(
            "Excessive information disclosure across multiple vectors "
            "provides attackers a complete infrastructure map."
        ),
        required_patterns=[
            FindingPattern(
                scanner="tech",
                role="entry",
                step_description="Detailed technology stack fingerprinted",
            ),
            FindingPattern(
                scanner="dns",
                role="pivot",
                step_description="DNS enumeration reveals infrastructure layout",
            ),
        ],
        optional_patterns=[
            FindingPattern(
                scanner="port",
                role="pivot",
                step_description="Multiple open ports map the network attack surface",
            ),
            FindingPattern(
                scanner="header",
                title_contains="Server",
                role="pivot",
                step_description="Server version enables CVE lookup",
            ),
            FindingPattern(
                scanner="directory",
                role="pivot",
                step_description="Exposed directories reveal application structure",
            ),
        ],
        impact="Complete infrastructure map aids targeted attacks — known software versions, network topology, directory structure.",
        likelihood="High",
        severity="Medium",
        remediation="1) Minimize information disclosure across all vectors. 2) Remove version headers. 3) Restrict DNS zone transfers. 4) Close unnecessary ports.",
        mitre_attack=["T1595", "T1592", "T1590"],
        tags=["recon", "information-disclosure", "attack-surface"],
    ),
]


# ─────────────────────────────────────────────────────────────────
# Analyzer Engine
# ─────────────────────────────────────────────────────────────────

class AttackChainAnalyzer:
    """Correlates findings from multiple scanners into multi-step attack chains."""

    def __init__(self, custom_rules: Optional[list[ChainRule]] = None):
        self.rules = CHAIN_RULES + (custom_rules or [])
        self._chain_counter = 0

    def analyze(self, findings: list[Finding]) -> list[AttackChain]:
        """Analyze a list of findings and return identified attack chains.
        
        Args:
            findings: All findings from all scanners
            
        Returns:
            List of AttackChain objects, sorted by risk score descending
        """
        chains: list[AttackChain] = []

        for rule in self.rules:
            chain = self._evaluate_rule(rule, findings)
            if chain is not None:
                chains.append(chain)

        # Sort by risk score, highest first
        chains.sort(key=lambda c: c.risk_score, reverse=True)
        return chains

    def _evaluate_rule(self, rule: ChainRule, findings: list[Finding]) -> Optional[AttackChain]:
        """Check if a rule's required patterns all match findings."""
        matched_steps: list[AttackStep] = []
        used_findings: set[int] = set()

        # All required patterns must match
        for pattern in rule.required_patterns:
            match = self._find_matching(pattern, findings, used_findings)
            if match is None:
                return None  # Required pattern not found — rule doesn't apply
            finding, _ = match
            used_findings.add(id(finding))
            matched_steps.append(AttackStep(
                order=len(matched_steps) + 1,
                finding=finding,
                role=pattern.role,
                description=pattern.step_description or finding.title,
            ))

        # Optional patterns enrich the chain
        for pattern in rule.optional_patterns:
            match = self._find_matching(pattern, findings, used_findings)
            if match is not None:
                finding, _ = match
                used_findings.add(id(finding))
                matched_steps.append(AttackStep(
                    order=len(matched_steps) + 1,
                    finding=finding,
                    role=pattern.role,
                    description=pattern.step_description or finding.title,
                ))

        # Build the chain
        self._chain_counter += 1
        return AttackChain(
            chain_id=f"AC-{self._chain_counter:03d}",
            name=rule.name,
            description=rule.description,
            steps=matched_steps,
            impact=rule.impact,
            likelihood=self._adjust_likelihood(rule.likelihood, len(matched_steps), len(rule.required_patterns) + len(rule.optional_patterns)),
            overall_severity=rule.severity,
            remediation=rule.remediation,
            mitre_attack=rule.mitre_attack,
            tags=rule.tags,
        )

    def _find_matching(
        self,
        pattern: FindingPattern,
        findings: list[Finding],
        used: set[int],
    ) -> Optional[tuple[Finding, float]]:
        """Find the best matching finding for a pattern."""
        import re as _re

        best: Optional[tuple[Finding, float]] = None
        best_score = 0.0

        for finding in findings:
            if id(finding) in used:
                continue

            score = 0.0

            # Scanner match
            if pattern.scanner is not None:
                if finding.scanner.lower() != pattern.scanner.lower():
                    continue
                score += 1.0

            # Title substring
            if pattern.title_contains is not None:
                if pattern.title_contains.lower() not in finding.title.lower():
                    continue
                score += 2.0

            # Title regex
            if pattern.title_regex is not None:
                if not _re.search(pattern.title_regex, finding.title, _re.IGNORECASE):
                    continue
                score += 2.0

            # Severity filter
            if pattern.severity_in is not None:
                if finding.severity not in pattern.severity_in:
                    continue
                score += 0.5

            # Detail substring
            if pattern.detail_contains is not None:
                if pattern.detail_contains.lower() not in finding.details.lower():
                    continue
                score += 1.5

            # Prefer higher severity findings
            sev_bonus = {"Critical": 2.0, "High": 1.5, "Medium": 1.0, "Low": 0.5, "Info": 0.0}
            score += sev_bonus.get(finding.severity, 0)

            if score > best_score:
                best_score = score
                best = (finding, score)

        return best

    @staticmethod
    def _adjust_likelihood(base: str, matched: int, total: int) -> str:
        """Adjust likelihood based on how many patterns matched."""
        levels = ["Very Low", "Low", "Medium", "High", "Very High"]
        base_idx = levels.index(base) if base in levels else 2
        ratio = matched / max(total, 1)

        if ratio >= 0.8:
            adjusted = min(base_idx + 1, 4)
        elif ratio <= 0.3:
            adjusted = max(base_idx - 1, 0)
        else:
            adjusted = base_idx

        return levels[adjusted]

    def get_summary(self, chains: list[AttackChain]) -> dict:
        """Generate a summary of attack chain analysis."""
        if not chains:
            return {
                "total_chains": 0,
                "critical_chains": 0,
                "high_chains": 0,
                "max_risk_score": 0,
                "top_chain": None,
                "all_mitre_techniques": [],
            }

        return {
            "total_chains": len(chains),
            "critical_chains": sum(1 for c in chains if c.overall_severity == "Critical"),
            "high_chains": sum(1 for c in chains if c.overall_severity == "High"),
            "max_risk_score": max(c.risk_score for c in chains),
            "top_chain": chains[0].name if chains else None,
            "all_mitre_techniques": list(set(
                t for c in chains for t in c.mitre_attack
            )),
        }
