"""
AI-Powered Report Generator — Template-based natural language security reports.

Generates audience-specific, natural language security reports from scan
findings without requiring external LLM APIs. Uses pattern-based templates
keyed on severity, CWE, technology stack, and audience type.

Audiences:
  - "board"       — Business-focused, risk & financial impact
  - "engineering"  — Technical details, code fixes, remediation steps
  - "compliance"   — Regulatory mappings, audit-ready language

Works fully offline — no API keys required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from secprobe.models import Finding


# ─────────────────────────────────────────────────────────────────
# Template Data
# ─────────────────────────────────────────────────────────────────

SEVERITY_LABELS = {
    "CRITICAL": "critical",
    "HIGH": "high-severity",
    "MEDIUM": "moderate",
    "LOW": "low-severity",
    "INFO": "informational",
}

SEVERITY_BUSINESS_IMPACT = {
    "CRITICAL": "poses an immediate and severe risk to the organization, potentially leading to full system compromise, data breach, or significant financial loss",
    "HIGH": "presents a significant security risk that could result in unauthorized access to sensitive data or major service disruption",
    "MEDIUM": "represents a notable security weakness that could be exploited under certain conditions to gain limited unauthorized access",
    "LOW": "is a minor security concern with limited direct impact but could contribute to more serious attacks if combined with other vulnerabilities",
    "INFO": "is an informational observation that does not directly pose a security risk but may warrant attention for defense-in-depth",
}

SEVERITY_URGENCY = {
    "CRITICAL": "Requires immediate remediation within 24 hours.",
    "HIGH": "Should be addressed within 1 week.",
    "MEDIUM": "Should be addressed within 30 days.",
    "LOW": "Should be addressed during the next development cycle.",
    "INFO": "Consider addressing as part of routine hardening.",
}

# CWE -> (short name, attack description, remediation pattern)
CWE_TEMPLATES: dict[str, tuple[str, str, str]] = {
    "CWE-79": (
        "Cross-Site Scripting (XSS)",
        "inject malicious scripts into web pages viewed by other users, stealing session tokens, credentials, or performing actions on their behalf",
        "Implement context-aware output encoding. Use Content-Security-Policy headers. Sanitize all user input before rendering.",
    ),
    "CWE-89": (
        "SQL Injection",
        "execute arbitrary SQL queries against the database, potentially reading, modifying, or deleting all data, and in some cases executing operating system commands",
        "Use parameterized queries or prepared statements exclusively. Never concatenate user input into SQL strings. Apply least-privilege database accounts.",
    ),
    "CWE-22": (
        "Path Traversal",
        "access files outside the intended directory, potentially reading sensitive configuration files, source code, or system files",
        "Validate and sanitize file paths. Use allowlists for permitted directories. Avoid passing user input to file system APIs directly.",
    ),
    "CWE-352": (
        "Cross-Site Request Forgery (CSRF)",
        "trick authenticated users into performing unintended actions such as changing passwords, transferring funds, or modifying account settings",
        "Implement anti-CSRF tokens on all state-changing operations. Use SameSite cookie attributes. Verify Origin/Referer headers.",
    ),
    "CWE-918": (
        "Server-Side Request Forgery (SSRF)",
        "make the server send requests to internal services, potentially accessing cloud metadata, internal APIs, or pivoting into the internal network",
        "Validate and allowlist destination URLs. Block requests to internal IP ranges. Use network segmentation.",
    ),
    "CWE-200": (
        "Information Exposure",
        "obtain sensitive information such as internal paths, software versions, or configuration details that aid further attacks",
        "Remove verbose error messages in production. Strip server version headers. Implement proper error handling that does not leak internals.",
    ),
    "CWE-287": (
        "Improper Authentication",
        "bypass authentication mechanisms to gain unauthorized access to protected resources or administrative functions",
        "Implement multi-factor authentication. Use strong session management. Enforce account lockout policies.",
    ),
    "CWE-311": (
        "Missing Encryption of Sensitive Data",
        "intercept sensitive data in transit or at rest, including credentials, personal information, and financial data",
        "Enforce TLS 1.2+ for all communications. Encrypt sensitive data at rest. Use HSTS headers.",
    ),
    "CWE-502": (
        "Deserialization of Untrusted Data",
        "execute arbitrary code on the server by sending crafted serialized objects, potentially gaining full system control",
        "Never deserialize untrusted data. Use safe serialization formats (JSON). Implement integrity checks on serialized data.",
    ),
    "CWE-611": (
        "XML External Entity (XXE)",
        "read arbitrary files from the server, perform SSRF attacks, or cause denial of service through entity expansion",
        "Disable external entity processing in XML parsers. Use less complex data formats where possible. Validate XML input.",
    ),
}

# Tech stack -> framework-specific remediation snippets
FRAMEWORK_REMEDIATION: dict[str, dict[str, str]] = {
    "CWE-89": {
        "django": (
            "Use Django ORM exclusively:\n"
            "  Entry.objects.filter(title__contains=user_input)\n"
            "  # NEVER use raw SQL with string formatting"
        ),
        "flask": (
            "Use SQLAlchemy parameterized queries:\n"
            '  db.session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": user_input})'
        ),
        "express": (
            "Use parameterized queries:\n"
            '  db.query("SELECT * FROM users WHERE name = $1", [userInput])'
        ),
        "spring": (
            "Use Spring Data JPA:\n"
            '  @Query("SELECT u FROM User u WHERE u.name = :name")\n'
            '  List<User> findByName(@Param("name") String name);'
        ),
        "rails": (
            "Use ActiveRecord safely:\n"
            '  User.where("name = ?", params[:name])'
        ),
    },
    "CWE-79": {
        "django": "Django auto-escapes templates by default. Avoid the safe filter and autoescape off blocks. Use mark_safe() only on trusted content.",
        "flask": "Use Jinja2 auto-escaping (enabled by default). Avoid the safe filter on user content. Use Markup() only on trusted strings.",
        "express": "Use a templating engine with auto-escaping (EJS, Handlebars). Sanitize with DOMPurify for rich content. Set CSP headers.",
        "react": "React escapes by default. Never use innerHTML-setting props with user input. Sanitize URLs in href attributes.",
        "rails": "Rails auto-escapes by default. Avoid html_safe and raw on user content. Use sanitize() helper for rich text.",
    },
    "CWE-352": {
        "django": "Django includes CSRF middleware by default. Ensure csrf_token tag in all forms. Use csrf_protect on views.",
        "flask": "Use Flask-WTF which includes CSRF protection. Add CSRFProtect(app) and include hidden_tag() in templates.",
        "express": (
            "Use csurf middleware:\n"
            "  const csrf = require('csurf');\n"
            "  app.use(csrf({ cookie: true }));"
        ),
        "spring": "Spring Security enables CSRF by default. Include the token in forms using the hidden input pattern.",
        "rails": "Rails includes CSRF protection by default. Ensure protect_from_forgery is in ApplicationController.",
    },
}

# Audience-specific tone templates
AUDIENCE_TEMPLATES = {
    "board": {
        "intro": "This security assessment identified {total} findings across the target application. {critical_high_summary} The overall security posture is rated as {risk_grade}.",
        "finding_template": "A {severity} vulnerability was identified that {business_impact}. {urgency}",
        "risk_focus": "Financial and reputational risk exposure",
        "closing": "Investment in the recommended remediation activities will reduce organizational risk exposure and strengthen the security posture against evolving threats.",
    },
    "engineering": {
        "intro": "Security scan completed with {total} findings ({critical} critical, {high} high, {medium} medium, {low} low). Target: {target}.",
        "finding_template": "[{severity}] {title} ({cwe})\n  Location: {url}\n  Details: {description}\n  Fix: {remediation}",
        "risk_focus": "Technical remediation priority",
        "closing": "Prioritize critical and high findings for immediate sprint work. Medium findings should be tracked in the backlog.",
    },
    "compliance": {
        "intro": "Security assessment report for compliance review. {total} findings identified, mapped to applicable regulatory frameworks. Assessment date: {date}.",
        "finding_template": "{title} [{severity}]\n  CWE: {cwe}\n  OWASP: {owasp}\n  PCI-DSS: {pci_dss}\n  NIST: {nist}\n  Status: Open — Remediation Required",
        "risk_focus": "Regulatory compliance gaps",
        "closing": "Findings should be tracked to closure with evidence of remediation for audit purposes. Compensating controls should be documented where immediate remediation is not feasible.",
    },
}


# ─────────────────────────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────────────────────────

class AIReportGenerator:
    """Generates natural language security reports using template-based patterns.

    Works entirely offline — no LLM API calls. Uses severity, CWE, tech stack,
    and audience to compose readable, actionable reports.
    """

    def __init__(
        self,
        target: str = "",
        tech_stack: Optional[list[str]] = None,
    ):
        self.target = target
        self.tech_stack = [t.lower() for t in (tech_stack or [])]

    # ── Executive Summary ───────────────────────────────────────

    def generate_executive_summary(self, findings: list[Finding]) -> str:
        """Generate a 3-5 sentence executive summary from findings.

        Covers: total count, severity breakdown, top risk, and recommended action.
        """
        if not findings:
            return (
                "The security assessment completed successfully with no findings identified. "
                "The target application demonstrates a strong security posture based on the "
                "tests performed. Continued periodic assessments are recommended to maintain "
                "this baseline."
            )

        counts = self._severity_counts(findings)
        total = len(findings)

        # Opening sentence
        sentences = [
            f"The security assessment of {self.target or 'the target application'} "
            f"identified {total} {'finding' if total == 1 else 'findings'} "
            f"across multiple security domains."
        ]

        # Severity breakdown
        critical_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
        if critical_high > 0:
            sentences.append(
                f"Of these, {critical_high} {'is' if critical_high == 1 else 'are'} "
                f"rated critical or high severity, requiring urgent attention."
            )
        else:
            sentences.append(
                "No critical or high severity findings were identified, indicating "
                "a reasonable baseline security posture."
            )

        # Top risk
        top = self._highest_severity_finding(findings)
        if top and top.severity in ("CRITICAL", "HIGH"):
            cwe_info = CWE_TEMPLATES.get(top.cwe, None)
            risk_name = cwe_info[0] if cwe_info else top.title
            sentences.append(
                f"The most significant risk is {risk_name}, which "
                f"{SEVERITY_BUSINESS_IMPACT.get(top.severity, 'may impact the organization')}."
            )

        # Action
        if counts.get("CRITICAL", 0) > 0:
            sentences.append(
                "Immediate action is recommended to address critical vulnerabilities "
                "before they can be exploited."
            )
        elif counts.get("HIGH", 0) > 0:
            sentences.append(
                "Prompt remediation of high-severity findings is recommended to "
                "reduce the attack surface."
            )
        else:
            sentences.append(
                "The identified findings should be addressed as part of the "
                "regular development cycle to strengthen defense-in-depth."
            )

        return " ".join(sentences)

    # ── Risk Narrative ──────────────────────────────────────────

    def generate_risk_narrative(
        self,
        findings: list[Finding],
        attack_chains: Optional[list[Any]] = None,
    ) -> str:
        """Generate a narrative of what an attacker could do with these findings.

        Describes realistic attack scenarios from an adversary's perspective.
        """
        if not findings:
            return (
                "Based on the assessment results, no actionable attack paths were identified. "
                "An attacker scanning this target would find limited opportunities for exploitation."
            )

        paragraphs: list[str] = []

        # Opening
        counts = self._severity_counts(findings)
        total = len(findings)
        paragraphs.append(
            f"An attacker targeting {self.target or 'this application'} would discover "
            f"{total} potential weakness{'es' if total != 1 else ''}. "
            f"The following narrative describes realistic exploitation scenarios."
        )

        # Attack chain narratives
        if attack_chains:
            paragraphs.append("--- Multi-Step Attack Paths ---")
            for chain in attack_chains:
                name = getattr(chain, "name", str(chain))
                impact = getattr(chain, "impact", "")
                steps = getattr(chain, "steps", [])
                step_count = len(steps) if steps else 0
                para = f"Attack Path: {name}."
                if step_count:
                    para += f" This attack chain involves {step_count} steps."
                if impact:
                    para += f" If successful, the attacker could {impact.lower() if impact[0].isupper() else impact}"
                    if not para.endswith("."):
                        para += "."
                paragraphs.append(para)

        # Individual high-severity finding narratives
        severe = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        if severe:
            paragraphs.append("--- Individual Exploitation Scenarios ---")
            for finding in severe[:5]:  # Cap at 5 to keep it readable
                cwe_info = CWE_TEMPLATES.get(finding.cwe, None)
                if cwe_info:
                    _, attack_desc, _ = cwe_info
                    paragraphs.append(
                        f"By exploiting the {finding.title} vulnerability"
                        f"{' at ' + finding.url if finding.url else ''}, "
                        f"an attacker could {attack_desc}."
                    )
                else:
                    paragraphs.append(
                        f"The {finding.title} vulnerability ({finding.severity}) "
                        f"could be exploited to compromise application security"
                        f"{' via ' + finding.url if finding.url else ''}."
                    )

        return "\n\n".join(paragraphs)

    # ── Remediation ─────────────────────────────────────────────

    def generate_remediation(self, finding: Finding) -> str:
        """Generate framework-specific remediation guidance for a finding.

        Returns code examples when the tech stack and CWE are known.
        """
        sections: list[str] = []

        # Header
        sections.append(f"Remediation: {finding.title} [{finding.severity}]")
        sections.append(f"Urgency: {SEVERITY_URGENCY.get(finding.severity, 'Address when possible.')}")

        # Generic CWE-based remediation
        cwe_info = CWE_TEMPLATES.get(finding.cwe, None)
        if cwe_info:
            _, _, generic_fix = cwe_info
            sections.append(f"General Fix:\n  {generic_fix}")

        # Framework-specific fix
        framework_fixes = FRAMEWORK_REMEDIATION.get(finding.cwe, {})
        matched_frameworks: list[str] = []
        for tech in self.tech_stack:
            if tech in framework_fixes:
                matched_frameworks.append(tech)

        if matched_frameworks:
            sections.append("Framework-Specific Guidance:")
            for fw in matched_frameworks:
                sections.append(f"  [{fw.title()}]\n  {framework_fixes[fw]}")
        elif framework_fixes:
            # Show the first available framework fix as example
            first_fw = next(iter(framework_fixes))
            sections.append(
                f"Example Fix ({first_fw.title()}):\n  {framework_fixes[first_fw]}"
            )

        # Finding's own recommendation
        if finding.recommendation:
            sections.append(f"Additional Guidance:\n  {finding.recommendation}")

        return "\n\n".join(sections)

    # ── Multi-Audience Report ───────────────────────────────────

    def generate_multi_audience_report(
        self,
        findings: list[Finding],
        audience: str = "engineering",
    ) -> str:
        """Generate a report tailored to a specific audience.

        Supported audiences: 'board', 'engineering', 'compliance'.
        """
        audience = audience.lower()
        if audience not in AUDIENCE_TEMPLATES:
            raise ValueError(
                f"Unknown audience '{audience}'. "
                f"Supported: {', '.join(AUDIENCE_TEMPLATES.keys())}"
            )

        template = AUDIENCE_TEMPLATES[audience]
        counts = self._severity_counts(findings)
        total = len(findings)

        # Risk grade
        risk_grade = self._compute_risk_grade(findings)

        # Critical/high summary for board
        critical_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
        if critical_high > 0:
            critical_high_summary = (
                f"{critical_high} {'finding requires' if critical_high == 1 else 'findings require'} "
                f"immediate management attention."
            )
        else:
            critical_high_summary = "No findings require immediate management attention."

        # Build intro
        from datetime import datetime
        intro = template["intro"].format(
            total=total,
            critical=counts.get("CRITICAL", 0),
            high=counts.get("HIGH", 0),
            medium=counts.get("MEDIUM", 0),
            low=counts.get("LOW", 0),
            info=counts.get("INFO", 0),
            target=self.target or "target application",
            risk_grade=risk_grade,
            critical_high_summary=critical_high_summary,
            date=datetime.now().strftime("%Y-%m-%d"),
        )

        sections: list[str] = [intro, ""]

        # Findings
        if findings:
            sections.append(f"--- Findings ({template['risk_focus']}) ---")
            sections.append("")

            for finding in sorted(findings, key=lambda f: self._severity_order(f.severity)):
                finding_text = template["finding_template"].format(
                    severity=finding.severity,
                    title=finding.title,
                    cwe=finding.cwe or "N/A",
                    url=finding.url or "N/A",
                    description=finding.description,
                    remediation=finding.recommendation or "See general guidance.",
                    owasp=finding.owasp_category or "N/A",
                    pci_dss=", ".join(finding.pci_dss) if finding.pci_dss else "N/A",
                    nist=", ".join(finding.nist) if finding.nist else "N/A",
                    business_impact=SEVERITY_BUSINESS_IMPACT.get(finding.severity, "may impact the organization"),
                    urgency=SEVERITY_URGENCY.get(finding.severity, ""),
                )
                sections.append(finding_text)
                sections.append("")

        # Closing
        sections.append(template["closing"])

        return "\n".join(sections)

    # ── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @staticmethod
    def _severity_order(severity: str) -> int:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return order.get(severity, 5)

    @staticmethod
    def _highest_severity_finding(findings: list[Finding]) -> Optional[Finding]:
        if not findings:
            return None
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return min(findings, key=lambda f: order.get(f.severity, 5))

    @staticmethod
    def _compute_risk_grade(findings: list[Finding]) -> str:
        """Compute a letter grade from A+ (best) to F (worst)."""
        if not findings:
            return "A+"
        score = 0
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "INFO": 0}
        for f in findings:
            score += weights.get(f.severity, 0)
        if score == 0:
            return "A+"
        elif score <= 5:
            return "A"
        elif score <= 15:
            return "B+"
        elif score <= 30:
            return "B"
        elif score <= 50:
            return "C+"
        elif score <= 80:
            return "C"
        elif score <= 120:
            return "D"
        else:
            return "F"
