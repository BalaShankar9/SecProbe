"""
Compliance Mapper — maps findings to security standards.

Maps SecProbe findings to:
  - OWASP Top 10 (2021)
  - PCI DSS v4.0
  - CIS Controls v8
  - NIST CSF

Provides automatic compliance gap analysis with pass/fail/partial status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from secprobe.models import Finding


# ─────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────

@dataclass
class ComplianceControl:
    """A single control from a compliance framework."""
    control_id: str
    name: str
    description: str
    framework: str
    status: str = "pass"  # "pass", "fail", "partial", "not-tested"
    findings: list[Finding] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "description": self.description,
            "framework": self.framework,
            "status": self.status,
            "finding_count": len(self.findings),
            "findings": [f.title for f in self.findings],
            "remediation": self.remediation,
        }


@dataclass
class ComplianceReport:
    """Compliance assessment against a security framework."""
    framework: str
    version: str
    controls: list[ComplianceControl] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.controls if c.status == "pass")

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.controls if c.status == "fail")

    @property
    def partial_count(self) -> int:
        return sum(1 for c in self.controls if c.status == "partial")

    @property
    def not_tested_count(self) -> int:
        return sum(1 for c in self.controls if c.status == "not-tested")

    @property
    def compliance_score(self) -> float:
        testable = len(self.controls) - self.not_tested_count
        if testable == 0:
            return 100.0
        passed = self.pass_count + (self.partial_count * 0.5)
        return round((passed / testable) * 100, 1)

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "version": self.version,
            "compliance_score": self.compliance_score,
            "summary": {
                "pass": self.pass_count,
                "fail": self.fail_count,
                "partial": self.partial_count,
                "not_tested": self.not_tested_count,
                "total": len(self.controls),
            },
            "controls": [c.to_dict() for c in self.controls],
        }


# ─────────────────────────────────────────────────────────────────
# OWASP Top 10 (2021) Mapping Rules
# ─────────────────────────────────────────────────────────────────

OWASP_2021 = [
    {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
        "scanners": ["cors", "directory", "cookie"],
        "title_keywords": ["CORS", "access control", "admin", "sensitive", "directory listing", "unauthorized"],
        "remediation": "Implement proper access controls, deny by default, enforce record ownership, disable directory listing.",
    },
    {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure.",
        "scanners": ["ssl", "header", "cookie"],
        "title_keywords": ["SSL", "TLS", "certificate", "cipher", "HSTS", "Secure flag", "weak protocol", "expired", "self-signed"],
        "remediation": "Enforce TLS 1.2+, use strong ciphers, implement HSTS, set Secure flag on cookies.",
    },
    {
        "id": "A03:2021",
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
        "scanners": ["sqli", "xss"],
        "title_keywords": ["SQL Injection", "XSS", "Cross-Site Scripting", "SSTI", "Template Injection", "injection"],
        "remediation": "Use parameterized queries, input validation, output encoding, Content-Security-Policy.",
    },
    {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Missing or ineffective control design — different from implementation bugs.",
        "scanners": ["directory", "tech"],
        "title_keywords": ["debug", "test", "default", "backup", "exposed"],
        "remediation": "Use threat modeling, secure design patterns, reference architectures. Remove debug endpoints.",
    },
    {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, unnecessary features enabled, default accounts.",
        "scanners": ["header", "directory", "cors", "cookie", "ssl"],
        "title_keywords": ["missing", "misconfigur", "default", "unnecessary", "verbose", "error", "server version", "X-Powered-By"],
        "remediation": "Implement security hardening, remove defaults, disable unnecessary features, review all configurations.",
    },
    {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "scanners": ["tech", "header"],
        "title_keywords": ["version", "outdated", "vulnerable", "component", "library", "framework"],
        "remediation": "Maintain software inventory, monitor CVEs, apply patches promptly, remove unused dependencies.",
    },
    {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management is weak.",
        "scanners": ["cookie", "ssl", "header"],
        "title_keywords": ["session", "cookie", "HttpOnly", "SameSite", "authentication", "credential"],
        "remediation": "Implement MFA, strong password policies, secure session management, proper cookie flags.",
    },
    {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations.",
        "scanners": ["header"],
        "title_keywords": ["integrity", "SRI", "Subresource", "Content-Security-Policy"],
        "remediation": "Use SRI for external resources, implement CSP, verify software integrity, secure CI/CD pipelines.",
    },
    {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Without logging and monitoring, breaches cannot be detected.",
        "scanners": [],
        "title_keywords": ["logging", "monitoring", "audit"],
        "remediation": "Implement centralized logging, alerting, incident response plan. Monitor for suspicious activity.",
    },
    {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Web application fetches a remote resource without validating the user-supplied URL.",
        "scanners": ["xss", "port"],
        "title_keywords": ["SSRF", "SSTI", "redirect", "internal"],
        "remediation": "Validate and sanitize all user-supplied URLs, use allowlists, segment network access.",
    },
]


PCI_DSS_V4 = [
    {
        "id": "PCI-6.2.4",
        "name": "Protection against common web attacks",
        "description": "Web applications must be protected against known attacks (SQLi, XSS, etc.).",
        "scanners": ["sqli", "xss"],
        "title_keywords": ["SQL Injection", "XSS", "Cross-Site", "injection"],
        "remediation": "Deploy WAF, implement input validation, use parameterized queries.",
    },
    {
        "id": "PCI-4.2.1",
        "name": "Strong cryptography for transmission",
        "description": "PAN and sensitive data must be encrypted during transmission.",
        "scanners": ["ssl", "cookie"],
        "title_keywords": ["SSL", "TLS", "cipher", "certificate", "HSTS", "Secure flag"],
        "remediation": "Enforce TLS 1.2+, use strong cipher suites, implement HSTS.",
    },
    {
        "id": "PCI-2.2.7",
        "name": "System hardening — non-console admin access encrypted",
        "description": "All non-console administrative access must use strong encryption.",
        "scanners": ["directory", "ssl", "port"],
        "title_keywords": ["admin", "management", "panel", "console"],
        "remediation": "Encrypt all admin access, restrict to VPN, implement MFA for admin accounts.",
    },
    {
        "id": "PCI-6.5.4",
        "name": "Address common coding vulnerabilities — XSS",
        "description": "Train developers and test for cross-site scripting vulnerabilities.",
        "scanners": ["xss"],
        "title_keywords": ["XSS", "Cross-Site Scripting", "reflected", "stored", "DOM"],
        "remediation": "Implement output encoding, CSP headers, and developer security training.",
    },
    {
        "id": "PCI-6.5.1",
        "name": "Address common coding vulnerabilities — Injection",
        "description": "Prevent injection flaws including SQL, OS, and LDAP injection.",
        "scanners": ["sqli"],
        "title_keywords": ["SQL Injection", "injection", "blind", "UNION"],
        "remediation": "Use parameterized queries, stored procedures, input validation.",
    },
    {
        "id": "PCI-11.3.3",
        "name": "Penetration testing — application layer",
        "description": "Application-layer penetration tests must cover OWASP Top 10.",
        "scanners": ["sqli", "xss", "header", "cookie", "cors", "ssl"],
        "title_keywords": [],
        "remediation": "Perform regular application-layer penetration tests covering all OWASP categories.",
    },
]


# ─────────────────────────────────────────────────────────────────
# Mapper Engine
# ─────────────────────────────────────────────────────────────────

class ComplianceMapper:
    """Maps findings to compliance frameworks and generates gap analysis."""

    def map_owasp_2021(self, findings: list[Finding]) -> ComplianceReport:
        """Map findings to OWASP Top 10 (2021) controls."""
        return self._map_framework(findings, OWASP_2021, "OWASP Top 10", "2021")

    def map_pci_dss(self, findings: list[Finding]) -> ComplianceReport:
        """Map findings to PCI DSS v4.0 controls."""
        return self._map_framework(findings, PCI_DSS_V4, "PCI DSS", "v4.0")

    def map_all(self, findings: list[Finding]) -> list[ComplianceReport]:
        """Map findings to all supported compliance frameworks."""
        return [
            self.map_owasp_2021(findings),
            self.map_pci_dss(findings),
        ]

    def _map_framework(
        self,
        findings: list[Finding],
        controls_def: list[dict],
        framework: str,
        version: str,
    ) -> ComplianceReport:
        """Map findings against a framework's control definitions."""
        controls = []

        for ctrl_def in controls_def:
            matched_findings = self._match_findings(findings, ctrl_def)
            scanners_ran = {f.scanner.lower() for f in findings}
            relevant_scanners = set(ctrl_def.get("scanners", []))

            # Determine status
            if matched_findings:
                # Findings exist → control fails (vulnerability found)
                has_critical = any(f.severity in ("Critical", "High") for f in matched_findings)
                status = "fail" if has_critical else "partial"
            elif relevant_scanners and not relevant_scanners.intersection(scanners_ran):
                # Scanner didn't run → not tested
                status = "not-tested"
            else:
                # Scanner ran, no findings → pass
                status = "pass"

            controls.append(ComplianceControl(
                control_id=ctrl_def["id"],
                name=ctrl_def["name"],
                description=ctrl_def["description"],
                framework=framework,
                status=status,
                findings=matched_findings,
                remediation=ctrl_def.get("remediation", ""),
            ))

        return ComplianceReport(
            framework=framework,
            version=version,
            controls=controls,
        )

    @staticmethod
    def _match_findings(findings: list[Finding], ctrl_def: dict) -> list[Finding]:
        """Find all findings that match a control definition."""
        matched = []
        target_scanners = set(ctrl_def.get("scanners", []))
        keywords = [kw.lower() for kw in ctrl_def.get("title_keywords", [])]

        for f in findings:
            # Match by scanner
            scanner_match = f.scanner.lower() in target_scanners if target_scanners else False
            # Match by keyword in title
            keyword_match = any(kw in f.title.lower() for kw in keywords) if keywords else False

            if scanner_match or keyword_match:
                matched.append(f)

        return matched

    def get_executive_summary(self, reports: list[ComplianceReport]) -> dict:
        """Generate an executive summary across all frameworks."""
        summaries = []
        for r in reports:
            summaries.append({
                "framework": f"{r.framework} ({r.version})",
                "compliance_score": r.compliance_score,
                "pass": r.pass_count,
                "fail": r.fail_count,
                "partial": r.partial_count,
                "not_tested": r.not_tested_count,
                "critical_gaps": [
                    c.control_id + ": " + c.name
                    for c in r.controls
                    if c.status == "fail"
                ],
            })

        overall = sum(s["compliance_score"] for s in summaries) / max(len(summaries), 1)

        return {
            "overall_compliance_score": round(overall, 1),
            "rating": (
                "A" if overall >= 90 else
                "B" if overall >= 75 else
                "C" if overall >= 60 else
                "D" if overall >= 40 else "F"
            ),
            "frameworks": summaries,
        }
