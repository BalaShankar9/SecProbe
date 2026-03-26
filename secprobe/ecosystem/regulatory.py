"""
Regulatory intelligence — track compliance frameworks and map to scans.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ComplianceControl:
    framework: str    # OWASP, PCI-DSS, NIST, etc.
    control_id: str   # e.g., "A01:2021"
    name: str
    description: str = ""
    scanner_types: list[str] = field(default_factory=list)  # Scanners that test this


COMPLIANCE_FRAMEWORKS = {
    "owasp_top10_2021": [
        ComplianceControl("OWASP", "A01:2021", "Broken Access Control", "", ["idor", "cors", "csrf"]),
        ComplianceControl("OWASP", "A02:2021", "Cryptographic Failures", "", ["ssl", "jwt", "cookies"]),
        ComplianceControl("OWASP", "A03:2021", "Injection", "", ["sqli", "xss", "cmdi", "ssti", "nosql", "ldap", "xpath"]),
        ComplianceControl("OWASP", "A04:2021", "Insecure Design", "", ["bizlogic", "race"]),
        ComplianceControl("OWASP", "A05:2021", "Security Misconfiguration", "", ["headers", "cors", "directory", "cloud"]),
        ComplianceControl("OWASP", "A06:2021", "Vulnerable Components", "", ["cve", "tech"]),
        ComplianceControl("OWASP", "A07:2021", "Auth Failures", "", ["auth", "jwt", "session", "csrf"]),
        ComplianceControl("OWASP", "A08:2021", "Software Integrity Failures", "", ["deserialization", "cve"]),
        ComplianceControl("OWASP", "A09:2021", "Logging Failures", "", ["headers"]),
        ComplianceControl("OWASP", "A10:2021", "SSRF", "", ["ssrf"]),
    ],
    "pci_dss_4": [
        ComplianceControl("PCI-DSS", "6.2", "Software Security", "", ["sqli", "xss", "cmdi"]),
        ComplianceControl("PCI-DSS", "6.3", "Security Vulnerabilities", "", ["cve", "tech"]),
        ComplianceControl("PCI-DSS", "6.4", "Public-Facing Web Apps", "", ["sqli", "xss", "csrf"]),
        ComplianceControl("PCI-DSS", "6.5", "Change Control", "", ["headers", "ssl"]),
        ComplianceControl("PCI-DSS", "11.3", "Penetration Testing", "", ["sqli", "xss", "ssrf"]),
    ],
    "nist_800_53": [
        ComplianceControl("NIST", "SI-10", "Information Input Validation", "", ["sqli", "xss", "cmdi", "ssti"]),
        ComplianceControl("NIST", "SC-8", "Transmission Confidentiality", "", ["ssl"]),
        ComplianceControl("NIST", "AC-4", "Information Flow Enforcement", "", ["cors", "csrf"]),
        ComplianceControl("NIST", "IA-5", "Authenticator Management", "", ["auth", "jwt"]),
    ],
}


class RegulatoryEngine:
    """Map scan results to compliance frameworks."""

    def assess_compliance(self, findings: list, framework: str = "owasp_top10_2021") -> dict:
        """Assess compliance against a framework."""
        controls = COMPLIANCE_FRAMEWORKS.get(framework, [])
        if not controls:
            return {"framework": framework, "error": "Unknown framework"}

        finding_categories = set()
        for f in findings:
            cat = (getattr(f, 'category', '') or '').lower()
            if cat:
                finding_categories.add(cat)

        results = []
        passed = 0
        failed = 0
        for control in controls:
            violations = [cat for cat in control.scanner_types if cat in finding_categories]
            status = "FAIL" if violations else "PASS"
            if status == "PASS":
                passed += 1
            else:
                failed += 1
            results.append({
                "control_id": control.control_id,
                "name": control.name,
                "status": status,
                "violations": violations,
            })

        total = passed + failed
        return {
            "framework": framework,
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "compliance_rate": passed / total if total > 0 else 0.0,
            "controls": results,
        }

    def gap_analysis(self, findings: list) -> dict:
        """Run gap analysis across all frameworks."""
        results = {}
        for framework in COMPLIANCE_FRAMEWORKS:
            results[framework] = self.assess_compliance(findings, framework)
        return results

    def get_supported_frameworks(self) -> list[str]:
        return list(COMPLIANCE_FRAMEWORKS.keys())
