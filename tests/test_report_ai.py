"""Tests for the AI-Powered Report Generator."""

import pytest

from secprobe.models import Finding
from secprobe.report_ai import (
    AIReportGenerator,
    CWE_TEMPLATES,
    FRAMEWORK_REMEDIATION,
    SEVERITY_BUSINESS_IMPACT,
)


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

def _finding(
    title="Test Finding",
    severity="HIGH",
    cwe="CWE-79",
    description="XSS found",
    url="https://example.com/search",
    recommendation="Fix it",
    owasp="A03:2021 - Injection",
    pci_dss=None,
    nist=None,
):
    return Finding(
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        url=url,
        cwe=cwe,
        owasp_category=owasp,
        pci_dss=pci_dss or ["6.5.7"],
        nist=nist or ["SI-10"],
    )


def _mixed_findings():
    return [
        _finding(title="SQL Injection", severity="CRITICAL", cwe="CWE-89",
                 description="SQLi in login form", url="https://example.com/login"),
        _finding(title="XSS in Search", severity="HIGH", cwe="CWE-79",
                 description="Reflected XSS in search parameter"),
        _finding(title="Missing HSTS", severity="MEDIUM", cwe="CWE-311",
                 description="HSTS header not set"),
        _finding(title="Server Version Disclosed", severity="LOW", cwe="CWE-200",
                 description="Apache version in headers"),
        _finding(title="Cookie Info", severity="INFO", cwe="",
                 description="Cookie attributes noted"),
    ]


# ─────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────

class TestExecutiveSummary:
    def test_empty_findings(self):
        gen = AIReportGenerator(target="https://example.com")
        summary = gen.generate_executive_summary([])
        assert "no findings" in summary.lower()
        assert "strong security posture" in summary.lower()

    def test_summary_with_critical(self):
        gen = AIReportGenerator(target="https://example.com")
        findings = _mixed_findings()
        summary = gen.generate_executive_summary(findings)
        assert "5 findings" in summary
        assert "critical or high severity" in summary.lower()
        assert "immediate action" in summary.lower()

    def test_summary_with_only_low(self):
        gen = AIReportGenerator(target="https://example.com")
        findings = [_finding(severity="LOW", cwe="CWE-200")]
        summary = gen.generate_executive_summary(findings)
        assert "1 finding" in summary
        assert "no critical or high" in summary.lower()

    def test_summary_mentions_target(self):
        gen = AIReportGenerator(target="https://myapp.com")
        summary = gen.generate_executive_summary([_finding()])
        assert "myapp.com" in summary


class TestRiskNarrative:
    def test_empty_findings(self):
        gen = AIReportGenerator()
        narrative = gen.generate_risk_narrative([])
        assert "no actionable attack paths" in narrative.lower()

    def test_narrative_with_findings(self):
        gen = AIReportGenerator(target="https://example.com")
        findings = _mixed_findings()
        narrative = gen.generate_risk_narrative(findings)
        assert "attacker" in narrative.lower()
        assert "exploitation scenarios" in narrative.lower()

    def test_narrative_with_attack_chains(self):
        gen = AIReportGenerator(target="https://example.com")
        # Mock attack chain objects
        class MockChain:
            name = "Full Database Compromise"
            impact = "Complete database access"
            steps = [1, 2, 3]

        findings = _mixed_findings()
        narrative = gen.generate_risk_narrative(findings, attack_chains=[MockChain()])
        assert "Full Database Compromise" in narrative
        assert "3 steps" in narrative
        assert "complete database access" in narrative.lower()

    def test_narrative_uses_cwe_attack_descriptions(self):
        gen = AIReportGenerator()
        findings = [_finding(title="SQL Injection", severity="CRITICAL", cwe="CWE-89")]
        narrative = gen.generate_risk_narrative(findings)
        # Should use the CWE-89 attack description
        assert "arbitrary SQL queries" in narrative


class TestRemediation:
    def test_generic_cwe_remediation(self):
        gen = AIReportGenerator()
        finding = _finding(title="SQL Injection", severity="CRITICAL", cwe="CWE-89")
        remediation = gen.generate_remediation(finding)
        assert "parameterized queries" in remediation.lower()
        assert "Remediation: SQL Injection [CRITICAL]" in remediation

    def test_framework_specific_remediation(self):
        gen = AIReportGenerator(tech_stack=["django"])
        finding = _finding(title="SQL Injection", severity="CRITICAL", cwe="CWE-89")
        remediation = gen.generate_remediation(finding)
        assert "Django" in remediation
        assert "ORM" in remediation

    def test_urgency_included(self):
        gen = AIReportGenerator()
        finding = _finding(severity="CRITICAL", cwe="CWE-89")
        remediation = gen.generate_remediation(finding)
        assert "24 hours" in remediation

    def test_finding_recommendation_included(self):
        gen = AIReportGenerator()
        finding = _finding(recommendation="Custom recommendation here")
        remediation = gen.generate_remediation(finding)
        assert "Custom recommendation here" in remediation

    def test_unknown_cwe_still_works(self):
        gen = AIReportGenerator()
        finding = _finding(cwe="CWE-99999")
        remediation = gen.generate_remediation(finding)
        assert "Remediation:" in remediation
        # Should still have urgency and recommendation
        assert "Urgency:" in remediation


class TestMultiAudienceReport:
    def test_board_report(self):
        gen = AIReportGenerator(target="https://example.com")
        findings = _mixed_findings()
        report = gen.generate_multi_audience_report(findings, audience="board")
        assert "5 findings" in report
        assert "risk exposure" in report.lower()
        assert "management attention" in report.lower()

    def test_engineering_report(self):
        gen = AIReportGenerator(target="https://example.com")
        findings = _mixed_findings()
        report = gen.generate_multi_audience_report(findings, audience="engineering")
        assert "critical" in report.lower()
        assert "Location:" in report
        assert "Fix:" in report
        assert "sprint" in report.lower()

    def test_compliance_report(self):
        gen = AIReportGenerator(target="https://example.com")
        findings = _mixed_findings()
        report = gen.generate_multi_audience_report(findings, audience="compliance")
        assert "compliance review" in report.lower()
        assert "CWE:" in report
        assert "OWASP:" in report
        assert "PCI-DSS:" in report
        assert "NIST:" in report
        assert "audit" in report.lower()

    def test_invalid_audience_raises(self):
        gen = AIReportGenerator()
        with pytest.raises(ValueError, match="Unknown audience"):
            gen.generate_multi_audience_report([], audience="invalid")

    def test_empty_findings_report(self):
        gen = AIReportGenerator()
        report = gen.generate_multi_audience_report([], audience="board")
        assert "0 findings" in report


class TestRiskGrade:
    def test_grade_no_findings(self):
        assert AIReportGenerator._compute_risk_grade([]) == "A+"

    def test_grade_critical_is_bad(self):
        findings = [_finding(severity="CRITICAL")]
        grade = AIReportGenerator._compute_risk_grade(findings)
        assert grade in ("C+", "C", "D", "F")

    def test_grade_info_only_is_good(self):
        findings = [_finding(severity="INFO"), _finding(severity="INFO")]
        grade = AIReportGenerator._compute_risk_grade(findings)
        assert grade == "A+"
