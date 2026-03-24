"""
Tests for v8 report generator enhancements:
  - Enhanced console output (scanner performance, remediation priorities, CVSS distribution)
  - Enhanced JSON report (executive summary, tech fingerprint, remediation, compliance, scanner perf)
  - Enhanced HTML report (executive summary, tech section, CVSS chart, remediation matrix, compliance)
  - ReportGenerator new constructor params (tech_profile, scan_duration, scan_config)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from io import StringIO
from unittest.mock import patch

import pytest

from secprobe.models import ScanResult, Finding
from secprobe.report import ReportGenerator


# ── Helpers ──────────────────────────────────────────────────────────

def _make_findings():
    """Create a realistic set of findings for testing."""
    return [
        Finding(
            title="SQL Injection in login form",
            severity="CRITICAL",
            description="Input not sanitized",
            recommendation="Use parameterized queries",
            scanner="sqli",
            category="Injection",
            url="https://example.com/login",
            cwe="CWE-89",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_severity="CRITICAL",
            owasp_category="A03:2021 - Injection",
            pci_dss=["6.5.1"],
            nist=["SI-10"],
        ),
        Finding(
            title="Reflected XSS in search",
            severity="HIGH",
            description="Script injection in query param",
            recommendation="Encode output",
            scanner="xss",
            category="XSS",
            url="https://example.com/search",
            cwe="CWE-79",
            cvss_score=7.1,
            cvss_severity="HIGH",
            owasp_category="A03:2021 - Injection",
        ),
        Finding(
            title="Missing HSTS Header",
            severity="MEDIUM",
            description="HSTS not configured",
            recommendation="Add Strict-Transport-Security header",
            scanner="headers",
            category="Headers",
            cwe="CWE-319",
            cvss_score=5.3,
            owasp_category="A05:2021 - Security Misconfiguration",
        ),
        Finding(
            title="Cookie without Secure flag",
            severity="LOW",
            description="Session cookie sent over HTTP",
            recommendation="Set Secure flag",
            scanner="cookies",
            category="Cookies",
            cwe="CWE-614",
            cvss_score=3.1,
        ),
        Finding(
            title="Server version disclosed",
            severity="INFO",
            description="Apache/2.4.52 in headers",
            scanner="headers",
            category="Information Disclosure",
        ),
    ]


def _make_results():
    """Create ScanResult objects with findings."""
    r1 = ScanResult(scanner_name="SQLi Scanner", target="example.com",
                    start_time=datetime(2025, 1, 1, 10, 0, 0),
                    end_time=datetime(2025, 1, 1, 10, 0, 15))
    r2 = ScanResult(scanner_name="XSS Scanner", target="example.com",
                    start_time=datetime(2025, 1, 1, 10, 0, 0),
                    end_time=datetime(2025, 1, 1, 10, 0, 8))
    r3 = ScanResult(scanner_name="Header Scanner", target="example.com",
                    start_time=datetime(2025, 1, 1, 10, 0, 0),
                    end_time=datetime(2025, 1, 1, 10, 0, 3))

    findings = _make_findings()
    r1.add_finding(findings[0])  # CRITICAL SQLi
    r2.add_finding(findings[1])  # HIGH XSS
    r3.add_finding(findings[2])  # MEDIUM HSTS
    r3.add_finding(findings[3])  # LOW Cookie
    r3.add_finding(findings[4])  # INFO Server version

    return [r1, r2, r3]


@dataclass
class MockTechProfile:
    """Simulates TechProfile for testing without importing scan_intelligence."""
    class _ServerType:
        value = "Nginx"
    class _LanguageType:
        value = "PHP"
    class _FrameworkType:
        value = "Laravel"
    server = _ServerType()
    language = _LanguageType()
    framework = _FrameworkType()
    waf_detected: bool = True
    waf_name: str = "Cloudflare"
    js_frameworks: list = field(default_factory=lambda: ["React", "jQuery"])
    cms: str = "WordPress"
    confidence: float = 0.85


# ═══════════════════════════════════════════════════════════════════════
# Constructor Tests
# ═══════════════════════════════════════════════════════════════════════

class TestReportGeneratorConstructor:
    """Test new constructor parameters."""

    def test_default_params(self):
        rg = ReportGenerator([], "example.com")
        assert rg.tech_profile is None
        assert rg.scan_duration == 0.0
        assert rg.scan_config == {}

    def test_with_tech_profile(self):
        tp = MockTechProfile()
        rg = ReportGenerator([], "example.com", tech_profile=tp)
        assert rg.tech_profile is tp

    def test_with_scan_duration(self):
        rg = ReportGenerator([], "example.com", scan_duration=42.5)
        assert rg.scan_duration == 42.5

    def test_with_scan_config(self):
        cfg = {"waf_evasion": True}
        rg = ReportGenerator([], "example.com", scan_config=cfg)
        assert rg.scan_config == cfg

    def test_backward_compatible(self):
        """Existing code that passes only results + target still works."""
        results = _make_results()
        rg = ReportGenerator(results, "example.com")
        assert len(rg.results) == 3


# ═══════════════════════════════════════════════════════════════════════
# Risk Assessment Tests
# ═══════════════════════════════════════════════════════════════════════

class TestRiskAssessment:
    """Test the new _risk_assessment method."""

    def test_zero_score(self):
        rg = ReportGenerator([], "example.com")
        text = rg._risk_assessment(0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
        assert "No security vulnerabilities" in text

    def test_low_score(self):
        rg = ReportGenerator([], "example.com")
        text = rg._risk_assessment(5, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 2})
        assert "low risk" in text

    def test_moderate_score(self):
        rg = ReportGenerator([], "example.com")
        text = rg._risk_assessment(30, {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0})
        assert "moderate risk" in text
        assert "2 high" in text

    def test_elevated_score(self):
        rg = ReportGenerator([], "example.com")
        text = rg._risk_assessment(50, {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0})
        assert "elevated risk" in text

    def test_critical_score(self):
        rg = ReportGenerator([], "example.com")
        text = rg._risk_assessment(85, {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0})
        assert "critical risk" in text
        assert "URGENT" in text


# ═══════════════════════════════════════════════════════════════════════
# JSON Report Tests
# ═══════════════════════════════════════════════════════════════════════

class TestEnhancedJSONReport:
    """Test the enhanced JSON report structure."""

    def test_json_version(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        assert data["secprobe_report"]["version"] == "7.0.0"

    def test_json_executive_summary(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        summary = data["secprobe_report"]["executive_summary"]
        assert summary["total_findings"] == 5
        assert summary["critical_count"] == 1
        assert summary["high_count"] == 1
        assert summary["scanners_run"] == 3
        assert "risk_assessment" in summary

    def test_json_risk_grade(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        report = data["secprobe_report"]
        assert "risk_score" in report
        assert "risk_grade" in report
        assert report["risk_grade"] in ("A+", "A", "B", "C", "D", "E", "F")

    def test_json_scan_duration(self):
        rg = ReportGenerator(_make_results(), "example.com", scan_duration=45.2)
        data = json.loads(rg.generate("json"))
        assert data["secprobe_report"]["scan_duration_seconds"] == 45.2

    def test_json_cvss_distribution(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        cvss = data["secprobe_report"]["cvss_distribution"]
        assert cvss["scored_count"] == 4
        assert cvss["max"] == 9.8
        assert cvss["min"] == 3.1
        assert 0 < cvss["average"] < 10

    def test_json_remediation_priorities(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        remediation = data["secprobe_report"]["remediation_priorities"]
        assert len(remediation) == 2  # CRITICAL + HIGH
        assert remediation[0]["severity"] == "CRITICAL"
        assert remediation[0]["priority"] == 1
        assert remediation[1]["severity"] == "HIGH"

    def test_json_compliance(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        compliance = data["secprobe_report"]["compliance"]
        assert "A03:2021 - Injection" in compliance["owasp_top_10"]
        assert "CWE-89" in compliance["unique_cwes"]

    def test_json_scanner_performance(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        perf = data["secprobe_report"]["scanner_performance"]
        assert len(perf) == 3
        names = [p["name"] for p in perf]
        assert "SQLi Scanner" in names

    def test_json_tech_fingerprint_absent(self):
        rg = ReportGenerator(_make_results(), "example.com")
        data = json.loads(rg.generate("json"))
        assert data["secprobe_report"]["technology_fingerprint"] == {}

    def test_json_tech_fingerprint_present(self):
        tp = MockTechProfile()
        rg = ReportGenerator(_make_results(), "example.com", tech_profile=tp)
        data = json.loads(rg.generate("json"))
        tech = data["secprobe_report"]["technology_fingerprint"]
        assert tech["server"] == "Nginx"
        assert tech["language"] == "PHP"
        assert tech["framework"] == "Laravel"
        assert tech["waf_detected"] is True
        assert tech["waf_name"] == "Cloudflare"
        assert tech["confidence"] == 0.85

    def test_json_empty_scan(self):
        rg = ReportGenerator([], "example.com")
        data = json.loads(rg.generate("json"))
        summary = data["secprobe_report"]["executive_summary"]
        assert summary["total_findings"] == 0
        assert data["secprobe_report"]["cvss_distribution"] == {}

    def test_json_file_output(self, tmp_path):
        out = str(tmp_path / "report.json")
        rg = ReportGenerator(_make_results(), "example.com")
        rg.generate("json", out)
        with open(out) as f:
            data = json.load(f)
        assert data["secprobe_report"]["version"] == "7.0.0"


# ═══════════════════════════════════════════════════════════════════════
# HTML Report Tests
# ═══════════════════════════════════════════════════════════════════════

class TestEnhancedHTMLReport:
    """Test the enhanced HTML report content."""

    def test_html_version(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "v7.0.0" in html

    def test_html_executive_summary(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "Executive Summary" in html
        assert "5 findings" in html
        assert "1 critical" in html
        assert "1 high" in html

    def test_html_risk_assessment_text(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        # score = 25*1 + 15*1 + 8*1 + 3*1 = 51 → elevated risk
        assert "elevated risk" in html or "moderate risk" in html or "critical risk" in html

    def test_html_scan_duration(self):
        rg = ReportGenerator(_make_results(), "example.com", scan_duration=42.7)
        html = rg.generate("html")
        assert "42.7s" in html

    def test_html_tech_fingerprint(self):
        tp = MockTechProfile()
        rg = ReportGenerator(_make_results(), "example.com", tech_profile=tp)
        html = rg.generate("html")
        assert "Technology Fingerprint" in html
        assert "Nginx" in html
        assert "PHP" in html
        assert "Laravel" in html
        assert "Cloudflare" in html
        assert "85%" in html  # confidence

    def test_html_no_tech_when_absent(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "Technology Fingerprint" not in html

    def test_html_cvss_distribution(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "CVSS Score Distribution" in html
        assert "dist-chart" in html
        assert "dist-bar" in html

    def test_html_no_cvss_chart_for_unscored(self):
        r = ScanResult(scanner_name="Test", target="example.com")
        r.add_finding(Finding(title="Test", severity="INFO", description="info"))
        rg = ReportGenerator([r], "example.com")
        html = rg.generate("html")
        assert "CVSS Score Distribution" not in html

    def test_html_remediation_priorities(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "Remediation Priorities" in html
        assert "SQL Injection in login form" in html
        assert "Use parameterized queries" in html

    def test_html_compliance_matrix(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "Compliance Mapping" in html
        assert "OWASP Top 10" in html
        assert "A03:2021 - Injection" in html
        assert "CWE-89" in html

    def test_html_scanner_performance_sorted(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "Scanner Performance" in html
        # SQLi Scanner has 15s duration, should appear first (sorted by duration desc)
        sqli_pos = html.index("SQLi Scanner")
        xss_pos = html.index("XSS Scanner")
        assert sqli_pos < xss_pos  # 15s before 8s

    def test_html_pci_badge(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "PCI: 6.5.1" in html

    def test_html_finding_url(self):
        rg = ReportGenerator(_make_results(), "example.com")
        html = rg.generate("html")
        assert "https://example.com/login" in html

    def test_html_file_output(self, tmp_path):
        out = str(tmp_path / "report.html")
        rg = ReportGenerator(_make_results(), "example.com")
        rg.generate("html", out)
        with open(out) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content

    def test_html_empty_findings(self):
        rg = ReportGenerator([], "example.com")
        html = rg.generate("html")
        assert "0 findings" in html
        assert "No security vulnerabilities" in html

    def test_html_escapes_xss(self):
        """Ensure user-controlled content is escaped in HTML output."""
        r = ScanResult(scanner_name="Test", target="example.com")
        r.add_finding(Finding(
            title='<script>alert("xss")</script>',
            severity="HIGH",
            description='<img onerror=alert(1) src=x>',
        ))
        rg = ReportGenerator([r], "example.com")
        html = rg.generate("html")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "&lt;img" in html


# ═══════════════════════════════════════════════════════════════════════
# Console Report Tests
# ═══════════════════════════════════════════════════════════════════════

class TestEnhancedConsoleReport:
    """Test the enhanced console output."""

    def _capture(self, rg):
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            rg.generate("console")
            return mock_out.getvalue()

    def test_console_scanner_performance(self):
        rg = ReportGenerator(_make_results(), "example.com")
        output = self._capture(rg)
        assert "Scanner Performance" in output
        assert "SQLi Scanner" in output

    def test_console_scan_duration(self):
        rg = ReportGenerator(_make_results(), "example.com", scan_duration=42.7)
        output = self._capture(rg)
        assert "42.7s" in output

    def test_console_tech_fingerprint(self):
        tp = MockTechProfile()
        rg = ReportGenerator(_make_results(), "example.com", tech_profile=tp)
        output = self._capture(rg)
        assert "Nginx" in output
        assert "PHP" in output
        assert "Laravel" in output

    def test_console_remediation_priorities(self):
        rg = ReportGenerator(_make_results(), "example.com")
        output = self._capture(rg)
        assert "Remediation Priorities" in output
        assert "SQL Injection" in output

    def test_console_cvss_distribution(self):
        rg = ReportGenerator(_make_results(), "example.com")
        output = self._capture(rg)
        assert "CVSS Distribution" in output
        assert "Average:" in output

    def test_console_owasp_coverage(self):
        rg = ReportGenerator(_make_results(), "example.com")
        output = self._capture(rg)
        assert "OWASP Top 10 Coverage" in output
        assert "A03:2021" in output

    def test_console_empty_scan(self):
        rg = ReportGenerator([], "example.com")
        output = self._capture(rg)
        assert "Total Findings: 0" in output

    def test_console_risk_score(self):
        rg = ReportGenerator(_make_results(), "example.com")
        output = self._capture(rg)
        assert "Risk Score:" in output
        assert "Grade:" in output

    def test_console_no_tech_when_absent(self):
        rg = ReportGenerator(_make_results(), "example.com")
        output = self._capture(rg)
        assert "Stack:" not in output

    def test_console_severity_bars(self):
        rg = ReportGenerator(_make_results(), "example.com")
        output = self._capture(rg)
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "█" in output


# ═══════════════════════════════════════════════════════════════════════
# SARIF Report Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSARIFReport:
    """Test SARIF report version update."""

    def test_sarif_version_string(self):
        rg = ReportGenerator(_make_results(), "example.com")
        content = rg.generate("sarif")
        data = json.loads(content)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["version"] == "7.0.0"
