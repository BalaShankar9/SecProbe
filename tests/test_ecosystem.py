import pytest
from secprobe.ecosystem.bounty_triage import BountyTriageEngine, BountyReport, TriageVerdict
from secprobe.ecosystem.regulatory import RegulatoryEngine


class FakeFinding:
    def __init__(self, title, category, severity="HIGH", url=""):
        self.title = title
        self.category = category
        self.severity = severity
        self.url = url


class TestBountyTriage:
    def test_duplicate_detection(self):
        engine = BountyTriageEngine()
        report = BountyReport(
            report_id="R001",
            target_url="http://example.com/search",
            vuln_type="sqli",
            description="SQL injection in search",
        )
        existing = [FakeFinding("SQL Injection", "sqli", "CRITICAL", "http://example.com/search")]
        result = engine.triage(report, existing)
        assert result.verdict == TriageVerdict.DUPLICATE

    def test_invalid_report(self):
        engine = BountyTriageEngine()
        report = BountyReport(report_id="R002", target_url="", vuln_type="", description="")
        result = engine.triage(report, [])
        assert result.verdict == TriageVerdict.INVALID

    def test_needs_review(self):
        engine = BountyTriageEngine()
        report = BountyReport(
            report_id="R003",
            target_url="http://example.com/api",
            vuln_type="xss",
            description="XSS in API",
        )
        result = engine.triage(report, [])
        assert result.verdict == TriageVerdict.NEEDS_REVIEW

    def test_severity_estimation(self):
        assert BountyTriageEngine._estimate_severity("sqli") == "CRITICAL"
        assert BountyTriageEngine._estimate_severity("xss") == "HIGH"
        assert BountyTriageEngine._estimate_severity("csrf") == "MEDIUM"
        assert BountyTriageEngine._estimate_severity("headers") == "LOW"


class TestRegulatoryEngine:
    def test_owasp_compliance(self):
        engine = RegulatoryEngine()
        findings = [FakeFinding("SQLi", "sqli"), FakeFinding("XSS", "xss")]
        result = engine.assess_compliance(findings, "owasp_top10_2021")
        assert result["total_controls"] == 10
        assert result["failed"] > 0  # Should fail A03 (Injection)
        assert result["passed"] > 0  # Some should pass

    def test_clean_scan_passes(self):
        engine = RegulatoryEngine()
        result = engine.assess_compliance([], "owasp_top10_2021")
        assert result["passed"] == 10
        assert result["compliance_rate"] == 1.0

    def test_gap_analysis(self):
        engine = RegulatoryEngine()
        findings = [FakeFinding("SQLi", "sqli")]
        gaps = engine.gap_analysis(findings)
        assert "owasp_top10_2021" in gaps
        assert "pci_dss_4" in gaps
        assert "nist_800_53" in gaps

    def test_supported_frameworks(self):
        engine = RegulatoryEngine()
        frameworks = engine.get_supported_frameworks()
        assert len(frameworks) >= 3
        assert "owasp_top10_2021" in frameworks

    def test_unknown_framework(self):
        engine = RegulatoryEngine()
        result = engine.assess_compliance([], "nonexistent")
        assert "error" in result
