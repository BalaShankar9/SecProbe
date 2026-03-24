"""
Tests for v5.0.0 enterprise systems:
  - CVSS 3.1 calculator
  - Vulnerability knowledge base
  - Plugin architecture
  - CI/CD integration (SARIF, JUnit)
  - Session manager & token analyzer
  - Report generator (SARIF/JUnit formats)
  - Updated models with CVSS fields
"""

import json
import math
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════
# CVSS 3.1 Calculator Tests
# ═══════════════════════════════════════════════════════════════════════

from secprobe.core.cvss import (
    CVSSVector,
    CVSSScore,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
    ExploitCodeMaturity,
    RemediationLevel,
    ReportConfidence,
    get_cvss_for_finding,
    VULN_CVSS_MAP,
)


class TestCVSSVector:
    """Test CVSS 3.1 vector creation and calculation."""

    def test_critical_vector(self):
        """Network/Low/None/None + Changed scope + High CIA = 10.0."""
        vec = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        result = vec.calculate()
        assert result.base_score == 10.0
        assert result.base_severity == "CRITICAL"

    def test_medium_vector(self):
        """Network/High/Low/Required + Unchanged scope + Low CI, None A."""
        vec = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        )
        result = vec.calculate()
        assert 3.0 <= result.base_score <= 5.0
        assert result.base_severity in ("LOW", "MEDIUM")

    def test_no_impact_is_zero(self):
        """Zero impact on all three should give 0.0."""
        vec = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )
        result = vec.calculate()
        assert result.base_score == 0.0
        assert result.base_severity == "NONE"

    def test_vector_string_generation(self):
        """Vector string should follow CVSS:3.1/... format."""
        vec = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        result = vec.calculate()
        assert result.vector_string.startswith("CVSS:3.1/")
        assert "AV:N" in result.vector_string
        assert "AC:L" in result.vector_string

    def test_from_vector_string(self):
        """Parse a CVSS vector string back into a CVSSVector object."""
        vec_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vec = CVSSVector.from_vector_string(vec_str)
        assert vec.attack_vector == AttackVector.NETWORK
        assert vec.attack_complexity == AttackComplexity.LOW
        assert vec.scope == Scope.UNCHANGED
        result = vec.calculate()
        assert result.base_score == 9.8
        assert result.base_severity == "CRITICAL"

    def test_temporal_score(self):
        """Temporal modifiers should reduce the base score."""
        vec = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
            exploit_code_maturity=ExploitCodeMaturity.PROOF_OF_CONCEPT,
            remediation_level=RemediationLevel.TEMPORARY_FIX,
            report_confidence=ReportConfidence.REASONABLE,
        )
        result = vec.calculate()
        assert result.temporal_score is not None
        assert result.temporal_score < result.base_score

    def test_physical_vector(self):
        """Physical access should yield lower score than network."""
        vec = CVSSVector(
            attack_vector=AttackVector.PHYSICAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        result = vec.calculate()
        assert result.base_score < 9.8  # Less than network vector

    def test_severity_boundaries(self):
        """Verify severity rating thresholds."""
        vec = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )
        assert vec._severity_rating(0.0) == "NONE"
        assert vec._severity_rating(0.1) == "LOW"
        assert vec._severity_rating(3.9) == "LOW"
        assert vec._severity_rating(4.0) == "MEDIUM"
        assert vec._severity_rating(6.9) == "MEDIUM"
        assert vec._severity_rating(7.0) == "HIGH"
        assert vec._severity_rating(8.9) == "HIGH"
        assert vec._severity_rating(9.0) == "CRITICAL"
        assert vec._severity_rating(10.0) == "CRITICAL"


class TestGetCVSSForFinding:
    """Test the convenience function for getting CVSS from scanner names."""

    def test_sqli_mapping(self):
        result = get_cvss_for_finding("SQLi Scanner", "HIGH")
        assert result is not None
        assert result.base_score >= 7.0

    def test_xss_mapping(self):
        result = get_cvss_for_finding("XSS Scanner", "MEDIUM")
        assert result is not None
        assert result.base_score >= 4.0

    def test_unknown_scanner_fallback(self):
        result = get_cvss_for_finding("Unknown Scanner", "CRITICAL")
        assert result is not None  # Should fallback based on severity

    def test_info_severity_returns_none_or_low(self):
        result = get_cvss_for_finding("Header Scanner", "INFO")
        # INFO findings may not have CVSS scores (None is acceptable)
        if result is not None:
            assert result.base_score < 4.0

    def test_vuln_map_coverage(self):
        """Ensure all mapped vuln types produce valid scores."""
        for vuln_type, vector in VULN_CVSS_MAP.items():
            result = vector.calculate()
            assert 0.0 <= result.base_score <= 10.0
            assert result.base_severity in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


# ═══════════════════════════════════════════════════════════════════════
# Vulnerability Knowledge Base Tests
# ═══════════════════════════════════════════════════════════════════════

from secprobe.core.vulnerability_db import (
    OWASP_TOP_10_2021,
    CWE_DATABASE,
    SCANNER_CWE_MAP,
    PCI_DSS_REQUIREMENTS,
    NIST_CONTROLS,
    get_cwe_info,
    get_owasp_category,
    get_scanner_cwes,
    get_pci_requirements,
    get_remediation_priority,
    generate_compliance_matrix,
)


class TestOWASPTop10:
    """Test OWASP Top 10 2021 data."""

    def test_all_10_categories_present(self):
        assert len(OWASP_TOP_10_2021) == 10
        for i in range(1, 11):
            key = f"A{i:02d}"
            assert key in OWASP_TOP_10_2021

    def test_category_has_required_fields(self):
        for key, cat in OWASP_TOP_10_2021.items():
            assert cat.code
            assert cat.name
            assert cat.description
            assert isinstance(cat.cwe_ids, list)


class TestCWEDatabase:
    """Test CWE knowledge base."""

    def test_common_cwes_present(self):
        assert "CWE-79" in CWE_DATABASE   # XSS
        assert "CWE-89" in CWE_DATABASE   # SQLi
        assert "CWE-78" in CWE_DATABASE   # OS Command Injection
        assert "CWE-352" in CWE_DATABASE  # CSRF

    def test_cwe_info_lookup(self):
        info = get_cwe_info("CWE-89")
        assert info is not None
        assert info.name
        assert "SQL" in info.name.upper() or "injection" in info.name.lower()

    def test_missing_cwe_returns_none(self):
        assert get_cwe_info("CWE-99999") is None


class TestScannerCWEMap:
    """Test scanner-to-CWE mapping."""

    def test_sqli_maps_to_cwe89(self):
        cwes = get_scanner_cwes("SQL Injection Scanner")
        cwe_ids = [c.cwe_id for c in cwes]
        assert "CWE-89" in cwe_ids

    def test_xss_maps_to_cwe79(self):
        cwes = get_scanner_cwes("XSS Scanner")
        cwe_ids = [c.cwe_id for c in cwes]
        assert "CWE-79" in cwe_ids

    def test_unknown_scanner_empty(self):
        cwes = get_scanner_cwes("nonexistent_scanner")
        assert cwes == []


class TestOWASPCategoryLookup:
    """Test OWASP category retrieval from CWE."""

    def test_injection_cwe_maps_to_a03(self):
        result = get_owasp_category("CWE-89")  # SQLi
        assert result is not None
        assert "A03" in result.code

    def test_unknown_cwe_returns_none(self):
        result = get_owasp_category("CWE-99999")
        assert result is None


class TestPCIDSSRequirements:
    """Test PCI-DSS compliance mapping."""

    def test_requirements_present(self):
        assert len(PCI_DSS_REQUIREMENTS) > 0

    def test_cwe_pci_mapping(self):
        reqs = get_pci_requirements("CWE-89")  # SQLi
        # SQLi should map to some PCI requirement
        assert isinstance(reqs, list)
        assert len(reqs) > 0


class TestRemediationPriority:
    """Test remediation priority scoring."""

    def test_critical_sqli_is_high_priority(self):
        from secprobe.models import Finding
        finding = Finding(
            title="SQL Injection",
            severity="CRITICAL",
            description="SQL injection found",
            cwe="CWE-89",
        )
        priority = get_remediation_priority([finding])
        assert len(priority) > 0
        assert priority[0]["finding"].severity == "CRITICAL"
        assert priority[0]["priority_score"] > 0


class TestComplianceMatrix:
    """Test compliance matrix generation."""

    def test_generates_matrix(self):
        from secprobe.models import Finding
        findings = [
            Finding(title="SQLi", severity="HIGH", description="test", cwe="CWE-89"),
            Finding(title="XSS", severity="MEDIUM", description="test", cwe="CWE-79"),
        ]
        matrix = generate_compliance_matrix(findings)
        assert "owasp" in matrix
        assert "pci_dss" in matrix
        assert "nist" in matrix


# ═══════════════════════════════════════════════════════════════════════
# Plugin Architecture Tests
# ═══════════════════════════════════════════════════════════════════════

from secprobe.core.plugins import (
    PluginType,
    HookPoint,
    PluginMetadata,
    BasePlugin,
    ScannerPlugin,
    ReporterPlugin,
    PluginManager,
)


class TestPluginMetadata:
    """Test plugin metadata dataclass."""

    def test_create_metadata(self):
        meta = PluginMetadata(
            name="TestPlugin",
            version="1.0",
            author="Test",
            description="A test plugin",
            plugin_type=PluginType.SCANNER,
            hooks=[HookPoint.PRE_SCAN, HookPoint.POST_SCAN],
        )
        assert meta.name == "TestPlugin"
        assert meta.plugin_type == PluginType.SCANNER
        assert len(meta.hooks) == 2


class TestPluginManager:
    """Test plugin manager lifecycle."""

    def test_create_manager(self):
        manager = PluginManager()
        assert manager is not None
        assert len(manager.list_plugins()) == 0

    def test_fire_hook_no_plugins(self):
        """Firing hooks with no plugins should not error."""
        manager = PluginManager()
        results = manager.fire_hook(HookPoint.PRE_SCAN, target="example.com")
        assert results == []

    def test_get_scanners_empty(self):
        manager = PluginManager()
        assert manager.get_scanners() == []

    def test_get_reporters_empty(self):
        manager = PluginManager()
        assert manager.get_reporters() == []


# ═══════════════════════════════════════════════════════════════════════
# CI/CD Integration Tests
# ═══════════════════════════════════════════════════════════════════════

from secprobe.core.cicd import (
    SARIFGenerator,
    JUnitGenerator,
    JSONSummaryGenerator,
    ExitCodeManager,
    GitHubAnnotationGenerator,
)
from secprobe.models import Finding, ScanResult


class TestSARIFGenerator:
    """Test SARIF 2.1.0 output."""

    def _make_results(self):
        result = ScanResult(scanner_name="Test Scanner", target="https://example.com")
        result.add_finding(Finding(
            title="SQL Injection",
            severity="CRITICAL",
            description="SQL injection in login form",
            evidence="' OR 1=1--",
            scanner="SQLi Scanner",
            cwe="CWE-89",
            url="https://example.com/login",
        ))
        result.add_finding(Finding(
            title="Missing HSTS",
            severity="INFO",
            description="HSTS header not set",
            scanner="Header Scanner",
            cwe="CWE-16",
            url="https://example.com",
        ))
        return [result]

    def test_generates_valid_sarif(self):
        gen = SARIFGenerator()
        results = self._make_results()
        sarif_str = gen.generate(results, "https://example.com")
        sarif = json.loads(sarif_str)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "SecProbe"

    def test_sarif_has_results(self):
        gen = SARIFGenerator()
        results = self._make_results()
        sarif_str = gen.generate(results, "https://example.com")
        sarif = json.loads(sarif_str)
        assert len(sarif["runs"][0]["results"]) == 2

    def test_sarif_severity_mapping(self):
        gen = SARIFGenerator()
        results = self._make_results()
        sarif_str = gen.generate(results, "https://example.com")
        sarif = json.loads(sarif_str)
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert "error" in levels  # CRITICAL -> error

    def test_empty_results(self):
        gen = SARIFGenerator()
        sarif_str = gen.generate([], "https://example.com")
        sarif = json.loads(sarif_str)
        assert sarif["runs"][0]["results"] == []


class TestJUnitGenerator:
    """Test JUnit XML output."""

    def _make_results(self):
        result = ScanResult(scanner_name="SQLi Scanner", target="https://example.com")
        result.add_finding(Finding(
            title="SQL Injection",
            severity="CRITICAL",
            description="SQL injection found",
            scanner="SQLi Scanner",
        ))
        return [result]

    def test_generates_xml(self):
        gen = JUnitGenerator()
        results = self._make_results()
        xml = gen.generate(results, "https://example.com")
        assert xml.startswith("<?xml")
        assert "<testsuites" in xml
        assert "<testsuite" in xml

    def test_failure_on_critical(self):
        gen = JUnitGenerator()
        results = self._make_results()
        xml = gen.generate(results, "https://example.com")
        assert "<failure" in xml

    def test_empty_results(self):
        gen = JUnitGenerator()
        xml = gen.generate([], "https://example.com")
        assert "<testsuites" in xml


class TestJSONSummaryGenerator:
    """Test JSON summary for CI/CD."""

    def test_generates_summary(self):
        gen = JSONSummaryGenerator()
        result = ScanResult(scanner_name="Test", target="example.com")
        result.add_finding(Finding(title="Issue", severity="HIGH", description="test"))
        summary_str = gen.generate([result], "example.com")
        summary = json.loads(summary_str)
        assert "secprobe" in summary
        assert summary["secprobe"]["total_findings"] == 1

    def test_pass_fail_status(self):
        gen = JSONSummaryGenerator()
        result = ScanResult(scanner_name="Test", target="example.com")
        result.add_finding(Finding(title="Issue", severity="HIGH", description="test"))
        summary = json.loads(gen.generate([result], "example.com"))
        assert summary["secprobe"]["pass"] is False


class TestExitCodeManager:
    """Test exit code management."""

    def test_no_threshold_passes_on_low(self):
        """Default threshold is 'high', so LOW findings pass."""
        mgr = ExitCodeManager()
        result = ScanResult(scanner_name="Test", target="example.com")
        result.add_finding(Finding(title="Low Issue", severity="LOW", description="test"))
        assert mgr.get_exit_code([result]) == 0

    def test_threshold_critical_fails(self):
        mgr = ExitCodeManager(fail_on="critical")
        result = ScanResult(scanner_name="Test", target="example.com")
        result.add_finding(Finding(title="Critical Issue", severity="CRITICAL", description="test"))
        assert mgr.get_exit_code([result]) == 1

    def test_threshold_high_passes_on_medium(self):
        mgr = ExitCodeManager(fail_on="high")
        result = ScanResult(scanner_name="Test", target="example.com")
        result.add_finding(Finding(title="Medium Issue", severity="MEDIUM", description="test"))
        assert mgr.get_exit_code([result]) == 0


class TestGitHubAnnotations:
    """Test GitHub annotation output."""

    def test_generates_annotations(self):
        gen = GitHubAnnotationGenerator()
        result = ScanResult(scanner_name="Test", target="example.com")
        result.add_finding(Finding(
            title="SQL Injection",
            severity="CRITICAL",
            description="Found SQLi",
            url="https://example.com/login",
        ))
        output = gen.generate([result])
        assert "::error" in output


# ═══════════════════════════════════════════════════════════════════════
# Session Manager Tests
# ═══════════════════════════════════════════════════════════════════════

from secprobe.core.session_manager import (
    AuthState,
    AuthStep,
    AuthFlow,
    SessionManager,
    TokenAnalyzer,
    EntropyResult,
    SessionSecurityTester,
)


class TestSessionManager:
    """Test authentication state machine."""

    def test_initial_state(self):
        mgr = SessionManager()
        assert mgr.state == AuthState.UNAUTHENTICATED

    def test_configure_flow(self):
        mgr = SessionManager()
        flow = AuthFlow(
            name="test_flow",
            steps=[
                AuthStep(name="login", url="https://example.com/login",
                        success_indicator="Welcome"),
            ],
        )
        mgr.configure_flow(flow)
        assert mgr.auth_flow is not None
        assert mgr.auth_flow.name == "test_flow"

    def test_authenticate_without_client_fails(self):
        mgr = SessionManager()
        flow = AuthFlow(name="test", steps=[
            AuthStep(name="login", url="https://example.com/login"),
        ])
        mgr.configure_flow(flow)
        assert mgr.authenticate() is False

    def test_logout_resets_state(self):
        mgr = SessionManager()
        mgr.state = AuthState.AUTHENTICATED
        mgr.tokens = {"csrf": "abc123"}
        mgr.cookies = {"session": "xyz"}
        mgr.logout()
        assert mgr.state == AuthState.UNAUTHENTICATED
        assert len(mgr.tokens) == 0
        assert len(mgr.cookies) == 0


class TestTokenAnalyzer:
    """Test session token entropy analysis."""

    def test_high_entropy_token(self):
        """A long random hex string should have high entropy."""
        import hashlib
        token = hashlib.sha256(b"random_seed_12345").hexdigest()
        analyzer = TokenAnalyzer()
        result = analyzer.analyze_entropy(token)
        assert result.entropy_bits > 100
        assert result.prediction_risk == "LOW"
        assert not result.is_predictable

    def test_low_entropy_token(self):
        """A simple numeric token should be flagged."""
        analyzer = TokenAnalyzer()
        result = analyzer.analyze_entropy("12345")
        assert result.entropy_bits < 64
        assert result.prediction_risk == "HIGH"
        assert result.is_predictable

    def test_sequential_detection(self):
        """Sequential digits should be detected."""
        analyzer = TokenAnalyzer()
        result = analyzer.analyze_entropy("abc123456789xyz")
        # Should detect sequential pattern in digits
        assert isinstance(result, EntropyResult)

    def test_token_set_analysis(self):
        """Analyzing a set of tokens should provide comparison data."""
        analyzer = TokenAnalyzer()
        import hashlib
        tokens = [
            hashlib.sha256(f"seed_{i}".encode()).hexdigest()
            for i in range(5)
        ]
        result = analyzer.analyze_token_set(tokens)
        assert result["token_count"] == 5
        assert result["avg_entropy_bits"] > 0
        assert "prediction_risk" in result

    def test_incremental_tokens_detected(self):
        """Incrementing numeric tokens should be flagged."""
        analyzer = TokenAnalyzer()
        tokens = ["100", "101", "102", "103"]
        result = analyzer.analyze_token_set(tokens)
        assert result["is_incremental"] is True

    def test_common_prefix_detection(self):
        """Tokens with common prefix should be detected."""
        analyzer = TokenAnalyzer()
        tokens = ["session_abc123", "session_def456", "session_ghi789"]
        result = analyzer.analyze_token_set(tokens)
        assert result["common_prefix"] == "session_"

    def test_single_token_error(self):
        """Token set analysis needs >= 2 tokens."""
        analyzer = TokenAnalyzer()
        result = analyzer.analyze_token_set(["single_token"])
        assert "error" in result


class TestSessionSecurityTester:
    """Test session security test suite."""

    def test_create_tester(self):
        tester = SessionSecurityTester()
        assert tester.findings == []

    def test_test_all_without_client(self):
        """Should handle missing HTTP client gracefully."""
        tester = SessionSecurityTester()
        findings = tester.test_all("https://example.com")
        assert isinstance(findings, list)


# ═══════════════════════════════════════════════════════════════════════
# Updated Models Tests
# ═══════════════════════════════════════════════════════════════════════

class TestUpdatedFinding:
    """Test Finding model with CVSS fields."""

    def test_finding_with_cvss(self):
        f = Finding(
            title="SQL Injection",
            severity="CRITICAL",
            description="SQL injection found",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_severity="CRITICAL",
        )
        assert f.cvss_score == 9.8
        assert f.cvss_vector.startswith("CVSS:3.1")
        assert f.cvss_severity == "CRITICAL"

    def test_finding_to_dict_includes_cvss(self):
        f = Finding(
            title="XSS",
            severity="MEDIUM",
            description="XSS found",
            cvss_score=6.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cvss_severity="MEDIUM",
            owasp_category="A03:2021 - Injection",
            pci_dss=["6.5.7"],
            nist=["SI-10"],
        )
        d = f.to_dict()
        assert d["cvss_score"] == 6.1
        assert d["cvss_vector"].startswith("CVSS:3.1")
        assert d["owasp_category"] == "A03:2021 - Injection"
        assert "6.5.7" in d["pci_dss"]
        assert "SI-10" in d["nist"]

    def test_finding_defaults_none(self):
        """CVSS fields default to None/empty."""
        f = Finding(title="Test", severity="INFO", description="test")
        assert f.cvss_score is None
        assert f.cvss_vector == ""
        assert f.owasp_category == ""
        assert f.pci_dss == []
        assert f.nist == []

    def test_backward_compatibility(self):
        """Existing code creating Findings without CVSS should still work."""
        f = Finding(
            title="Test",
            severity="LOW",
            description="test",
            recommendation="fix it",
            evidence="proof",
            scanner="TestScanner",
            category="Testing",
            url="https://example.com",
            cwe="CWE-200",
        )
        d = f.to_dict()
        assert d["title"] == "Test"
        assert d["cwe"] == "CWE-200"
        assert d["cvss_score"] is None


# ═══════════════════════════════════════════════════════════════════════
# Report Generator Tests (SARIF/JUnit formats)
# ═══════════════════════════════════════════════════════════════════════

from secprobe.report import ReportGenerator


class TestReportGeneratorSARIF:
    """Test SARIF report generation via ReportGenerator."""

    def _make_results(self):
        result = ScanResult(scanner_name="SQLi Scanner", target="example.com")
        result.add_finding(Finding(
            title="SQL Injection",
            severity="CRITICAL",
            description="SQL injection in login",
            scanner="SQLi Scanner",
            cwe="CWE-89",
            url="https://example.com/login",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ))
        return [result]

    def test_sarif_format(self):
        reporter = ReportGenerator(self._make_results(), "example.com")
        sarif_str = reporter.generate("sarif")
        sarif = json.loads(sarif_str)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_junit_format(self):
        reporter = ReportGenerator(self._make_results(), "example.com")
        junit_str = reporter.generate("junit")
        assert "<?xml" in junit_str
        assert "<testsuites" in junit_str
        assert "<failure" in junit_str


class TestReportGeneratorHTML:
    """Test HTML report with CVSS badges."""

    def test_html_contains_cvss(self):
        result = ScanResult(scanner_name="Test", target="example.com")
        result.add_finding(Finding(
            title="SQLi",
            severity="HIGH",
            description="test",
            cvss_score=8.6,
        ))
        reporter = ReportGenerator([result], "example.com")
        html = reporter.generate("html")
        assert "CVSS 8.6" in html
        assert "v7.0.0" in html


# ═══════════════════════════════════════════════════════════════════════
# Scanner Registration Tests
# ═══════════════════════════════════════════════════════════════════════

class TestScannerRegistry:
    """Test that new scanners are registered."""

    def test_24_scanners_registered(self):
        from secprobe.scanners import SCANNER_REGISTRY
        assert len(SCANNER_REGISTRY) == 45

    def test_api_scanner_registered(self):
        from secprobe.scanners import SCANNER_REGISTRY
        assert "api" in SCANNER_REGISTRY

    def test_graphql_scanner_registered(self):
        from secprobe.scanners import SCANNER_REGISTRY
        assert "graphql" in SCANNER_REGISTRY

    def test_websocket_scanner_registered(self):
        from secprobe.scanners import SCANNER_REGISTRY
        assert "websocket" in SCANNER_REGISTRY

    def test_original_scanners_still_present(self):
        from secprobe.scanners import SCANNER_REGISTRY
        for name in ["sqli", "xss", "ports", "ssl", "headers", "cors",
                     "csrf", "ssrf", "ssti", "cmdi", "lfi", "xxe",
                     "nosql", "jwt", "redirect", "smuggling"]:
            assert name in SCANNER_REGISTRY


# ═══════════════════════════════════════════════════════════════════════
# Version Tests
# ═══════════════════════════════════════════════════════════════════════

class TestVersion:
    """Test version bumps."""

    def test_version_is_5(self):
        from secprobe import __version__
        assert __version__ == "7.0.0"

    def test_banner_version(self):
        from secprobe.utils import BANNER
        assert "v7.0.0" in BANNER
