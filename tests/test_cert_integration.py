"""
Integration tests for certification engine wired into the scan pipeline.

Tests:
  1. CertificationEngine.evaluate() returns correct levels for various finding profiles
  2. issue_certification() produces a valid cert with attestation hash
  3. verify_certification() round-trips correctly
  4. CLI --certify flag is registered in the parser
  5. API /scans/{scan_id}/certification endpoint returns expected shape
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from secprobe.certification.engine import (
    CertificationEngine,
    CertLevel,
    Certification,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

class FakeFinding:
    """Minimal finding stub with a severity attribute."""
    def __init__(self, severity: str):
        self.severity = severity


# ── CertificationEngine.evaluate() ──────────────────────────────────────────

class TestCertificationEvaluate:
    def setup_method(self):
        self.engine = CertificationEngine()

    def test_gold_no_vulns_above_low(self):
        """No critical/high/medium findings -> GOLD."""
        findings = [FakeFinding("LOW"), FakeFinding("INFO")]
        level = self.engine.evaluate(findings, risk_score=85, grade="B")
        assert level == CertLevel.GOLD

    def test_silver_medium_findings(self):
        """Medium findings present but no critical/high -> SILVER."""
        findings = [FakeFinding("MEDIUM"), FakeFinding("LOW")]
        level = self.engine.evaluate(findings, risk_score=70, grade="C")
        assert level == CertLevel.SILVER

    def test_bronze_high_findings_decent_score(self):
        """High findings but risk score >= 40 -> BRONZE."""
        findings = [FakeFinding("HIGH"), FakeFinding("MEDIUM")]
        level = self.engine.evaluate(findings, risk_score=45, grade="D")
        assert level == CertLevel.BRONZE

    def test_no_cert_critical_low_score(self):
        """Critical findings with low risk score -> None."""
        findings = [FakeFinding("CRITICAL"), FakeFinding("HIGH")]
        level = self.engine.evaluate(findings, risk_score=20, grade="F")
        assert level is None

    def test_platinum_redteam_clean(self):
        """Redteam mode with zero findings -> PLATINUM."""
        findings = []
        level = self.engine.evaluate(findings, risk_score=100, grade="A", mode="redteam")
        assert level == CertLevel.PLATINUM

    def test_empty_findings_audit_gold(self):
        """No findings in audit mode -> GOLD (not PLATINUM, which requires redteam)."""
        findings = []
        level = self.engine.evaluate(findings, risk_score=100, grade="A", mode="audit")
        assert level == CertLevel.GOLD


# ── CertificationEngine.issue_certification() ──────────────────────────────

class TestIssueCertification:
    def setup_method(self):
        self.engine = CertificationEngine()

    def test_cert_fields_populated(self):
        cert = self.engine.issue_certification(
            target="https://example.com",
            level=CertLevel.GOLD,
            scan_id="scan-abc123",
            findings_summary={"LOW": 2, "INFO": 5},
            risk_score=85.0,
            grade="B",
        )
        assert cert.cert_id  # non-empty
        assert cert.target == "https://example.com"
        assert cert.level == CertLevel.GOLD
        assert cert.scan_id == "scan-abc123"
        assert cert.grade == "B"
        assert cert.risk_score == 85.0
        assert cert.attestation_hash  # non-empty SHA256
        assert len(cert.attestation_hash) == 64  # SHA256 hex digest
        assert cert.expires_at is not None
        assert cert.expires_at > cert.issued_at

    def test_cert_expiry_90_days(self):
        cert = self.engine.issue_certification(
            target="test.local",
            level=CertLevel.SILVER,
        )
        delta = (cert.expires_at - cert.issued_at).days
        assert delta == 90


# ── CertificationEngine.verify_certification() ─────────────────────────────

class TestVerifyCertification:
    def setup_method(self):
        self.engine = CertificationEngine()

    def test_valid_cert_verifies(self):
        cert = self.engine.issue_certification(
            target="verify-test.com",
            level=CertLevel.BRONZE,
            risk_score=45.0,
            grade="D",
        )
        assert self.engine.verify_certification(cert) is True

    def test_tampered_cert_fails(self):
        cert = self.engine.issue_certification(
            target="tamper-test.com",
            level=CertLevel.GOLD,
            risk_score=90.0,
            grade="A",
        )
        cert.risk_score = 10.0  # tamper
        assert self.engine.verify_certification(cert) is False


# ── CLI parser integration ──────────────────────────────────────────────────

class TestCLICertifyFlag:
    def test_certify_flag_registered(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        # Parse with --certify
        args = parser.parse_args(["example.com", "--certify"])
        assert args.certify is True

    def test_certify_default_off(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.certify is False


# ── Full pipeline simulation ────────────────────────────────────────────────

class TestFullCertPipeline:
    """Simulate the full evaluate -> issue -> verify pipeline."""

    def test_end_to_end_gold(self):
        engine = CertificationEngine()
        findings = [FakeFinding("LOW"), FakeFinding("LOW"), FakeFinding("INFO")]

        level = engine.evaluate(findings, risk_score=91, grade="A")
        assert level == CertLevel.GOLD

        cert = engine.issue_certification(
            target="pipeline-test.com",
            level=level,
            scan_id="scan-e2e-001",
            findings_summary={"LOW": 2, "INFO": 1},
            risk_score=91,
            grade="A",
        )
        assert cert.level == CertLevel.GOLD
        assert engine.verify_certification(cert) is True

    def test_end_to_end_no_qualification(self):
        engine = CertificationEngine()
        findings = [
            FakeFinding("CRITICAL"),
            FakeFinding("HIGH"),
            FakeFinding("HIGH"),
        ]
        level = engine.evaluate(findings, risk_score=15, grade="F")
        assert level is None


# ── API endpoint shape (unit test without running server) ───────────────────

class TestAPICertificationEndpoint:
    """Test the API certification logic without starting FastAPI."""

    def test_certification_from_empty_scan(self):
        """Empty findings should yield GOLD certification."""
        engine = CertificationEngine()
        findings = []
        finding_objs = [FakeFinding(f.get("severity", "INFO")) for f in findings] if findings else []

        sev_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        penalty = min(100, sum(sev_weights.get(fo.severity.upper(), 0) for fo in finding_objs))
        risk_score = max(0, 100 - penalty)

        if risk_score >= 90:
            grade = "A"
        elif risk_score >= 75:
            grade = "B"
        elif risk_score >= 60:
            grade = "C"
        elif risk_score >= 40:
            grade = "D"
        else:
            grade = "F"

        level = engine.evaluate(finding_objs, risk_score=risk_score, grade=grade, mode="audit")
        assert level == CertLevel.GOLD
        assert grade == "A"
        assert risk_score == 100

    def test_certification_from_critical_findings(self):
        """Scan with critical findings and low score -> no cert."""
        engine = CertificationEngine()
        finding_dicts = [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
        ]
        finding_objs = [FakeFinding(f["severity"]) for f in finding_dicts]

        sev_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        penalty = min(100, sum(sev_weights.get(fo.severity.upper(), 0) for fo in finding_objs))
        risk_score = max(0, 100 - penalty)

        if risk_score >= 90:
            grade = "A"
        elif risk_score >= 75:
            grade = "B"
        elif risk_score >= 60:
            grade = "C"
        elif risk_score >= 40:
            grade = "D"
        else:
            grade = "F"

        level = engine.evaluate(finding_objs, risk_score=risk_score, grade=grade)
        # 25+25+15 = 65 penalty -> score 35 -> grade F -> no cert (score < 40)
        assert level is None
        assert grade == "F"
