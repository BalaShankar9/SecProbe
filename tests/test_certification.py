import pytest
from secprobe.certification.engine import CertificationEngine, CertLevel, Certification


class FakeFinding:
    def __init__(self, severity):
        self.severity = severity


class TestCertificationEngine:
    def setup_method(self):
        self.engine = CertificationEngine()

    def test_gold_no_vulns(self):
        level = self.engine.evaluate([], 95.0, "A+")
        assert level == CertLevel.GOLD

    def test_silver_only_medium(self):
        findings = [FakeFinding("MEDIUM"), FakeFinding("LOW")]
        level = self.engine.evaluate(findings, 70.0, "C")
        assert level == CertLevel.SILVER

    def test_bronze_with_high(self):
        findings = [FakeFinding("HIGH"), FakeFinding("LOW")]
        level = self.engine.evaluate(findings, 50.0, "D")
        assert level == CertLevel.BRONZE

    def test_no_cert_low_score(self):
        findings = [FakeFinding("CRITICAL")]
        level = self.engine.evaluate(findings, 20.0, "F")
        assert level is None

    def test_platinum_redteam_clean(self):
        level = self.engine.evaluate([], 100.0, "A+", mode="redteam")
        assert level == CertLevel.PLATINUM

    def test_issue_and_verify(self):
        cert = self.engine.issue_certification("example.com", CertLevel.GOLD, risk_score=95.0, grade="A+")
        assert cert.cert_id
        assert cert.target == "example.com"
        assert cert.level == CertLevel.GOLD
        assert cert.expires_at > cert.issued_at
        assert self.engine.verify_certification(cert) is True

    def test_tampered_cert_fails_verify(self):
        cert = self.engine.issue_certification("example.com", CertLevel.GOLD)
        cert.risk_score = 999  # Tamper
        assert self.engine.verify_certification(cert) is False
