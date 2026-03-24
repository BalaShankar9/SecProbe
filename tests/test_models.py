"""Tests for secprobe.models — Finding and ScanResult dataclasses."""

import unittest
from secprobe.models import Finding, ScanResult


class TestFinding(unittest.TestCase):
    def test_create_finding_required_fields(self):
        f = Finding(title="Test", severity="HIGH", description="desc", scanner="test_scanner")
        self.assertEqual(f.title, "Test")
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.description, "desc")
        self.assertEqual(f.scanner, "test_scanner")

    def test_finding_optional_defaults(self):
        f = Finding(title="T", severity="LOW", description="d", scanner="s")
        self.assertEqual(f.recommendation, "")
        self.assertEqual(f.evidence, "")
        self.assertEqual(f.category, "")
        self.assertEqual(f.url, "")
        self.assertEqual(f.cwe, "")

    def test_finding_details_alias(self):
        f = Finding(title="T", severity="HIGH", description="my desc", scanner="s")
        self.assertEqual(f.details, "my desc")

    def test_finding_remediation_alias(self):
        f = Finding(title="T", severity="HIGH", description="d", scanner="s", recommendation="fix it")
        self.assertEqual(f.remediation, "fix it")

    def test_finding_with_all_fields(self):
        f = Finding(
            title="SQLi", severity="CRITICAL", description="SQL injection found",
            recommendation="Use prepared statements", evidence="payload: ' OR 1=1",
            scanner="sqli", category="Injection", url="http://test.com?id=1", cwe="CWE-89",
        )
        self.assertEqual(f.cwe, "CWE-89")
        self.assertEqual(f.url, "http://test.com?id=1")
        self.assertEqual(f.category, "Injection")


class TestScanResult(unittest.TestCase):
    def test_empty_result(self):
        r = ScanResult(scanner_name="test", target="http://example.com")
        counts = r.finding_count
        self.assertIsInstance(counts, dict)
        self.assertEqual(sum(counts.values()), 0)
        self.assertEqual(r.findings, [])

    def test_finding_count(self):
        r = ScanResult(scanner_name="test", target="http://example.com")
        r.findings.append(Finding(title="F1", severity="LOW", description="d", scanner="test"))
        r.findings.append(Finding(title="F2", severity="HIGH", description="d", scanner="test"))
        counts = r.finding_count
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(sum(counts.values()), 2)

    def test_raw_data_default(self):
        r = ScanResult(scanner_name="test", target="http://example.com")
        self.assertIsInstance(r.raw_data, dict)


if __name__ == "__main__":
    unittest.main()
