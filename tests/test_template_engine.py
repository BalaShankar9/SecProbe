"""Tests for secprobe.templates.engine — template engine and result."""

import unittest
from unittest.mock import MagicMock
from secprobe.templates.engine import TemplateEngine, VulnTemplate, TemplateResult


class TestVulnTemplate(unittest.TestCase):
    def test_template_fields(self):
        t = VulnTemplate(
            template_id="test-001",
            name="test_template",
            severity="HIGH",
            description="Test template",
            remediation="Fix it",
        )
        self.assertEqual(t.name, "test_template")
        self.assertEqual(t.severity, "HIGH")
        self.assertEqual(t.template_id, "test-001")


class TestTemplateResult(unittest.TestCase):
    def test_to_finding_creates_valid_finding(self):
        t = VulnTemplate(
            template_id="CVE-2021-1234",
            name="CVE-2021-1234",
            severity="CRITICAL",
            description="Test vuln",
            remediation="Patch now",
        )
        result = TemplateResult(
            template=t,
            matched=True,
            target="http://test.com",
            response_status=200,
        )
        finding = result.to_finding()
        self.assertIsNotNone(finding)
        self.assertIn("CVE-2021-1234", finding.title)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.recommendation, "Patch now")
        self.assertEqual(finding.url, "http://test.com")

    def test_to_finding_returns_none_when_not_matched(self):
        t = VulnTemplate(
            template_id="test-002",
            name="Test",
            description="Default desc",
            severity="LOW",
            remediation="None",
        )
        result = TemplateResult(template=t, matched=False, target="http://test.com")
        finding = result.to_finding()
        self.assertIsNone(finding)


class TestTemplateEngine(unittest.TestCase):
    def test_engine_loads(self):
        engine = TemplateEngine()
        self.assertIsNotNone(engine)

    def test_filter_templates(self):
        engine = TemplateEngine()
        templates = engine.filter_templates()
        self.assertIsInstance(templates, list)


if __name__ == "__main__":
    unittest.main()
