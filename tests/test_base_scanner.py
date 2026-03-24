"""Tests for secprobe.scanners.base — BaseScanner ABC."""

import unittest
from unittest.mock import MagicMock
from secprobe.scanners.base import BaseScanner
from secprobe.core.context import ScanContext
from secprobe.config import ScanConfig, Severity
from secprobe.models import ScanResult


class ConcreteScanner(BaseScanner):
    """Minimal concrete implementation for testing."""
    name = "Test Scanner"
    description = "A test scanner"

    def scan(self):
        self.add_finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Found something",
            recommendation="Fix it",
            evidence="evidence here",
            category="Test",
            url="http://test.com",
            cwe="CWE-001",
        )


class ErrorScanner(BaseScanner):
    """Scanner that raises an exception."""
    name = "Error Scanner"
    description = "Always errors"

    def scan(self):
        raise RuntimeError("boom")


class TestBaseScanner(unittest.TestCase):
    def _make_config(self, target="http://example.com"):
        return ScanConfig(target=target)

    def test_init_without_context(self):
        config = self._make_config()
        scanner = ConcreteScanner(config)
        self.assertEqual(scanner.config, config)
        self.assertIsNone(scanner.context)
        self.assertIsInstance(scanner.result, ScanResult)

    def test_init_with_context(self):
        config = self._make_config()
        ctx = ScanContext(http_client=MagicMock())
        scanner = ConcreteScanner(config, ctx)
        self.assertEqual(scanner.context, ctx)

    def test_http_client_from_context(self):
        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client)
        scanner = ConcreteScanner(self._make_config(), ctx)
        self.assertEqual(scanner.http_client, mock_client)

    def test_http_client_without_context(self):
        scanner = ConcreteScanner(self._make_config())
        # Without context, http_client returns None
        client = scanner.http_client
        self.assertIsNone(client)

    def test_attack_surface_from_context(self):
        mock_surface = MagicMock()
        ctx = ScanContext(http_client=MagicMock(), attack_surface=mock_surface)
        scanner = ConcreteScanner(self._make_config(), ctx)
        self.assertEqual(scanner.attack_surface, mock_surface)

    def test_waf_detected_false_by_default(self):
        ctx = ScanContext(http_client=MagicMock())
        scanner = ConcreteScanner(self._make_config(), ctx)
        self.assertFalse(scanner.waf_detected)

    def test_waf_detected_true(self):
        ctx = ScanContext(http_client=MagicMock(), waf_detector=MagicMock())
        ctx.waf_name = "Cloudflare"
        scanner = ConcreteScanner(self._make_config(), ctx)
        self.assertTrue(scanner.waf_detected)

    def test_add_finding(self):
        scanner = ConcreteScanner(self._make_config())
        scanner.scan()
        self.assertEqual(len(scanner.result.findings), 1)
        f = scanner.result.findings[0]
        self.assertEqual(f.title, "Test Finding")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.cwe, "CWE-001")
        self.assertEqual(f.url, "http://test.com")
        self.assertEqual(f.scanner, "Test Scanner")

    def test_run_catches_exceptions(self):
        scanner = ErrorScanner(self._make_config())
        result = scanner.run()
        # Should not raise, should return result with error
        self.assertIsInstance(result, ScanResult)

    def test_run_returns_result(self):
        scanner = ConcreteScanner(self._make_config())
        result = scanner.run()
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.finding_count["HIGH"], 1)


if __name__ == "__main__":
    unittest.main()
