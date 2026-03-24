"""Integration test — validates the full pipeline wires up without errors."""

import unittest
from unittest.mock import MagicMock, patch
from secprobe.config import ScanConfig
from secprobe.core.context import ScanContext
from secprobe.core.http_client import HTTPClient, HTTPClientConfig
from secprobe.scanners import SCANNER_REGISTRY


class TestPipelineIntegration(unittest.TestCase):
    """Test that the full scan pipeline initializes correctly."""

    def test_context_to_scanner_wiring(self):
        """Context -> BaseScanner -> http_client property chain."""
        cfg = HTTPClientConfig(timeout=5)
        client = HTTPClient(cfg)
        ctx = ScanContext(http_client=client)
        scan_config = ScanConfig(target="http://example.com")

        for name, cls in SCANNER_REGISTRY.items():
            scanner = cls(scan_config, ctx)
            self.assertEqual(scanner.http_client, client,
                             f"{name} scanner doesn't reference shared client")

        client.close()

    def test_scanner_run_without_network(self):
        """All scanners should handle TargetUnreachableError gracefully."""
        mock_client = MagicMock()
        from secprobe.core.exceptions import TargetUnreachableError
        mock_client.get.side_effect = TargetUnreachableError("mock unreachable")
        mock_client.post.side_effect = TargetUnreachableError("mock unreachable")
        mock_client.options.side_effect = TargetUnreachableError("mock unreachable")

        ctx = ScanContext(http_client=mock_client)
        scan_config = ScanConfig(target="http://unreachable.test")

        # Only test HTTP-based scanners (skip dns, port, ssl which use sockets)
        http_scanners = ["headers", "cookies", "cors", "tech",
                         "ssrf", "ssti", "cmdi", "redirect", "jwt"]

        for name in http_scanners:
            cls = SCANNER_REGISTRY[name]
            scanner = cls(scan_config, ctx)
            try:
                result = scanner.run()
                self.assertIsNotNone(result, f"{name} returned None")
            except Exception as e:
                self.fail(f"{name} scanner crashed: {e}")

    def test_all_scanners_return_scan_result(self):
        """Every scanner.run() must return a ScanResult instance."""
        from secprobe.models import ScanResult
        mock_client = MagicMock()
        # Return a mock response for any HTTP call
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Test</body></html>"
        mock_resp.headers = {}
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.items.return_value = []
        mock_resp.cookies.__iter__ = MagicMock(return_value=iter([]))
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp
        mock_client.options.return_value = mock_resp
        mock_client.session = MagicMock()
        mock_client.session.cookies = MagicMock()
        mock_client.session.cookies.__iter__ = MagicMock(return_value=iter([]))
        mock_client.session.cookies.items.return_value = []

        ctx = ScanContext(http_client=mock_client)
        scan_config = ScanConfig(target="http://example.com")

        http_scanners = ["headers", "cookies", "cors", "tech", "jwt"]
        for name in http_scanners:
            cls = SCANNER_REGISTRY[name]
            scanner = cls(scan_config, ctx)
            result = scanner.run()
            self.assertIsInstance(result, ScanResult, f"{name} didn't return ScanResult")

    def test_payload_files_load(self):
        """Payload files should load without errors."""
        try:
            from secprobe.payloads import load_payloads
            sqli = load_payloads("sqli")
            self.assertTrue(len(sqli) > 0, "SQLi payloads empty")
            xss = load_payloads("xss")
            self.assertTrue(len(xss) > 0, "XSS payloads empty")
            dirs = load_payloads("directories")
            self.assertTrue(len(dirs) > 0, "Directory payloads empty")
            subs = load_payloads("subdomains")
            self.assertTrue(len(subs) > 0, "Subdomain payloads empty")
        except ImportError:
            self.skipTest("Payloads module not available")

    def test_analysis_modules_import(self):
        """Analysis modules should import cleanly."""
        from secprobe.analysis import attack_chain, compliance, dedup
        self.assertTrue(hasattr(attack_chain, "AttackChainAnalyzer") or callable(getattr(attack_chain, "analyze_chains", None)))


if __name__ == "__main__":
    unittest.main()
