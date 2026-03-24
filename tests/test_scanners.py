"""Tests for secprobe.scanners — registry and scanner instantiation."""

import unittest
from unittest.mock import MagicMock, patch
from secprobe.scanners import SCANNER_REGISTRY, BaseScanner
from secprobe.config import ScanConfig
from secprobe.core.context import ScanContext


class TestScannerRegistry(unittest.TestCase):
    def test_all_scanners_registered(self):
        expected = {
            "ports", "ssl", "headers", "sqli", "xss", "dirs",
            "dns", "cookies", "cors", "tech",
            "ssrf", "ssti", "cmdi", "redirect", "jwt",
            "lfi", "xxe", "nosql", "hostheader", "csrf", "smuggling",
            "api", "graphql", "websocket",
            "upload", "deser", "oauth", "race", "ldap", "xpath", "crlf", "hpp",
            "js", "cve", "takeover", "domxss", "idor", "wafid", "email",
            "bizlogic", "prototype", "cloud", "fuzz", "passive",
            "cachepoisoning",
        }
        self.assertEqual(set(SCANNER_REGISTRY.keys()), expected)

    def test_registry_count(self):
        self.assertEqual(len(SCANNER_REGISTRY), 45)

    def test_all_subclass_base_scanner(self):
        for name, cls in SCANNER_REGISTRY.items():
            self.assertTrue(
                issubclass(cls, BaseScanner),
                f"{name} -> {cls.__name__} is not a BaseScanner subclass",
            )

    def test_all_have_name_and_description(self):
        for key, cls in SCANNER_REGISTRY.items():
            self.assertTrue(hasattr(cls, "name"), f"{key} missing name")
            self.assertTrue(hasattr(cls, "description"), f"{key} missing description")
            self.assertTrue(len(cls.name) > 0, f"{key} has empty name")
            self.assertTrue(len(cls.description) > 0, f"{key} has empty description")

    def test_all_scanners_instantiate(self):
        config = ScanConfig(target="http://example.com")
        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client)
        for key, cls in SCANNER_REGISTRY.items():
            try:
                scanner = cls(config, ctx)
                self.assertIsNotNone(scanner)
            except Exception as e:
                self.fail(f"Failed to instantiate {key} ({cls.__name__}): {e}")

    def test_all_scanners_have_scan_method(self):
        for key, cls in SCANNER_REGISTRY.items():
            self.assertTrue(
                callable(getattr(cls, "scan", None)),
                f"{key} -> {cls.__name__} has no scan() method",
            )


class TestScannerHTTPClientAccess(unittest.TestCase):
    """Verify scanners that need HTTP use the shared client."""

    def test_http_scanners_use_context_client(self):
        http_scanners = ["headers", "cookies", "cors", "sqli", "xss", "dirs", "tech",
                         "ssrf", "ssti", "cmdi", "redirect", "jwt"]
        config = ScanConfig(target="http://example.com")
        mock_client = MagicMock()
        ctx = ScanContext(http_client=mock_client)

        for key in http_scanners:
            cls = SCANNER_REGISTRY[key]
            scanner = cls(config, ctx)
            self.assertEqual(scanner.http_client, mock_client,
                             f"{key} does not use context's http_client")


if __name__ == "__main__":
    unittest.main()
