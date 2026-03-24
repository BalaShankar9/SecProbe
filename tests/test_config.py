"""Tests for secprobe.config — ScanConfig, Severity, constants."""

import unittest
from secprobe.config import ScanConfig, Severity, COMMON_PORTS, SECURITY_HEADERS


class TestSeverity(unittest.TestCase):
    def test_severity_levels_exist(self):
        self.assertTrue(hasattr(Severity, "CRITICAL"))
        self.assertTrue(hasattr(Severity, "HIGH"))
        self.assertTrue(hasattr(Severity, "MEDIUM"))
        self.assertTrue(hasattr(Severity, "LOW"))
        self.assertTrue(hasattr(Severity, "INFO"))


class TestScanConfig(unittest.TestCase):
    def test_default_config(self):
        cfg = ScanConfig(target="http://example.com")
        self.assertEqual(cfg.target, "http://example.com")

    def test_config_attributes(self):
        cfg = ScanConfig(target="http://test.com")
        # Should have common attributes
        self.assertTrue(hasattr(cfg, "target"))


class TestConstants(unittest.TestCase):
    def test_common_ports(self):
        self.assertIsInstance(COMMON_PORTS, (list, dict, set, tuple))
        self.assertTrue(len(COMMON_PORTS) > 0)

    def test_security_headers(self):
        self.assertIsInstance(SECURITY_HEADERS, (list, dict, set, tuple))
        self.assertTrue(len(SECURITY_HEADERS) > 0)


if __name__ == "__main__":
    unittest.main()
