"""Tests for secprobe.core.exceptions — exception hierarchy."""

import unittest
from secprobe.core.exceptions import (
    SecProbeError,
    TargetUnreachableError,
    AuthenticationError,
    WAFBlockedError,
    ScannerError,
    PayloadLoadError,
    ScanTimeoutError,
    CrawlerError,
    TemplateError,
    TemplateParseError,
    TemplateExecutionError,
)


class TestExceptionHierarchy(unittest.TestCase):
    def test_base_error(self):
        e = SecProbeError("test")
        self.assertIsInstance(e, Exception)
        self.assertEqual(str(e), "test")

    def test_target_unreachable(self):
        e = TargetUnreachableError("http://bad.test")
        self.assertIsInstance(e, SecProbeError)

    def test_auth_error(self):
        e = AuthenticationError("bad creds")
        self.assertIsInstance(e, SecProbeError)

    def test_waf_blocked(self):
        e = WAFBlockedError("Cloudflare")
        self.assertIsInstance(e, SecProbeError)

    def test_scanner_error_subclasses(self):
        self.assertTrue(issubclass(PayloadLoadError, ScannerError))
        self.assertTrue(issubclass(ScanTimeoutError, ScannerError))
        self.assertTrue(issubclass(ScannerError, SecProbeError))

    def test_crawler_error(self):
        e = CrawlerError("depth exceeded")
        self.assertIsInstance(e, SecProbeError)

    def test_template_error_subclasses(self):
        self.assertTrue(issubclass(TemplateParseError, TemplateError))
        self.assertTrue(issubclass(TemplateExecutionError, TemplateError))
        self.assertTrue(issubclass(TemplateError, SecProbeError))


if __name__ == "__main__":
    unittest.main()
