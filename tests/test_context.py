"""Tests for secprobe.core.context — ScanContext DI container."""

import unittest
from unittest.mock import MagicMock
from secprobe.core.context import ScanContext


class TestScanContext(unittest.TestCase):
    def test_create_empty_context(self):
        ctx = ScanContext(http_client=MagicMock())
        self.assertIsNotNone(ctx.http_client)
        self.assertIsNone(ctx.auth_handler)
        self.assertIsNone(ctx.waf_detector)
        self.assertIsNone(ctx.attack_surface)

    def test_get_injection_urls_no_surface(self):
        ctx = ScanContext(http_client=MagicMock())
        self.assertEqual(ctx.get_injection_urls(), [])

    def test_get_injectable_forms_no_surface(self):
        ctx = ScanContext(http_client=MagicMock())
        self.assertEqual(ctx.get_injectable_forms(), [])

    def test_get_crawled_urls_no_surface(self):
        ctx = ScanContext(http_client=MagicMock())
        self.assertEqual(ctx.get_crawled_urls(), [])

    def test_get_injection_urls_with_surface(self):
        surface = MagicMock()
        surface.urls = ["http://test.com/page?id=1", "http://test.com/about"]
        ctx = ScanContext(http_client=MagicMock(), attack_surface=surface)
        urls = ctx.get_injection_urls()
        self.assertIn("http://test.com/page?id=1", urls)

    def test_get_injectable_forms_with_surface(self):
        surface = MagicMock()
        mock_form = MagicMock()
        mock_form.action = "http://test.com/login"
        mock_form.method = "POST"
        mock_form.fields = {"user": "", "pass": ""}
        surface.forms = [mock_form]
        ctx = ScanContext(http_client=MagicMock(), attack_surface=surface)
        forms = ctx.get_injectable_forms()
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "http://test.com/login")

    def test_discovered_urls_runtime(self):
        ctx = ScanContext(http_client=MagicMock())
        ctx.discovered_urls.append("http://test.com/new")
        self.assertIn("http://test.com/new", ctx.discovered_urls)

    def test_full_context(self):
        ctx = ScanContext(
            http_client=MagicMock(),
            auth_handler=MagicMock(),
            waf_detector=MagicMock(),
            attack_surface=MagicMock(),
        )
        self.assertIsNotNone(ctx.auth_handler)
        self.assertIsNotNone(ctx.waf_detector)
        self.assertIsNotNone(ctx.attack_surface)


if __name__ == "__main__":
    unittest.main()
