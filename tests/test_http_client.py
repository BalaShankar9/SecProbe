"""Tests for secprobe.core.http_client — HTTPClient and config."""

import unittest
from unittest.mock import patch, MagicMock
from secprobe.core.http_client import HTTPClientConfig, HTTPClient


class TestHTTPClientConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = HTTPClientConfig()
        self.assertEqual(cfg.timeout, 15)
        self.assertFalse(cfg.verify_ssl)
        self.assertIsNone(cfg.proxy)
        self.assertEqual(cfg.max_retries, 3)

    def test_custom_config(self):
        cfg = HTTPClientConfig(timeout=30, verify_ssl=False, proxy="http://proxy:8080")
        self.assertEqual(cfg.timeout, 30)
        self.assertFalse(cfg.verify_ssl)
        self.assertEqual(cfg.proxy, "http://proxy:8080")


class TestHTTPClient(unittest.TestCase):
    def test_create_client(self):
        cfg = HTTPClientConfig(timeout=5)
        client = HTTPClient(cfg)
        self.assertIsNotNone(client)
        self.assertIsNotNone(client._session)

    def test_client_has_session(self):
        client = HTTPClient(HTTPClientConfig())
        import requests
        self.assertIsInstance(client._session, requests.Session)

    def test_set_waf_detector(self):
        client = HTTPClient(HTTPClientConfig())
        mock_waf = MagicMock()
        client.set_waf_detector(mock_waf)
        self.assertEqual(client._waf_detector, mock_waf)

    def test_close(self):
        client = HTTPClient(HTTPClientConfig())
        client.close()  # Should not raise

    def test_context_manager(self):
        cfg = HTTPClientConfig()
        with HTTPClient(cfg) as client:
            self.assertIsNotNone(client._session)


if __name__ == "__main__":
    unittest.main()
