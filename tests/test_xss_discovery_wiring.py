import pytest
from unittest.mock import MagicMock
from secprobe.scanners.xss_scanner import XSSScanner
from secprobe.config import ScanConfig
from secprobe.core.crawler import AttackSurface, Endpoint


class TestXSSEndpointWiring:
    def test_scanner_uses_discovered_endpoints(self):
        config = ScanConfig(target="http://example.com")
        context = MagicMock()
        surface = AttackSurface()
        surface.endpoints.append(Endpoint(
            url="http://example.com/search",
            method="GET",
            params={"q": "test"},
            source="js_analysis",
        ))
        surface.urls.add("http://example.com/search?q=test")
        context.attack_surface = surface
        context.get_injection_urls.return_value = list(surface.urls)

        scanner = XSSScanner(config, context)
        urls = scanner._get_injectable_urls()
        assert any("/search" in u for u in urls)

    def test_reflection_detection_present(self):
        config = ScanConfig(target="http://example.com")
        scanner = XSSScanner(config)
        payload = "secprobe_xss_test_12345"
        response = f'<html><body>Search results for: {payload}</body></html>'
        assert scanner._check_reflection(payload, response) is True

    def test_reflection_detection_absent(self):
        config = ScanConfig(target="http://example.com")
        scanner = XSSScanner(config)
        payload = "secprobe_xss_test_12345"
        response = '<html><body>Search results for: hello</body></html>'
        assert scanner._check_reflection(payload, response) is False

    def test_reflection_detection_encoded(self):
        config = ScanConfig(target="http://example.com")
        scanner = XSSScanner(config)
        payload = '<img src=x onerror=alert(1)>'
        # HTML-encoded version of the payload in response
        response = '<html>&lt;img src=x onerror=alert(1)&gt;</html>'
        # Should detect HTML-encoded reflection too
        assert scanner._check_reflection(payload, response) is True
