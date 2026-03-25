"""Tests for SQLi scanner endpoint discovery wiring and UNION detection."""

import pytest
from unittest.mock import MagicMock
from secprobe.scanners.sqli_scanner import SQLiScanner
from secprobe.config import ScanConfig
from secprobe.core.crawler import AttackSurface, Endpoint


class TestSQLiEndpointWiring:
    def test_scanner_uses_discovered_endpoints(self):
        config = ScanConfig(target="http://example.com")
        context = MagicMock()
        surface = AttackSurface()
        surface.endpoints.append(Endpoint(
            url="http://example.com/rest/products/search",
            method="GET",
            params={"q": "test"},
            source="js_analysis",
        ))
        surface.urls.add("http://example.com/rest/products/search?q=test")
        context.attack_surface = surface
        context.get_injection_urls.return_value = list(surface.urls)

        scanner = SQLiScanner(config, context)
        urls = scanner._get_injectable_urls()
        assert any("/rest/products/search" in u for u in urls)

    def test_scanner_includes_root_target(self):
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        urls = scanner._get_injectable_urls()
        assert "http://example.com" in urls

    def test_scanner_deduplicates_urls(self):
        config = ScanConfig(target="http://example.com/api?q=test")
        context = MagicMock()
        surface = AttackSurface()
        surface.endpoints.append(Endpoint(
            url="http://example.com/api",
            method="GET",
            params={"q": "test"},
            source="js_analysis",
        ))
        surface.urls.add("http://example.com/api?q=test")
        context.attack_surface = surface
        context.get_injection_urls.return_value = list(surface.urls)

        scanner = SQLiScanner(config, context)
        urls = scanner._get_injectable_urls()
        # Should not have duplicate entries
        assert len(urls) == len(set(urls))


class TestUnionDetection:
    def test_union_detection_sequential(self):
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        # UNION SELECT 1,2,3,4,5,6,7,8,9 returned as field values
        response_text = '{"data":[{"id":1,"name":"2","description":"3","price":4,"deluxePrice":5,"image":"6","createdAt":"7","updatedAt":"8","deletedAt":"9"}]}'
        assert scanner._detect_union_response(response_text, columns=9) is True

    def test_union_detection_no_match(self):
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        response_text = '{"data":[{"id":42,"name":"Apple Juice","price":1.99}]}'
        assert scanner._detect_union_response(response_text, columns=9) is False

    def test_union_detection_nested_data(self):
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        response_text = '{"results":{"items":[{"a":1,"b":"2","c":"3","d":4}]}}'
        assert scanner._detect_union_response(response_text, columns=5) is True

    def test_union_detection_invalid_json_with_pattern(self):
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        # Fallback to raw text matching
        response_text = 'not json "1","2","3","4","5"'
        assert scanner._detect_union_response(response_text, columns=9) is True

    def test_union_detection_invalid_json_no_pattern(self):
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        response_text = 'not json at all, no sequential ints'
        assert scanner._detect_union_response(response_text, columns=9) is False
