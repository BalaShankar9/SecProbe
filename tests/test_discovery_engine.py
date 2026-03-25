"""Tests for the unified discovery engine (Task 3)."""

import asyncio
import pytest
from unittest.mock import MagicMock

from secprobe.core.discovery_engine import DiscoveryEngine, DiscoveryConfig
from secprobe.core.crawler import AttackSurface, Endpoint


class TestDiscoveryConfig:
    def test_config_defaults(self):
        config = DiscoveryConfig(target="http://example.com")
        assert config.enable_js_analysis is True
        assert config.enable_api_brute is True
        assert config.enable_browser is False
        assert config.max_api_probes == 500

    def test_config_custom(self):
        config = DiscoveryConfig(
            target="http://example.com",
            enable_js_analysis=False,
            crawl_depth=5,
            timeout=30.0,
        )
        assert config.enable_js_analysis is False
        assert config.crawl_depth == 5
        assert config.timeout == 30.0


class TestMergeSurfaces:
    def test_merge_surfaces_deduplicates(self):
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        s1 = AttackSurface()
        s1.urls.add("http://example.com/api/users")
        s1.endpoints.append(Endpoint(url="http://example.com/api/users", method="GET"))

        s2 = AttackSurface()
        s2.urls.add("http://example.com/api/products")
        s2.urls.add("http://example.com/api/users")  # Duplicate
        s2.endpoints.append(Endpoint(url="http://example.com/api/products", method="GET"))
        s2.endpoints.append(Endpoint(url="http://example.com/api/users", method="GET"))  # Dup

        merged = engine.merge_surfaces([s1, s2])
        assert len(merged.urls) == 2
        # Endpoints should be deduped by method:url
        endpoint_keys = {f"{e.method}:{e.url}" for e in merged.endpoints}
        assert len(endpoint_keys) == 2

    def test_merge_preserves_forms(self):
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        s1 = AttackSurface()
        s1.forms.append({"action": "/login", "method": "POST"})
        merged = engine.merge_surfaces([s1])
        assert len(merged.forms) == 1

    def test_empty_merge(self):
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        merged = engine.merge_surfaces([])
        assert len(merged.urls) == 0
        assert len(merged.endpoints) == 0

    def test_merge_deduplicates_parameters(self):
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        s1 = AttackSurface()
        s1.parameters.add("username")
        s1.parameters.add("password")
        s2 = AttackSurface()
        s2.parameters.add("username")  # Duplicate
        s2.parameters.add("token")
        merged = engine.merge_surfaces([s1, s2])
        assert merged.parameters == {"username", "password", "token"}

    def test_merge_combines_js_files(self):
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        s1 = AttackSurface()
        s1.js_files.add("http://example.com/app.js")
        s2 = AttackSurface()
        s2.js_files.add("http://example.com/vendor.js")
        s2.js_files.add("http://example.com/app.js")  # Duplicate
        merged = engine.merge_surfaces([s1, s2])
        assert len(merged.js_files) == 2


class TestEndpointsToSurface:
    def test_endpoints_to_surface(self):
        from secprobe.core.js_endpoint_extractor import DiscoveredEndpoint
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        endpoints = [
            DiscoveredEndpoint(url="/api/users", method="GET"),
            DiscoveredEndpoint(url="/api/products", method="POST", params={"name": "test"}),
        ]
        surface = engine.endpoints_to_surface("http://example.com", endpoints)
        assert len(surface.endpoints) == 2
        assert len(surface.urls) == 2
        assert "name" in surface.parameters

    def test_endpoints_to_surface_resolves_relative_urls(self):
        from secprobe.core.js_endpoint_extractor import DiscoveredEndpoint
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        endpoints = [
            DiscoveredEndpoint(url="/api/users", method="GET"),
        ]
        surface = engine.endpoints_to_surface("http://example.com", endpoints)
        full_urls = list(surface.urls)
        assert full_urls[0] == "http://example.com/api/users"

    def test_endpoints_to_surface_absolute_urls(self):
        from secprobe.core.js_endpoint_extractor import DiscoveredEndpoint
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        endpoints = [
            DiscoveredEndpoint(url="http://example.com/api/data", method="GET"),
        ]
        surface = engine.endpoints_to_surface("http://example.com", endpoints)
        assert "http://example.com/api/data" in surface.urls

    def test_endpoints_to_surface_empty(self):
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        surface = engine.endpoints_to_surface("http://example.com", [])
        assert len(surface.endpoints) == 0
        assert len(surface.urls) == 0


class TestDiscoverAsync:
    def test_discover_returns_attack_surface(self):
        """discover() should return an AttackSurface even with all layers disabled."""
        config = DiscoveryConfig(
            target="http://example.com",
            enable_html_crawl=False,
            enable_js_analysis=False,
            enable_api_brute=False,
            enable_browser=False,
        )
        engine = DiscoveryEngine(config)
        mock_client = MagicMock()
        result = asyncio.run(engine.discover(mock_client))
        assert isinstance(result, AttackSurface)

    def test_discover_js_layer(self):
        """JS analysis layer should extract endpoints from fetched HTML."""
        config = DiscoveryConfig(
            target="http://example.com",
            enable_html_crawl=False,
            enable_js_analysis=True,
            enable_api_brute=False,
            enable_browser=False,
        )
        engine = DiscoveryEngine(config)

        mock_resp = MagicMock()
        mock_resp.text = '<html><script>fetch("/api/users")</script></html>'
        mock_resp.status_code = 200

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        result = asyncio.run(engine.discover(mock_client))
        # Should have found the /api/users endpoint from inline JS
        found_urls = {e.url for e in result.endpoints}
        assert any("/api/users" in u for u in found_urls)

    def test_discover_layer_failure_doesnt_block(self):
        """One layer failing should not prevent others from running."""
        config = DiscoveryConfig(
            target="http://example.com",
            enable_html_crawl=False,
            enable_js_analysis=True,
            enable_api_brute=False,
            enable_browser=False,
        )
        engine = DiscoveryEngine(config)

        mock_client = MagicMock()
        mock_client.get.side_effect = Exception("Network error")

        # Should not raise, should return empty surface
        result = asyncio.run(engine.discover(mock_client))
        assert isinstance(result, AttackSurface)
