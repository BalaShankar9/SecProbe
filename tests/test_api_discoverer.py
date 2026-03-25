import pytest
from secprobe.core.api_discoverer import APIDiscoverer, DiscoveredAPI


class TestAPIDiscoverer:
    def setup_method(self):
        self.discoverer = APIDiscoverer()

    def test_probe_paths_loaded(self):
        paths = self.discoverer.get_probe_paths()
        assert len(paths) > 100
        assert "/api/users" in paths or "/api/v1/users" in paths
        assert "/swagger.json" in paths
        assert "/graphql" in paths

    def test_classify_status_code(self):
        assert self.discoverer.is_interesting_status(200) is True
        assert self.discoverer.is_interesting_status(301) is True
        assert self.discoverer.is_interesting_status(401) is True
        assert self.discoverer.is_interesting_status(403) is True
        assert self.discoverer.is_interesting_status(404) is False
        assert self.discoverer.is_interesting_status(500) is True

    def test_parse_openapi_spec(self):
        swagger = {
            "paths": {
                "/api/products": {"get": {}, "post": {}},
                "/api/users/{id}": {"get": {}, "put": {}, "delete": {}},
            }
        }
        endpoints = self.discoverer.parse_openapi(swagger)
        assert len(endpoints) >= 4
        urls = {e.url for e in endpoints}
        assert "/api/products" in urls
        assert "/api/users/{id}" in urls

    def test_parse_empty_openapi(self):
        endpoints = self.discoverer.parse_openapi({})
        assert endpoints == []

    def test_swagger_discovery_paths(self):
        paths = self.discoverer.get_swagger_paths()
        assert "/swagger.json" in paths
        assert "/openapi.json" in paths
        assert "/api-docs" in paths

    def test_methods_from_openapi(self):
        swagger = {"paths": {"/api/test": {"get": {}, "post": {}, "delete": {}}}}
        endpoints = self.discoverer.parse_openapi(swagger)
        methods = {e.method for e in endpoints if e.url == "/api/test"}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods
