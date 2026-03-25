import pytest
from secprobe.core.js_endpoint_extractor import JSEndpointExtractor


class TestJSEndpointExtractor:
    def setup_method(self):
        self.extractor = JSEndpointExtractor()

    def test_extract_fetch_calls(self):
        js = """fetch("/api/products")\nfetch('/rest/user/login', {method: 'POST'})\nfetch('/api/users/' + userId)"""
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/api/products" in paths
        assert "/rest/user/login" in paths

    def test_extract_axios_calls(self):
        js = """axios.get("/api/orders")\naxios.post("/api/cart", data)\naxios("/api/reviews")"""
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/api/orders" in paths
        assert "/api/cart" in paths

    def test_extract_xhr_calls(self):
        js = """xhr.open("GET", "/api/users")\nxhr.open('POST', '/rest/products/search')"""
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/api/users" in paths
        assert "/rest/products/search" in paths

    def test_extract_string_literals(self):
        js = """const API_BASE = "/rest/products"\nvar endpoint = '/api/v1/challenges'\nlet url = "/graphql" """
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/rest/products" in paths
        assert "/api/v1/challenges" in paths

    def test_extract_angular_routes(self):
        js = """{path: 'search', component: SearchComponent}\n{path: 'login', component: LoginComponent}"""
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert any("search" in p for p in paths)

    def test_ignore_static_assets(self):
        js = """fetch("/assets/logo.png")\nfetch("/styles/main.css")\nfetch("/favicon.ico")"""
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/assets/logo.png" not in paths
        assert "/styles/main.css" not in paths

    def test_extract_from_html_script_tags(self):
        html = '<script>fetch("/api/products")</script><script src="/main.js"></script>'
        endpoints = self.extractor.extract_from_html(html)
        assert len(endpoints) >= 1

    def test_empty_input(self):
        endpoints = self.extractor.extract("")
        assert endpoints == []

    def test_extract_jquery(self):
        js = """$.get("/api/data")\n$.post("/api/submit", payload)"""
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/api/data" in paths or "/api/submit" in paths

    def test_method_detection(self):
        js = """fetch('/api/users', {method: 'POST'})"""
        endpoints = self.extractor.extract(js)
        post_endpoints = [e for e in endpoints if e.method == "POST"]
        assert len(post_endpoints) >= 1
