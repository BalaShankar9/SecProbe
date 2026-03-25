# Phase 1: Unbeatable Detection Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Achieve 80%+ detection rate on OWASP Juice Shop (100+ known vulns) by fixing endpoint discovery, scanner-to-endpoint wiring, and injection detection.

**Architecture:** 4-layer endpoint discovery (HTML + JS analysis + API brute-force + browser interception) feeds a unified AttackSurface into all 48 scanners. Each scanner receives discovered endpoints instead of just the root URL. A benchmark suite tracks detection rate per commit.

**Tech Stack:** Python 3.10+, httpx (async HTTP), Playwright (browser), SQLite (benchmark tracking), pytest

**Spec:** `docs/superpowers/specs/2026-03-25-secprobe-world-class-platform-design.md`

---

## File Structure

### New files
| File | Responsibility |
|------|---------------|
| `secprobe/core/js_endpoint_extractor.py` | Parse JavaScript files to extract API endpoints, fetch/axios calls, router definitions |
| `secprobe/core/api_discoverer.py` | Brute-force common API paths, Swagger/OpenAPI auto-discovery |
| `secprobe/core/discovery_engine.py` | Orchestrate all 4 discovery layers into unified AttackSurface |
| `secprobe/payloads/api_paths.txt` | 2000+ common API paths wordlist |
| `secprobe/benchmark/__init__.py` | Benchmark package |
| `secprobe/benchmark/runner.py` | Orchestrate benchmark runs against Docker targets |
| `secprobe/benchmark/juice_shop.py` | Map SecProbe findings to Juice Shop challenge list |
| `secprobe/benchmark/report.py` | Detection rate calculation and reporting |
| `tests/test_js_extractor.py` | Tests for JS endpoint extraction |
| `tests/test_api_discoverer.py` | Tests for API path discovery |
| `tests/test_discovery_engine.py` | Tests for unified discovery orchestration |
| `tests/test_benchmark.py` | Tests for benchmark suite |

### Modified files
| File | What changes |
|------|-------------|
| `secprobe/core/crawler.py` | Add `discover_all()` method that calls discovery engine |
| `secprobe/scanners/base.py` | Add `get_target_urls()` helper that returns discovered endpoints for this scanner's attack types |
| `secprobe/scanners/sqli_scanner.py` | Use discovered endpoints instead of root URL; fix UNION detection |
| `secprobe/scanners/xss_scanner.py` | Use discovered endpoints; add reflection-based detection |
| `secprobe/core/scan_session.py` | Always run discovery before active scanning; pass AttackSurface |
| `secprobe/cli.py` | Auto-enable discovery when running injection scanners |

---

## Task 1: JavaScript Endpoint Extractor

**Files:**
- Create: `secprobe/core/js_endpoint_extractor.py`
- Create: `tests/test_js_extractor.py`

- [ ] **Step 1: Write failing tests for JS extraction**

```python
# tests/test_js_extractor.py
import pytest
from secprobe.core.js_endpoint_extractor import JSEndpointExtractor


class TestJSEndpointExtractor:
    def setup_method(self):
        self.extractor = JSEndpointExtractor()

    def test_extract_fetch_calls(self):
        js = '''
        fetch("/api/products")
        fetch('/rest/user/login', {method: 'POST'})
        fetch(`/api/users/${userId}`)
        '''
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/api/products" in paths
        assert "/rest/user/login" in paths

    def test_extract_axios_calls(self):
        js = '''
        axios.get("/api/orders")
        axios.post("/api/cart", data)
        axios("/api/reviews")
        '''
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/api/orders" in paths
        assert "/api/cart" in paths

    def test_extract_xhr_calls(self):
        js = '''
        xhr.open("GET", "/api/users")
        xhr.open('POST', '/rest/products/search')
        '''
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/api/users" in paths
        assert "/rest/products/search" in paths

    def test_extract_string_literals(self):
        js = '''
        const API_BASE = "/rest/products"
        var endpoint = '/api/v1/challenges'
        let url = "/graphql"
        '''
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/rest/products" in paths
        assert "/api/v1/challenges" in paths
        assert "/graphql" in paths

    def test_extract_angular_routes(self):
        js = '''
        {path: 'search', component: SearchComponent}
        {path: 'login', component: LoginComponent}
        '''
        endpoints = self.extractor.extract(js)
        paths = {e.url for e in endpoints}
        assert "/search" in paths or "search" in paths

    def test_ignore_non_api_paths(self):
        js = '''
        fetch("/assets/logo.png")
        fetch("/styles/main.css")
        fetch("/favicon.ico")
        '''
        endpoints = self.extractor.extract(js)
        # Static assets should be filtered out
        paths = {e.url for e in endpoints}
        assert "/assets/logo.png" not in paths
        assert "/styles/main.css" not in paths

    def test_extract_from_html_script_tags(self):
        html = '''
        <script>fetch("/api/products")</script>
        <script src="/main.js"></script>
        '''
        scripts = self.extractor.extract_from_html(html)
        assert len(scripts) >= 1

    def test_empty_input(self):
        endpoints = self.extractor.extract("")
        assert endpoints == []

    def test_extract_with_query_params(self):
        js = '''fetch("/rest/products/search?q=test")'''
        endpoints = self.extractor.extract(js)
        assert len(endpoints) >= 1
        assert "q" in endpoints[0].params or "search" in endpoints[0].url
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_js_extractor.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'secprobe.core.js_endpoint_extractor'`

- [ ] **Step 3: Implement JSEndpointExtractor**

Create `secprobe/core/js_endpoint_extractor.py`:

```python
"""
JavaScript endpoint extraction engine.

Parses JavaScript source code and HTML to discover API endpoints,
fetch/axios/XHR calls, route definitions, and hardcoded paths.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# Static asset extensions to filter out
_STATIC_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".map", ".br", ".gz",
})

# Patterns that indicate API paths (kept broad intentionally)
_API_PATH_INDICATORS = re.compile(
    r"^/(?:api|rest|graphql|v[0-9]|ws|socket|auth|oauth|login|register|"
    r"admin|user|account|product|order|cart|search|upload|download|webhook|"
    r"callback|token|session|config|setting|dashboard|report|export|import|"
    r"notification|message|comment|review|challenge|score|flag|"
    r"\.well-known)/?"
, re.IGNORECASE)


@dataclass
class DiscoveredEndpoint:
    """An endpoint discovered from JavaScript analysis."""
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    source: str = "js_analysis"
    confidence: float = 0.8

    def __hash__(self):
        return hash((self.url, self.method))

    def __eq__(self, other):
        if not isinstance(other, DiscoveredEndpoint):
            return NotImplemented
        return self.url == other.url and self.method == other.method


class JSEndpointExtractor:
    """Extract API endpoints from JavaScript source code."""

    # ── Regex patterns for common HTTP call patterns ──────────────

    # fetch("/path") or fetch('/path') or fetch(`/path`)
    _RE_FETCH = re.compile(
        r"""fetch\s*\(\s*[`'"](\/[^`'"{\s]+)[`'"]\s*(?:,\s*\{[^}]*method\s*:\s*['"](\w+)['"])?""",
        re.IGNORECASE,
    )

    # axios.get/post/put/delete("/path") or axios("/path")
    _RE_AXIOS = re.compile(
        r"""axios(?:\.(\w+))?\s*\(\s*['"`](\/[^'"`\s]+)['"`]""",
        re.IGNORECASE,
    )

    # xhr.open("METHOD", "/path")
    _RE_XHR = re.compile(
        r"""\.open\s*\(\s*['"](\w+)['"]\s*,\s*['"`](\/[^'"`\s]+)['"`]""",
        re.IGNORECASE,
    )

    # String literals that look like API paths: "/api/...", "/rest/..."
    _RE_STRING_PATH = re.compile(
        r"""(?:['"`])(\/(?:api|rest|graphql|v[0-9]|ws|auth|oauth)[^'"`\s]*?)(?:['"`])""",
        re.IGNORECASE,
    )

    # Generic path strings: any "/word/word" pattern in quotes
    _RE_GENERIC_PATH = re.compile(
        r"""(?:['"`])(\/[a-zA-Z][a-zA-Z0-9._-]*(?:\/[a-zA-Z0-9._{}:-]+)+\/?)(?:['"`])""",
    )

    # Angular/React route definitions: {path: 'xxx', ...}
    _RE_ROUTE = re.compile(
        r"""\{\s*path\s*:\s*['"]([^'"]+)['"]""",
    )

    # jQuery $.ajax, $.get, $.post
    _RE_JQUERY = re.compile(
        r"""\$\.(?:ajax|get|post|put|delete)\s*\(\s*['"`](\/[^'"`\s]+)['"`]""",
        re.IGNORECASE,
    )

    def extract(self, js_source: str) -> list[DiscoveredEndpoint]:
        """Extract endpoints from a JavaScript source string."""
        if not js_source or not js_source.strip():
            return []

        seen: set[tuple[str, str]] = set()
        endpoints: list[DiscoveredEndpoint] = []

        def _add(url: str, method: str = "GET", confidence: float = 0.8):
            url = url.split("?")[0].rstrip("/") or url  # Normalize
            key = (url, method.upper())
            if key not in seen and not self._is_static_asset(url):
                seen.add(key)
                params = self._extract_params(url)
                endpoints.append(DiscoveredEndpoint(
                    url=url.split("?")[0],
                    method=method.upper(),
                    params=params,
                    source="js_analysis",
                    confidence=confidence,
                ))

        # fetch() calls
        for m in self._RE_FETCH.finditer(js_source):
            method = m.group(2) or "GET"
            _add(m.group(1), method, 0.95)

        # axios calls
        for m in self._RE_AXIOS.finditer(js_source):
            method = m.group(1) or "GET"
            _add(m.group(2), method, 0.95)

        # XHR calls
        for m in self._RE_XHR.finditer(js_source):
            _add(m.group(2), m.group(1), 0.9)

        # jQuery calls
        for m in self._RE_JQUERY.finditer(js_source):
            _add(m.group(1), "GET", 0.85)

        # Explicit API path strings
        for m in self._RE_STRING_PATH.finditer(js_source):
            _add(m.group(1), "GET", 0.7)

        # Generic multi-segment paths
        for m in self._RE_GENERIC_PATH.finditer(js_source):
            path = m.group(1)
            if _API_PATH_INDICATORS.match(path):
                _add(path, "GET", 0.6)

        # Angular/React routes
        for m in self._RE_ROUTE.finditer(js_source):
            route = m.group(1)
            if route and route != "**" and not route.startswith("http"):
                _add(f"/{route.lstrip('/')}", "GET", 0.5)

        logger.debug("Extracted %d endpoints from JS (%d bytes)", len(endpoints), len(js_source))
        return endpoints

    def extract_from_html(self, html: str) -> list[DiscoveredEndpoint]:
        """Extract endpoints from inline scripts in HTML."""
        all_endpoints: list[DiscoveredEndpoint] = []

        # Inline scripts
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
            content = m.group(1).strip()
            if content:
                all_endpoints.extend(self.extract(content))

        # Also check for data attributes with URLs
        for m in re.finditer(r'data-(?:url|api|endpoint|href)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = m.group(1)
            if url.startswith("/"):
                all_endpoints.append(DiscoveredEndpoint(url=url, source="html_data_attr", confidence=0.7))

        return all_endpoints

    def extract_from_url(self, js_url: str, js_content: str) -> list[DiscoveredEndpoint]:
        """Extract endpoints from a fetched JS file."""
        endpoints = self.extract(js_content)
        for ep in endpoints:
            ep.source = f"js_file:{js_url}"
        return endpoints

    @staticmethod
    def _is_static_asset(url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in _STATIC_EXTENSIONS)

    @staticmethod
    def _extract_params(url: str) -> dict:
        parsed = urlparse(url)
        if parsed.query:
            return {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}
        return {}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_js_extractor.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add secprobe/core/js_endpoint_extractor.py tests/test_js_extractor.py
git commit -m "feat: add JavaScript endpoint extractor for SPA API discovery"
```

---

## Task 2: API Path Discoverer

**Files:**
- Create: `secprobe/core/api_discoverer.py`
- Create: `secprobe/payloads/api_paths.txt`
- Create: `tests/test_api_discoverer.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_api_discoverer.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from secprobe.core.api_discoverer import APIDiscoverer, DiscoveredAPI


class TestAPIDiscoverer:
    def setup_method(self):
        self.discoverer = APIDiscoverer()

    def test_build_paths(self):
        paths = self.discoverer.get_probe_paths()
        assert len(paths) > 100
        assert "/api/v1/users" in paths or "/api/users" in paths
        assert "/swagger.json" in paths
        assert "/graphql" in paths

    def test_classify_status_code(self):
        assert self.discoverer.is_interesting_status(200) is True
        assert self.discoverer.is_interesting_status(301) is True
        assert self.discoverer.is_interesting_status(401) is True
        assert self.discoverer.is_interesting_status(403) is True
        assert self.discoverer.is_interesting_status(404) is False
        assert self.discoverer.is_interesting_status(500) is True

    def test_parse_swagger_spec(self):
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

    def test_parse_empty_swagger(self):
        endpoints = self.discoverer.parse_openapi({})
        assert endpoints == []

    def test_swagger_discovery_paths(self):
        paths = self.discoverer.get_swagger_paths()
        assert "/swagger.json" in paths
        assert "/openapi.json" in paths
        assert "/api-docs" in paths
        assert "/v2/api-docs" in paths
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_api_discoverer.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Create API paths wordlist**

Create `secprobe/payloads/api_paths.txt` with 2000+ common API paths. Include:
- REST conventions: /api/users, /api/products, /api/orders, /api/v1/*, /api/v2/*
- Common frameworks: /rest/*, /graphql, /ws, /socket.io
- Admin: /admin, /dashboard, /panel, /console, /manage
- Auth: /login, /register, /oauth, /token, /session, /logout, /forgot-password
- Docs: /swagger.json, /openapi.json, /api-docs, /redoc, /docs
- Health: /health, /healthz, /ready, /status, /ping, /info, /metrics, /version
- Debug: /debug, /trace, /env, /config, /.env, /phpinfo.php, /server-status
- Files: /robots.txt, /sitemap.xml, /.git/HEAD, /.well-known/security.txt

- [ ] **Step 4: Implement APIDiscoverer**

Create `secprobe/core/api_discoverer.py`:
- `get_probe_paths()` — Load from api_paths.txt
- `get_swagger_paths()` — Known Swagger/OpenAPI discovery URLs
- `is_interesting_status(code)` — 200, 301, 302, 401, 403, 405, 500 are interesting
- `parse_openapi(spec)` — Parse Swagger/OpenAPI JSON into DiscoveredAPI list
- `async discover(base_url, http_client)` — Probe all paths, collect interesting responses
- `async discover_swagger(base_url, http_client)` — Try Swagger URLs, parse if found

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_api_discoverer.py -v`
Expected: All 5 tests PASS

- [ ] **Step 6: Commit**

```bash
git add secprobe/core/api_discoverer.py secprobe/payloads/api_paths.txt tests/test_api_discoverer.py
git commit -m "feat: add API path discoverer with Swagger/OpenAPI auto-detection"
```

---

## Task 3: Unified Discovery Engine

**Files:**
- Create: `secprobe/core/discovery_engine.py`
- Create: `tests/test_discovery_engine.py`
- Modify: `secprobe/core/crawler.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_discovery_engine.py
import pytest
from secprobe.core.discovery_engine import DiscoveryEngine, DiscoveryConfig
from secprobe.core.crawler import AttackSurface


class TestDiscoveryEngine:
    def test_merge_surfaces(self):
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        surface1 = AttackSurface()
        surface1.urls.add("http://example.com/api/users")
        surface2 = AttackSurface()
        surface2.urls.add("http://example.com/api/products")
        surface2.urls.add("http://example.com/api/users")  # Duplicate

        merged = engine.merge_surfaces([surface1, surface2])
        assert "http://example.com/api/users" in merged.urls
        assert "http://example.com/api/products" in merged.urls
        assert len([u for u in merged.urls if "api/users" in u]) == 1  # No dupes

    def test_config_defaults(self):
        config = DiscoveryConfig(target="http://example.com")
        assert config.enable_js_analysis is True
        assert config.enable_api_brute is True
        assert config.enable_browser is False  # Browser off by default (needs playwright)
        assert config.max_api_probes == 500

    def test_endpoints_to_attack_surface(self):
        from secprobe.core.js_endpoint_extractor import DiscoveredEndpoint
        engine = DiscoveryEngine(DiscoveryConfig(target="http://example.com"))
        endpoints = [
            DiscoveredEndpoint(url="/api/users", method="GET"),
            DiscoveredEndpoint(url="/api/products", method="POST"),
        ]
        surface = engine.endpoints_to_surface("http://example.com", endpoints)
        assert len(surface.endpoints) == 2
        assert len(surface.urls) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_discovery_engine.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement DiscoveryEngine**

Create `secprobe/core/discovery_engine.py`:

```python
"""
Unified 4-layer endpoint discovery engine.

Orchestrates: HTML crawling + JS analysis + API brute-force + browser interception
to build a comprehensive AttackSurface for scanner consumption.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from secprobe.core.crawler import AttackSurface, Endpoint
from secprobe.core.js_endpoint_extractor import JSEndpointExtractor, DiscoveredEndpoint

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryConfig:
    """Configuration for the discovery engine."""
    target: str
    enable_html_crawl: bool = True
    enable_js_analysis: bool = True
    enable_api_brute: bool = True
    enable_browser: bool = False  # Requires playwright
    crawl_depth: int = 3
    max_api_probes: int = 500
    timeout: float = 10.0
    rate_limit_rps: float = 20.0


class DiscoveryEngine:
    """Orchestrate all 4 discovery layers."""

    def __init__(self, config: DiscoveryConfig):
        self.config = config
        self._js_extractor = JSEndpointExtractor()

    async def discover(self, http_client) -> AttackSurface:
        """Run all enabled discovery layers and merge results."""
        surfaces: list[AttackSurface] = []

        # Layer A: HTML crawling (existing crawler)
        if self.config.enable_html_crawl:
            try:
                from secprobe.core.crawler import Crawler
                crawler = Crawler(
                    self.config.target,
                    max_depth=self.config.crawl_depth,
                    http_client=http_client,
                )
                html_surface = crawler.crawl()
                surfaces.append(html_surface)
                logger.info("HTML crawl: %d URLs, %d forms", len(html_surface.urls), len(html_surface.forms))
            except Exception:
                logger.warning("HTML crawl failed", exc_info=True)

        # Layer B: JavaScript analysis
        if self.config.enable_js_analysis:
            try:
                js_surface = await self._run_js_analysis(http_client)
                surfaces.append(js_surface)
                logger.info("JS analysis: %d endpoints", len(js_surface.endpoints))
            except Exception:
                logger.warning("JS analysis failed", exc_info=True)

        # Layer C: API brute-force
        if self.config.enable_api_brute:
            try:
                api_surface = await self._run_api_discovery(http_client)
                surfaces.append(api_surface)
                logger.info("API discovery: %d endpoints", len(api_surface.endpoints))
            except Exception:
                logger.warning("API discovery failed", exc_info=True)

        # Layer D: Browser interception (optional)
        if self.config.enable_browser:
            try:
                browser_surface = await self._run_browser_discovery()
                surfaces.append(browser_surface)
                logger.info("Browser discovery: %d URLs", len(browser_surface.urls))
            except Exception:
                logger.warning("Browser discovery failed", exc_info=True)

        merged = self.merge_surfaces(surfaces)
        logger.info(
            "Discovery complete: %d URLs, %d endpoints, %d forms, %d params",
            len(merged.urls), len(merged.endpoints),
            len(merged.forms), len(merged.parameters),
        )
        return merged

    async def _run_js_analysis(self, http_client) -> AttackSurface:
        """Fetch root page, extract JS files, parse for endpoints."""
        surface = AttackSurface()
        target = self.config.target

        # Fetch root page
        try:
            resp = http_client.get(target, timeout=self.config.timeout)
            html = resp.text if hasattr(resp, 'text') else str(resp.content, 'utf-8', errors='replace')
        except Exception:
            return surface

        # Extract from inline scripts
        inline_endpoints = self._js_extractor.extract_from_html(html)

        # Find and fetch external JS files
        import re
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        external_endpoints: list[DiscoveredEndpoint] = []

        for js_url in js_urls[:20]:  # Limit to 20 JS files
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                js_url = target.rstrip("/") + js_url
            elif not js_url.startswith("http"):
                js_url = target.rstrip("/") + "/" + js_url

            try:
                js_resp = http_client.get(js_url, timeout=self.config.timeout)
                js_content = js_resp.text if hasattr(js_resp, 'text') else str(js_resp.content, 'utf-8', errors='replace')
                if js_content and len(js_content) > 10:
                    found = self._js_extractor.extract_from_url(js_url, js_content)
                    external_endpoints.extend(found)
            except Exception:
                continue

        all_endpoints = inline_endpoints + external_endpoints
        return self.endpoints_to_surface(target, all_endpoints)

    async def _run_api_discovery(self, http_client) -> AttackSurface:
        """Probe common API paths."""
        from secprobe.core.api_discoverer import APIDiscoverer
        discoverer = APIDiscoverer()
        surface = AttackSurface()
        target = self.config.target.rstrip("/")

        # Try Swagger/OpenAPI first
        for swagger_path in discoverer.get_swagger_paths():
            try:
                resp = http_client.get(f"{target}{swagger_path}", timeout=5.0)
                if resp.status_code == 200:
                    try:
                        spec = resp.json() if hasattr(resp, 'json') else {}
                        if isinstance(spec, dict) and ("paths" in spec or "openapi" in spec or "swagger" in spec):
                            openapi_endpoints = discoverer.parse_openapi(spec)
                            for ep in openapi_endpoints:
                                full_url = f"{target}{ep.url}"
                                surface.urls.add(full_url)
                                surface.endpoints.append(Endpoint(
                                    url=full_url, method=ep.method,
                                    params=ep.params, source="openapi",
                                ))
                            logger.info("Found OpenAPI spec at %s: %d endpoints", swagger_path, len(openapi_endpoints))
                            return surface  # OpenAPI found — no need to brute-force
                    except Exception:
                        pass
            except Exception:
                continue

        # Brute-force common paths
        probe_paths = discoverer.get_probe_paths()[:self.config.max_api_probes]
        for path in probe_paths:
            try:
                resp = http_client.get(f"{target}{path}", timeout=3.0)
                if discoverer.is_interesting_status(resp.status_code):
                    full_url = f"{target}{path}"
                    surface.urls.add(full_url)
                    surface.endpoints.append(Endpoint(
                        url=full_url,
                        method="GET",
                        params={},
                        source="api_brute",
                    ))
            except Exception:
                continue

        return surface

    async def _run_browser_discovery(self) -> AttackSurface:
        """Use Playwright to intercept network requests."""
        surface = AttackSurface()
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not available — skipping browser discovery")
            return surface

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # Intercept all network requests
            discovered_urls: set[str] = set()

            def on_request(request):
                url = request.url
                if request.resource_type in ("xhr", "fetch", "websocket"):
                    discovered_urls.add(url)

            page.on("request", on_request)

            try:
                await page.goto(self.config.target, wait_until="networkidle", timeout=30000)
                # Click common interactive elements
                for selector in ["button", "a[href]", "input[type=submit]"]:
                    try:
                        elements = await page.query_selector_all(selector)
                        for el in elements[:5]:  # Click up to 5 of each
                            try:
                                await el.click(timeout=2000)
                                await page.wait_for_timeout(500)
                            except Exception:
                                continue
                    except Exception:
                        continue
            except Exception:
                logger.warning("Browser navigation failed", exc_info=True)
            finally:
                await browser.close()

            for url in discovered_urls:
                surface.urls.add(url)
                surface.endpoints.append(Endpoint(
                    url=url, method="GET", params={}, source="browser",
                ))

        return surface

    def merge_surfaces(self, surfaces: list[AttackSurface]) -> AttackSurface:
        """Merge multiple AttackSurface objects, deduplicating."""
        merged = AttackSurface()
        seen_endpoints: set[str] = set()

        for surface in surfaces:
            merged.urls.update(surface.urls)
            merged.forms.extend(surface.forms)
            merged.parameters.update(surface.parameters)

            for ep in surface.endpoints:
                key = f"{ep.method}:{ep.url}"
                if key not in seen_endpoints:
                    seen_endpoints.add(key)
                    merged.endpoints.append(ep)

            if hasattr(surface, 'js_files'):
                merged.js_files.update(surface.js_files)
            if hasattr(surface, 'technologies'):
                merged.technologies.update(surface.technologies)

        return merged

    def endpoints_to_surface(self, base_url: str, endpoints: list[DiscoveredEndpoint]) -> AttackSurface:
        """Convert DiscoveredEndpoint list to AttackSurface."""
        surface = AttackSurface()
        base = base_url.rstrip("/")

        for ep in endpoints:
            full_url = f"{base}{ep.url}" if ep.url.startswith("/") else ep.url
            surface.urls.add(full_url)
            surface.endpoints.append(Endpoint(
                url=full_url,
                method=ep.method,
                params=ep.params,
                source=ep.source,
            ))
            surface.parameters.update(ep.params.keys())

        return surface
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_discovery_engine.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add secprobe/core/discovery_engine.py tests/test_discovery_engine.py
git commit -m "feat: add unified 4-layer discovery engine"
```

---

## Task 4: Wire Discovery into Scan Session

**Files:**
- Modify: `secprobe/core/scan_session.py`
- Modify: `secprobe/cli.py`

- [ ] **Step 1: Read current scan_session.py RECON phase** to understand where to inject discovery

- [ ] **Step 2: Add discovery engine invocation in RECON phase**

In `scan_session.py`, after the existing crawl logic in the RECON phase, add:

```python
# After existing crawler runs, run discovery engine for deeper coverage
if self._config.crawl or any(s in injection_scanners for s in self._config.scan_types):
    try:
        from secprobe.core.discovery_engine import DiscoveryEngine, DiscoveryConfig
        discovery_config = DiscoveryConfig(
            target=self._config.target,
            enable_js_analysis=True,
            enable_api_brute=True,
            enable_browser=False,  # Enable with --browser flag
            crawl_depth=self._config.crawl_depth,
        )
        engine = DiscoveryEngine(discovery_config)
        import asyncio
        discovered = asyncio.run(engine.discover(self._context.http_client))
        # Merge with existing attack surface
        if self._context.attack_surface:
            existing = self._context.attack_surface
            existing.urls.update(discovered.urls)
            existing.endpoints.extend(discovered.endpoints)
            existing.parameters.update(discovered.parameters)
        else:
            self._context.attack_surface = discovered
    except Exception:
        logger.warning("Discovery engine failed", exc_info=True)
```

- [ ] **Step 3: Auto-enable discovery for injection scanners in CLI**

In `cli.py`, before scan session creation, add logic:
```python
injection_scanners = {"sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "nosql", "ldap", "xpath", "crlf", "hpp", "ssrf"}
if any(s in injection_scanners for s in config.scan_types) and not config.crawl:
    config.crawl = True  # Auto-enable discovery for injection scanners
```

- [ ] **Step 4: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=short -x`
Expected: All 1528+ tests PASS (no regressions)

- [ ] **Step 5: Commit**

```bash
git add secprobe/core/scan_session.py secprobe/cli.py
git commit -m "feat: wire discovery engine into scan session and auto-enable for injection scanners"
```

---

## Task 5: Fix SQLi Scanner — Use Discovered Endpoints + UNION Detection

**Files:**
- Modify: `secprobe/scanners/sqli_scanner.py`
- Create: `tests/test_sqli_discovery_wiring.py`

- [ ] **Step 1: Write failing test for endpoint wiring**

```python
# tests/test_sqli_discovery_wiring.py
import pytest
from unittest.mock import MagicMock, patch
from secprobe.scanners.sqli_scanner import SQLiScanner
from secprobe.config import ScanConfig
from secprobe.core.crawler import AttackSurface, Endpoint


class TestSQLiEndpointWiring:
    def test_scanner_uses_discovered_endpoints(self):
        """SQLi scanner should test discovered API endpoints, not just root URL."""
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

    def test_union_detection_pattern(self):
        """UNION injection should be detected when controlled data appears in response."""
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        # Response contains controlled column values from UNION SELECT
        response_text = '{"data":[{"id":1,"name":"2","description":"3","price":4}]}'
        assert scanner._detect_union_response(response_text, columns=9) is True

    def test_union_detection_no_match(self):
        """Normal responses should not trigger UNION detection."""
        config = ScanConfig(target="http://example.com")
        scanner = SQLiScanner(config)
        response_text = '{"data":[{"id":1,"name":"Apple Juice","price":1.99}]}'
        assert scanner._detect_union_response(response_text, columns=9) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_sqli_discovery_wiring.py -v`
Expected: FAIL — methods don't exist yet

- [ ] **Step 3: Add `_get_injectable_urls()` method to SQLi scanner**

Read the current sqli_scanner.py scan() method. Find where it gets target URLs. Add a method that checks attack_surface first:

```python
def _get_injectable_urls(self) -> list[str]:
    """Get all injectable URLs from attack surface + root target."""
    urls = set()
    # From attack surface (discovered endpoints)
    if self.context and self.context.attack_surface:
        for ep in self.context.attack_surface.endpoints:
            if ep.params:  # Has query parameters
                urls.add(ep.url)
        urls.update(self.context.get_injection_urls())
    # Always include the root target
    urls.add(self.config.target)
    return list(urls)
```

- [ ] **Step 4: Add `_detect_union_response()` for UNION-based SQLi**

```python
def _detect_union_response(self, response_text: str, columns: int) -> bool:
    """Detect UNION injection by checking if sequential numbers appear as values."""
    # If UNION SELECT 1,2,3,...,N injected successfully,
    # the response will contain sequential integers as field values
    import json
    try:
        data = json.loads(response_text)
    except (json.JSONDecodeError, TypeError):
        # Check raw text for sequential number pattern
        import re
        # Look for pattern like "1","2","3" or 1,2,3 in sequence
        sequential = ",".join(str(i) for i in range(1, min(columns + 1, 6)))
        return sequential in response_text

    # Check JSON response for controlled values
    def check_values(obj, depth=0):
        if depth > 5:
            return False
        if isinstance(obj, dict):
            values = list(obj.values())
            str_values = [str(v) for v in values if isinstance(v, (int, float, str))]
            # Check if values contain sequential integers we injected
            sequential_count = sum(1 for i, v in enumerate(str_values) if v == str(i + 1))
            if sequential_count >= 3:  # At least 3 sequential matches
                return True
            return any(check_values(v, depth + 1) for v in values)
        elif isinstance(obj, list):
            return any(check_values(item, depth + 1) for item in obj)
        return False

    return check_values(data)
```

- [ ] **Step 5: Wire `_get_injectable_urls()` into the scan() method**

Find where the scanner iterates over URLs in scan() and replace root-URL-only with `self._get_injectable_urls()`.

- [ ] **Step 6: Add UNION detection phase to scan()**

After the existing error-based phase, add a UNION detection phase that:
1. For each injectable URL with params:
2. Try `param=') UNION SELECT 1,2,3,4,5,6,7,8,9--`
3. Check response with `_detect_union_response()`
4. If detected, add CRITICAL finding with evidence

- [ ] **Step 7: Run tests**

Run: `python3 -m pytest tests/test_sqli_discovery_wiring.py -v`
Expected: All 3 tests PASS

Run: `python3 -m pytest tests/ -q --tb=short -x`
Expected: All tests PASS (no regressions)

- [ ] **Step 8: Commit**

```bash
git add secprobe/scanners/sqli_scanner.py tests/test_sqli_discovery_wiring.py
git commit -m "feat: wire SQLi scanner to discovered endpoints and add UNION detection"
```

---

## Task 6: Fix XSS Scanner — Use Discovered Endpoints

**Files:**
- Modify: `secprobe/scanners/xss_scanner.py`
- Create: `tests/test_xss_discovery_wiring.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_xss_discovery_wiring.py
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

    def test_reflection_detection(self):
        config = ScanConfig(target="http://example.com")
        scanner = XSSScanner(config)
        # Payload reflected in response
        payload = '<script>alert(1)</script>'
        response = f'<html><body>Results for: {payload}</body></html>'
        assert scanner._check_reflection(payload, response) is True

    def test_no_reflection(self):
        config = ScanConfig(target="http://example.com")
        scanner = XSSScanner(config)
        payload = '<script>alert(1)</script>'
        response = '<html><body>Results for: test</body></html>'
        assert scanner._check_reflection(payload, response) is False
```

- [ ] **Step 2: Run tests, verify fail**

- [ ] **Step 3: Add `_get_injectable_urls()` and `_check_reflection()` to XSS scanner**

Same pattern as SQLi — check attack_surface for discovered endpoints. Add reflection check that looks for payload string in response body.

- [ ] **Step 4: Wire into scan() method**

- [ ] **Step 5: Run tests, verify pass + no regressions**

- [ ] **Step 6: Commit**

```bash
git add secprobe/scanners/xss_scanner.py tests/test_xss_discovery_wiring.py
git commit -m "feat: wire XSS scanner to discovered endpoints and add reflection detection"
```

---

## Task 7: Benchmark Suite — Juice Shop

**Files:**
- Create: `secprobe/benchmark/__init__.py`
- Create: `secprobe/benchmark/runner.py`
- Create: `secprobe/benchmark/juice_shop.py`
- Create: `secprobe/benchmark/report.py`
- Create: `tests/test_benchmark.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_benchmark.py
import pytest
from secprobe.benchmark.juice_shop import JuiceShopBenchmark
from secprobe.benchmark.report import BenchmarkReport


class TestJuiceShopBenchmark:
    def test_challenge_list(self):
        bench = JuiceShopBenchmark()
        challenges = bench.get_challenges()
        assert len(challenges) >= 50
        # Check some known challenges exist
        names = {c["name"] for c in challenges}
        assert any("SQL" in n or "sqli" in n.lower() for n in names)
        assert any("XSS" in n or "xss" in n.lower() for n in names)

    def test_map_finding_to_challenge(self):
        bench = JuiceShopBenchmark()
        # A finding about SQL injection should map to SQLi challenges
        finding = {"category": "sqli", "title": "SQL Injection", "url": "/rest/products/search"}
        matches = bench.match_finding(finding)
        assert len(matches) >= 1

    def test_detection_rate_calculation(self):
        report = BenchmarkReport()
        report.total_challenges = 100
        report.detected = 80
        report.false_positives = 2
        assert report.detection_rate == 0.80
        assert report.fp_rate == pytest.approx(2 / 82, rel=0.01)

    def test_empty_report(self):
        report = BenchmarkReport()
        report.total_challenges = 100
        report.detected = 0
        assert report.detection_rate == 0.0
```

- [ ] **Step 2: Run tests, verify fail**

- [ ] **Step 3: Create Juice Shop challenge mapping**

Create `secprobe/benchmark/juice_shop.py` with:
- Complete list of Juice Shop challenges (name, category, difficulty, description)
- Categories: sqli, xss, auth, access-control, injection, misconfiguration, cryptographic, etc.
- `match_finding(finding)` — Match a SecProbe finding to challenge(s) by category + URL pattern
- `get_challenges()` — Return full challenge list

- [ ] **Step 4: Create benchmark report**

Create `secprobe/benchmark/report.py` with:
- `BenchmarkReport` dataclass: total_challenges, detected, false_positives, findings, duration
- Properties: detection_rate, fp_rate, grade
- `to_dict()`, `to_markdown()` — Serialization

- [ ] **Step 5: Create benchmark runner**

Create `secprobe/benchmark/runner.py` with:
- `run_juice_shop(target_url)` — Run full SecProbe scan against Juice Shop
- Parse findings, map to challenges
- Return BenchmarkReport

- [ ] **Step 6: Run tests, verify pass**

Run: `python3 -m pytest tests/test_benchmark.py -v`
Expected: All 4 tests PASS

- [ ] **Step 7: Commit**

```bash
git add secprobe/benchmark/ tests/test_benchmark.py
git commit -m "feat: add benchmark suite with Juice Shop challenge mapping"
```

---

## Task 8: Integration Test — Run Against Juice Shop

**Files:**
- Create: `tests/test_juice_shop_integration.py`

- [ ] **Step 1: Write integration test**

```python
# tests/test_juice_shop_integration.py
"""
Integration test against OWASP Juice Shop.
Requires: docker run -d -p 3333:3000 bkimminich/juice-shop
Skip if Juice Shop not running.
"""
import pytest
import requests

JUICE_SHOP_URL = "http://127.0.0.1:3333"


def juice_shop_running():
    try:
        r = requests.get(JUICE_SHOP_URL, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


@pytest.mark.skipif(not juice_shop_running(), reason="Juice Shop not running on port 3333")
class TestJuiceShopIntegration:
    def test_discovery_finds_api_endpoints(self):
        """Discovery engine should find /rest/products/search and /api/Products."""
        from secprobe.core.discovery_engine import DiscoveryEngine, DiscoveryConfig
        from secprobe.core.http_client import HTTPClient
        import asyncio

        config = DiscoveryConfig(target=JUICE_SHOP_URL, enable_browser=False)
        engine = DiscoveryEngine(config)
        client = HTTPClient()

        surface = asyncio.run(engine.discover(client))

        discovered_paths = {ep.url for ep in surface.endpoints}
        all_urls = surface.urls

        # Should find at least some API endpoints
        assert len(surface.endpoints) > 0, "Discovery found no endpoints"

        # Specifically should find the search endpoint (from JS analysis)
        has_search = any("search" in u.lower() or "product" in u.lower() for u in all_urls)
        assert has_search, f"Should find search/product endpoints. Found: {all_urls}"

    def test_sqli_detects_union_injection(self):
        """SQLi scanner should detect the known UNION injection in /rest/products/search."""
        from secprobe.scanners.sqli_scanner import SQLiScanner
        from secprobe.config import ScanConfig
        from secprobe.core.crawler import AttackSurface, Endpoint

        config = ScanConfig(target=JUICE_SHOP_URL, timeout=30)
        surface = AttackSurface()
        surface.endpoints.append(Endpoint(
            url=f"{JUICE_SHOP_URL}/rest/products/search",
            method="GET",
            params={"q": "test"},
            source="test",
        ))
        surface.urls.add(f"{JUICE_SHOP_URL}/rest/products/search?q=test")

        from unittest.mock import MagicMock
        context = MagicMock()
        context.attack_surface = surface
        context.get_injection_urls.return_value = list(surface.urls)
        context.http_client = None  # Scanner uses its own client

        scanner = SQLiScanner(config, context)
        result = scanner.run()

        sqli_findings = [f for f in result.findings if "sql" in f.title.lower() or "sqli" in f.category.lower()]
        assert len(sqli_findings) > 0, f"Should detect SQLi. Findings: {[f.title for f in result.findings]}"
```

- [ ] **Step 2: Start Juice Shop if not running**

```bash
docker ps | grep juice-shop || docker start juice-shop || docker run -d --name juice-shop -p 3333:3000 bkimminich/juice-shop
```

- [ ] **Step 3: Run integration test**

Run: `python3 -m pytest tests/test_juice_shop_integration.py -v -s`
Expected: Both tests PASS — discovery finds API endpoints AND SQLi is detected

- [ ] **Step 4: If tests fail, debug and fix**

The most likely failures:
- Discovery doesn't find `/rest/products/search` → Fix JS extractor patterns
- SQLi scanner doesn't detect UNION → Fix UNION detection logic
- Iterate until both tests pass

- [ ] **Step 5: Run full benchmark**

```bash
python3 -c "
from secprobe.benchmark.runner import run_juice_shop
report = run_juice_shop('http://127.0.0.1:3333')
print(report.to_markdown())
"
```

Track: detection_rate, fp_rate, scan_time

- [ ] **Step 6: Commit**

```bash
git add tests/test_juice_shop_integration.py
git commit -m "test: add Juice Shop integration tests for discovery and SQLi detection"
```

---

## Task 9: Final Verification and Metrics

- [ ] **Step 1: Run full test suite**

```bash
python3 -m pytest tests/ -q --tb=short
```
Expected: All tests PASS (1528+ existing + new tests)

- [ ] **Step 2: Run Juice Shop full scan with discovery**

```bash
python3 -m secprobe http://127.0.0.1:3333 -s sqli xss cors headers cookies tech --crawl --crawl-depth 3
```
Expected: SQLi finding appears in results

- [ ] **Step 3: Record metrics**

```
Detection rate: ___/100 Juice Shop challenges
False positives: ___
Scan time: ___ seconds
Endpoints discovered: ___
```

- [ ] **Step 4: Update version to 8.1.0**

Edit `secprobe/__init__.py`: change version to "8.1.0"

- [ ] **Step 5: Final commit and push**

```bash
git add -A
git commit -m "SecProbe v8.1.0 — Phase 1: Detection engine with 4-layer discovery and UNION SQLi detection"
git push origin main
```

---

## Success Criteria

| Metric | Before Phase 1 | After Phase 1 | Target |
|--------|---------------|--------------|--------|
| Juice Shop SQLi | NOT DETECTED | DETECTED | Must detect |
| Endpoint discovery | HTML only (20 URLs) | HTML+JS+API (100+ URLs) | 50+ endpoints |
| SQLi UNION detection | Broken | Working | Confirmed on Juice Shop |
| XSS reflection check | Crashing | Working | No crashes |
| False positive rate | Unknown | Measured | Below 5% |
| Total tests | 1,528 | 1,550+ | All passing |
| Scan time (full) | 4+ hours | Below 30 min | Below 30 min |
