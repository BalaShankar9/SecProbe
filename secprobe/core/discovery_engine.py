"""
Unified Discovery Engine — orchestrates 4 layers of endpoint discovery.

Layers:
    A. HTML crawl (existing Crawler)
    B. JavaScript static analysis (JSEndpointExtractor)
    C. API brute-force probing (APIDiscoverer)
    D. Browser interception (Playwright, optional)

All layers run independently; one failure does not block others.
Results are merged and deduplicated into a single AttackSurface.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin

from secprobe.core.crawler import AttackSurface, Endpoint, Crawler
from secprobe.core.js_endpoint_extractor import JSEndpointExtractor, DiscoveredEndpoint
from secprobe.core.logger import get_logger

log = get_logger("discovery_engine")


@dataclass
class DiscoveryConfig:
    """Configuration for the unified discovery engine."""
    target: str
    enable_html_crawl: bool = True
    enable_js_analysis: bool = True
    enable_api_brute: bool = True
    enable_browser: bool = False
    crawl_depth: int = 3
    max_api_probes: int = 500
    timeout: float = 10.0


class DiscoveryEngine:
    """
    Orchestrates multiple discovery layers into a unified AttackSurface.

    Usage:
        config = DiscoveryConfig(target="http://example.com")
        engine = DiscoveryEngine(config)
        surface = await engine.discover(http_client)
    """

    def __init__(self, config: DiscoveryConfig):
        self.config = config

    async def discover(self, http_client) -> AttackSurface:
        """
        Run all enabled discovery layers and merge results.

        Args:
            http_client: An HTTPClient instance (sync) for making requests.

        Returns:
            Merged and deduplicated AttackSurface.
        """
        surfaces: list[AttackSurface] = []

        # Layer A: HTML crawl
        if self.config.enable_html_crawl:
            try:
                log.info("Layer A: HTML crawl starting for %s", self.config.target)
                crawler = Crawler(
                    http_client,
                    self.config.target,
                    max_depth=self.config.crawl_depth,
                )
                surface = crawler.crawl()
                surfaces.append(surface)
                log.info("Layer A: found %d URLs, %d endpoints",
                         len(surface.urls), len(surface.endpoints))
            except Exception as e:
                log.warning("Layer A (HTML crawl) failed: %s", e)

        # Layer B: JavaScript static analysis
        if self.config.enable_js_analysis:
            try:
                log.info("Layer B: JS analysis starting for %s", self.config.target)
                surface = self._run_js_analysis(http_client)
                surfaces.append(surface)
                log.info("Layer B: found %d endpoints", len(surface.endpoints))
            except Exception as e:
                log.warning("Layer B (JS analysis) failed: %s", e)

        # Layer C: API brute-force probing
        if self.config.enable_api_brute:
            try:
                log.info("Layer C: API brute-force starting for %s", self.config.target)
                surface = self._run_api_brute(http_client)
                surfaces.append(surface)
                log.info("Layer C: found %d endpoints", len(surface.endpoints))
            except Exception as e:
                log.warning("Layer C (API brute-force) failed: %s", e)

        # Layer D: Browser interception (Playwright)
        if self.config.enable_browser:
            try:
                log.info("Layer D: Browser interception starting for %s", self.config.target)
                surface = await self._run_browser_interception()
                surfaces.append(surface)
                log.info("Layer D: found %d endpoints", len(surface.endpoints))
            except Exception as e:
                log.warning("Layer D (browser interception) failed: %s", e)

        return self.merge_surfaces(surfaces)

    def _run_js_analysis(self, http_client) -> AttackSurface:
        """Layer B: Fetch root page + JS files, extract endpoints with JSEndpointExtractor."""
        extractor = JSEndpointExtractor()
        all_endpoints: list[DiscoveredEndpoint] = []

        # Fetch root page and extract from inline scripts
        resp = http_client.get(self.config.target, timeout=self.config.timeout)
        html = resp.text

        # Extract from inline <script> tags
        inline_eps = extractor.extract_from_html(html)
        all_endpoints.extend(inline_eps)

        # Find JS file URLs in the HTML and extract from each
        import re
        js_urls: set[str] = set()
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)', html, re.IGNORECASE):
            js_url = urljoin(self.config.target, match.group(1))
            js_urls.add(js_url)

        for js_url in js_urls:
            try:
                js_resp = http_client.get(js_url, timeout=self.config.timeout)
                js_eps = extractor.extract_from_url(js_url, js_resp.text)
                all_endpoints.extend(js_eps)
            except Exception as e:
                log.debug("Failed to fetch JS file %s: %s", js_url, e)

        surface = self.endpoints_to_surface(self.config.target, all_endpoints)
        surface.js_files = js_urls
        return surface

    def _run_api_brute(self, http_client) -> AttackSurface:
        """Layer C: Use APIDiscoverer to probe common API paths."""
        # Lazy import — APIDiscoverer may not exist yet (built in parallel)
        try:
            from secprobe.core.api_discoverer import APIDiscoverer
        except ImportError:
            log.warning("APIDiscoverer not available — skipping Layer C")
            return AttackSurface()

        discoverer = APIDiscoverer(http_client, self.config.target)
        surface = AttackSurface()

        # Probe common API paths
        probe_paths = discoverer.get_probe_paths()
        probed = 0
        for path in probe_paths:
            if probed >= self.config.max_api_probes:
                break
            try:
                url = urljoin(self.config.target, path)
                resp = http_client.get(url, timeout=self.config.timeout)
                if discoverer.is_interesting_status(resp.status_code):
                    surface.urls.add(url)
                    surface.endpoints.append(Endpoint(
                        url=url,
                        method="GET",
                        source="api_brute",
                    ))
                probed += 1
            except Exception:
                probed += 1
                continue

        # Try swagger/openapi paths
        for swagger_path in discoverer.get_swagger_paths():
            try:
                url = urljoin(self.config.target, swagger_path)
                resp = http_client.get(url, timeout=self.config.timeout)
                if resp.status_code == 200:
                    parsed = discoverer.parse_openapi(resp.text)
                    for ep_info in parsed:
                        ep_url = urljoin(self.config.target, ep_info.get("path", ""))
                        surface.urls.add(ep_url)
                        surface.endpoints.append(Endpoint(
                            url=ep_url,
                            method=ep_info.get("method", "GET").upper(),
                            source="openapi",
                        ))
            except Exception as e:
                log.debug("Swagger probe failed for %s: %s", swagger_path, e)

        return surface

    async def _run_browser_interception(self) -> AttackSurface:
        """Layer D: Use Playwright to intercept network requests from the browser."""
        surface = AttackSurface()

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log.warning("Playwright not available — skipping Layer D")
            return surface

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            intercepted_urls: set[str] = set()

            def on_request(request):
                url = request.url
                intercepted_urls.add(url)

            page.on("request", on_request)

            try:
                await page.goto(self.config.target, timeout=int(self.config.timeout * 1000))
                # Wait for network activity to settle
                await page.wait_for_load_state("networkidle", timeout=int(self.config.timeout * 1000))
            except Exception as e:
                log.debug("Browser navigation issue: %s", e)

            await browser.close()

        for url in intercepted_urls:
            surface.urls.add(url)
            surface.endpoints.append(Endpoint(
                url=url,
                method="GET",
                source="browser_interception",
            ))

        return surface

    def merge_surfaces(self, surfaces: list[AttackSurface]) -> AttackSurface:
        """
        Merge multiple AttackSurface objects, deduplicating URLs and endpoints.

        Args:
            surfaces: List of AttackSurface objects to merge.

        Returns:
            A single merged and deduplicated AttackSurface.
        """
        merged = AttackSurface()

        seen_endpoints: set[str] = set()  # "METHOD:url" keys

        for surface in surfaces:
            # URLs are sets, so union handles dedup
            merged.urls |= surface.urls

            # Deduplicate endpoints by method:url
            for ep in surface.endpoints:
                key = f"{ep.method}:{ep.url}"
                if key not in seen_endpoints:
                    seen_endpoints.add(key)
                    merged.endpoints.append(ep)

            # Forms — append all (no natural dedup key)
            merged.forms.extend(surface.forms)

            # Parameters are sets
            merged.parameters |= surface.parameters

            # JS files are sets
            merged.js_files |= surface.js_files

            # Emails are sets
            merged.emails |= surface.emails

            # Comments — append all
            merged.comments.extend(surface.comments)

            # Technologies are sets
            merged.technologies |= surface.technologies

        return merged

    def endpoints_to_surface(self, base_url: str, endpoints: list[DiscoveredEndpoint]) -> AttackSurface:
        """
        Convert a list of DiscoveredEndpoint (from JSEndpointExtractor) into an AttackSurface.

        Resolves relative URLs against base_url and extracts parameter names.

        Args:
            base_url: The base URL to resolve relative paths against.
            endpoints: List of DiscoveredEndpoint objects.

        Returns:
            An AttackSurface populated with the converted endpoints.
        """
        surface = AttackSurface()

        for dep in endpoints:
            # Resolve relative URLs
            if dep.url.startswith(("http://", "https://")):
                full_url = dep.url
            else:
                full_url = urljoin(base_url, dep.url)

            surface.urls.add(full_url)
            surface.endpoints.append(Endpoint(
                url=full_url,
                method=dep.method,
                params=dep.params,
                source=dep.source,
            ))

            # Extract parameter names
            for param_name in dep.params:
                surface.parameters.add(param_name)

        return surface
