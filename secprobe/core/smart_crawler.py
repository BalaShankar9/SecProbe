"""
Smart Crawler — Hybrid static + browser-rendered crawling.

This combines the speed of the existing regex-based Crawler with the
power of the BrowserEngine for JavaScript-rendered pages.

Strategy:
    1. Start with static crawl (fast, low resource) to discover the surface
    2. For each page, detect if it's a SPA/JS-heavy app
    3. If SPA detected, switch to BrowserEngine for that page
    4. Capture network requests from browser → discover hidden API endpoints
    5. Merge static + browser results into one unified AttackSurface

This gives us:
    - Traditional sites: Fast regex crawl (same as before)
    - SPAs (React/Angular/Vue): Full JS rendering via Playwright
    - API discovery: Intercept XHR/fetch from browser
    - Best of both worlds: Speed + completeness

The SmartCrawler is a DROP-IN replacement for the existing Crawler.
It produces the same AttackSurface/FormData/Endpoint objects that
all 21 scanners already consume.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qs

from secprobe.core.crawler import Crawler, AttackSurface, FormData, Endpoint
from secprobe.core.logger import get_logger

log = get_logger("smart_crawler")


# ── SPA Detection Heuristics ────────────────────────────────────────────

SPA_INDICATORS = [
    # React
    r'<div\s+id=["\'](?:root|app|__next)["\']',
    r'_react',
    r'react-dom',
    r'__NEXT_DATA__',
    # Angular
    r'ng-app',
    r'ng-version',
    r'<app-root',
    r'angular\.min\.js',
    # Vue
    r'__vue__',
    r'<div\s+id=["\']app["\']',
    r'vue\.runtime',
    r'nuxt',
    # Svelte / SvelteKit
    r'__sveltekit',
    r'svelte-',
    # General SPA markers
    r'<script[^>]*type=["\']module["\']',
    r'window\.__INITIAL_STATE__',
    r'window\.__APOLLO_STATE__',
    r'<script[^>]+src=["\'][^"\']*(?:bundle|chunk|main)\.[a-f0-9]+\.js',
]

SPA_PATTERN = re.compile("|".join(SPA_INDICATORS), re.IGNORECASE)


@dataclass
class SmartCrawlConfig:
    """Configuration for the smart crawler."""
    max_depth: int = 3
    max_pages: int = 200
    use_browser: bool = True        # Enable browser rendering
    spa_detection: bool = True      # Auto-detect SPAs
    force_browser: bool = False     # Always use browser (slower but thorough)
    browser_timeout: int = 30000    # Browser page load timeout (ms)
    extra_wait_ms: int = 3000       # Extra wait for SPA rendering
    intercept_network: bool = True  # Capture XHR/fetch from browser
    discover_spa_routes: bool = True
    scope_regex: str = ""
    exclude_regex: str = r"\.(jpg|jpeg|png|gif|svg|ico|css|woff2?|ttf|eot|mp[34]|avi|mov|pdf|zip|gz|tar)$"


class SmartCrawler:
    """
    Hybrid static + browser-rendered crawler.

    Drop-in replacement for Crawler — produces the same AttackSurface.

    Usage:
        # Simple (auto-detects SPA)
        crawler = SmartCrawler(http_client, "https://target.com")
        surface = crawler.crawl()

        # With browser engine
        crawler = SmartCrawler(http_client, "https://target.com",
                               browser_engine=browser_engine)
        surface = crawler.crawl()
    """

    def __init__(self, http_client, base_url: str, *,
                 browser_engine=None,
                 config: Optional[SmartCrawlConfig] = None):
        self.http_client = http_client
        self.base_url = base_url.rstrip("/")
        self.config = config or SmartCrawlConfig()
        self.browser = browser_engine

        parsed = urlparse(self.base_url)
        self.base_domain = parsed.netloc

        self.surface = AttackSurface()
        self._is_spa = False
        self._browser_rendered_urls: set[str] = set()
        self._api_endpoints_from_browser: set[str] = set()
        self._stats = {
            "static_pages": 0,
            "browser_pages": 0,
            "spa_detected": False,
            "api_endpoints": 0,
            "total_time": 0.0,
        }

    def crawl(self) -> AttackSurface:
        """
        Execute the smart crawl.

        Strategy:
            1. Static crawl to discover the initial surface
            2. Check if the target is a SPA
            3. If SPA, render key pages in browser to get JS content
            4. Merge everything into a unified AttackSurface
        """
        start_time = time.monotonic()
        log.info("SmartCrawl starting: %s", self.base_url)

        # ── Phase 1: Static Crawl ────────────────────────────────
        log.info("Phase 1: Static crawl")
        static_crawler = Crawler(
            self.http_client,
            self.base_url,
            max_depth=self.config.max_depth,
            max_pages=self.config.max_pages,
            scope_regex=self.config.scope_regex,
            exclude_regex=self.config.exclude_regex,
        )
        self.surface = static_crawler.crawl()
        self._stats["static_pages"] = len(self.surface.urls)

        log.info("Static crawl found: %d URLs, %d forms, %d endpoints",
                 len(self.surface.urls), len(self.surface.forms),
                 len(self.surface.endpoints))

        # ── Phase 2: SPA Detection ───────────────────────────────
        if self.config.spa_detection and not self.config.force_browser:
            self._is_spa = self._detect_spa()
            self._stats["spa_detected"] = self._is_spa
            if self._is_spa:
                log.info("SPA detected — activating browser rendering")

        # ── Phase 3: Browser Rendering ────────────────────────
        # When a BrowserEngine is provided and use_browser is True, ALWAYS
        # render key pages.  Modern sites (booking.com, etc.) use SSR React
        # that fails SPA heuristics but still needs JS for interactive forms,
        # date pickers, and client-side routing.
        should_use_browser = (
            self.browser is not None and self.config.use_browser
        )

        if should_use_browser:
            log.info("Phase 2: Browser-rendered crawl%s",
                     " (SPA detected)" if self._is_spa else "")
            self._browser_crawl()
        else:
            if self.browser is None and (
                    self._is_spa or self._forms_look_empty()):
                log.warning("SPA or empty forms detected but no BrowserEngine — "
                            "results may be incomplete. Use --browser flag.")

        # ── Phase 4: SPA Route Discovery ─────────────────────────
        if should_use_browser and self.config.discover_spa_routes:
            log.info("Phase 3: SPA route discovery")
            self._discover_routes()

        elapsed = time.monotonic() - start_time
        self._stats["total_time"] = elapsed

        log.info(
            "SmartCrawl complete: %d URLs, %d forms, %d endpoints, "
            "%d API endpoints, %d browser-rendered (%.1fs)",
            len(self.surface.urls), len(self.surface.forms),
            len(self.surface.endpoints), len(self._api_endpoints_from_browser),
            self._stats["browser_pages"], elapsed,
        )

        # ── Phase 5: URL Hygiene ────────────────────────────────
        self._clean_urls()

        return self.surface

    # ── URL hygiene ──────────────────────────────────────────────────

    _STATIC_EXTENSIONS = re.compile(
        r'\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|mp4'
        r'|mp3|webm|pdf|zip|gz)(?:\?|$)',
        re.IGNORECASE,
    )

    def _clean_urls(self):
        """Post-process the attack surface: decode entities, remove static assets."""
        import html as html_mod

        cleaned_urls: set[str] = set()
        for url in self.surface.urls:
            url = html_mod.unescape(url)  # &amp; → &
            if self._STATIC_EXTENSIONS.search(urlparse(url).path):
                continue
            cleaned_urls.add(url)
        self.surface.urls = cleaned_urls

        # Clean endpoints too
        cleaned_endpoints = []
        for ep in self.surface.endpoints:
            ep.url = html_mod.unescape(ep.url)
            if self._STATIC_EXTENSIONS.search(urlparse(ep.url).path):
                continue
            cleaned_endpoints.append(ep)
        self.surface.endpoints = cleaned_endpoints

        # Clean form actions
        for form in self.surface.forms:
            form.action = html_mod.unescape(form.action)

    def _forms_look_empty(self) -> bool:
        """Return True if we found forms but they have no fields (needs JS)."""
        return any(not f.field_names for f in self.surface.forms)

    def _detect_spa(self) -> bool:
        """Detect if the target is a JavaScript SPA."""
        try:
            resp = self.http_client.get(self.base_url)
            if resp and resp.text:
                # Check for SPA framework signatures
                if SPA_PATTERN.search(resp.text):
                    return True

                # Heuristic: Very little text content but lots of JS
                text_ratio = len(re.sub(r'<[^>]+>', '', resp.text)) / max(len(resp.text), 1)
                script_count = len(re.findall(r'<script', resp.text, re.IGNORECASE))

                # Low text-to-HTML ratio + many scripts = likely SPA
                if text_ratio < 0.1 and script_count > 5:
                    return True

                # Minimal body content (SPA hasn't rendered yet)
                body_match = re.search(r'<body[^>]*>(.*?)</body>', resp.text, re.DOTALL | re.IGNORECASE)
                if body_match:
                    body_content = re.sub(r'<script[^>]*>.*?</script>', '', body_match.group(1), flags=re.DOTALL)
                    body_content = re.sub(r'<[^>]+>', '', body_content).strip()
                    if len(body_content) < 100 and script_count > 3:
                        return True

        except Exception as e:
            log.debug("SPA detection error: %s", e)

        return False

    def _browser_crawl(self):
        """Render pages in the browser and extract additional content."""
        from secprobe.core.browser import BrowserConfig

        if not self.browser:
            return

        # Determine which URLs to render in the browser
        # Priority: pages with forms, pages with parameters, landing page
        import html as html_mod
        urls_to_render = set()

        # Always render the landing page
        urls_to_render.add(self.base_url)

        # Render pages that had forms (forms might be JS-rendered)
        for form in self.surface.forms:
            if form.url:
                urls_to_render.add(html_mod.unescape(form.url))

        # Render pages with parameters (might have dynamic content)
        for ep in self.surface.endpoints:
            if ep.params:
                urls_to_render.add(html_mod.unescape(ep.url.split("?")[0]))

        # Render top-level pages (not too deep)
        for url in sorted(self.surface.urls):
            url = html_mod.unescape(url)
            parsed = urlparse(url)
            depth = len([p for p in parsed.path.split("/") if p])
            if depth <= 2:
                urls_to_render.add(url)
            if len(urls_to_render) >= 30:  # Cap browser renders
                break

        log.info("Browser rendering %d key pages", len(urls_to_render))

        for url in urls_to_render:
            try:
                result = self.browser.render_page(
                    url,
                    extra_wait_ms=self.config.extra_wait_ms,
                )
                self._stats["browser_pages"] += 1
                self._browser_rendered_urls.add(url)

                # Merge browser-discovered forms
                for form_data in result.forms:
                    browser_form = FormData(
                        action=form_data.get("action", ""),
                        method=form_data.get("method", "GET"),
                        fields=form_data.get("fields", []),
                        url=url,
                    )
                    # Only add if not a duplicate
                    if not self._is_duplicate_form(browser_form):
                        self.surface.forms.append(browser_form)
                        for f in browser_form.fields:
                            if f.get("name"):
                                self.surface.parameters.add(f["name"])

                # Merge browser-discovered links
                for link in result.links:
                    if self._is_in_scope(link):
                        self.surface.urls.add(link)

                # Extract API endpoints from network requests
                for api_url in result.api_endpoints:
                    if api_url not in self._api_endpoints_from_browser:
                        self._api_endpoints_from_browser.add(api_url)
                        self.surface.endpoints.append(Endpoint(
                            url=api_url,
                            method="GET",  # Will be refined by scanner
                            source="browser_network",
                        ))
                        self.surface.urls.add(api_url)

                # Check for additional API calls from XHR/fetch
                for nr in result.network_requests:
                    if nr.resource_type in ("xhr", "fetch") and self._is_in_scope(nr.url):
                        clean_url = nr.url.split("?")[0]
                        if clean_url not in self._api_endpoints_from_browser:
                            self._api_endpoints_from_browser.add(clean_url)
                            self.surface.endpoints.append(Endpoint(
                                url=nr.url,
                                method=nr.method,
                                params=self._extract_params(nr.url),
                                source="browser_xhr",
                                content_type=nr.response_headers.get("content-type", ""),
                            ))
                            self.surface.urls.add(clean_url)

                            # Extract parameter names from XHR
                            for param_name in self._extract_params(nr.url):
                                self.surface.parameters.add(param_name)

                            # POST body parameters
                            if nr.post_data and nr.method == "POST":
                                try:
                                    post_json = __import__("json").loads(nr.post_data)
                                    if isinstance(post_json, dict):
                                        for key in post_json:
                                            self.surface.parameters.add(key)
                                except Exception:
                                    # Form-encoded
                                    for part in nr.post_data.split("&"):
                                        if "=" in part:
                                            self.surface.parameters.add(part.split("=")[0])

                # Scan console logs for secrets
                for log_entry in result.console_logs:
                    if any(kw in log_entry.lower() for kw in
                           ("api_key", "apikey", "token", "secret", "password",
                            "bearer", "authorization")):
                        self.surface.comments.append(f"[CONSOLE] {log_entry}")

            except Exception as e:
                log.error("Browser render failed for %s: %s", url, e)

        self._stats["api_endpoints"] = len(self._api_endpoints_from_browser)

    def _discover_routes(self):
        """Use BrowserEngine to discover SPA client-side routes."""
        if not self.browser:
            return

        try:
            routes = self.browser.discover_spa_routes(self.base_url, max_routes=200)
            new_routes = 0
            for route in routes:
                if route not in self.surface.urls and self._is_in_scope(route):
                    self.surface.urls.add(route)
                    self.surface.endpoints.append(Endpoint(
                        url=route,
                        method="GET",
                        source="spa_route",
                    ))
                    new_routes += 1

            if new_routes:
                log.info("Discovered %d new SPA routes", new_routes)

        except Exception as e:
            log.error("SPA route discovery error: %s", e)

    def _is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the crawl scope."""
        try:
            parsed = urlparse(url)
            # Same domain check
            if parsed.netloc != self.base_domain:
                return False
            # Exclude static resources
            if self.config.exclude_regex:
                if re.search(self.config.exclude_regex, url, re.IGNORECASE):
                    return False
            # Custom scope regex
            if self.config.scope_regex:
                if not re.search(self.config.scope_regex, url):
                    return False
            return True
        except Exception:
            return False

    def _is_duplicate_form(self, form: FormData) -> bool:
        """Check if a form is a duplicate of an existing one."""
        for existing in self.surface.forms:
            if (existing.action == form.action and
                    existing.method == form.method and
                    set(existing.field_names) == set(form.field_names)):
                return True
        return False

    def _extract_params(self, url: str) -> dict:
        """Extract query parameters from a URL."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        except Exception:
            return {}

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    @property
    def is_spa(self) -> bool:
        return self._is_spa
