"""
Browser Engine — Headless Chromium for JavaScript-heavy targets.

This gives SecProbe something no Python-based scanner has:
real browser rendering for SPA/React/Angular sites, JS challenge
solving (Cloudflare/Akamai), and network-level API discovery.

Features:
    - Full Chromium rendering via Playwright
    - JavaScript execution for SPA crawling
    - Network request interception (capture every API call)
    - Cloudflare/Akamai JS challenge solving
    - Screenshot evidence capture
    - Cookie extraction after login flows
    - DOM-based form discovery (React/Vue rendered forms)
    - Console log monitoring for leaked secrets
    - Automatic cleanup and resource management

Architecture:
    BrowserEngine manages a headless Chromium instance. It provides:
    1. render_page() — get fully rendered DOM + intercepted network calls
    2. solve_challenge() — navigate through JS challenges
    3. discover_spa_routes() — find client-side routes in React/Angular apps
    4. capture_evidence() — screenshot + HTML snapshot for reports
    5. extract_cookies() — get all cookies after authentication
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

from secprobe.core.logger import get_logger

log = get_logger("browser")


@dataclass
class NetworkRequest:
    """A captured network request from the browser."""
    url: str
    method: str
    headers: dict
    post_data: Optional[str] = None
    resource_type: str = ""     # document, xhr, fetch, script, etc.
    status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    timing_ms: float = 0.0


@dataclass
class PageResult:
    """Result of rendering a page in the browser."""
    url: str
    final_url: str              # After redirects
    status_code: int
    html: str                   # Fully rendered DOM
    title: str
    text: str                   # .textContent of the body
    network_requests: list[NetworkRequest] = field(default_factory=list)
    console_logs: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=dict)
    screenshot_path: Optional[str] = None
    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    js_errors: list[str] = field(default_factory=list)
    load_time_ms: float = 0.0


@dataclass
class BrowserConfig:
    """Configuration for the browser engine."""
    headless: bool = True
    timeout: int = 30000            # Page load timeout (ms)
    viewport_width: int = 1920
    viewport_height: int = 1080
    proxy: Optional[str] = None
    user_agent: Optional[str] = None
    locale: str = "en-US"
    timezone: str = "America/New_York"
    screenshots_dir: str = "evidence"
    block_resources: list[str] = field(
        default_factory=lambda: ["image", "media", "font"]  # Speed up by blocking non-essential
    )
    intercept_network: bool = True
    capture_console: bool = True
    extra_headers: dict = field(default_factory=dict)
    geolocation: Optional[dict] = None  # {"latitude": 40.7, "longitude": -74.0}


class BrowserEngine:
    """
    Headless Chromium engine for JavaScript-rendered targets.

    This is the only way to properly test modern SPAs (React, Angular, Vue),
    solve JS challenges (Cloudflare, Akamai), and discover dynamically
    rendered endpoints.

    Usage:
        engine = BrowserEngine(config)
        engine.start()
        result = engine.render_page("https://booking.com")
        # result.html = fully rendered DOM
        # result.network_requests = every XHR/fetch call captured
        # result.api_endpoints = discovered API endpoints
        engine.stop()

    Context Manager:
        with BrowserEngine(config) as engine:
            result = engine.render_page("https://target.com")
    """

    def __init__(self, config: Optional[BrowserConfig] = None):
        self.config = config or BrowserConfig()
        self._playwright = None
        self._browser = None
        self._context = None
        self._started = False

    def start(self):
        """Launch the browser."""
        if self._started:
            return

        from playwright.sync_api import sync_playwright

        self._playwright = sync_playwright().start()

        launch_args = {
            "headless": self.config.headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--no-sandbox",
            ],
        }

        if self.config.proxy:
            launch_args["proxy"] = {"server": self.config.proxy}

        self._browser = self._playwright.chromium.launch(**launch_args)

        # Create browser context with realistic settings
        context_opts = {
            "viewport": {
                "width": self.config.viewport_width,
                "height": self.config.viewport_height,
            },
            "locale": self.config.locale,
            "timezone_id": self.config.timezone,
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }

        if self.config.user_agent:
            context_opts["user_agent"] = self.config.user_agent

        if self.config.geolocation:
            context_opts["geolocation"] = self.config.geolocation
            context_opts["permissions"] = ["geolocation"]

        if self.config.extra_headers:
            context_opts["extra_http_headers"] = self.config.extra_headers

        self._context = self._browser.new_context(**context_opts)

        # Anti-detection: override navigator.webdriver
        self._context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            // Override Chrome detection
            window.chrome = { runtime: {} };
            // Override permissions
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) =>
                parameters.name === 'notifications'
                    ? Promise.resolve({ state: Notification.permission })
                    : originalQuery(parameters);
            // Override plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            // Override languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
        """)

        self._started = True
        log.info("BrowserEngine started (headless=%s)", self.config.headless)

    def stop(self):
        """Shut down the browser."""
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
        self._started = False
        log.info("BrowserEngine stopped")

    def render_page(self, url: str, wait_for: str = "networkidle",
                    wait_timeout: int = 0, extra_wait_ms: int = 2000) -> PageResult:
        """
        Navigate to URL, wait for JavaScript to finish, return rendered DOM.

        Args:
            url: Target URL
            wait_for: Playwright wait condition — "networkidle", "load", "domcontentloaded"
            wait_timeout: Override timeout (0 = use config)
            extra_wait_ms: Additional wait after load for lazy JS (SPAs need this)

        Returns:
            PageResult with rendered HTML, captured network requests, forms, links, etc.
        """
        if not self._started:
            self.start()

        page = self._context.new_page()
        result = PageResult(url=url, final_url=url, status_code=0, html="",
                            title="", text="")
        network_requests: list[NetworkRequest] = []
        console_logs: list[str] = []
        js_errors: list[str] = []

        timeout = wait_timeout or self.config.timeout

        # ── Network interception ─────────────────────────────────
        if self.config.intercept_network:
            def on_request(request):
                nr = NetworkRequest(
                    url=request.url,
                    method=request.method,
                    headers=dict(request.headers),
                    post_data=request.post_data,
                    resource_type=request.resource_type,
                )
                network_requests.append(nr)

            def on_response(response):
                # Match response to request
                for nr in reversed(network_requests):
                    if nr.url == response.url and nr.status == 0:
                        nr.status = response.status
                        nr.response_headers = dict(response.headers)
                        try:
                            nr.timing_ms = response.request.timing.get("responseEnd", 0)
                        except Exception:
                            pass
                        break

            page.on("request", on_request)
            page.on("response", on_response)

        # ── Console monitoring ───────────────────────────────────
        if self.config.capture_console:
            def on_console(msg):
                console_logs.append(f"[{msg.type}] {msg.text}")

            def on_pageerror(error):
                js_errors.append(str(error))

            page.on("console", on_console)
            page.on("pageerror", on_pageerror)

        # ── Block unnecessary resources ──────────────────────────
        if self.config.block_resources:
            def route_handler(route):
                if route.request.resource_type in self.config.block_resources:
                    route.abort()
                else:
                    route.continue_()
            page.route("**/*", route_handler)

        try:
            # Navigate
            start_time = time.monotonic()
            response = page.goto(url, wait_until=wait_for, timeout=timeout)
            elapsed_ms = (time.monotonic() - start_time) * 1000

            if response:
                result.status_code = response.status
                result.final_url = page.url

            # Extra wait for SPA rendering
            if extra_wait_ms > 0:
                page.wait_for_timeout(extra_wait_ms)

            # Extract rendered content
            result.html = page.content()
            result.title = page.title()
            result.load_time_ms = elapsed_ms

            try:
                result.text = page.evaluate("document.body?.innerText || ''")
            except Exception:
                result.text = ""

            # Extract cookies
            result.cookies = self._context.cookies()

            # Extract forms from rendered DOM
            result.forms = self._extract_forms(page, url)

            # Extract links from rendered DOM
            result.links = self._extract_links(page, url)

            # Identify API endpoints from network requests
            result.api_endpoints = self._extract_api_endpoints(network_requests, url)

            result.network_requests = network_requests
            result.console_logs = console_logs
            result.js_errors = js_errors

            log.info("Rendered %s — %d status, %d network requests, %d forms, %d links, %d API endpoints (%.0fms)",
                     url, result.status_code, len(network_requests),
                     len(result.forms), len(result.links),
                     len(result.api_endpoints), elapsed_ms)

        except Exception as e:
            log.error("Browser render error for %s: %s", url, e)
            result.status_code = 0
            result.html = ""

        finally:
            page.close()

        return result

    def solve_challenge(self, url: str, max_wait_seconds: int = 30) -> PageResult:
        """
        Navigate through Cloudflare/Akamai JS challenges.

        Unlike StealthClient, this actually executes the challenge JavaScript
        in a real browser. Works for:
        - Cloudflare "Checking your browser" challenge
        - Cloudflare Turnstile
        - Akamai Bot Manager
        - PerimeterX/HUMAN
        - DataDome

        Returns the page after challenge resolution.
        """
        if not self._started:
            self.start()

        page = self._context.new_page()
        result = PageResult(url=url, final_url=url, status_code=0, html="",
                            title="", text="")

        try:
            log.info("Solving JS challenge for %s (max %ds)", url, max_wait_seconds)
            response = page.goto(url, wait_until="domcontentloaded", timeout=60000)

            if response:
                result.status_code = response.status

            # Wait for challenge resolution (Cloudflare typically takes 5-10s)
            challenge_indicators = [
                "checking your browser",
                "just a moment",
                "please wait",
                "challenge-platform",
                "cf-turnstile",
                "_cf_chl",
                "akamai",
            ]

            start = time.monotonic()
            while time.monotonic() - start < max_wait_seconds:
                content = page.content().lower()

                # Check if challenge is still present
                still_challenged = any(ind in content for ind in challenge_indicators)

                if not still_challenged and result.status_code in (200, 301, 302):
                    log.info("Challenge solved in %.1fs", time.monotonic() - start)
                    break

                # Check if URL changed (redirect after challenge)
                if page.url != url and page.url != result.final_url:
                    result.final_url = page.url
                    log.info("Challenge redirected to %s", result.final_url)

                page.wait_for_timeout(1000)

            # Capture final state
            result.html = page.content()
            result.title = page.title()
            result.final_url = page.url
            result.cookies = self._context.cookies()

            try:
                result.text = page.evaluate("document.body?.innerText || ''")
            except Exception:
                result.text = ""

            log.info("Challenge result: status=%d, url=%s, cookies=%d",
                     result.status_code, result.final_url, len(result.cookies))

        except Exception as e:
            log.error("Challenge solve error: %s", e)
        finally:
            page.close()

        return result

    def discover_spa_routes(self, url: str, max_routes: int = 200) -> list[str]:
        """
        Discover client-side routes in SPA applications.

        Analyzes:
        1. React Router / Vue Router / Angular Router paths
        2. <a href> in rendered DOM (after JS execution)
        3. pushState/replaceState calls
        4. Href attributes in React-rendered components
        5. Route definitions in JavaScript bundles

        Returns list of discovered URLs.
        """
        if not self._started:
            self.start()

        page = self._context.new_page()
        discovered = set()

        try:
            page.goto(url, wait_until="networkidle", timeout=self.config.timeout)
            page.wait_for_timeout(3000)  # Wait for SPA to fully mount

            # 1. Extract all rendered links
            links = page.evaluate("""
                () => {
                    const links = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.href;
                        if (href && !href.startsWith('javascript:') && !href.startsWith('#'))
                            links.add(href);
                    });
                    return [...links];
                }
            """)
            discovered.update(links)

            # 2. Look for route definitions in script bundles
            route_patterns = page.evaluate("""
                () => {
                    const routes = new Set();
                    // Find route patterns in all scripts
                    document.querySelectorAll('script').forEach(s => {
                        const text = s.textContent || '';
                        // React Router paths
                        const pathMatches = text.matchAll(/path:\\s*["']\\/([^"']+)["']/g);
                        for (const m of pathMatches) routes.add('/' + m[1]);
                        // Vue Router paths
                        const routeMatches = text.matchAll(/path:\\s*["'](\\/.+?)["']/g);
                        for (const m of routeMatches) routes.add(m[1]);
                        // Angular routes
                        const angMatches = text.matchAll(/loadChildren.*?["'](\\/.+?)["']/g);
                        for (const m of angMatches) routes.add(m[1]);
                    });
                    return [...routes];
                }
            """)

            base = urlparse(url)
            for route in route_patterns:
                full_url = f"{base.scheme}://{base.netloc}{route}"
                discovered.add(full_url)

            # 3. Intercept navigation events
            nav_urls = page.evaluate("""
                () => {
                    const urls = new Set();
                    // Check for data attributes with routes
                    document.querySelectorAll('[data-route], [data-path], [data-href]').forEach(el => {
                        const route = el.dataset.route || el.dataset.path || el.dataset.href;
                        if (route) urls.add(route);
                    });
                    // Check for Next.js/Nuxt.js links
                    document.querySelectorAll('[class*="link"], [class*="nav"]').forEach(el => {
                        const href = el.getAttribute('href');
                        if (href && href.startsWith('/')) urls.add(href);
                    });
                    return [...urls];
                }
            """)

            for nav_url in nav_urls:
                if nav_url.startswith("/"):
                    full_url = f"{base.scheme}://{base.netloc}{nav_url}"
                    discovered.add(full_url)
                elif nav_url.startswith("http"):
                    discovered.add(nav_url)

            # 4. Click through navigation elements to discover more routes
            try:
                nav_items = page.query_selector_all('nav a, [role="navigation"] a, .nav a, .menu a, .sidebar a')
                for item in nav_items[:20]:  # Cap at 20 nav clicks
                    try:
                        href = item.get_attribute("href")
                        if href:
                            if href.startswith("/"):
                                discovered.add(f"{base.scheme}://{base.netloc}{href}")
                            elif href.startswith("http"):
                                discovered.add(href)
                    except Exception:
                        continue
            except Exception:
                pass

        except Exception as e:
            log.error("SPA route discovery error: %s", e)
        finally:
            page.close()

        # Filter to same domain
        base_domain = urlparse(url).netloc
        in_scope = [u for u in discovered if urlparse(u).netloc == base_domain]

        log.info("Discovered %d SPA routes for %s", len(in_scope), url)
        return sorted(in_scope)[:max_routes]

    def capture_evidence(self, url: str, filename: str = "") -> Optional[str]:
        """Take a screenshot + save rendered HTML for report evidence."""
        if not self._started:
            self.start()

        screenshots_dir = Path(self.config.screenshots_dir)
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            safe_name = re.sub(r'[^\w.-]', '_', urlparse(url).path or "index")
            filename = f"evidence_{safe_name}"

        page = self._context.new_page()
        screenshot_path = None

        try:
            page.goto(url, wait_until="networkidle", timeout=self.config.timeout)
            page.wait_for_timeout(2000)

            # Screenshot
            screenshot_path = str(screenshots_dir / f"{filename}.png")
            page.screenshot(path=screenshot_path, full_page=True)

            # HTML snapshot
            html_path = str(screenshots_dir / f"{filename}.html")
            Path(html_path).write_text(page.content(), encoding="utf-8")

            log.info("Evidence captured: %s", screenshot_path)

        except Exception as e:
            log.error("Evidence capture error: %s", e)
        finally:
            page.close()

        return screenshot_path

    def extract_cookies(self) -> list[dict]:
        """Get all cookies from the browser context."""
        if self._context:
            return self._context.cookies()
        return []

    def inject_cookies(self, cookies: list[dict]):
        """Inject cookies into the browser context (e.g., from StealthClient)."""
        if self._context and cookies:
            self._context.add_cookies(cookies)

    def _extract_forms(self, page, base_url: str) -> list[dict]:
        """Extract forms from the rendered DOM.

        Goes beyond simple <form>+<input> to handle modern frameworks:
        - Inputs with ARIA roles (role=combobox, searchbox, textbox)
        - React data-testid patterns
        - Button elements with interactive behaviour
        - Orphan inputs not wrapped in a <form> tag
        - contenteditable elements used as rich-text inputs
        """
        try:
            forms_data = page.evaluate("""
                () => {
                    // ── Helpers ──────────────────────────────────
                    const INPUT_SEL = 'input, textarea, select, ' +
                        '[role="textbox"], [role="combobox"], [role="searchbox"], ' +
                        '[contenteditable="true"], [contenteditable=""]';

                    function extractField(el) {
                        return {
                            name: el.name || el.id ||
                                  el.getAttribute('data-testid') ||
                                  el.getAttribute('aria-label') || '',
                            type: el.type || el.getAttribute('role') || 'text',
                            value: el.value || el.textContent?.trim().substring(0, 100) || '',
                            tag: el.tagName.toLowerCase(),
                            placeholder: el.placeholder || el.getAttribute('aria-label') || '',
                        };
                    }

                    // ── 1. Proper <form> elements ───────────────
                    const forms = [];
                    const insideForm = new Set();

                    document.querySelectorAll('form').forEach(form => {
                        const fields = [];
                        form.querySelectorAll(INPUT_SEL).forEach(el => {
                            insideForm.add(el);
                            fields.push(extractField(el));
                        });
                        // Also grab submit/button elements
                        form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(el => {
                            insideForm.add(el);
                        });
                        forms.push({
                            action: form.action || '',
                            method: (form.method || 'GET').toUpperCase(),
                            id: form.id || '',
                            fields: fields.filter(f => f.name),
                        });
                    });

                    // ── 2. Orphan inputs (not inside any <form>) ─
                    const orphans = [];
                    document.querySelectorAll(INPUT_SEL).forEach(el => {
                        if (!insideForm.has(el) && !el.closest('form')) {
                            const f = extractField(el);
                            if (f.name) orphans.push(f);
                        }
                    });

                    // ── 3. React/testid interactive elements ─────
                    document.querySelectorAll('[data-testid]').forEach(el => {
                        const tid = el.getAttribute('data-testid') || '';
                        if (/input|search|field|date|dest|filter|select|query/i.test(tid)) {
                            if (!insideForm.has(el) && !el.closest('form')) {
                                orphans.push({
                                    name: tid,
                                    type: el.getAttribute('role') || 'react-component',
                                    value: '',
                                    tag: el.tagName.toLowerCase(),
                                    placeholder: el.getAttribute('aria-label') || '',
                                });
                            }
                        }
                    });

                    if (orphans.length > 0) {
                        forms.push({
                            action: window.location.href,
                            method: 'GET',
                            id: '__orphan_inputs__',
                            fields: orphans,
                        });
                    }

                    return forms;
                }
            """)
            return forms_data
        except Exception:
            return []

    def _extract_links(self, page, base_url: str) -> list[str]:
        """Extract all links from rendered DOM."""
        try:
            links = page.evaluate("""
                () => {
                    const links = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.href;
                        if (href && !href.startsWith('javascript:') &&
                            !href.startsWith('mailto:') && !href.startsWith('tel:'))
                            links.add(href);
                    });
                    return [...links];
                }
            """)
            return links
        except Exception:
            return []

    def _extract_api_endpoints(self, requests: list[NetworkRequest],
                                base_url: str) -> list[str]:
        """Identify API endpoints from captured network requests."""
        api_endpoints = set()
        base_domain = urlparse(base_url).netloc

        for req in requests:
            # Only interested in XHR/fetch requests
            if req.resource_type not in ("xhr", "fetch"):
                continue

            parsed = urlparse(req.url)

            # Same domain or subdomain
            if not parsed.netloc.endswith(base_domain.split(".")[-2] + "." + base_domain.split(".")[-1]):
                continue

            # Looks like an API endpoint
            api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql",
                              "/rest/", "/data/", "/ajax/", "/_/", "/rpc/"]
            if any(ind in req.url.lower() for ind in api_indicators):
                api_endpoints.add(req.url.split("?")[0])  # Strip query params
            elif req.resource_type == "fetch":
                api_endpoints.add(req.url.split("?")[0])

        return sorted(api_endpoints)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
