"""
Web Crawler / Spider Engine.

Discovers the attack surface of a target by crawling:
    - HTML links (<a href>, <form action>, <script src>, etc.)
    - Form inputs (parameters, methods, actions)
    - JavaScript endpoints (API calls, fetch/XHR URLs)
    - Robots.txt and sitemap.xml
    - Redirect chains

Produces a structured AttackSurface with all discovered:
    - URLs
    - Forms (with fields, methods)
    - Parameters (GET and POST)
    - API endpoints
"""

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs

from secprobe.core.logger import get_logger

log = get_logger("crawler")


@dataclass
class FormData:
    """A discovered HTML form."""
    action: str
    method: str  # GET or POST
    fields: list[dict] = field(default_factory=list)  # [{"name": ..., "type": ..., "value": ...}]
    url: str = ""  # Page where the form was found

    @property
    def field_names(self) -> list[str]:
        return [f["name"] for f in self.fields if f.get("name")]


@dataclass
class Endpoint:
    """A discovered URL endpoint with its parameters."""
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    source: str = ""  # Where this was discovered (link, form, js, sitemap, etc.)
    content_type: str = ""


@dataclass
class AttackSurface:
    """The complete attack surface discovered by crawling."""
    urls: set = field(default_factory=set)
    forms: list[FormData] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    parameters: set = field(default_factory=set)  # All unique parameter names found
    js_files: set = field(default_factory=set)
    emails: set = field(default_factory=set)
    comments: list[str] = field(default_factory=list)  # HTML comments (often leak info)
    technologies: set = field(default_factory=set)

    @property
    def total_inputs(self) -> int:
        return len(self.parameters) + sum(len(f.fields) for f in self.forms)


class Crawler:
    """
    Web crawler that discovers the attack surface of a target.

    Usage:
        crawler = Crawler(http_client, base_url, max_depth=3, max_pages=100)
        surface = crawler.crawl()
    """

    def __init__(self, http_client, base_url: str, *,
                 max_depth: int = 3,
                 max_pages: int = 100,
                 scope_regex: str = "",
                 exclude_regex: str = r"\.(jpg|jpeg|png|gif|svg|ico|css|woff2?|ttf|eot|mp[34]|avi|mov|pdf|zip|gz|tar)$"):
        self.client = http_client
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.scope_regex = scope_regex
        self.exclude_pattern = re.compile(exclude_regex, re.IGNORECASE) if exclude_regex else None

        parsed = urlparse(self.base_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        self.surface = AttackSurface()
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()  # (url, depth)

    def crawl(self) -> AttackSurface:
        """Execute the crawl and return the discovered attack surface."""
        log.info("Starting crawl of %s (max_depth=%d, max_pages=%d)",
                 self.base_url, self.max_depth, self.max_pages)

        # Seed with initial URL
        self._queue.append((self.base_url, 0))

        # Also seed with robots.txt and sitemap
        self._parse_robots()
        self._parse_sitemap()

        while self._queue and len(self._visited) < self.max_pages:
            url, depth = self._queue.popleft()

            if url in self._visited:
                continue
            if depth > self.max_depth:
                continue
            if not self._in_scope(url):
                continue
            if self.exclude_pattern and self.exclude_pattern.search(url):
                continue

            self._visited.add(url)
            self.surface.urls.add(url)

            try:
                resp = self.client.get(url, allow_redirects=True)
                content_type = resp.headers.get("Content-Type", "")

                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue

                html = resp.text
                self._extract_links(html, url, depth)
                self._extract_forms(html, url)
                self._extract_js_endpoints(html, url)
                self._extract_params_from_url(url)
                self._extract_comments(html)
                self._extract_emails(html)

            except Exception as e:
                log.debug("Crawl error on %s: %s", url, e)
                continue

        log.info("Crawl complete: %d URLs, %d forms, %d parameters, %d JS files",
                 len(self.surface.urls), len(self.surface.forms),
                 len(self.surface.parameters), len(self.surface.js_files))

        return self.surface

    def _in_scope(self, url: str) -> bool:
        """Check if URL is within scope."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        # Must be same domain or subdomain
        if not parsed.netloc.endswith(self.base_domain.split(":")[-1].split(".")[-2] + "." +
                                       self.base_domain.split(":")[-1].split(".")[-1]):
            # Simplified: just check if it's the same netloc
            if parsed.netloc != self.base_domain:
                return False
        if self.scope_regex:
            return bool(re.search(self.scope_regex, url))
        return True

    def _extract_links(self, html: str, page_url: str, current_depth: int):
        """Extract links from HTML."""
        # <a href="...">
        for match in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)', html, re.IGNORECASE):
            link = self._resolve_url(match.group(1), page_url)
            if link and link not in self._visited:
                self._queue.append((link, current_depth + 1))

        # <script src="...">
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)', html, re.IGNORECASE):
            js_url = self._resolve_url(match.group(1), page_url)
            if js_url:
                self.surface.js_files.add(js_url)

        # <iframe src="...">
        for match in re.finditer(r'<iframe[^>]+src=["\']([^"\']+)', html, re.IGNORECASE):
            link = self._resolve_url(match.group(1), page_url)
            if link and link not in self._visited:
                self._queue.append((link, current_depth + 1))

        # <link href="..."> (for discovery, not crawling)
        for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)', html, re.IGNORECASE):
            link = self._resolve_url(match.group(1), page_url)
            if link:
                self.surface.urls.add(link)

        # Meta refresh
        for match in re.finditer(r'<meta[^>]+content=["\'][^"\']*url=([^"\';\s]+)', html, re.IGNORECASE):
            link = self._resolve_url(match.group(1), page_url)
            if link and link not in self._visited:
                self._queue.append((link, current_depth + 1))

    def _extract_forms(self, html: str, page_url: str):
        """Extract form actions and input fields."""
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.IGNORECASE | re.DOTALL,
        )
        action_pattern = re.compile(r'action=["\']([^"\']*)', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']*)', re.IGNORECASE)
        input_pattern = re.compile(
            r'<(?:input|textarea|select)[^>]*?'
            r'(?:name=["\']([^"\']+)["\'])?[^>]*?'
            r'(?:type=["\']([^"\']+)["\'])?[^>]*?'
            r'(?:value=["\']([^"\']*)["\'])?',
            re.IGNORECASE,
        )

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            full_form = form_match.group(1)

            # Extract action
            action_match = action_pattern.search(form_html)
            action = self._resolve_url(
                action_match.group(1) if action_match else "", page_url
            )

            # Extract method
            method_match = method_pattern.search(form_html)
            method = (method_match.group(1).upper() if method_match else "GET")

            # Extract fields
            fields = []
            for inp in input_pattern.finditer(form_html):
                name = inp.group(1) or ""
                input_type = inp.group(2) or "text"
                value = inp.group(3) or ""
                if name:
                    fields.append({"name": name, "type": input_type, "value": value})
                    self.surface.parameters.add(name)

            # Also capture hidden inputs that the regex might have missed
            for hidden in re.finditer(r'name=["\']([^"\']+)["\']', full_form):
                param_name = hidden.group(1)
                self.surface.parameters.add(param_name)

            form = FormData(
                action=action or page_url,
                method=method,
                fields=fields,
                url=page_url,
            )
            self.surface.forms.append(form)

            # Create endpoint for the form
            self.surface.endpoints.append(Endpoint(
                url=form.action,
                method=form.method,
                params={f["name"]: f["value"] for f in fields if f.get("name")},
                source=f"form@{page_url}",
            ))

    def _extract_js_endpoints(self, html: str, page_url: str):
        """Extract API endpoints and URLs from inline JavaScript."""
        # Patterns commonly used in JS for API calls
        js_url_patterns = [
            r'(?:fetch|axios\.get|axios\.post|\$\.ajax|\$\.get|\$\.post)\s*\(\s*["\']([^"\']+)',
            r'(?:url|endpoint|api|href|action|src)\s*[:=]\s*["\']([^"\']+)',
            r'(?:XMLHttpRequest|\.open)\s*\([^,]*,\s*["\']([^"\']+)',
            r'/api/[a-zA-Z0-9/_-]+',
            r'/v[0-9]+/[a-zA-Z0-9/_-]+',
        ]

        for pattern in js_url_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                path = match.group(1) if match.lastindex else match.group(0)
                if path.startswith(("/", "http")):
                    url = self._resolve_url(path, page_url)
                    if url and self._in_scope(url):
                        self.surface.endpoints.append(Endpoint(
                            url=url, source="javascript", method="GET",
                        ))
                        self.surface.urls.add(url)

        # Extract inline JS variable assignments with URLs
        for match in re.finditer(r'["\'](/[a-zA-Z0-9._/-]+\?[^"\']+)["\']', html):
            url = self._resolve_url(match.group(1), page_url)
            if url:
                self._extract_params_from_url(url)
                self.surface.urls.add(url)

    def _extract_params_from_url(self, url: str):
        """Extract query parameters from a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for key in params:
            self.surface.parameters.add(key)

    def _extract_comments(self, html: str):
        """Extract HTML comments (often leak sensitive info)."""
        for match in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
            comment = match.group(1).strip()
            if len(comment) > 10:  # Skip trivial comments
                self.surface.comments.append(comment[:500])

    def _extract_emails(self, html: str):
        """Extract email addresses."""
        for match in re.finditer(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html):
            self.surface.emails.add(match.group(0))

    def _parse_robots(self):
        """Parse robots.txt for disallowed paths (juicy targets)."""
        try:
            resp = self.client.get(f"{self.base_url}/robots.txt")
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                        parts = line.split(":", 1)
                        path = parts[1].strip()
                        if path.startswith("http"):
                            self._queue.append((path, 1))
                        elif path.startswith("/"):
                            url = f"{self.base_url}{path}"
                            self._queue.append((url, 1))
                            self.surface.endpoints.append(Endpoint(
                                url=url, source="robots.txt",
                            ))
                log.info("Parsed robots.txt — added %d paths", len(self.surface.endpoints))
        except Exception:
            pass

    def _parse_sitemap(self):
        """Parse sitemap.xml for URLs."""
        try:
            resp = self.client.get(f"{self.base_url}/sitemap.xml")
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                for match in re.finditer(r'<loc>([^<]+)</loc>', resp.text):
                    url = match.group(1).strip()
                    if self._in_scope(url):
                        self._queue.append((url, 1))
                        self.surface.endpoints.append(Endpoint(
                            url=url, source="sitemap.xml",
                        ))
                log.info("Parsed sitemap.xml")
        except Exception:
            pass

    def _resolve_url(self, href: str, base: str) -> str | None:
        """Resolve a relative URL against a base URL."""
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return None
        try:
            resolved = urljoin(base, href)
            # Remove fragments
            parsed = urlparse(resolved)
            clean = parsed._replace(fragment="").geturl()
            return clean
        except Exception:
            return None
