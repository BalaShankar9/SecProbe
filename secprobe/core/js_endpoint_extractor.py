"""
JavaScript Endpoint Extractor for SPA/API discovery.

Parses JavaScript source code to find API endpoints from fetch(), axios,
XHR, jQuery calls, string literals, and framework route definitions.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DiscoveredEndpoint:
    """Represents an API endpoint discovered from JavaScript source."""

    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    source: str = ""
    confidence: float = 0.5


# Static asset extensions to filter out
_STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp",
    ".css", ".less", ".scss", ".sass",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".js.map", ".css.map",
    ".mp3", ".mp4", ".webm", ".ogg", ".wav",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
)

# Patterns that indicate static asset paths
_STATIC_PATH_PREFIXES = ("/assets/", "/static/", "/styles/", "/fonts/", "/images/", "/img/")


def _is_static_asset(url: str) -> bool:
    """Check if a URL points to a static asset."""
    url_lower = url.lower()
    # Check extensions
    for ext in _STATIC_EXTENSIONS:
        if url_lower.endswith(ext):
            return True
    # Check favicon specifically
    if "favicon" in url_lower:
        return True
    return False


class JSEndpointExtractor:
    """Extracts API endpoints from JavaScript source code."""

    def __init__(self):
        self._patterns = self._compile_patterns()

    @staticmethod
    def _compile_patterns():
        """Compile regex patterns for endpoint extraction."""
        return {
            # fetch("/path") or fetch('/path') with optional options
            "fetch": re.compile(
                r"""fetch\(\s*["']([^"']+)["']"""
                r"""(?:\s*,\s*\{[^}]*method\s*:\s*["'](\w+)["'][^}]*\})?""",
                re.DOTALL,
            ),
            # axios.get/post/put/delete("/path") or axios("/path")
            "axios_method": re.compile(
                r"""axios\.(get|post|put|delete|patch|head|options)\(\s*["']([^"']+)["']""",
                re.IGNORECASE,
            ),
            "axios_direct": re.compile(
                r"""axios\(\s*["']([^"']+)["']""",
            ),
            # xhr.open("METHOD", "/path")
            "xhr": re.compile(
                r"""\.open\(\s*["'](\w+)["']\s*,\s*["']([^"']+)["']""",
            ),
            # $.get("/path"), $.post("/path"), $.ajax({url: "/path"})
            "jquery_shorthand": re.compile(
                r"""\$\.(get|post)\(\s*["']([^"']+)["']""",
            ),
            "jquery_ajax": re.compile(
                r"""\$\.ajax\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']""",
                re.DOTALL,
            ),
            # String literals matching API patterns: /api/*, /rest/*, /graphql, /v1/*, /v2/*
            "api_strings": re.compile(
                r"""["'`](\/(?:api|rest|graphql|v[0-9]+)(?:\/[a-zA-Z0-9_\-\.]*)*)\/?["'`]""",
            ),
            # Template literal paths with interpolation: `${host}/rest/products/search?q=${var}`
            "template_paths": re.compile(
                r"""(\/(?:api|rest|graphql|v[0-9]+)(?:\/[a-zA-Z0-9_\-\.]+)+)(?:\?[^`'"]*)?""",
            ),
            # Angular/React route definitions: {path: 'something', component: ...}
            "routes": re.compile(
                r"""\{\s*path\s*:\s*["']([^"']+)["']\s*,\s*component\s*:""",
            ),
        }

    def extract(self, js_source: str) -> list[DiscoveredEndpoint]:
        """Extract API endpoints from JavaScript source code.

        Args:
            js_source: JavaScript source code string.

        Returns:
            List of DiscoveredEndpoint objects found in the source.
        """
        if not js_source or not js_source.strip():
            return []

        seen = set()  # (url, method) dedup
        endpoints = []

        def _add(url: str, method: str = "GET", source: str = "", confidence: float = 0.5):
            if _is_static_asset(url):
                return
            key = (url, method.upper())
            if key not in seen:
                seen.add(key)
                endpoints.append(DiscoveredEndpoint(
                    url=url,
                    method=method.upper(),
                    source=source,
                    confidence=confidence,
                ))

        # fetch() calls
        for m in self._patterns["fetch"].finditer(js_source):
            url = m.group(1)
            method = m.group(2).upper() if m.group(2) else "GET"
            _add(url, method, source="fetch", confidence=0.9)

        # Also catch fetch calls where method is in a separate match
        # Handle fetch with method in options that our main regex might miss
        fetch_url_pattern = re.compile(r"""fetch\(\s*["']([^"']+)["']""")
        fetch_method_pattern = re.compile(
            r"""fetch\(\s*["']([^"']+)["']\s*,\s*\{[^}]*method\s*:\s*["'](\w+)["']""",
            re.DOTALL,
        )
        for m in fetch_method_pattern.finditer(js_source):
            url = m.group(1)
            method = m.group(2).upper()
            _add(url, method, source="fetch", confidence=0.9)

        # axios.method() calls
        for m in self._patterns["axios_method"].finditer(js_source):
            method = m.group(1).upper()
            url = m.group(2)
            _add(url, method, source="axios", confidence=0.9)

        # axios() direct calls
        for m in self._patterns["axios_direct"].finditer(js_source):
            url = m.group(1)
            _add(url, "GET", source="axios", confidence=0.8)

        # XHR calls
        for m in self._patterns["xhr"].finditer(js_source):
            method = m.group(1).upper()
            url = m.group(2)
            _add(url, method, source="xhr", confidence=0.9)

        # jQuery shorthand
        for m in self._patterns["jquery_shorthand"].finditer(js_source):
            method = m.group(1).upper()
            url = m.group(2)
            _add(url, method, source="jquery", confidence=0.9)

        # jQuery ajax
        for m in self._patterns["jquery_ajax"].finditer(js_source):
            url = m.group(1)
            _add(url, "GET", source="jquery_ajax", confidence=0.8)

        # API string literals
        for m in self._patterns["api_strings"].finditer(js_source):
            url = m.group(1)
            _add(url, "GET", source="string_literal", confidence=0.5)

        # Template literal paths (e.g., `${host}/rest/products/search?q=${query}`)
        for m in self._patterns["template_paths"].finditer(js_source):
            url = m.group(1)
            # Strip query params with template variables
            clean_url = re.sub(r'\?.*$', '', url)
            _add(clean_url, "GET", source="template_literal", confidence=0.6)
            # Also add with query param placeholder if there was one
            if '?' in url:
                param_part = url.split('?', 1)[1]
                param_name = re.sub(r'=\$\{[^}]+\}', '=test', param_part)
                param_name = re.sub(r'=\$.*$', '=test', param_name)
                _add(f"{clean_url}?{param_name}", "GET", source="template_literal", confidence=0.6)

        # Angular/React routes
        for m in self._patterns["routes"].finditer(js_source):
            path = m.group(1)
            if not path.startswith("/"):
                path = "/" + path
            _add(path, "GET", source="route_definition", confidence=0.7)

        return endpoints

    def extract_from_html(self, html: str) -> list[DiscoveredEndpoint]:
        """Extract endpoints from inline <script> tags in HTML.

        Args:
            html: HTML source containing script tags.

        Returns:
            List of DiscoveredEndpoint objects found in inline scripts.
        """
        if not html:
            return []

        endpoints = []
        seen = set()

        # Extract inline script content
        script_pattern = re.compile(
            r"<script[^>]*>([^<]+)</script>",
            re.DOTALL | re.IGNORECASE,
        )
        for m in script_pattern.finditer(html):
            src_attr = html[m.start():m.end()]
            # Skip external scripts (those with src= attribute only, no inline content)
            script_content = m.group(1).strip()
            if script_content:
                found = self.extract(script_content)
                for ep in found:
                    key = (ep.url, ep.method)
                    if key not in seen:
                        seen.add(key)
                        ep.source = f"inline_script:{ep.source}"
                        endpoints.append(ep)

        return endpoints

    def extract_from_url(self, js_url: str, js_content: str) -> list[DiscoveredEndpoint]:
        """Extract endpoints from a fetched JavaScript file.

        Args:
            js_url: The URL the JS was fetched from (for source tracking).
            js_content: The JavaScript source code content.

        Returns:
            List of DiscoveredEndpoint objects found in the JS file.
        """
        endpoints = self.extract(js_content)
        for ep in endpoints:
            ep.source = f"{js_url}:{ep.source}"
        return endpoints
