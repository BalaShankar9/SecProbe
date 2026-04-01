"""
Insertion Point Engine — the foundation of accurate vulnerability scanning.

Burp Suite's #1 advantage is systematic insertion point management:
instead of testing all parameters at once, it identifies every possible
injection location and tests each ONE AT A TIME while holding all others
at their baseline values.

This module provides:
  - InsertionPoint: a single testable location (query param, path segment,
    cookie, header, JSON field, POST field, multipart field)
  - InsertionPointDiscovery: auto-discover all insertion points from a URL,
    response, forms, cookies, and API specs
  - inject(): apply a payload to ONE insertion point, return the full request spec

Usage in scanners:
    from secprobe.core.insertion_points import InsertionPointDiscovery, InsertionType

    discovery = InsertionPointDiscovery(http_client)
    points = discovery.discover(url, response)

    for point in points:
        request = point.inject(payload)
        resp = http_client.request(**request)
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin


class InsertionType(Enum):
    """Where the injection point lives in the HTTP request."""
    QUERY_PARAM = "query_param"
    PATH_SEGMENT = "path_segment"
    POST_PARAM = "post_param"
    JSON_FIELD = "json_field"
    COOKIE = "cookie"
    HEADER = "header"
    MULTIPART_FIELD = "multipart_field"
    URL_FILENAME = "url_filename"
    XML_ELEMENT = "xml_element"


@dataclass
class RequestSpec:
    """Fully specified HTTP request ready to send."""
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    data: Optional[dict[str, str]] = None
    json_body: Optional[dict] = None
    body: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class InsertionPoint:
    """
    A single testable injection location.

    Each insertion point knows:
      - WHERE it is (type + name)
      - What the BASELINE value is (original value without payload)
      - How to build a complete request with the payload injected ONLY here
    """
    type: InsertionType
    name: str                           # param name, header name, path index, etc.
    original_value: str                 # baseline value
    base_url: str                       # the URL this point belongs to
    method: str = "GET"                 # HTTP method
    _baseline_params: dict = field(default_factory=dict)    # all query params at baseline
    _baseline_headers: dict = field(default_factory=dict)   # all headers at baseline
    _baseline_cookies: dict = field(default_factory=dict)   # all cookies at baseline
    _baseline_data: Optional[dict] = None                   # POST form data at baseline
    _baseline_json: Optional[dict] = None                   # JSON body at baseline
    _path_segments: list = field(default_factory=list)       # URL path segments
    _segment_index: int = -1                                 # which segment to inject

    @property
    def display_name(self) -> str:
        """Human-readable description of this insertion point."""
        return f"{self.type.value}:{self.name}"

    def inject(self, payload: str, mode: str = "append") -> RequestSpec:
        """
        Build a complete HTTP request with payload injected ONLY at this point.

        All other parameters/headers/cookies remain at their baseline values.

        Args:
            payload: The attack payload to inject
            mode: "append" (add to original value), "replace" (replace entirely),
                  "insert" (prepend payload to original value)

        Returns:
            RequestSpec ready to send via http_client
        """
        value = self._apply_payload(payload, mode)

        if self.type == InsertionType.QUERY_PARAM:
            return self._inject_query_param(value)
        elif self.type == InsertionType.PATH_SEGMENT:
            return self._inject_path_segment(value)
        elif self.type == InsertionType.POST_PARAM:
            return self._inject_post_param(value)
        elif self.type == InsertionType.JSON_FIELD:
            return self._inject_json_field(value)
        elif self.type == InsertionType.COOKIE:
            return self._inject_cookie(value)
        elif self.type == InsertionType.HEADER:
            return self._inject_header(value)
        elif self.type == InsertionType.URL_FILENAME:
            return self._inject_filename(value)
        else:
            # Fallback: treat as query param
            return self._inject_query_param(value)

    def _apply_payload(self, payload: str, mode: str) -> str:
        if mode == "replace":
            return payload
        elif mode == "insert":
            return payload + self.original_value
        else:  # append
            return self.original_value + payload

    def _inject_query_param(self, value: str) -> RequestSpec:
        """Inject into one query parameter, keep all others at baseline."""
        parsed = urlparse(self.base_url)
        params = dict(self._baseline_params)  # copy baseline
        params[self.name] = value             # override ONE param
        new_query = urlencode(params, doseq=False)
        new_url = urlunparse(parsed._replace(query=new_query))
        return RequestSpec(
            method=self.method,
            url=new_url,
            headers=dict(self._baseline_headers),
            cookies=dict(self._baseline_cookies),
        )

    def _inject_path_segment(self, value: str) -> RequestSpec:
        """Inject into one path segment."""
        parsed = urlparse(self.base_url)
        segments = list(self._path_segments)
        if 0 <= self._segment_index < len(segments):
            segments[self._segment_index] = value
        new_path = "/" + "/".join(segments)
        # Preserve query string
        new_url = urlunparse(parsed._replace(path=new_path))
        return RequestSpec(
            method=self.method,
            url=new_url,
            headers=dict(self._baseline_headers),
            cookies=dict(self._baseline_cookies),
        )

    def _inject_post_param(self, value: str) -> RequestSpec:
        """Inject into one POST form parameter."""
        data = dict(self._baseline_data) if self._baseline_data else {}
        data[self.name] = value
        return RequestSpec(
            method="POST",
            url=self.base_url,
            headers=dict(self._baseline_headers),
            cookies=dict(self._baseline_cookies),
            data=data,
            content_type="application/x-www-form-urlencoded",
        )

    def _inject_json_field(self, value: str) -> RequestSpec:
        """Inject into one JSON body field (supports nested paths with dot notation)."""
        json_body = deepcopy(self._baseline_json) if self._baseline_json else {}
        # Support dot notation: "user.name" -> json_body["user"]["name"]
        keys = self.name.split(".")
        target = json_body
        for key in keys[:-1]:
            if isinstance(target, dict) and key in target:
                target = target[key]
            else:
                break
        if isinstance(target, dict):
            target[keys[-1]] = value
        return RequestSpec(
            method=self.method if self.method != "GET" else "POST",
            url=self.base_url,
            headers=dict(self._baseline_headers),
            cookies=dict(self._baseline_cookies),
            json_body=json_body,
            content_type="application/json",
        )

    def _inject_cookie(self, value: str) -> RequestSpec:
        """Inject into one cookie, keep all others at baseline."""
        cookies = dict(self._baseline_cookies)
        cookies[self.name] = value
        return RequestSpec(
            method=self.method,
            url=self.base_url,
            headers=dict(self._baseline_headers),
            cookies=cookies,
        )

    def _inject_header(self, value: str) -> RequestSpec:
        """Inject into one HTTP header."""
        headers = dict(self._baseline_headers)
        headers[self.name] = value
        return RequestSpec(
            method=self.method,
            url=self.base_url,
            headers=headers,
            cookies=dict(self._baseline_cookies),
        )

    def _inject_filename(self, value: str) -> RequestSpec:
        """Inject into the URL filename (last path segment)."""
        parsed = urlparse(self.base_url)
        path_parts = parsed.path.rsplit("/", 1)
        if len(path_parts) == 2:
            new_path = path_parts[0] + "/" + value
        else:
            new_path = "/" + value
        new_url = urlunparse(parsed._replace(path=new_path))
        return RequestSpec(
            method=self.method,
            url=new_url,
            headers=dict(self._baseline_headers),
            cookies=dict(self._baseline_cookies),
        )


# ═══════════════════════════════════════════════════════════════════
#  Insertion Point Discovery
# ═══════════════════════════════════════════════════════════════════

# Path segments that look like injectable values (IDs, slugs, filenames)
_ID_PATTERNS = re.compile(
    r'^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|'
    r'[a-z0-9_-]{2,30}\.\w{2,5}|[A-Za-z0-9_-]{20,})$'
)

# Headers worth testing for injection (reduced to most commonly injectable)
INJECTABLE_HEADERS = [
    "Referer", "X-Forwarded-For", "User-Agent", "Cookie", "X-Custom-Header",
]


class InsertionPointDiscovery:
    """
    Automatically discover all insertion points from a target.

    Examines:
      1. Query string parameters
      2. REST-style path segments (numeric IDs, UUIDs, filenames)
      3. POST form fields (from HTML forms)
      4. JSON body fields (from API discovery)
      5. Cookies (from response Set-Cookie headers)
      6. HTTP headers (injectable request headers)
    """

    def __init__(self, http_client=None, include_headers: bool = True,
                 include_cookies: bool = True, include_paths: bool = True):
        self.http_client = http_client
        self.include_headers = include_headers
        self.include_cookies = include_cookies
        self.include_paths = include_paths

    def discover(self, url: str, response=None, forms: list[dict] | None = None,
                 json_bodies: list[dict] | None = None,
                 extra_cookies: dict | None = None) -> list[InsertionPoint]:
        """
        Discover all insertion points for a URL.

        Args:
            url: Target URL
            response: HTTP response object (for cookie/form extraction)
            forms: Pre-discovered forms [{"action", "method", "fields"}]
            json_bodies: JSON request bodies to test
            extra_cookies: Additional cookies to test

        Returns:
            List of InsertionPoint objects, each representing one testable location
        """
        points: list[InsertionPoint] = []
        parsed = urlparse(url)

        # Shared baseline state
        baseline_params = {}
        if parsed.query:
            raw_params = parse_qs(parsed.query, keep_blank_values=True)
            baseline_params = {k: v[0] if v else "" for k, v in raw_params.items()}

        baseline_headers = {}
        baseline_cookies = {}

        # Extract cookies from response
        if response is not None:
            try:
                if hasattr(response, 'cookies'):
                    for name, value in response.cookies.items():
                        baseline_cookies[name] = value
                # Also check Set-Cookie headers
                set_cookies = response.headers.get("Set-Cookie", "")
                if set_cookies:
                    for part in set_cookies.split(","):
                        if "=" in part:
                            cookie_part = part.strip().split(";")[0]
                            if "=" in cookie_part:
                                cname, cvalue = cookie_part.split("=", 1)
                                baseline_cookies[cname.strip()] = cvalue.strip()
            except Exception:
                pass

        if extra_cookies:
            baseline_cookies.update(extra_cookies)

        # ── 1. Query Parameters ──────────────────────────────────
        for param_name, param_value in baseline_params.items():
            points.append(InsertionPoint(
                type=InsertionType.QUERY_PARAM,
                name=param_name,
                original_value=param_value,
                base_url=url,
                method="GET",
                _baseline_params=baseline_params,
                _baseline_headers=baseline_headers,
                _baseline_cookies=baseline_cookies,
            ))

        # ── 2. Path Segments ─────────────────────────────────────
        if self.include_paths:
            path = parsed.path.strip("/")
            if path:
                segments = path.split("/")
                for i, segment in enumerate(segments):
                    # Only test segments that look like dynamic values
                    if self._is_injectable_segment(segment):
                        points.append(InsertionPoint(
                            type=InsertionType.PATH_SEGMENT,
                            name=f"path[{i}]:{segment}",
                            original_value=segment,
                            base_url=url,
                            method="GET",
                            _baseline_params=baseline_params,
                            _baseline_headers=baseline_headers,
                            _baseline_cookies=baseline_cookies,
                            _path_segments=segments,
                            _segment_index=i,
                        ))

        # ── 3. POST Form Fields ──────────────────────────────────
        discovered_forms = forms or []
        if response is not None and not forms:
            discovered_forms = self._extract_forms(url, response)

        for form in discovered_forms:
            action = form.get("action", url)
            method = form.get("method", "POST").upper()
            fields = form.get("fields", {})
            for field_name, field_value in fields.items():
                points.append(InsertionPoint(
                    type=InsertionType.POST_PARAM,
                    name=field_name,
                    original_value=field_value or "test",
                    base_url=action,
                    method=method,
                    _baseline_params=baseline_params,
                    _baseline_headers=baseline_headers,
                    _baseline_cookies=baseline_cookies,
                    _baseline_data=fields,
                ))

        # ── 4. JSON Body Fields ──────────────────────────────────
        if json_bodies:
            for json_body in json_bodies:
                json_points = self._extract_json_fields(url, json_body, baseline_headers, baseline_cookies)
                points.extend(json_points)

        # ── 5. Cookies ───────────────────────────────────────────
        if self.include_cookies and baseline_cookies:
            for cookie_name, cookie_value in baseline_cookies.items():
                # Skip common non-injectable cookies
                if cookie_name.lower() in ("__cfduid", "_ga", "_gid", "_gat",
                                           "__utm", "fbp", "_fbp"):
                    continue
                points.append(InsertionPoint(
                    type=InsertionType.COOKIE,
                    name=cookie_name,
                    original_value=cookie_value,
                    base_url=url,
                    method="GET",
                    _baseline_params=baseline_params,
                    _baseline_headers=baseline_headers,
                    _baseline_cookies=baseline_cookies,
                ))

        # ── 6. HTTP Headers ──────────────────────────────────────
        if self.include_headers:
            for header_name in INJECTABLE_HEADERS:
                points.append(InsertionPoint(
                    type=InsertionType.HEADER,
                    name=header_name,
                    original_value="",
                    base_url=url,
                    method="GET",
                    _baseline_params=baseline_params,
                    _baseline_headers=baseline_headers,
                    _baseline_cookies=baseline_cookies,
                ))

        return points

    def discover_from_urls(self, urls: list[str], responses: dict | None = None,
                           forms: list[dict] | None = None) -> list[InsertionPoint]:
        """
        Discover insertion points from multiple URLs.

        Deduplicates: same (type, name, base_endpoint) = one point.
        """
        all_points: list[InsertionPoint] = []
        seen = set()

        for url in urls:
            resp = responses.get(url) if responses else None
            points = self.discover(url, response=resp, forms=forms)
            for pt in points:
                key = (pt.type, pt.name, pt.base_url.split("?")[0])
                if key not in seen:
                    seen.add(key)
                    all_points.append(pt)

        return all_points

    def _is_injectable_segment(self, segment: str) -> bool:
        """Check if a path segment looks like a dynamic/injectable value."""
        if not segment:
            return False
        # Numeric IDs
        if segment.isdigit():
            return True
        # UUIDs
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment, re.I):
            return True
        # Filenames with extensions
        if re.match(r'^[a-zA-Z0-9_-]+\.\w{2,5}$', segment):
            return True
        # Base64-looking tokens (20+ chars, mixed case + digits)
        if len(segment) >= 20 and re.match(r'^[A-Za-z0-9_-]+$', segment):
            return True
        return False

    def _extract_forms(self, base_url: str, response) -> list[dict]:
        """Extract HTML forms from a response."""
        forms = []
        try:
            html = response.text if hasattr(response, 'text') else str(response)
            form_pattern = re.compile(
                r'<form[^>]*?(?:action=["\']?([^"\'>\s]*)["\']?)?[^>]*?'
                r'(?:method=["\']?(\w+)["\']?)?[^>]*>(.*?)</form>',
                re.IGNORECASE | re.DOTALL,
            )
            for match in form_pattern.finditer(html):
                action = match.group(1) or base_url
                if not action.startswith("http"):
                    action = urljoin(base_url, action)
                method = match.group(2) or "GET"
                form_html = match.group(3)
                fields = {}
                # Input fields
                for inp in re.finditer(
                    r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']'
                    r'(?:[^>]*value=["\']([^"\']*)["\'])?',
                    form_html, re.IGNORECASE
                ):
                    fields[inp.group(1)] = inp.group(2) or ""
                if fields:
                    forms.append({"action": action, "method": method.upper(), "fields": fields})
        except Exception:
            pass
        return forms

    def _extract_json_fields(self, url: str, json_body: dict,
                             baseline_headers: dict,
                             baseline_cookies: dict,
                             prefix: str = "") -> list[InsertionPoint]:
        """Recursively extract all JSON fields as insertion points."""
        points = []
        for key, value in json_body.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                # Recurse into nested objects
                points.extend(self._extract_json_fields(
                    url, value, baseline_headers, baseline_cookies, prefix=full_key
                ))
            elif isinstance(value, list):
                # Test first element if it's a scalar
                if value and not isinstance(value[0], (dict, list)):
                    points.append(InsertionPoint(
                        type=InsertionType.JSON_FIELD,
                        name=f"{full_key}[0]",
                        original_value=str(value[0]),
                        base_url=url,
                        method="POST",
                        _baseline_headers=baseline_headers,
                        _baseline_cookies=baseline_cookies,
                        _baseline_json=json_body,
                    ))
            else:
                points.append(InsertionPoint(
                    type=InsertionType.JSON_FIELD,
                    name=full_key,
                    original_value=str(value) if value is not None else "",
                    base_url=url,
                    method="POST",
                    _baseline_headers=baseline_headers,
                    _baseline_cookies=baseline_cookies,
                    _baseline_json=json_body,
                ))
        return points


# ═══════════════════════════════════════════════════════════════════
#  Utility: send a RequestSpec through an HTTP client
# ═══════════════════════════════════════════════════════════════════

def send_request(http_client, spec: RequestSpec, **kwargs):
    """
    Send a RequestSpec through an HTTP client.

    This is the bridge between InsertionPoint.inject() and the HTTP client.
    Handles all request types: GET with params, POST with data/json, custom headers.
    """
    method = spec.method.upper()
    headers = dict(spec.headers)
    if spec.content_type:
        headers["Content-Type"] = spec.content_type

    # Merge cookies into Cookie header
    if spec.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in spec.cookies.items())
        if "Cookie" in headers:
            headers["Cookie"] += "; " + cookie_str
        else:
            headers["Cookie"] = cookie_str

    if method == "GET":
        return http_client.get(spec.url, headers=headers, **kwargs)
    elif method == "POST":
        if spec.json_body is not None:
            return http_client.post(spec.url, json=spec.json_body,
                                    headers=headers, **kwargs)
        elif spec.data is not None:
            return http_client.post(spec.url, data=spec.data,
                                    headers=headers, **kwargs)
        elif spec.body is not None:
            return http_client.post(spec.url, data=spec.body,
                                    headers=headers, **kwargs)
        else:
            return http_client.post(spec.url, headers=headers, **kwargs)
    elif method == "PUT":
        return http_client.put(spec.url, json=spec.json_body or spec.data,
                               headers=headers, **kwargs)
    elif method == "PATCH":
        return http_client.patch(spec.url, json=spec.json_body or spec.data,
                                 headers=headers, **kwargs)
    elif method == "DELETE":
        return http_client.delete(spec.url, headers=headers, **kwargs)
    else:
        return http_client.request(method, spec.url, headers=headers, **kwargs)
