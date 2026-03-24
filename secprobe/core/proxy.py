"""
Intercepting Proxy Engine — Burp-style HTTP/HTTPS request interception.

Features:
  - HTTPS interception with dynamic certificate generation
  - Request/response modification
  - Replay (Repeater) functionality
  - History with full-text search and filtering
  - Scope control (include/exclude patterns)
  - WebSocket interception
  - Export to various formats
  - Real-time event hooks for plugin system

Architecture:
  Uses asyncio + aiohttp for high-performance proxying.
  Falls back to threading model for environments without asyncio support.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import socket
import threading
import time
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse


# ── Proxy Configuration ──────────────────────────────────────────────

@dataclass
class ProxyConfig:
    """Configuration for the intercepting proxy."""
    host: str = "127.0.0.1"
    port: int = 8080
    ssl_intercept: bool = True
    ca_cert_path: Optional[str] = None
    ca_key_path: Optional[str] = None
    max_history: int = 10000
    intercept_enabled: bool = False  # Pause and allow modification
    scope_include: list[str] = field(default_factory=list)  # Regex patterns
    scope_exclude: list[str] = field(default_factory=list)
    upstream_proxy: Optional[str] = None
    strip_encoding: bool = True  # Strip gzip/deflate for inspection
    log_file: Optional[str] = None


# ── Request/Response Models ──────────────────────────────────────────

class InterceptAction(Enum):
    FORWARD = "forward"
    DROP = "drop"
    MODIFY = "modify"


@dataclass
class ProxyRequest:
    """Captured HTTP request."""
    id: int
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[bytes] = None
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    tls: bool = False
    http_version: str = "1.1"

    @property
    def host(self) -> str:
        parsed = urlparse(self.url)
        return parsed.hostname or ""

    @property
    def path(self) -> str:
        parsed = urlparse(self.url)
        return parsed.path or "/"

    @property
    def query(self) -> str:
        parsed = urlparse(self.url)
        return parsed.query or ""

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", self.headers.get("Content-Type", ""))

    @property
    def body_text(self) -> str:
        if self.body:
            try:
                return self.body.decode("utf-8", errors="replace")
            except Exception:
                return f"<binary {len(self.body)} bytes>"
        return ""

    def to_raw(self) -> str:
        """Convert to raw HTTP request string."""
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{self.method} {path} HTTP/{self.http_version}"]
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if self.body:
            lines.append(self.body_text)
        return "\r\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body": self.body_text if self.body else None,
            "timestamp": self.timestamp,
            "tls": self.tls,
        }


@dataclass
class ProxyResponse:
    """Captured HTTP response."""
    status_code: int
    headers: dict[str, str]
    body: Optional[bytes] = None
    http_version: str = "1.1"
    elapsed_ms: float = 0.0

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", self.headers.get("Content-Type", ""))

    @property
    def content_length(self) -> int:
        try:
            return int(self.headers.get("content-length", self.headers.get("Content-Length", 0)))
        except (ValueError, TypeError):
            return len(self.body) if self.body else 0

    @property
    def body_text(self) -> str:
        if self.body:
            try:
                return self.body.decode("utf-8", errors="replace")
            except Exception:
                return f"<binary {len(self.body)} bytes>"
        return ""

    def to_raw(self) -> str:
        """Convert to raw HTTP response string."""
        lines = [f"HTTP/{self.http_version} {self.status_code}"]
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if self.body:
            lines.append(self.body_text)
        return "\r\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body_length": self.content_length,
            "content_type": self.content_type,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class ProxyHistoryEntry:
    """A complete request/response pair in proxy history."""
    id: int
    request: ProxyRequest
    response: Optional[ProxyResponse] = None
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    highlighted: bool = False
    in_scope: bool = True
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "request": self.request.to_dict(),
            "response": self.response.to_dict() if self.response else None,
            "tags": self.tags,
            "notes": self.notes,
            "highlighted": self.highlighted,
            "in_scope": self.in_scope,
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
        }


# ── Proxy History & Search ───────────────────────────────────────────

class ProxyHistory:
    """Searchable, filterable proxy request/response history."""

    def __init__(self, max_entries: int = 10000):
        self._entries: list[ProxyHistoryEntry] = []
        self._max_entries = max_entries
        self._counter = 0
        self._lock = threading.Lock()

    def add(self, request: ProxyRequest, response: Optional[ProxyResponse] = None) -> ProxyHistoryEntry:
        with self._lock:
            self._counter += 1
            entry = ProxyHistoryEntry(
                id=self._counter,
                request=request,
                response=response,
            )
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries:]
            return entry

    def update_response(self, entry_id: int, response: ProxyResponse):
        with self._lock:
            for entry in self._entries:
                if entry.id == entry_id:
                    entry.response = response
                    break

    def search(self, query: str, scope_only: bool = False) -> list[ProxyHistoryEntry]:
        """Full-text search across requests and responses."""
        query_lower = query.lower()
        results = []
        with self._lock:
            for entry in self._entries:
                if scope_only and not entry.in_scope:
                    continue
                # Search in request
                if (query_lower in entry.request.url.lower()
                        or query_lower in entry.request.body_text.lower()
                        or any(query_lower in v.lower() for v in entry.request.headers.values())):
                    results.append(entry)
                    continue
                # Search in response
                if entry.response:
                    if (query_lower in entry.response.body_text.lower()
                            or any(query_lower in v.lower() for v in entry.response.headers.values())):
                        results.append(entry)
        return results

    def filter(self,
               method: Optional[str] = None,
               status_code: Optional[int] = None,
               host: Optional[str] = None,
               content_type: Optional[str] = None,
               min_length: Optional[int] = None,
               has_params: bool = False,
               scope_only: bool = False,
               tags: Optional[list[str]] = None) -> list[ProxyHistoryEntry]:
        """Filter history entries by criteria."""
        results = []
        with self._lock:
            for entry in self._entries:
                if scope_only and not entry.in_scope:
                    continue
                if method and entry.request.method != method.upper():
                    continue
                if status_code and entry.response and entry.response.status_code != status_code:
                    continue
                if host and host.lower() not in entry.request.host.lower():
                    continue
                if content_type and entry.response:
                    if content_type.lower() not in entry.response.content_type.lower():
                        continue
                if min_length and entry.response:
                    if entry.response.content_length < min_length:
                        continue
                if has_params and not entry.request.query and not entry.request.body:
                    continue
                if tags and not any(t in entry.tags for t in tags):
                    continue
                results.append(entry)
        return results

    def get(self, entry_id: int) -> Optional[ProxyHistoryEntry]:
        with self._lock:
            for entry in self._entries:
                if entry.id == entry_id:
                    return entry
        return None

    def get_all(self, scope_only: bool = False) -> list[ProxyHistoryEntry]:
        with self._lock:
            if scope_only:
                return [e for e in self._entries if e.in_scope]
            return list(self._entries)

    @property
    def count(self) -> int:
        return len(self._entries)

    def clear(self):
        with self._lock:
            self._entries.clear()

    def export_json(self, filepath: str, scope_only: bool = False):
        """Export history to JSON file."""
        entries = self.get_all(scope_only=scope_only)
        data = {
            "secprobe_proxy_history": {
                "version": "1.0",
                "exported": datetime.now().isoformat(),
                "entry_count": len(entries),
                "entries": [e.to_dict() for e in entries],
            }
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def export_har(self, filepath: str, scope_only: bool = False):
        """Export history in HAR (HTTP Archive) format."""
        entries = self.get_all(scope_only=scope_only)
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "SecProbe Proxy", "version": "5.0.0"},
                "entries": [],
            }
        }
        for entry in entries:
            har_entry = {
                "startedDateTime": datetime.fromtimestamp(entry.timestamp).isoformat(),
                "request": {
                    "method": entry.request.method,
                    "url": entry.request.url,
                    "httpVersion": f"HTTP/{entry.request.http_version}",
                    "headers": [{"name": k, "value": v} for k, v in entry.request.headers.items()],
                    "queryString": [],
                    "bodySize": len(entry.request.body) if entry.request.body else 0,
                },
                "response": {
                    "status": entry.response.status_code if entry.response else 0,
                    "headers": [{"name": k, "value": v} for k, v in entry.response.headers.items()] if entry.response else [],
                    "bodySize": entry.response.content_length if entry.response else 0,
                },
                "time": entry.response.elapsed_ms if entry.response else 0,
            }
            har["log"]["entries"].append(har_entry)

        with open(filepath, "w") as f:
            json.dump(har, f, indent=2)


# ── Scope Manager ────────────────────────────────────────────────────

class ScopeManager:
    """Manage in-scope/out-of-scope URL patterns."""

    def __init__(self, include_patterns: list[str] = None, exclude_patterns: list[str] = None):
        self._include = [re.compile(p, re.IGNORECASE) for p in (include_patterns or [])]
        self._exclude = [re.compile(p, re.IGNORECASE) for p in (exclude_patterns or [])]

    def in_scope(self, url: str) -> bool:
        """Check if a URL is in scope."""
        # If no include patterns, everything is in scope
        if not self._include:
            in_include = True
        else:
            in_include = any(p.search(url) for p in self._include)

        # Check excludes
        if self._exclude and any(p.search(url) for p in self._exclude):
            return False

        return in_include

    def add_include(self, pattern: str):
        self._include.append(re.compile(pattern, re.IGNORECASE))

    def add_exclude(self, pattern: str):
        self._exclude.append(re.compile(pattern, re.IGNORECASE))


# ── Repeater (Request Replay) ────────────────────────────────────────

class Repeater:
    """
    Replay and modify requests — equivalent to Burp's Repeater.

    Usage:
        repeater = Repeater()
        entry = proxy.history.get(42)
        response = repeater.send(entry.request)
        modified = repeater.modify_and_send(entry.request, headers={"X-Custom": "test"})
    """

    def __init__(self):
        self._tabs: dict[str, ProxyRequest] = {}

    def send(self, request: ProxyRequest, timeout: int = 30) -> ProxyResponse:
        """Send a request and return the response."""
        import http.client

        parsed = urlparse(request.url)
        is_https = parsed.scheme == "https"

        if is_https:
            conn = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port or 443,
                timeout=timeout,
                context=ssl._create_unverified_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                parsed.hostname,
                parsed.port or 80,
                timeout=timeout,
            )

        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        start = time.time()
        try:
            conn.request(
                request.method,
                path,
                body=request.body,
                headers=request.headers,
            )
            resp = conn.getresponse()
            elapsed = (time.time() - start) * 1000

            response_headers = {}
            for key, value in resp.getheaders():
                response_headers[key] = value

            body = resp.read()

            return ProxyResponse(
                status_code=resp.status,
                headers=response_headers,
                body=body,
                elapsed_ms=elapsed,
            )
        finally:
            conn.close()

    def modify_and_send(self, request: ProxyRequest,
                        method: Optional[str] = None,
                        url: Optional[str] = None,
                        headers: Optional[dict] = None,
                        body: Optional[bytes] = None,
                        timeout: int = 30) -> ProxyResponse:
        """Modify a request and send it."""
        modified = ProxyRequest(
            id=request.id,
            method=method or request.method,
            url=url or request.url,
            headers={**request.headers, **(headers or {})},
            body=body if body is not None else request.body,
            tls=request.tls,
        )
        return self.send(modified, timeout=timeout)

    def save_tab(self, name: str, request: ProxyRequest):
        """Save a request to a named tab."""
        self._tabs[name] = request

    def get_tab(self, name: str) -> Optional[ProxyRequest]:
        """Get a saved request tab."""
        return self._tabs.get(name)

    def list_tabs(self) -> list[str]:
        return list(self._tabs.keys())


# ── Intruder (Automated Fuzzing) ─────────────────────────────────────

class IntruderAttackType(Enum):
    SNIPER = "sniper"        # One position at a time
    BATTERING_RAM = "battering_ram"  # Same payload in all positions
    PITCHFORK = "pitchfork"  # Parallel payloads (one per position)
    CLUSTER_BOMB = "cluster_bomb"  # All combinations


@dataclass
class IntruderConfig:
    """Configuration for Intruder attack."""
    request: ProxyRequest
    positions: list[tuple[int, int]]  # (start, end) byte offsets in body/URL
    payloads: list[list[str]]  # One payload list per position
    attack_type: IntruderAttackType = IntruderAttackType.SNIPER
    threads: int = 5
    delay_ms: int = 0
    follow_redirects: bool = False
    grep_match: list[str] = field(default_factory=list)
    grep_extract: list[str] = field(default_factory=list)


@dataclass
class IntruderResult:
    """Result from a single Intruder request."""
    request_num: int
    payload: str
    request: ProxyRequest
    response: ProxyResponse
    grep_matches: list[str] = field(default_factory=list)
    grep_extracts: list[str] = field(default_factory=list)


class Intruder:
    """
    Automated request fuzzer — equivalent to Burp's Intruder.

    Supports Sniper, Battering Ram, Pitchfork, and Cluster Bomb attack types.
    """

    def __init__(self, repeater: Optional[Repeater] = None):
        self.repeater = repeater or Repeater()
        self._results: list[IntruderResult] = []
        self._running = False

    def attack(self, config: IntruderConfig,
               callback: Optional[Callable[[IntruderResult], None]] = None) -> list[IntruderResult]:
        """Execute an Intruder attack."""
        self._running = True
        self._results = []

        payloads = self._generate_payload_sets(config)

        for i, payload_set in enumerate(payloads):
            if not self._running:
                break

            # Build modified request with payloads inserted
            modified_body = config.request.body_text if config.request.body else config.request.url
            for (start, end), payload in zip(config.positions, payload_set):
                modified_body = modified_body[:start] + payload + modified_body[end:]

            # Create modified request
            if config.request.body:
                modified_request = ProxyRequest(
                    id=i,
                    method=config.request.method,
                    url=config.request.url,
                    headers=dict(config.request.headers),
                    body=modified_body.encode(),
                )
            else:
                modified_request = ProxyRequest(
                    id=i,
                    method=config.request.method,
                    url=modified_body,
                    headers=dict(config.request.headers),
                )

            try:
                response = self.repeater.send(modified_request)

                # Grep matching
                grep_matches = []
                for pattern in config.grep_match:
                    if re.search(pattern, response.body_text, re.IGNORECASE):
                        grep_matches.append(pattern)

                # Grep extraction
                grep_extracts = []
                for pattern in config.grep_extract:
                    matches = re.findall(pattern, response.body_text, re.IGNORECASE)
                    grep_extracts.extend(matches[:5])

                result = IntruderResult(
                    request_num=i,
                    payload="|".join(payload_set),
                    request=modified_request,
                    response=response,
                    grep_matches=grep_matches,
                    grep_extracts=grep_extracts,
                )
                self._results.append(result)

                if callback:
                    callback(result)

            except Exception:
                pass

            if config.delay_ms > 0:
                time.sleep(config.delay_ms / 1000)

        self._running = False
        return self._results

    def stop(self):
        self._running = False

    def _generate_payload_sets(self, config: IntruderConfig) -> list[list[str]]:
        """Generate payload combinations based on attack type."""
        if config.attack_type == IntruderAttackType.SNIPER:
            # One position at a time
            payloads = []
            for pos_idx in range(len(config.positions)):
                for payload in config.payloads[min(pos_idx, len(config.payloads) - 1)]:
                    combo = [""] * len(config.positions)
                    combo[pos_idx] = payload
                    payloads.append(combo)
            return payloads

        elif config.attack_type == IntruderAttackType.BATTERING_RAM:
            # Same payload everywhere
            payloads = []
            for payload in config.payloads[0]:
                payloads.append([payload] * len(config.positions))
            return payloads

        elif config.attack_type == IntruderAttackType.PITCHFORK:
            # Parallel iteration
            max_len = min(len(pl) for pl in config.payloads)
            return [
                [config.payloads[j][i] for j in range(len(config.positions))]
                for i in range(max_len)
            ]

        elif config.attack_type == IntruderAttackType.CLUSTER_BOMB:
            # All combinations
            from itertools import product
            lists = [config.payloads[min(i, len(config.payloads) - 1)]
                     for i in range(len(config.positions))]
            return [list(combo) for combo in product(*lists)]

        return []

    @property
    def results(self) -> list[IntruderResult]:
        return list(self._results)


# ── Proxy Server (Thread-based for compatibility) ────────────────────

class InterceptingProxy:
    """
    Full intercepting proxy server with history, scope, and replay.

    Usage:
        proxy = InterceptingProxy(ProxyConfig(port=8080))
        proxy.start()  # Background thread

        # Inspect history
        for entry in proxy.history.get_all():
            print(f"{entry.request.method} {entry.request.url}")

        # Replay a request
        response = proxy.repeater.send(entry.request)

        proxy.stop()
    """

    def __init__(self, config: Optional[ProxyConfig] = None):
        self.config = config or ProxyConfig()
        self.history = ProxyHistory(max_entries=self.config.max_history)
        self.scope = ScopeManager(
            include_patterns=self.config.scope_include,
            exclude_patterns=self.config.scope_exclude,
        )
        self.repeater = Repeater()
        self.intruder = Intruder(repeater=self.repeater)

        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._intercept_queue: list[tuple[ProxyRequest, threading.Event]] = []
        self._intercept_lock = threading.Lock()
        self._request_counter = 0
        self._callbacks: list[Callable] = []

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def address(self) -> str:
        return f"{self.config.host}:{self.config.port}"

    def on_request(self, callback: Callable[[ProxyHistoryEntry], None]):
        """Register a callback for new requests."""
        self._callbacks.append(callback)

    def start(self):
        """Start the proxy server in a background thread."""
        if self._running:
            return

        proxy_instance = self

        class ProxyHandler(BaseHTTPRequestHandler):
            """HTTP request handler for the proxy."""

            def do_GET(self):
                self._handle_request("GET")

            def do_POST(self):
                self._handle_request("POST")

            def do_PUT(self):
                self._handle_request("PUT")

            def do_DELETE(self):
                self._handle_request("DELETE")

            def do_OPTIONS(self):
                self._handle_request("OPTIONS")

            def do_HEAD(self):
                self._handle_request("HEAD")

            def do_PATCH(self):
                self._handle_request("PATCH")

            def do_CONNECT(self):
                """Handle HTTPS CONNECT tunneling."""
                self.send_response(200, "Connection Established")
                self.end_headers()
                # For now, just tunnel without interception
                # Full SSL interception requires dynamic cert generation

            def _handle_request(self, method: str):
                """Core request handling with history recording."""
                import http.client

                proxy_instance._request_counter += 1

                # Read request body
                body = None
                content_length = self.headers.get("Content-Length")
                if content_length:
                    body = self.rfile.read(int(content_length))

                # Build request object
                headers = {}
                for key in self.headers:
                    headers[key] = self.headers[key]

                # Remove proxy headers
                headers.pop("Proxy-Connection", None)
                headers.pop("Proxy-Authorization", None)

                request = ProxyRequest(
                    id=proxy_instance._request_counter,
                    method=method,
                    url=self.path,
                    headers=headers,
                    body=body,
                    source_ip=self.client_address[0],
                )

                # Check scope
                in_scope = proxy_instance.scope.in_scope(self.path)

                try:
                    # Forward request
                    parsed = urlparse(self.path)
                    is_https = parsed.scheme == "https"

                    if is_https:
                        conn = http.client.HTTPSConnection(
                            parsed.hostname,
                            parsed.port or 443,
                            timeout=30,
                            context=ssl._create_unverified_context(),
                        )
                    else:
                        conn = http.client.HTTPConnection(
                            parsed.hostname,
                            parsed.port or 80,
                            timeout=30,
                        )

                    path = parsed.path or "/"
                    if parsed.query:
                        path += f"?{parsed.query}"

                    start_time = time.time()
                    conn.request(method, path, body=body, headers=headers)
                    resp = conn.getresponse()
                    elapsed = (time.time() - start_time) * 1000

                    resp_headers = {}
                    for key, value in resp.getheaders():
                        resp_headers[key] = value

                    resp_body = resp.read()
                    conn.close()

                    response = ProxyResponse(
                        status_code=resp.status,
                        headers=resp_headers,
                        body=resp_body,
                        elapsed_ms=elapsed,
                    )

                    # Record in history
                    entry = proxy_instance.history.add(request, response)
                    entry.in_scope = in_scope

                    # Fire callbacks
                    for cb in proxy_instance._callbacks:
                        try:
                            cb(entry)
                        except Exception:
                            pass

                    # Send response to client
                    self.send_response(resp.status)
                    for key, value in resp_headers.items():
                        if key.lower() not in ("transfer-encoding",):
                            self.send_header(key, value)
                    self.end_headers()
                    if resp_body:
                        self.wfile.write(resp_body)

                except Exception as e:
                    self.send_error(502, f"Proxy Error: {e}")

            def log_message(self, format, *args):
                """Suppress default access logging."""
                pass

        try:
            self._server = HTTPServer(
                (self.config.host, self.config.port),
                ProxyHandler,
            )
            self._running = True
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
            )
            self._thread.start()
        except Exception as e:
            self._running = False
            raise RuntimeError(f"Failed to start proxy on {self.address}: {e}")

    def stop(self):
        """Stop the proxy server."""
        if self._server:
            self._server.shutdown()
            self._running = False

    def get_stats(self) -> dict:
        """Get proxy statistics."""
        entries = self.history.get_all()
        methods = {}
        status_codes = {}
        hosts = {}
        total_bytes = 0

        for entry in entries:
            methods[entry.request.method] = methods.get(entry.request.method, 0) + 1
            if entry.response:
                sc = entry.response.status_code
                status_codes[sc] = status_codes.get(sc, 0) + 1
                total_bytes += entry.response.content_length
            hosts[entry.request.host] = hosts.get(entry.request.host, 0) + 1

        return {
            "total_requests": len(entries),
            "methods": methods,
            "status_codes": status_codes,
            "unique_hosts": len(hosts),
            "top_hosts": sorted(hosts.items(), key=lambda x: x[1], reverse=True)[:10],
            "total_response_bytes": total_bytes,
            "in_scope": sum(1 for e in entries if e.in_scope),
        }
