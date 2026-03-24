"""
WebSocket Scanner — Connection security, injection, and hijacking tests.

Capabilities:
  - WebSocket endpoint discovery
  - Connection security analysis (wss:// vs ws://)
  - Cross-Site WebSocket Hijacking (CSWSH)
  - Origin validation testing
  - Message injection testing
  - Authentication/authorization testing
  - DoS resilience testing (large messages, rapid connections)
  - Subprotocol enumeration
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import struct
import time
import base64
import os
from typing import Optional
from urllib.parse import urlparse, urljoin

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


class WebSocketScanner(SmartScanner):
    """WebSocket security scanner."""

    name = "WebSocket Scanner"
    description = "WebSocket connection security, injection, and hijacking tests"

    WS_PATHS = [
        "/ws", "/websocket", "/socket", "/ws/",
        "/api/ws", "/api/websocket",
        "/socket.io/", "/sockjs/",
        "/realtime", "/live", "/stream",
        "/cable", "/chat", "/notifications",
        "/hub", "/signalr", "/signalr/negotiate",
    ]

    INJECTION_PAYLOADS = [
        # XSS via WebSocket
        '<script>alert("ws")</script>',
        '<img src=x onerror=alert(1)>',
        '{"type":"message","data":"<script>alert(1)</script>"}',
        # SQL Injection
        "' OR '1'='1",
        '{"query":"mutation { deleteAll }"}',
        # Command Injection
        '; ls -la',
        '$(cat /etc/passwd)',
        # JSON injection
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        # Path traversal
        '../../../etc/passwd',
    ]

    def scan(self):
        """Execute WebSocket security scan."""
        target = normalize_url(self.config.target)
        parsed = urlparse(target)

        # Step 1: Discover WebSocket endpoints
        endpoints = self._discover_endpoints(target)
        if not endpoints:
            print_status("No WebSocket endpoints found", "info")
            return

        print_status(f"Found {len(endpoints)} WebSocket endpoint(s)", "success")

        for endpoint in endpoints:
            print_status(f"Testing: {endpoint}", "info")
            # Step 2: Test connection security
            self._test_connection_security(endpoint, parsed)
            # Step 3: Test origin validation (CSWSH)
            self._test_origin_validation(endpoint, target)
            # Step 4: Test authentication
            self._test_authentication(endpoint)
            # Step 5: Test message injection
            self._test_message_injection(endpoint)
            # Step 6: Test DoS resilience
            self._test_dos_resilience(endpoint)
            # Step 7: Subprotocol enumeration
            self._test_subprotocols(endpoint)

    def _discover_endpoints(self, target: str) -> list[str]:
        """Discover WebSocket endpoints."""
        endpoints = []
        parsed = urlparse(target)

        for path in self.WS_PATHS:
            url = urljoin(target, path)
            try:
                # Try HTTP upgrade request
                resp = self.http_client.get(
                    url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
                        "Sec-WebSocket-Version": "13",
                    },
                    timeout=self.config.timeout,
                )
                if resp and resp.status_code in (101, 200, 400, 426):
                    # 101 = switching protocols (WebSocket)
                    # 400/426 = bad request / upgrade required (WS exists but needs proper handshake)
                    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
                    ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
                    endpoints.append(ws_url)

                    if resp.status_code == 101:
                        self.add_finding(
                            title=f"WebSocket Endpoint Found: {path}",
                            severity=Severity.INFO,
                            description=f"Active WebSocket endpoint discovered at {ws_url}.",
                            category="WebSocket",
                            url=ws_url,
                            cwe="CWE-200",
                        )
            except Exception:
                continue

        # Also check for WebSocket indicators in HTML
        try:
            resp = self.http_client.get(target, timeout=self.config.timeout)
            if resp and resp.status_code == 200:
                ws_patterns = [
                    r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                    r'wss?://[^\s"\'<>]+',
                    r'socket\.io',
                    r'sockjs',
                    r'signalr',
                ]
                for pattern in ws_patterns:
                    matches = re.findall(pattern, resp.text, re.IGNORECASE)
                    for match in matches:
                        if match.startswith("ws://") or match.startswith("wss://"):
                            if match not in endpoints:
                                endpoints.append(match)
        except Exception:
            pass

        return endpoints

    def _ws_handshake(self, ws_url: str, extra_headers: Optional[dict] = None,
                      timeout: int = 5) -> Optional[tuple[socket.socket, dict]]:
        """Perform WebSocket handshake and return socket + response headers."""
        parsed = urlparse(ws_url)
        is_secure = parsed.scheme == "wss"
        host = parsed.hostname
        port = parsed.port or (443 if is_secure else 80)
        path = parsed.path or "/"

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if is_secure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            # Generate WebSocket key
            ws_key = base64.b64encode(os.urandom(16)).decode()

            headers = {
                "Host": f"{host}:{port}" if port not in (80, 443) else host,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": ws_key,
                "Sec-WebSocket-Version": "13",
            }
            if extra_headers:
                headers.update(extra_headers)

            # Build HTTP request
            request = f"GET {path} HTTP/1.1\r\n"
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            request += "\r\n"

            sock.sendall(request.encode())

            # Read response
            response_data = b""
            while b"\r\n\r\n" not in response_data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk

            response_text = response_data.decode("utf-8", errors="replace")
            status_line = response_text.split("\r\n")[0]

            # Parse response headers
            resp_headers = {}
            for line in response_text.split("\r\n")[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    resp_headers[key.lower()] = value

            if "101" in status_line:
                return sock, resp_headers
            else:
                sock.close()
                return None
        except Exception:
            return None

    def _test_connection_security(self, ws_url: str, parsed):
        """Test WebSocket connection security."""
        if ws_url.startswith("ws://"):
            self.add_finding(
                title=f"Unencrypted WebSocket Connection (ws://)",
                severity=Severity.HIGH,
                description=f"WebSocket at {ws_url} uses unencrypted ws:// protocol. "
                           f"All messages are transmitted in plaintext.",
                recommendation="Use wss:// (WebSocket Secure) for all WebSocket connections. "
                              "Configure TLS certificates for the WebSocket server.",
                evidence=f"Endpoint: {ws_url}",
                category="WebSocket",
                url=ws_url,
                cwe="CWE-319",
            )

    def _test_origin_validation(self, ws_url: str, target: str):
        """Test for Cross-Site WebSocket Hijacking (CSWSH)."""
        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]

        for origin in evil_origins:
            result = self._ws_handshake(ws_url, extra_headers={"Origin": origin})
            if result:
                sock, headers = result
                sock.close()
                self.add_finding(
                    title="Cross-Site WebSocket Hijacking (CSWSH)",
                    severity=Severity.HIGH,
                    description=f"The WebSocket endpoint {ws_url} accepts connections from "
                               f"arbitrary origins (tested: {origin}). This allows attackers to "
                               f"hijack WebSocket sessions from malicious websites.",
                    recommendation="Validate the Origin header on WebSocket connections. "
                                  "Only accept connections from trusted origins. "
                                  "Implement CSRF tokens in WebSocket handshake.",
                    evidence=f"Origin: {origin}\nResult: Connection accepted (HTTP 101)",
                    category="WebSocket",
                    url=ws_url,
                    cwe="CWE-346",
                )
                break  # One is enough to prove the point

    def _test_authentication(self, ws_url: str):
        """Test if WebSocket requires authentication."""
        # Try connecting without any auth
        result = self._ws_handshake(ws_url)
        if result:
            sock, headers = result
            # Try sending a message to see if we get data back
            try:
                self._ws_send(sock, '{"type":"ping"}')
                response = self._ws_recv(sock, timeout=3)
                if response:
                    self.add_finding(
                        title="WebSocket Accessible Without Authentication",
                        severity=Severity.MEDIUM,
                        description=f"The WebSocket endpoint {ws_url} accepts connections and "
                                   f"responds to messages without authentication.",
                        recommendation="Require authentication before establishing WebSocket connections. "
                                      "Validate session tokens during handshake.",
                        evidence=f"Connected without auth. Response: {response[:200]}",
                        category="WebSocket",
                        url=ws_url,
                        cwe="CWE-306",
                    )
            except Exception:
                pass
            finally:
                sock.close()

    def _test_message_injection(self, ws_url: str):
        """Test for injection vulnerabilities through WebSocket messages."""
        result = self._ws_handshake(ws_url)
        if not result:
            return

        sock, _ = result
        try:
            for payload in self.INJECTION_PAYLOADS:
                try:
                    self._ws_send(sock, payload)
                    response = self._ws_recv(sock, timeout=2)
                    if response:
                        # Check for reflection (XSS)
                        if "<script>" in response or "onerror=" in response:
                            self.add_finding(
                                title="WebSocket XSS — Payload Reflected",
                                severity=Severity.HIGH,
                                description=f"Injected XSS payload reflected in WebSocket response: {payload}",
                                recommendation="Sanitize all WebSocket message content before rendering. "
                                              "Implement output encoding.",
                                evidence=f"Payload: {payload}\nResponse: {response[:200]}",
                                category="WebSocket",
                                url=ws_url,
                                cwe="CWE-79",
                            )
                            break

                        # Check for error indicators
                        error_patterns = [
                            "sql", "syntax error", "exception", "traceback",
                            "mongodb", "command not found", "root:",
                        ]
                        for pattern in error_patterns:
                            if pattern in response.lower():
                                self.add_finding(
                                    title=f"WebSocket Error Disclosure on Injection",
                                    severity=Severity.MEDIUM,
                                    description=f"Injecting malicious content through WebSocket triggers "
                                               f"error messages containing '{pattern}'.",
                                    recommendation="Implement proper error handling for WebSocket messages. "
                                                  "Do not expose internal errors to clients.",
                                    evidence=f"Payload: {payload}\nError indicator: {pattern}\n"
                                            f"Response: {response[:200]}",
                                    category="WebSocket",
                                    url=ws_url,
                                    cwe="CWE-209",
                                )
                                break
                except Exception:
                    continue
        finally:
            sock.close()

    def _test_dos_resilience(self, ws_url: str):
        """Test WebSocket DoS resilience."""
        # Test 1: Large message
        result = self._ws_handshake(ws_url)
        if result:
            sock, _ = result
            try:
                large_msg = "A" * 1_000_000  # 1MB message
                self._ws_send(sock, large_msg)
                response = self._ws_recv(sock, timeout=3)
                if response:
                    self.add_finding(
                        title="WebSocket Accepts Very Large Messages",
                        severity=Severity.LOW,
                        description="The WebSocket server accepts messages of 1MB+, "
                                   "which could enable memory exhaustion attacks.",
                        recommendation="Implement maximum message size limits. "
                                      "Use streaming for large data transfers.",
                        evidence="Sent 1MB message — connection remained open",
                        category="WebSocket",
                        url=ws_url,
                        cwe="CWE-770",
                    )
            except Exception:
                pass
            finally:
                sock.close()

        # Test 2: Rapid connections
        success_count = 0
        for _ in range(10):
            result = self._ws_handshake(ws_url)
            if result:
                success_count += 1
                result[0].close()

        if success_count >= 10:
            self.add_finding(
                title="No WebSocket Connection Rate Limiting",
                severity=Severity.LOW,
                description="10 rapid WebSocket connections were all accepted without rate limiting.",
                recommendation="Implement connection rate limiting per IP. "
                              "Limit concurrent WebSocket connections.",
                evidence=f"10 rapid connections → {success_count} successful",
                category="WebSocket",
                url=ws_url,
                cwe="CWE-770",
            )

    def _test_subprotocols(self, ws_url: str):
        """Enumerate supported WebSocket subprotocols."""
        subprotocols = [
            "graphql-ws", "graphql-transport-ws",
            "soap", "wamp", "stomp",
            "mqtt", "amqp", "xmpp",
            "binary", "json", "protobuf",
        ]

        supported = []
        for proto in subprotocols:
            result = self._ws_handshake(
                ws_url,
                extra_headers={"Sec-WebSocket-Protocol": proto},
            )
            if result:
                _, headers = result
                accepted = headers.get("sec-websocket-protocol", "")
                if proto.lower() in accepted.lower():
                    supported.append(proto)
                result[0].close()

        if supported:
            self.add_finding(
                title=f"WebSocket Subprotocols: {', '.join(supported)}",
                severity=Severity.INFO,
                description=f"The WebSocket server supports subprotocols: {', '.join(supported)}.",
                category="WebSocket",
                url=ws_url,
                cwe="CWE-200",
            )

    # ── WebSocket Frame Helpers ──────────────────────────────────────

    def _ws_send(self, sock: socket.socket, message: str):
        """Send a WebSocket text frame."""
        payload = message.encode("utf-8")
        mask_key = os.urandom(4)

        # Build frame
        frame = bytearray()
        frame.append(0x81)  # FIN + Text opcode

        length = len(payload)
        if length <= 125:
            frame.append(0x80 | length)  # Masked
        elif length <= 65535:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", length))

        frame.extend(mask_key)

        # Mask the payload
        masked = bytearray(len(payload))
        for i in range(len(payload)):
            masked[i] = payload[i] ^ mask_key[i % 4]
        frame.extend(masked)

        sock.sendall(bytes(frame))

    def _ws_recv(self, sock: socket.socket, timeout: int = 5) -> Optional[str]:
        """Receive a WebSocket text frame."""
        sock.settimeout(timeout)
        try:
            header = sock.recv(2)
            if len(header) < 2:
                return None

            opcode = header[0] & 0x0F
            masked = (header[1] & 0x80) != 0
            length = header[1] & 0x7F

            if length == 126:
                data = sock.recv(2)
                length = struct.unpack(">H", data)[0]
            elif length == 127:
                data = sock.recv(8)
                length = struct.unpack(">Q", data)[0]

            if masked:
                mask_key = sock.recv(4)

            payload = b""
            while len(payload) < length:
                chunk = sock.recv(min(length - len(payload), 4096))
                if not chunk:
                    break
                payload += chunk

            if masked:
                unmasked = bytearray(len(payload))
                for i in range(len(payload)):
                    unmasked[i] = payload[i] ^ mask_key[i % 4]
                payload = bytes(unmasked)

            if opcode == 0x1:  # Text
                return payload.decode("utf-8", errors="replace")
            elif opcode == 0x2:  # Binary
                return payload.hex()
            elif opcode == 0x8:  # Close
                return None

            return payload.decode("utf-8", errors="replace")
        except (socket.timeout, Exception):
            return None
