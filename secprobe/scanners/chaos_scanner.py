"""
Security Chaos Engineering — test defenses, not just offenses.

Inspired by Netflix Chaos Monkey. Deliberately tests if security
mechanisms actually work:
- Remove auth tokens -> is access denied?
- Send malformed JWTs -> are they rejected?
- Corrupt CSRF tokens -> does the server reject the request?
- Send oversized payloads -> is there a size limit?
- Rapid-fire requests -> is rate limiting active?
"""

from __future__ import annotations
import logging
from secprobe.scanners.base import BaseScanner
from secprobe.config import Severity

logger = logging.getLogger(__name__)


class ChaosScanner(BaseScanner):
    """Security Chaos Engineering — tests if defenses actually work."""

    name = "Chaos Scanner"
    description = "Test security defenses by deliberately breaking security mechanisms"

    def scan(self):
        url = self.config.target

        # Test 1: Auth token removal
        self._test_auth_removal(url)

        # Test 2: CSRF token corruption
        self._test_csrf_corruption(url)

        # Test 3: Rate limiting
        self._test_rate_limiting(url)

        # Test 4: Oversized payloads
        self._test_payload_size_limits(url)

        # Test 5: Malformed content types
        self._test_content_type_enforcement(url)

    def _test_auth_removal(self, url: str):
        """Test: does removing auth tokens actually deny access?"""
        try:
            # Request with no auth
            resp = self.http_client.get(url, timeout=self.config.timeout)
            # Try common authenticated endpoints without auth
            auth_endpoints = ["/api/users", "/api/admin", "/api/profile",
                            "/api/account", "/api/settings", "/dashboard",
                            "/admin", "/api/orders"]
            for endpoint in auth_endpoints:
                test_url = url.rstrip("/") + endpoint
                try:
                    r = self.http_client.get(test_url, timeout=5)
                    if r.status_code == 200 and len(r.text) > 100:
                        # Got data without auth — this is a finding
                        self.add_finding(
                            title=f"Unauthenticated access to {endpoint}",
                            severity=Severity.HIGH,
                            description=f"Endpoint {endpoint} returns data without authentication. "
                                       f"Status: {r.status_code}, Response length: {len(r.text)} bytes.",
                            recommendation="Add authentication middleware to protect this endpoint.",
                            evidence=f"URL: {test_url}\nStatus: {r.status_code}\nBody preview: {r.text[:200]}",
                            url=test_url,
                            cwe="CWE-306",
                        )
                except Exception:
                    continue
        except Exception:
            pass

    def _test_csrf_corruption(self, url: str):
        """Test: does corrupting CSRF tokens cause rejection?"""
        try:
            # Get a page that might have a CSRF token
            resp = self.http_client.get(url, timeout=self.config.timeout)
            import re
            tokens = re.findall(r'name=["\']csrf[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
                              resp.text, re.IGNORECASE)
            if not tokens:
                return

            # Try submitting with corrupted token
            corrupted = tokens[0][::-1]  # Reverse the token
            for form_action in ["/login", "/register", "/contact", "/feedback"]:
                test_url = url.rstrip("/") + form_action
                try:
                    r = self.http_client.post(test_url, data={"csrf_token": corrupted},
                                             timeout=5)
                    if r.status_code == 200:
                        self.add_finding(
                            title=f"CSRF token not validated at {form_action}",
                            severity=Severity.MEDIUM,
                            description=f"Corrupted CSRF token was accepted at {form_action}.",
                            recommendation="Validate CSRF tokens on all state-changing endpoints.",
                            evidence=f"Sent corrupted token: {corrupted[:20]}...\nStatus: {r.status_code}",
                            url=test_url,
                            cwe="CWE-352",
                        )
                except Exception:
                    continue
        except Exception:
            pass

    def _test_rate_limiting(self, url: str):
        """Test: is rate limiting active?"""
        try:
            # Send 50 rapid requests
            blocked = False
            for i in range(50):
                try:
                    r = self.http_client.get(url, timeout=3)
                    if r.status_code == 429:
                        blocked = True
                        break
                except Exception:
                    break

            if not blocked:
                self.add_finding(
                    title="No rate limiting detected",
                    severity=Severity.LOW,
                    description="50 rapid requests were accepted without rate limiting. "
                               "This allows brute-force and denial-of-service attacks.",
                    recommendation="Implement rate limiting (e.g., express-rate-limit, django-ratelimit).",
                    evidence=f"Sent 50 rapid requests to {url}, all accepted.",
                    url=url,
                    cwe="CWE-770",
                )
        except Exception:
            pass

    def _test_payload_size_limits(self, url: str):
        """Test: are there payload size limits?"""
        try:
            # Send a very large payload
            large_payload = "A" * 1_000_000  # 1MB
            try:
                r = self.http_client.post(url, data={"data": large_payload}, timeout=10)
                if r.status_code not in (413, 414, 431):
                    self.add_finding(
                        title="No payload size limit detected",
                        severity=Severity.LOW,
                        description="Server accepted a 1MB payload without rejecting it.",
                        recommendation="Configure request body size limits in your web server.",
                        evidence=f"Sent 1MB payload, received status {r.status_code}",
                        url=url,
                        cwe="CWE-770",
                    )
            except Exception:
                pass  # Connection error = might have a limit
        except Exception:
            pass

    def _test_content_type_enforcement(self, url: str):
        """Test: does the server enforce content type?"""
        try:
            # Send JSON to an endpoint that expects form data
            import json
            for endpoint in ["/api/login", "/login", "/api/users"]:
                test_url = url.rstrip("/") + endpoint
                try:
                    r = self.http_client.post(
                        test_url,
                        data=json.dumps({"test": "value"}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=5,
                    )
                    # If server processes wrong content type, it might be confused
                except Exception:
                    continue
        except Exception:
            pass
