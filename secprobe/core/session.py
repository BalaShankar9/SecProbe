"""
Session Management Engine — Automatic session handling for scans.

Provides:
  - Cookie jar persistence across requests
  - Automatic re-authentication on 401/403
  - CSRF token extraction and injection
  - Session health monitoring
  - Multi-session support (e.g., admin vs user roles)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import urljoin

from secprobe.core.logger import get_logger

log = get_logger("session")


# ═══════════════════════════════════════════════════════════════════
#  CSRF Token Extraction
# ═══════════════════════════════════════════════════════════════════

# Common CSRF token field/header names
CSRF_FIELD_NAMES = [
    "csrf_token", "csrfmiddlewaretoken", "_token", "csrf",
    "authenticity_token", "_csrf_token", "XSRF-TOKEN",
    "__RequestVerificationToken", "antiForgery", "csrfToken",
    "nonce", "formToken", "anti-csrf-token",
]

CSRF_HEADER_NAMES = [
    "X-CSRF-Token", "X-XSRF-Token", "X-CSRFToken",
    "X-Requested-With", "X-CSRF-Header",
]

# Regex to extract CSRF tokens from HTML
CSRF_HTML_RE = re.compile(
    r'<input[^>]*?name=["\']('
    + "|".join(re.escape(n) for n in CSRF_FIELD_NAMES)
    + r')["\'][^>]*?value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

CSRF_META_RE = re.compile(
    r'<meta[^>]*?name=["\']csrf-token["\'][^>]*?content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@dataclass
class SessionCredentials:
    """Credentials for authentication."""
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict = field(default_factory=dict)
    auth_type: str = "form"  # form, basic, bearer, api_key, cookie
    token: str = ""  # For bearer/api_key auth
    header_name: str = ""  # For custom header auth
    success_indicator: str = ""  # String that appears on successful login
    failure_indicator: str = ""  # String that appears on failed login


@dataclass
class SessionState:
    """Current state of a scan session."""
    cookies: dict = field(default_factory=dict)
    csrf_token: Optional[str] = None
    csrf_field_name: str = "csrf_token"
    auth_headers: dict = field(default_factory=dict)
    is_authenticated: bool = False
    last_auth_time: float = 0.0
    auth_failures: int = 0
    total_requests: int = 0
    reauth_count: int = 0


class SessionManager:
    """
    Manages HTTP sessions for security scanning.

    Handles cookie persistence, CSRF tokens, and automatic
    re-authentication when sessions expire.
    """

    def __init__(
        self,
        http_client,
        credentials: Optional[SessionCredentials] = None,
        *,
        max_reauth_attempts: int = 3,
        session_timeout: int = 1800,  # 30 minutes
        reauth_on_codes: tuple[int, ...] = (401, 403),
    ):
        self.http_client = http_client
        self.credentials = credentials
        self.max_reauth_attempts = max_reauth_attempts
        self.session_timeout = session_timeout
        self.reauth_on_codes = reauth_on_codes
        self.state = SessionState()
        self._on_reauth_callbacks: list[Callable] = []

    # ── Public API ───────────────────────────────────────────────

    def authenticate(self) -> bool:
        """
        Perform initial authentication.

        Returns True if authentication succeeded.
        """
        if not self.credentials:
            log.warning("No credentials configured for authentication")
            return False

        auth_type = self.credentials.auth_type.lower()

        if auth_type == "form":
            return self._form_login()
        elif auth_type == "basic":
            return self._basic_auth()
        elif auth_type == "bearer":
            return self._bearer_auth()
        elif auth_type == "api_key":
            return self._api_key_auth()
        elif auth_type == "cookie":
            return self._cookie_auth()
        else:
            log.error("Unknown auth type: %s", auth_type)
            return False

    def get_headers(self) -> dict:
        """
        Get headers to include with requests (auth + CSRF).

        Returns a dict of headers to merge into request headers.
        """
        headers = dict(self.state.auth_headers)

        # Add CSRF token header if available
        if self.state.csrf_token:
            headers["X-CSRF-Token"] = self.state.csrf_token

        return headers

    def get_cookies(self) -> dict:
        """Get current session cookies."""
        return dict(self.state.cookies)

    def get_csrf_form_data(self) -> dict:
        """Get CSRF token as form data for POST requests."""
        if self.state.csrf_token:
            return {self.state.csrf_field_name: self.state.csrf_token}
        return {}

    def handle_response(self, response, url: str = "") -> bool:
        """
        Process a response to update session state.

        - Updates cookies from Set-Cookie headers
        - Extracts CSRF tokens from HTML
        - Triggers re-auth on 401/403
        - Returns True if the response is valid (not an auth failure)
        """
        self.state.total_requests += 1

        # Update cookies
        self._update_cookies(response)

        # Extract CSRF token from response body
        body = getattr(response, "text", "") or ""
        self._extract_csrf_token(body)

        # Check for auth failure
        status_code = getattr(response, "status_code", 200)
        if status_code in self.reauth_on_codes:
            log.info("Auth failure detected (HTTP %d) at %s", status_code, url)
            return self._handle_auth_failure(url)

        return True

    def is_session_valid(self) -> bool:
        """Check if the current session is likely still valid."""
        if not self.state.is_authenticated:
            return False

        # Check session timeout
        elapsed = time.time() - self.state.last_auth_time
        if elapsed > self.session_timeout:
            log.info("Session timeout after %.0fs", elapsed)
            return False

        return True

    def ensure_authenticated(self) -> bool:
        """
        Ensure we have a valid session, re-authenticating if needed.

        Returns True if we have a valid session.
        """
        if self.is_session_valid():
            return True

        log.info("Session expired or invalid, re-authenticating...")
        return self.authenticate()

    def on_reauth(self, callback: Callable):
        """Register a callback for when re-authentication occurs."""
        self._on_reauth_callbacks.append(callback)

    # ── Authentication Methods ───────────────────────────────────

    def _form_login(self) -> bool:
        """Perform form-based login."""
        creds = self.credentials
        if not creds.login_url:
            log.error("No login URL configured for form auth")
            return False

        try:
            # Step 1: GET the login page to extract CSRF token
            login_page = self.http_client.get(
                creds.login_url,
                timeout=15,
            )
            body = getattr(login_page, "text", "") or ""
            self._update_cookies(login_page)
            self._extract_csrf_token(body)

            # Step 2: Build login form data
            form_data = {
                creds.username_field: creds.username,
                creds.password_field: creds.password,
            }

            # Add CSRF token if found
            if self.state.csrf_token:
                form_data[self.state.csrf_field_name] = self.state.csrf_token

            # Add any extra fields
            form_data.update(creds.extra_fields)

            # Step 3: POST the login form
            login_resp = self.http_client.post(
                creds.login_url,
                data=form_data,
                cookies=self.state.cookies,
                timeout=15,
                allow_redirects=True,
            )

            self._update_cookies(login_resp)

            # Step 4: Verify login success
            return self._verify_login(login_resp)

        except Exception as e:
            log.error("Form login failed: %s", e)
            self.state.auth_failures += 1
            return False

    def _basic_auth(self) -> bool:
        """Configure HTTP Basic authentication."""
        creds = self.credentials
        import base64
        token = base64.b64encode(
            f"{creds.username}:{creds.password}".encode()
        ).decode()
        self.state.auth_headers["Authorization"] = f"Basic {token}"
        self.state.is_authenticated = True
        self.state.last_auth_time = time.time()
        log.info("Basic auth configured for user: %s", creds.username)
        return True

    def _bearer_auth(self) -> bool:
        """Configure Bearer token authentication."""
        creds = self.credentials
        if not creds.token:
            log.error("No bearer token configured")
            return False
        self.state.auth_headers["Authorization"] = f"Bearer {creds.token}"
        self.state.is_authenticated = True
        self.state.last_auth_time = time.time()
        log.info("Bearer token auth configured")
        return True

    def _api_key_auth(self) -> bool:
        """Configure API key authentication."""
        creds = self.credentials
        if not creds.token:
            log.error("No API key configured")
            return False
        header = creds.header_name or "X-API-Key"
        self.state.auth_headers[header] = creds.token
        self.state.is_authenticated = True
        self.state.last_auth_time = time.time()
        log.info("API key auth configured via %s header", header)
        return True

    def _cookie_auth(self) -> bool:
        """Configure cookie-based authentication from a provided cookie string."""
        creds = self.credentials
        if not creds.token:
            log.error("No session cookie configured")
            return False
        # Parse cookie string: "name1=value1; name2=value2"
        for part in creds.token.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                self.state.cookies[name.strip()] = value.strip()
        self.state.is_authenticated = True
        self.state.last_auth_time = time.time()
        log.info("Cookie auth configured with %d cookies", len(self.state.cookies))
        return True

    # ── Session Maintenance ──────────────────────────────────────

    def _handle_auth_failure(self, url: str) -> bool:
        """Handle an authentication failure by re-authenticating."""
        if self.state.auth_failures >= self.max_reauth_attempts:
            log.error(
                "Max re-auth attempts (%d) reached, giving up",
                self.max_reauth_attempts,
            )
            return False

        self.state.auth_failures += 1
        self.state.is_authenticated = False

        log.info(
            "Attempting re-authentication (attempt %d/%d)",
            self.state.auth_failures,
            self.max_reauth_attempts,
        )

        success = self.authenticate()
        if success:
            self.state.reauth_count += 1
            self.state.auth_failures = 0
            for callback in self._on_reauth_callbacks:
                try:
                    callback()
                except Exception as e:
                    log.warning("Reauth callback failed: %s", e)

        return success

    def _update_cookies(self, response):
        """Extract and store cookies from a response."""
        # Try response.cookies (requests-style)
        cookies = getattr(response, "cookies", None)
        if cookies:
            if hasattr(cookies, "get_dict"):
                self.state.cookies.update(cookies.get_dict())
            elif hasattr(cookies, "items"):
                for name, value in cookies.items():
                    self.state.cookies[name] = value

        # Also check Set-Cookie headers
        headers = getattr(response, "headers", {}) or {}
        set_cookie = None
        for key in headers:
            if key.lower() == "set-cookie":
                set_cookie = headers[key]
                break

        if set_cookie:
            # Basic Set-Cookie parsing
            parts = set_cookie.split(";")
            if parts:
                cookie_part = parts[0].strip()
                if "=" in cookie_part:
                    name, _, value = cookie_part.partition("=")
                    self.state.cookies[name.strip()] = value.strip()

    def _extract_csrf_token(self, html: str):
        """Extract CSRF token from HTML response."""
        # Try input field pattern
        match = CSRF_HTML_RE.search(html)
        if match:
            self.state.csrf_field_name = match.group(1)
            self.state.csrf_token = match.group(2)
            log.debug("CSRF token extracted: %s=%s...",
                      self.state.csrf_field_name,
                      self.state.csrf_token[:20])
            return

        # Try meta tag pattern
        match = CSRF_META_RE.search(html)
        if match:
            self.state.csrf_field_name = "csrf-token"
            self.state.csrf_token = match.group(1)
            log.debug("CSRF meta token extracted: %s...",
                      self.state.csrf_token[:20])
            return

    def _verify_login(self, response) -> bool:
        """Verify whether a login attempt was successful."""
        creds = self.credentials
        body = getattr(response, "text", "") or ""
        status = getattr(response, "status_code", 200)

        # Check explicit success indicator
        if creds.success_indicator and creds.success_indicator in body:
            self.state.is_authenticated = True
            self.state.last_auth_time = time.time()
            log.info("Login successful (success indicator found)")
            return True

        # Check explicit failure indicator
        if creds.failure_indicator and creds.failure_indicator in body:
            log.warning("Login failed (failure indicator found)")
            return False

        # Heuristic: successful login usually redirects (302/303) or returns 200
        # with a session cookie
        if status in (200, 302, 303) and self.state.cookies:
            # Check for common failure strings
            failure_strings = [
                "invalid password", "incorrect password",
                "login failed", "authentication failed",
                "invalid credentials", "bad credentials",
                "wrong password", "access denied",
                "invalid username", "user not found",
            ]
            body_lower = body.lower()
            for fail_str in failure_strings:
                if fail_str in body_lower:
                    log.warning("Login likely failed: '%s' found in response", fail_str)
                    return False

            self.state.is_authenticated = True
            self.state.last_auth_time = time.time()
            log.info("Login likely successful (cookies set, no failure indicators)")
            return True

        log.warning("Login status uncertain (HTTP %d, %d cookies)",
                    status, len(self.state.cookies))
        return False
