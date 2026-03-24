"""
Authentication handler for SecProbe.

Supports:
    - Basic Auth (username:password)
    - Bearer Token
    - Cookie-based session auth (auto-login via form)
    - Custom header auth (API keys, etc.)
"""

from dataclasses import dataclass
from typing import Optional
from enum import Enum

from secprobe.core.logger import get_logger
from secprobe.core.exceptions import AuthenticationError

log = get_logger("auth")


class AuthType(Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    COOKIE = "cookie"
    HEADER = "header"
    FORM = "form"


@dataclass
class AuthConfig:
    """Authentication configuration."""
    auth_type: AuthType = AuthType.NONE
    username: str = ""
    password: str = ""
    token: str = ""
    header_name: str = ""
    header_value: str = ""
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    success_indicator: str = ""      # String expected in successful login response
    failure_indicator: str = ""      # String that indicates login failure

    @classmethod
    def from_string(cls, auth_string: str) -> "AuthConfig":
        """
        Parse auth from CLI string.

        Formats:
            basic:user:pass
            bearer:eyJhbG...
            header:X-API-Key:abc123
            form:https://site.com/login:user:pass
            cookie:session=abc123
        """
        if not auth_string:
            return cls()

        parts = auth_string.split(":", 1)
        atype = parts[0].lower()

        if atype == "basic" and ":" in parts[1]:
            user, pw = parts[1].split(":", 1)
            return cls(auth_type=AuthType.BASIC, username=user, password=pw)

        elif atype == "bearer":
            return cls(auth_type=AuthType.BEARER, token=parts[1])

        elif atype == "header":
            name, value = parts[1].split(":", 1)
            return cls(auth_type=AuthType.HEADER, header_name=name, header_value=value)

        elif atype == "form":
            # form:url:user:pass
            remaining = parts[1]
            url, rest = remaining.split(":", 1) if ":" in remaining else (remaining, "")
            # Handle URL with http(s)://
            if rest.startswith("//"):
                # URL contained a scheme, re-join
                scheme_part = parts[1].split(":", 2)
                url = f"{scheme_part[0]}:{scheme_part[1]}"
                rest = scheme_part[2] if len(scheme_part) > 2 else ""
            if ":" in rest:
                user, pw = rest.rsplit(":", 1)
                return cls(auth_type=AuthType.FORM, login_url=url, username=user, password=pw)
            return cls(auth_type=AuthType.FORM, login_url=url)

        elif atype == "cookie":
            return cls(auth_type=AuthType.COOKIE, token=parts[1])

        raise AuthenticationError(f"Unknown auth format: {auth_string}")


class AuthHandler:
    """Handles authentication for HTTP requests."""

    def __init__(self, config: AuthConfig):
        self.config = config
        self._session_cookies: dict = {}

    def get_headers(self) -> dict:
        """Return auth headers to inject into requests."""
        cfg = self.config

        if cfg.auth_type == AuthType.BASIC:
            import base64
            creds = base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
            log.info("Using Basic auth for user: %s", cfg.username)
            return {"Authorization": f"Basic {creds}"}

        elif cfg.auth_type == AuthType.BEARER:
            log.info("Using Bearer token auth")
            return {"Authorization": f"Bearer {cfg.token}"}

        elif cfg.auth_type == AuthType.HEADER:
            log.info("Using custom header auth: %s", cfg.header_name)
            return {cfg.header_name: cfg.header_value}

        return {}

    def get_cookies(self) -> dict:
        """Return auth cookies."""
        if self.config.auth_type == AuthType.COOKIE:
            cookies = {}
            for pair in self.config.token.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()
            log.info("Using cookie auth: %d cookies", len(cookies))
            return cookies
        return self._session_cookies

    def perform_form_login(self, http_client) -> bool:
        """
        Perform form-based login and capture session cookies.

        Args:
            http_client: The shared HTTPClient instance.

        Returns:
            True if login appeared successful.
        """
        cfg = self.config
        if cfg.auth_type != AuthType.FORM or not cfg.login_url:
            return False

        log.info("Performing form login at %s", cfg.login_url)

        try:
            data = {
                cfg.username_field: cfg.username,
                cfg.password_field: cfg.password,
            }
            resp = http_client.post(cfg.login_url, data=data, allow_redirects=True)

            # Check for success/failure indicators
            if cfg.failure_indicator and cfg.failure_indicator in resp.text:
                raise AuthenticationError(
                    f"Login failed — failure indicator found in response",
                    url=cfg.login_url,
                )

            if cfg.success_indicator and cfg.success_indicator not in resp.text:
                log.warning("Login success indicator not found in response")

            # Capture cookies from the response
            for cookie in resp.cookies:
                self._session_cookies[cookie.name] = cookie.value

            if self._session_cookies:
                log.info("Login successful — captured %d session cookies", len(self._session_cookies))
                return True
            else:
                # Even without cookies, a redirect might mean success
                if resp.status_code in (200, 302) and not cfg.failure_indicator:
                    log.info("Login completed (no cookies captured, but no failure detected)")
                    return True

            return False

        except Exception as e:
            raise AuthenticationError(f"Form login failed: {e}", url=cfg.login_url) from e
