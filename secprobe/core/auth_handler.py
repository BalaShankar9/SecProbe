"""
Auth-aware scanning handler for SecProbe.

Provides automatic auth-type detection, login flows, and token lifecycle
management so that scanners can reach authenticated endpoints.

Supports:
    - Auto-detection of auth mechanism (JWT, cookie, basic, API key)
    - JWT/Bearer token authentication with refresh
    - Cookie/session-based authentication
    - HTTP Basic authentication
    - Custom API key header authentication
"""

import base64
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urljoin

from secprobe.core.logger import get_logger
from secprobe.core.exceptions import AuthenticationError

log = get_logger("auth_handler")


# ── Auth type enum ──────────────────────────────────────────────────

class AuthType(Enum):
    """Authentication mechanism detected or configured."""
    NONE = "none"
    FORM_LOGIN = "form_login"
    JWT_BEARER = "jwt_bearer"
    BASIC = "basic"
    API_KEY = "api_key"
    COOKIE_SESSION = "cookie_session"


# ── Auth context dataclass ──────────────────────────────────────────

@dataclass
class AuthContext:
    """Holds all state needed to authenticate subsequent requests."""
    auth_type: AuthType
    token: Optional[str] = None
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    username: str = ""
    expiry: Optional[float] = None


# ── Common login endpoint paths ─────────────────────────────────────

COMMON_LOGIN_PATHS = [
    "/rest/user/login",
    "/api/login",
    "/auth/login",
    "/login",
    "/api/auth/signin",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/users/login",
    "/account/login",
]

OAUTH_PATHS = [
    "/oauth/token",
    "/oauth2/token",
    "/oauth/authorize",
    "/.well-known/openid-configuration",
]

JWT_INDICATOR_KEYS = {"token", "access_token", "accessToken", "jwt", "id_token"}


# ── AuthHandler ─────────────────────────────────────────────────────

class AuthHandler:
    """
    Detects auth mechanisms, performs login flows, and manages token
    lifecycle for authenticated scanning.

    Usage::

        handler = AuthHandler(http_client)
        auth_type = handler.auto_detect_auth("http://target:3000")
        ctx = handler.authenticate("http://target:3000", {"email": "a@b.c", "password": "x"})
        headers = handler.get_auth_headers(ctx)
        # ... later ...
        ctx = handler.refresh_if_needed(ctx)
    """

    def __init__(self, http_client):
        self.http_client = http_client
        self._login_endpoint: Optional[str] = None
        self._credentials: dict = {}

    # ── Auto-detection ──────────────────────────────────────────

    def auto_detect_auth(self, target_url: str) -> AuthType:
        """
        Probe common auth endpoints on *target_url* and return the
        detected :class:`AuthType`.

        Detection heuristic:
        1. POST to common login endpoints with empty/minimal JSON.
           - If the endpoint exists and response JSON contains a JWT
             indicator key, return ``JWT_BEARER``.
           - If the endpoint sets ``Set-Cookie``, return ``COOKIE_SESSION``.
        2. Check for OAuth / OIDC well-known endpoints.
        3. If a login page returns 401 with ``WWW-Authenticate: Basic``,
           return ``BASIC``.
        4. Fall back to ``NONE``.
        """
        target_url = target_url.rstrip("/")

        # --- Check common login endpoints ---
        for path in COMMON_LOGIN_PATHS:
            url = urljoin(target_url + "/", path.lstrip("/"))
            try:
                resp = self.http_client.post(
                    url,
                    json={"email": "", "password": ""},
                    timeout=5,
                )
                # Endpoint exists (not 404)
                if resp.status_code == 404:
                    continue

                # JWT indicator in JSON body
                try:
                    body = resp.json()
                    if isinstance(body, dict):
                        if JWT_INDICATOR_KEYS & set(body.keys()):
                            self._login_endpoint = url
                            log.info("Detected JWT auth at %s", url)
                            return AuthType.JWT_BEARER
                except (ValueError, TypeError):
                    pass

                # Cookie indicator
                if resp.cookies:
                    self._login_endpoint = url
                    log.info("Detected cookie/session auth at %s", url)
                    return AuthType.COOKIE_SESSION

                # If endpoint exists but gave 401 with challenge
                if resp.status_code == 401:
                    www_auth = resp.headers.get("WWW-Authenticate", "")
                    if "basic" in www_auth.lower():
                        log.info("Detected Basic auth via WWW-Authenticate at %s", url)
                        return AuthType.BASIC
                    if "bearer" in www_auth.lower():
                        self._login_endpoint = url
                        log.info("Detected Bearer auth via WWW-Authenticate at %s", url)
                        return AuthType.JWT_BEARER

                # Endpoint exists and returned something useful — remember it
                if resp.status_code in (200, 400, 401, 422):
                    self._login_endpoint = url

            except Exception:
                # Connection errors, timeouts — skip to next path
                continue

        # --- Check OAuth / OIDC ---
        for path in OAUTH_PATHS:
            url = urljoin(target_url + "/", path.lstrip("/"))
            try:
                resp = self.http_client.get(url, timeout=5)
                if resp.status_code != 404:
                    self._login_endpoint = url
                    log.info("Detected OAuth endpoint at %s", url)
                    return AuthType.JWT_BEARER
            except Exception:
                continue

        # --- Check if root returns Basic challenge ---
        try:
            resp = self.http_client.get(target_url, timeout=5)
            www_auth = resp.headers.get("WWW-Authenticate", "")
            if "basic" in www_auth.lower():
                log.info("Detected Basic auth on root URL")
                return AuthType.BASIC
        except Exception:
            pass

        log.info("No auth mechanism detected for %s", target_url)
        return AuthType.NONE

    # ── Authenticate ────────────────────────────────────────────

    def authenticate(
        self,
        target_url: str,
        credentials: dict,
        auth_type: Optional[AuthType] = None,
        auth_url: Optional[str] = None,
        auth_header_name: Optional[str] = None,
    ) -> AuthContext:
        """
        Attempt login against *target_url* and return an :class:`AuthContext`.

        Parameters
        ----------
        target_url : str
            Base URL of the target application.
        credentials : dict
            Keys typically include ``email``/``username`` and ``password``,
            or ``api_key`` for API key auth.
        auth_type : AuthType, optional
            Override detected auth type. If ``None``, runs auto-detection.
        auth_url : str, optional
            Explicit login endpoint URL (skips auto-detection of endpoint).
        auth_header_name : str, optional
            Custom header name for API key auth (default ``X-API-Key``).
        """
        target_url = target_url.rstrip("/")
        self._credentials = credentials

        if auth_type is None:
            auth_type = self.auto_detect_auth(target_url)

        login_url = auth_url or self._login_endpoint
        username = credentials.get("email") or credentials.get("username", "")

        if auth_type == AuthType.JWT_BEARER:
            return self._auth_jwt(target_url, login_url, credentials, username)

        if auth_type == AuthType.COOKIE_SESSION:
            return self._auth_cookie(target_url, login_url, credentials, username)

        if auth_type == AuthType.BASIC:
            return self._auth_basic(credentials, username)

        if auth_type == AuthType.API_KEY:
            return self._auth_api_key(credentials, auth_header_name or "X-API-Key")

        # NONE / unrecognised — return empty context
        log.warning("No usable auth type — returning unauthenticated context")
        return AuthContext(auth_type=AuthType.NONE, username=username)

    # ── JWT / Bearer flow ───────────────────────────────────────

    def _auth_jwt(self, target_url, login_url, credentials, username) -> AuthContext:
        if not login_url:
            raise AuthenticationError(
                "JWT auth selected but no login endpoint found",
                url=target_url,
            )

        log.info("Attempting JWT login at %s", login_url)
        try:
            resp = self.http_client.post(login_url, json=credentials, timeout=10)
        except Exception as exc:
            raise AuthenticationError(
                f"JWT login request failed: {exc}", url=login_url
            ) from exc

        if resp.status_code not in (200, 201):
            raise AuthenticationError(
                f"JWT login returned HTTP {resp.status_code}", url=login_url
            )

        try:
            body = resp.json()
        except (ValueError, TypeError) as exc:
            raise AuthenticationError(
                "JWT login response is not valid JSON", url=login_url
            ) from exc

        token = self._extract_token(body)
        if not token:
            raise AuthenticationError(
                "Could not extract token from login response", url=login_url
            )

        # Estimate expiry — default 15 min if we cannot decode the JWT
        expiry = time.time() + 900
        try:
            import json as _json
            # Decode JWT payload (no verification — we just need exp)
            payload_b64 = token.split(".")[1]
            # Fix padding
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = _json.loads(base64.urlsafe_b64decode(payload_b64))
            if "exp" in payload:
                expiry = float(payload["exp"])
        except Exception:
            pass

        log.info("JWT authentication successful for %s", username)
        return AuthContext(
            auth_type=AuthType.JWT_BEARER,
            token=token,
            headers={"Authorization": f"Bearer {token}"},
            username=username,
            expiry=expiry,
        )

    @staticmethod
    def _extract_token(body) -> Optional[str]:
        """Walk a JSON response looking for a JWT-like string."""
        if isinstance(body, dict):
            # Direct top-level keys
            for key in JWT_INDICATOR_KEYS:
                if key in body and isinstance(body[key], str):
                    return body[key]
            # One level of nesting (e.g. {"authentication": {"token": "..."}})
            for value in body.values():
                if isinstance(value, dict):
                    for key in JWT_INDICATOR_KEYS:
                        if key in value and isinstance(value[key], str):
                            return value[key]
        return None

    # ── Cookie / session flow ───────────────────────────────────

    def _auth_cookie(self, target_url, login_url, credentials, username) -> AuthContext:
        if not login_url:
            raise AuthenticationError(
                "Cookie auth selected but no login endpoint found",
                url=target_url,
            )

        log.info("Attempting cookie/session login at %s", login_url)
        try:
            resp = self.http_client.post(
                login_url, json=credentials, timeout=10, allow_redirects=True,
            )
        except Exception as exc:
            raise AuthenticationError(
                f"Cookie login request failed: {exc}", url=login_url
            ) from exc

        cookies = {}
        for cookie in resp.cookies:
            cookies[cookie.name] = cookie.value

        if not cookies:
            # Try form-encoded as fallback
            try:
                resp = self.http_client.post(
                    login_url, data=credentials, timeout=10, allow_redirects=True,
                )
                for cookie in resp.cookies:
                    cookies[cookie.name] = cookie.value
            except Exception:
                pass

        if not cookies:
            raise AuthenticationError(
                "Cookie login did not return any session cookies", url=login_url
            )

        log.info("Cookie authentication successful — %d cookies captured", len(cookies))
        return AuthContext(
            auth_type=AuthType.COOKIE_SESSION,
            cookies=cookies,
            username=username,
            # Session cookies typically don't have a fixed expiry we can read
            expiry=time.time() + 3600,
        )

    # ── Basic auth ──────────────────────────────────────────────

    def _auth_basic(self, credentials, username) -> AuthContext:
        password = credentials.get("password", "")
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        log.info("Basic auth configured for user %s", username)
        return AuthContext(
            auth_type=AuthType.BASIC,
            token=encoded,
            headers={"Authorization": f"Basic {encoded}"},
            username=username,
        )

    # ── API key ─────────────────────────────────────────────────

    def _auth_api_key(self, credentials, header_name) -> AuthContext:
        api_key = credentials.get("api_key", credentials.get("password", ""))
        log.info("API key auth configured via header %s", header_name)
        return AuthContext(
            auth_type=AuthType.API_KEY,
            token=api_key,
            headers={header_name: api_key},
        )

    # ── Header generation ───────────────────────────────────────

    @staticmethod
    def get_auth_headers(auth_context: AuthContext) -> dict:
        """
        Return a dict of HTTP headers to inject into requests for the
        given *auth_context*.
        """
        headers = dict(auth_context.headers)

        if auth_context.auth_type == AuthType.JWT_BEARER and auth_context.token:
            headers.setdefault("Authorization", f"Bearer {auth_context.token}")

        elif auth_context.auth_type == AuthType.BASIC and auth_context.token:
            headers.setdefault("Authorization", f"Basic {auth_context.token}")

        return headers

    # ── Token refresh ───────────────────────────────────────────

    def refresh_if_needed(
        self,
        auth_context: AuthContext,
        target_url: Optional[str] = None,
        buffer_seconds: int = 60,
    ) -> AuthContext:
        """
        Re-authenticate if the token in *auth_context* has expired or
        will expire within *buffer_seconds*.

        Returns the original context if still valid, or a fresh one.
        """
        if auth_context.auth_type == AuthType.NONE:
            return auth_context

        if auth_context.expiry is None:
            return auth_context

        if time.time() + buffer_seconds < auth_context.expiry:
            return auth_context

        log.info("Auth token expired or expiring soon — refreshing")

        if not self._credentials:
            log.warning("No stored credentials — cannot refresh token")
            return auth_context

        url = target_url or ""
        try:
            return self.authenticate(
                url,
                self._credentials,
                auth_type=auth_context.auth_type,
                auth_url=self._login_endpoint,
            )
        except AuthenticationError as exc:
            log.warning("Token refresh failed: %s — using existing context", exc)
            return auth_context
