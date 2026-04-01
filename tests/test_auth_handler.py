"""Tests for secprobe.core.auth_handler — AuthHandler, AuthContext, AuthType."""

import base64
import json
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from secprobe.core.auth_handler import (
    AuthHandler,
    AuthContext,
    AuthType,
    COMMON_LOGIN_PATHS,
    JWT_INDICATOR_KEYS,
)
from secprobe.core.exceptions import AuthenticationError


def _make_response(status_code=200, json_body=None, cookies=None, headers=None):
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.side_effect = ValueError("No JSON")
    resp.cookies = cookies or []
    return resp


def _make_cookie(name, value):
    c = MagicMock()
    c.name = name
    c.value = value
    return c


def _make_jwt(payload=None, exp=None):
    """Build a minimal JWT string (header.payload.signature)."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    body = payload or {}
    if exp is not None:
        body["exp"] = exp
    payload_b64 = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    return f"{header}.{payload_b64}.fakesig"


class TestAuthType(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(AuthType.JWT_BEARER.value, "jwt_bearer")
        self.assertEqual(AuthType.COOKIE_SESSION.value, "cookie_session")
        self.assertEqual(AuthType.BASIC.value, "basic")
        self.assertEqual(AuthType.API_KEY.value, "api_key")
        self.assertEqual(AuthType.NONE.value, "none")
        self.assertEqual(AuthType.FORM_LOGIN.value, "form_login")


class TestAuthContext(unittest.TestCase):
    def test_defaults(self):
        ctx = AuthContext(auth_type=AuthType.NONE)
        self.assertIsNone(ctx.token)
        self.assertEqual(ctx.cookies, {})
        self.assertEqual(ctx.headers, {})
        self.assertEqual(ctx.username, "")
        self.assertIsNone(ctx.expiry)

    def test_jwt_context(self):
        ctx = AuthContext(
            auth_type=AuthType.JWT_BEARER,
            token="eyJ...",
            headers={"Authorization": "Bearer eyJ..."},
            username="admin@test.com",
            expiry=time.time() + 900,
        )
        self.assertEqual(ctx.auth_type, AuthType.JWT_BEARER)
        self.assertEqual(ctx.token, "eyJ...")
        self.assertIn("Authorization", ctx.headers)

    def test_cookie_context(self):
        ctx = AuthContext(
            auth_type=AuthType.COOKIE_SESSION,
            cookies={"session": "abc123"},
            username="user",
        )
        self.assertEqual(ctx.cookies["session"], "abc123")


class TestAutoDetectAuth(unittest.TestCase):
    """Test AuthHandler.auto_detect_auth with mocked HTTP responses."""

    def _handler(self, http_client=None):
        return AuthHandler(http_client or MagicMock())

    def test_detects_jwt_via_token_key(self):
        client = MagicMock()
        jwt = _make_jwt()
        # First login path returns JSON with "token" key
        client.post.return_value = _make_response(200, json_body={"token": jwt})
        client.get.return_value = _make_response(404)

        handler = self._handler(client)
        result = handler.auto_detect_auth("http://target:3000")

        self.assertEqual(result, AuthType.JWT_BEARER)

    def test_detects_cookie_session(self):
        client = MagicMock()
        cookie = _make_cookie("session", "abc")
        resp = _make_response(200, json_body={"message": "ok"}, cookies=[cookie])
        # JSON has no JWT keys, but response has cookies
        client.post.return_value = resp
        client.get.return_value = _make_response(404)

        handler = self._handler(client)
        result = handler.auto_detect_auth("http://target:3000")

        self.assertEqual(result, AuthType.COOKIE_SESSION)

    def test_detects_basic_via_www_authenticate(self):
        client = MagicMock()
        # All login POSTs return 404
        client.post.return_value = _make_response(404)
        # OAuth GETs also 404
        # Root GET returns Basic challenge
        client.get.side_effect = [
            _make_response(404),  # OAuth paths
            _make_response(404),
            _make_response(404),
            _make_response(404),
            _make_response(401, headers={"WWW-Authenticate": "Basic realm=\"app\""}),
        ]

        handler = self._handler(client)
        result = handler.auto_detect_auth("http://target:3000")

        self.assertEqual(result, AuthType.BASIC)

    def test_returns_none_when_nothing_found(self):
        client = MagicMock()
        client.post.return_value = _make_response(404)
        client.get.return_value = _make_response(200)

        handler = self._handler(client)
        result = handler.auto_detect_auth("http://target:3000")

        self.assertEqual(result, AuthType.NONE)

    def test_detects_bearer_via_www_authenticate(self):
        client = MagicMock()
        resp_401 = _make_response(401, headers={"WWW-Authenticate": "Bearer realm=\"api\""})
        client.post.return_value = resp_401
        client.get.return_value = _make_response(404)

        handler = self._handler(client)
        result = handler.auto_detect_auth("http://target:3000")

        self.assertEqual(result, AuthType.JWT_BEARER)


class TestAuthenticateJWT(unittest.TestCase):
    """Test the JWT authentication flow."""

    def test_jwt_success(self):
        client = MagicMock()
        jwt = _make_jwt(exp=time.time() + 3600)
        # auto_detect POST returns JWT
        client.post.return_value = _make_response(200, json_body={"token": jwt})
        client.get.return_value = _make_response(404)

        handler = AuthHandler(client)
        ctx = handler.authenticate(
            "http://target:3000",
            {"email": "admin@juice.sh", "password": "admin123"},
            auth_type=AuthType.JWT_BEARER,
            auth_url="http://target:3000/rest/user/login",
        )

        self.assertEqual(ctx.auth_type, AuthType.JWT_BEARER)
        self.assertEqual(ctx.token, jwt)
        self.assertIn("Authorization", ctx.headers)
        self.assertTrue(ctx.headers["Authorization"].startswith("Bearer "))
        self.assertEqual(ctx.username, "admin@juice.sh")

    def test_jwt_extracts_access_token(self):
        client = MagicMock()
        jwt = _make_jwt()
        client.post.return_value = _make_response(
            200, json_body={"authentication": {"token": jwt, "bid": 1}}
        )
        client.get.return_value = _make_response(404)

        handler = AuthHandler(client)
        ctx = handler.authenticate(
            "http://target:3000",
            {"email": "a@b.c", "password": "x"},
            auth_type=AuthType.JWT_BEARER,
            auth_url="http://target:3000/rest/user/login",
        )
        self.assertEqual(ctx.token, jwt)

    def test_jwt_failure_raises(self):
        client = MagicMock()
        client.post.return_value = _make_response(401, json_body={"error": "Invalid"})

        handler = AuthHandler(client)
        handler._login_endpoint = "http://target:3000/rest/user/login"

        with self.assertRaises(AuthenticationError):
            handler.authenticate(
                "http://target:3000",
                {"email": "bad@user", "password": "wrong"},
                auth_type=AuthType.JWT_BEARER,
                auth_url="http://target:3000/rest/user/login",
            )

    def test_jwt_no_token_in_response_raises(self):
        client = MagicMock()
        client.post.return_value = _make_response(200, json_body={"status": "ok"})

        handler = AuthHandler(client)
        with self.assertRaises(AuthenticationError):
            handler.authenticate(
                "http://target:3000",
                {"email": "a@b.c", "password": "x"},
                auth_type=AuthType.JWT_BEARER,
                auth_url="http://target:3000/rest/user/login",
            )


class TestAuthenticateCookie(unittest.TestCase):
    """Test the Cookie/session authentication flow."""

    def test_cookie_success(self):
        client = MagicMock()
        cookie = _make_cookie("connect.sid", "s%3Aabc123")
        client.post.return_value = _make_response(
            200, json_body={"status": "ok"}, cookies=[cookie]
        )
        client.get.return_value = _make_response(404)

        handler = AuthHandler(client)
        ctx = handler.authenticate(
            "http://target:3000",
            {"email": "user@test.com", "password": "pass"},
            auth_type=AuthType.COOKIE_SESSION,
            auth_url="http://target:3000/login",
        )

        self.assertEqual(ctx.auth_type, AuthType.COOKIE_SESSION)
        self.assertIn("connect.sid", ctx.cookies)
        self.assertEqual(ctx.username, "user@test.com")

    def test_cookie_no_cookies_raises(self):
        client = MagicMock()
        client.post.return_value = _make_response(200, json_body={}, cookies=[])

        handler = AuthHandler(client)
        with self.assertRaises(AuthenticationError):
            handler.authenticate(
                "http://target:3000",
                {"email": "a@b.c", "password": "x"},
                auth_type=AuthType.COOKIE_SESSION,
                auth_url="http://target:3000/login",
            )


class TestAuthenticateBasic(unittest.TestCase):
    """Test Basic auth flow."""

    def test_basic_auth(self):
        client = MagicMock()
        client.post.return_value = _make_response(404)
        client.get.return_value = _make_response(200)

        handler = AuthHandler(client)
        ctx = handler.authenticate(
            "http://target:3000",
            {"username": "admin", "password": "secret"},
            auth_type=AuthType.BASIC,
        )

        self.assertEqual(ctx.auth_type, AuthType.BASIC)
        expected = base64.b64encode(b"admin:secret").decode()
        self.assertEqual(ctx.token, expected)
        self.assertEqual(ctx.headers["Authorization"], f"Basic {expected}")


class TestAuthenticateAPIKey(unittest.TestCase):
    """Test API key auth flow."""

    def test_api_key_default_header(self):
        client = MagicMock()

        handler = AuthHandler(client)
        ctx = handler.authenticate(
            "http://target:3000",
            {"api_key": "my-secret-key"},
            auth_type=AuthType.API_KEY,
        )

        self.assertEqual(ctx.auth_type, AuthType.API_KEY)
        self.assertEqual(ctx.headers["X-API-Key"], "my-secret-key")

    def test_api_key_custom_header(self):
        client = MagicMock()

        handler = AuthHandler(client)
        ctx = handler.authenticate(
            "http://target:3000",
            {"api_key": "key123"},
            auth_type=AuthType.API_KEY,
            auth_header_name="X-Custom-Auth",
        )

        self.assertEqual(ctx.headers["X-Custom-Auth"], "key123")


class TestGetAuthHeaders(unittest.TestCase):
    """Test static header generation."""

    def test_jwt_headers(self):
        ctx = AuthContext(
            auth_type=AuthType.JWT_BEARER,
            token="abc.def.ghi",
            headers={"Authorization": "Bearer abc.def.ghi"},
        )
        headers = AuthHandler.get_auth_headers(ctx)
        self.assertEqual(headers["Authorization"], "Bearer abc.def.ghi")

    def test_basic_headers(self):
        encoded = base64.b64encode(b"user:pass").decode()
        ctx = AuthContext(
            auth_type=AuthType.BASIC,
            token=encoded,
            headers={"Authorization": f"Basic {encoded}"},
        )
        headers = AuthHandler.get_auth_headers(ctx)
        self.assertTrue(headers["Authorization"].startswith("Basic "))

    def test_none_headers_empty(self):
        ctx = AuthContext(auth_type=AuthType.NONE)
        headers = AuthHandler.get_auth_headers(ctx)
        self.assertEqual(headers, {})

    def test_api_key_headers(self):
        ctx = AuthContext(
            auth_type=AuthType.API_KEY,
            token="key123",
            headers={"X-API-Key": "key123"},
        )
        headers = AuthHandler.get_auth_headers(ctx)
        self.assertEqual(headers["X-API-Key"], "key123")


class TestRefreshIfNeeded(unittest.TestCase):
    """Test token refresh logic."""

    def test_no_refresh_when_valid(self):
        client = MagicMock()
        handler = AuthHandler(client)
        ctx = AuthContext(
            auth_type=AuthType.JWT_BEARER,
            token="valid",
            expiry=time.time() + 3600,
        )
        result = handler.refresh_if_needed(ctx)
        self.assertIs(result, ctx)

    def test_refresh_when_expired(self):
        client = MagicMock()
        jwt = _make_jwt(exp=time.time() + 3600)
        client.post.return_value = _make_response(200, json_body={"token": jwt})
        client.get.return_value = _make_response(404)

        handler = AuthHandler(client)
        handler._credentials = {"email": "a@b.c", "password": "x"}
        handler._login_endpoint = "http://target:3000/rest/user/login"

        expired_ctx = AuthContext(
            auth_type=AuthType.JWT_BEARER,
            token="old",
            expiry=time.time() - 100,
        )
        result = handler.refresh_if_needed(expired_ctx, target_url="http://target:3000")

        self.assertIsNot(result, expired_ctx)
        self.assertEqual(result.auth_type, AuthType.JWT_BEARER)
        self.assertEqual(result.token, jwt)

    def test_no_refresh_for_none_type(self):
        client = MagicMock()
        handler = AuthHandler(client)
        ctx = AuthContext(auth_type=AuthType.NONE)
        result = handler.refresh_if_needed(ctx)
        self.assertIs(result, ctx)

    def test_no_refresh_without_expiry(self):
        client = MagicMock()
        handler = AuthHandler(client)
        ctx = AuthContext(auth_type=AuthType.JWT_BEARER, token="tok", expiry=None)
        result = handler.refresh_if_needed(ctx)
        self.assertIs(result, ctx)

    def test_refresh_fails_returns_original(self):
        client = MagicMock()
        client.post.side_effect = Exception("network error")
        client.get.return_value = _make_response(404)

        handler = AuthHandler(client)
        handler._credentials = {"email": "a@b.c", "password": "x"}
        handler._login_endpoint = "http://target:3000/rest/user/login"

        expired_ctx = AuthContext(
            auth_type=AuthType.JWT_BEARER,
            token="old",
            expiry=time.time() - 100,
        )
        result = handler.refresh_if_needed(expired_ctx, target_url="http://target:3000")
        # Should return original context when refresh fails
        self.assertIs(result, expired_ctx)


class TestExtractToken(unittest.TestCase):
    """Test token extraction from various JSON shapes."""

    def test_top_level_token(self):
        self.assertEqual(AuthHandler._extract_token({"token": "abc"}), "abc")

    def test_top_level_access_token(self):
        self.assertEqual(AuthHandler._extract_token({"access_token": "xyz"}), "xyz")

    def test_nested_token(self):
        body = {"authentication": {"token": "nested_jwt"}}
        self.assertEqual(AuthHandler._extract_token(body), "nested_jwt")

    def test_no_token(self):
        self.assertIsNone(AuthHandler._extract_token({"status": "ok"}))

    def test_non_dict(self):
        self.assertIsNone(AuthHandler._extract_token("just a string"))
        self.assertIsNone(AuthHandler._extract_token(None))


if __name__ == "__main__":
    unittest.main()
