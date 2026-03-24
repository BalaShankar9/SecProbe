"""
Shared HTTP client for all scanners.

Centralises:
    - Session management (connection pooling)
    - Proxy routing (Burp / ZAP / SOCKS)
    - Authentication (Basic, Bearer, Cookie, Custom)
    - Rate limiting (token-bucket)
    - Retry with exponential back-off
    - WAF detection on every response
    - Request / response logging
    - User-Agent rotation
"""

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from secprobe.core.logger import get_logger
from secprobe.core.exceptions import (
    TargetUnreachableError,
    WAFBlockedError,
)

log = get_logger("http")


# ── User-Agent Rotation Pool ────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
]


# ── Token-bucket rate limiter ────────────────────────────────────────

class RateLimiter:
    """Thread-safe token-bucket rate limiter."""

    def __init__(self, requests_per_second: float):
        self.rate = requests_per_second
        self.tokens = 1.0
        self.max_tokens = 1.0
        self.last_time = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        if self.rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_time
            self.last_time = now
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
            if self.tokens < 1.0:
                sleep_time = (1.0 - self.tokens) / self.rate
                time.sleep(sleep_time)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0


# ── HTTP Client ──────────────────────────────────────────────────────

@dataclass
class HTTPClientConfig:
    """Configuration for the shared HTTP client."""
    timeout: int = 15
    max_retries: int = 3
    backoff_factor: float = 0.5
    proxy: Optional[str] = None
    verify_ssl: bool = False
    follow_redirects: bool = True
    rate_limit: float = 0.0         # requests per second (0 = unlimited)
    rotate_user_agent: bool = False
    user_agent: Optional[str] = None
    auth_header: Optional[dict] = None
    cookies: dict = field(default_factory=dict)
    extra_headers: dict = field(default_factory=dict)


class HTTPClient:
    """
    Thread-safe, shared HTTP client used by all scanners.

    Usage:
        client = HTTPClient(config)
        resp = client.get("https://example.com")
        resp = client.post("https://example.com/api", json={"key": "value"})
    """

    def __init__(self, config: Optional[HTTPClientConfig] = None):
        self.config = config or HTTPClientConfig()
        self._session = self._build_session()
        self._rate_limiter = RateLimiter(
            self.config.rate_limit if self.config.rate_limit > 0 else 0
        )
        self._request_count = 0
        self._lock = threading.Lock()
        self._waf_detector = None  # Set externally after import to avoid circular

    def _build_session(self) -> requests.Session:
        session = requests.Session()

        # Retry strategy
        retry = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS", "POST", "PUT"],
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=50,
            pool_maxsize=100,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Proxy
        if self.config.proxy:
            session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }
            log.info("Proxy configured: %s", self.config.proxy)

        # SSL verification
        session.verify = self.config.verify_ssl

        # Base headers
        session.headers.update({
            "User-Agent": self.config.user_agent or USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

        # Auth
        if self.config.auth_header:
            session.headers.update(self.config.auth_header)

        # Cookies
        if self.config.cookies:
            session.cookies.update(self.config.cookies)

        # Extra headers
        if self.config.extra_headers:
            session.headers.update(self.config.extra_headers)

        return session

    def set_waf_detector(self, detector):
        self._waf_detector = detector

    @property
    def request_count(self) -> int:
        return self._request_count

    def _pre_request(self):
        """Rate limiting and UA rotation before each request."""
        self._rate_limiter.acquire()
        if self.config.rotate_user_agent:
            self._session.headers["User-Agent"] = random.choice(USER_AGENTS)
        with self._lock:
            self._request_count += 1

    def _check_waf(self, response: requests.Response, url: str):
        """Check if the response indicates WAF blocking."""
        if self._waf_detector:
            waf_name = self._waf_detector.detect_in_response(response)
            if waf_name and response.status_code in (403, 406, 429, 503):
                log.warning("WAF detected: %s (HTTP %d) for %s", waf_name, response.status_code, url)
                raise WAFBlockedError(waf_name, status_code=response.status_code, url=url)

    def get(self, url: str, **kwargs) -> requests.Response:
        """Send a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Send a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        """Send a PUT request."""
        return self.request("PUT", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        """Send an OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """Send a HEAD request."""
        return self.request("HEAD", url, **kwargs)

    def request(self, method: str, url: str, *,
                timeout: Optional[int] = None,
                allow_redirects: Optional[bool] = None,
                check_waf: bool = False,
                **kwargs) -> requests.Response:
        """
        Core request method used by all HTTP verbs.

        Args:
            method: HTTP method
            url: Target URL
            timeout: Override default timeout
            allow_redirects: Override default redirect policy
            check_waf: If True, raise WAFBlockedError on WAF detection
            **kwargs: Passed to requests.Session.request()
        """
        self._pre_request()

        if timeout is None:
            timeout = self.config.timeout
        if allow_redirects is None:
            allow_redirects = self.config.follow_redirects

        try:
            response = self._session.request(
                method, url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs,
            )

            log.debug("%s %s → %d (%d bytes)",
                      method, url, response.status_code, len(response.content))

            if check_waf:
                self._check_waf(response, url)

            return response

        except requests.ConnectionError as e:
            raise TargetUnreachableError(url, reason=str(e)) from e
        except requests.Timeout as e:
            raise TargetUnreachableError(url, reason=f"Timeout after {timeout}s") from e

    def close(self):
        """Close the underlying session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
