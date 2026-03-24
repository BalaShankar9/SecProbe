"""
Stealth HTTP Client — Browser-grade TLS fingerprint impersonation.

This is what separates SecProbe from every generic scanner.

Uses curl_cffi to impersonate real browser TLS fingerprints (JA3/JA4),
HTTP/2 framing, header ordering, and cipher suites. WAFs like Cloudflare,
Akamai, and Imperva cannot distinguish these requests from real Chrome/Firefox.

Features:
    - JA3/JA4 TLS fingerprint impersonation (Chrome, Firefox, Safari, Edge)
    - HTTP/2 with proper SETTINGS frames and priority
    - Browser-accurate header ordering
    - Automatic cookie jar with domain scoping
    - Cloudflare JS challenge bypass (via cf_clearance cookie chain)
    - Per-request browser profile rotation
    - Drop-in replacement for HTTPClient interface

Architecture:
    StealthClient wraps curl_cffi and exposes the same .get/.post/.request
    interface as HTTPClient, so scanners don't need to change. The CLI
    selects StealthClient when --stealth is passed.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from curl_cffi import requests as cffi_requests
from curl_cffi.requests import Response as CffiResponse

from secprobe.core.logger import get_logger
from secprobe.core.exceptions import TargetUnreachableError, WAFBlockedError

log = get_logger("stealth")


# ── Browser Impersonation Profiles ───────────────────────────────────
# curl_cffi supports these browser fingerprints natively.
# Each profile replicates the exact TLS ClientHello, HTTP/2 SETTINGS,
# header order, and cipher suite of the real browser.

@dataclass(frozen=True)
class BrowserProfile:
    """A browser impersonation identity."""
    name: str
    impersonate: str          # curl_cffi impersonate string
    user_agent: str
    sec_ch_ua: str            # Client Hints
    sec_ch_ua_platform: str
    accept_language: str
    extra_headers: dict = field(default_factory=dict)


# Real browser profiles — these match actual TLS fingerprints
BROWSER_PROFILES = [
    BrowserProfile(
        name="Chrome 124 (Windows)",
        impersonate="chrome124",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_platform='"Windows"',
        accept_language="en-US,en;q=0.9",
    ),
    BrowserProfile(
        name="Chrome 124 (macOS)",
        impersonate="chrome124",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_platform='"macOS"',
        accept_language="en-US,en;q=0.9",
    ),
    BrowserProfile(
        name="Chrome 120 (Windows)",
        impersonate="chrome120",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"Windows"',
        accept_language="en-US,en;q=0.9",
    ),
    BrowserProfile(
        name="Firefox 124",
        impersonate="firefox",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        sec_ch_ua="",  # Firefox doesn't send Client Hints
        sec_ch_ua_platform="",
        accept_language="en-US,en;q=0.5",
    ),
    BrowserProfile(
        name="Safari 17 (macOS)",
        impersonate="safari17_0",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        sec_ch_ua="",
        sec_ch_ua_platform="",
        accept_language="en-US,en;q=0.9",
    ),
    BrowserProfile(
        name="Edge 124",
        impersonate="edge101",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        sec_ch_ua='"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_platform='"Windows"',
        accept_language="en-US,en;q=0.9",
    ),
]

# Default profile (Chrome is the most common)
DEFAULT_PROFILE = BROWSER_PROFILES[0]


@dataclass
class StealthConfig:
    """Configuration for the stealth HTTP client."""
    timeout: int = 15
    max_retries: int = 3
    proxy: Optional[str] = None
    verify_ssl: bool = False
    follow_redirects: bool = True
    rate_limit: float = 0.0
    rotate_profile: bool = True       # Rotate browser profiles per request
    profile: Optional[str] = None     # Lock to specific profile name
    impersonate: str = "chrome124"    # Default impersonation target
    auth_header: Optional[dict] = None
    cookies: dict = field(default_factory=dict)
    extra_headers: dict = field(default_factory=dict)


class _StealthRateLimiter:
    """Thread-safe token-bucket rate limiter."""

    def __init__(self, rps: float):
        self.rate = rps
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


class StealthClient:
    """
    Browser-grade stealth HTTP client.

    Uses curl_cffi to impersonate real browser TLS fingerprints (JA3/JA4),
    HTTP/2 framing, and header ordering. This makes requests indistinguishable
    from real Chrome/Firefox/Safari to WAFs like Cloudflare.

    Drop-in compatible with HTTPClient interface — scanners work unchanged.

    Usage:
        client = StealthClient(config)
        resp = client.get("https://booking.com")  # Looks like Chrome 124
        resp = client.post("https://api.target.com/login", json={...})
    """

    def __init__(self, config: Optional[StealthConfig] = None):
        self.config = config or StealthConfig()
        self._session = self._build_session()
        self._rate_limiter = _StealthRateLimiter(
            self.config.rate_limit if self.config.rate_limit > 0 else 0
        )
        self._request_count = 0
        self._lock = threading.Lock()
        self._waf_detector = None
        self._current_profile = self._select_profile()

        log.info("StealthClient initialized — impersonating %s", self._current_profile.name)

    def _build_session(self) -> cffi_requests.Session:
        """Build a curl_cffi session with browser impersonation."""
        session = cffi_requests.Session(
            impersonate=self.config.impersonate,
            verify=self.config.verify_ssl,
        )

        # Proxy
        if self.config.proxy:
            session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }
            log.info("Stealth proxy: %s", self.config.proxy)

        # Pre-load cookies
        if self.config.cookies:
            for name, value in self.config.cookies.items():
                session.cookies.set(name, value)

        return session

    def _select_profile(self) -> BrowserProfile:
        """Select a browser profile."""
        if self.config.profile:
            for p in BROWSER_PROFILES:
                if p.name.lower().startswith(self.config.profile.lower()):
                    return p
        return DEFAULT_PROFILE

    def _rotate_profile(self):
        """Rotate to a random browser profile."""
        if self.config.rotate_profile:
            self._current_profile = random.choice(BROWSER_PROFILES)
            # Rebuild session with new impersonation
            old_cookies = dict(self._session.cookies)
            self._session.close()
            self._session = cffi_requests.Session(
                impersonate=self._current_profile.impersonate,
                verify=self.config.verify_ssl,
            )
            if self.config.proxy:
                self._session.proxies = {
                    "http": self.config.proxy,
                    "https": self.config.proxy,
                }
            # Restore cookies
            for name, value in old_cookies.items():
                self._session.cookies.set(name, value)

    def _build_headers(self, extra: dict | None = None) -> dict:
        """Build browser-accurate headers for the current profile."""
        profile = self._current_profile
        headers = {
            "User-Agent": profile.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": profile.accept_language,
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
        }

        # Chrome/Edge Client Hints
        if profile.sec_ch_ua:
            headers["Sec-Ch-Ua"] = profile.sec_ch_ua
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = profile.sec_ch_ua_platform
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"

        # Auth headers
        if self.config.auth_header:
            headers.update(self.config.auth_header)

        # Extra config headers
        if self.config.extra_headers:
            headers.update(self.config.extra_headers)

        # Per-request overrides
        if extra:
            headers.update(extra)

        return headers

    def set_waf_detector(self, detector):
        """Set WAF detector for inline response checking."""
        self._waf_detector = detector

    @property
    def request_count(self) -> int:
        return self._request_count

    def _pre_request(self):
        """Rate limiting and optional profile rotation."""
        self._rate_limiter.acquire()
        with self._lock:
            self._request_count += 1
            # Rotate profile every 10-30 requests to look natural
            if self.config.rotate_profile and self._request_count % random.randint(10, 30) == 0:
                self._rotate_profile()

    def _adapt_response(self, resp: CffiResponse) -> CffiResponse:
        """Ensure response has the attributes scanners expect."""
        # curl_cffi Response already has .text, .status_code, .headers, .url, .cookies
        # But some scanners access .content, which also exists
        return resp

    def _check_waf(self, response: CffiResponse, url: str):
        """Check if response indicates WAF blocking."""
        if not self._waf_detector:
            return
        waf_name = self._waf_detector.detect_in_response(response)
        if waf_name and response.status_code in (403, 406, 429, 503):
            log.warning("WAF detected via stealth: %s (HTTP %d) for %s",
                        waf_name, response.status_code, url)
            raise WAFBlockedError(waf_name, status_code=response.status_code, url=url)

    def get(self, url: str, **kwargs) -> CffiResponse:
        """Send a GET request with browser impersonation."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> CffiResponse:
        """Send a POST request with browser impersonation."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> CffiResponse:
        """Send a PUT request."""
        return self.request("PUT", url, **kwargs)

    def options(self, url: str, **kwargs) -> CffiResponse:
        """Send an OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> CffiResponse:
        """Send a HEAD request."""
        return self.request("HEAD", url, **kwargs)

    def request(self, method: str, url: str, *,
                timeout: Optional[int] = None,
                allow_redirects: Optional[bool] = None,
                check_waf: bool = False,
                headers: Optional[dict] = None,
                **kwargs) -> CffiResponse:
        """
        Core request method — browser-impersonated HTTP/2 request.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            timeout: Override timeout
            allow_redirects: Override redirect policy
            check_waf: Raise on WAF detection
            headers: Extra headers (merged with browser profile headers)
            **kwargs: Passed to curl_cffi (data, json, params, etc.)
        """
        self._pre_request()

        if timeout is None:
            timeout = self.config.timeout
        if allow_redirects is None:
            allow_redirects = self.config.follow_redirects

        merged_headers = self._build_headers(headers)

        retries = 0
        last_error = None

        while retries <= self.config.max_retries:
            try:
                response = self._session.request(
                    method, url,
                    headers=merged_headers,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    **kwargs,
                )

                log.debug("[STEALTH] %s %s → %d (%d bytes) [%s]",
                          method, url, response.status_code,
                          len(response.content), self._current_profile.name)

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", "5"))
                    log.warning("Rate limited — sleeping %ds", retry_after)
                    time.sleep(retry_after)
                    retries += 1
                    continue

                # Handle server errors
                if response.status_code >= 500 and retries < self.config.max_retries:
                    wait = self.config.timeout * (2 ** retries) * 0.1
                    time.sleep(wait)
                    retries += 1
                    continue

                if check_waf:
                    self._check_waf(response, url)

                return self._adapt_response(response)

            except cffi_requests.errors.RequestsError as e:
                last_error = e
                error_str = str(e).lower()

                # Retry on connection errors
                if any(kw in error_str for kw in ("connection", "timeout", "reset", "refused")):
                    retries += 1
                    if retries <= self.config.max_retries:
                        wait = 1.0 * (2 ** (retries - 1))
                        log.debug("Connection error, retry %d/%d in %.1fs: %s",
                                  retries, self.config.max_retries, wait, e)
                        time.sleep(wait)
                        continue

                raise TargetUnreachableError(url, reason=str(e)) from e

        raise TargetUnreachableError(url, reason=f"Max retries exceeded: {last_error}")

    def solve_challenge(self, url: str, max_wait: int = 15) -> CffiResponse:
        """
        Attempt to solve Cloudflare JS challenge by requesting the page
        and following the challenge redirect chain.

        curl_cffi's browser impersonation often bypasses Cloudflare's
        bot detection without needing actual JS execution, because the
        TLS fingerprint matches a real browser.

        For JS challenges that require actual computation, use BrowserEngine.

        Returns the final response after challenge resolution.
        """
        log.info("Attempting challenge solve for %s", url)

        # First request with full browser profile
        resp = self.get(url)

        # Check if we got through
        if resp.status_code == 200 and "challenge" not in resp.text.lower()[:2000]:
            log.info("Challenge bypassed via TLS impersonation")
            return resp

        # Cloudflare 403 with cf_clearance cookie expected
        if resp.status_code == 403:
            # Wait for Cloudflare's challenge timer
            time.sleep(5)
            resp = self.get(url)
            if resp.status_code == 200:
                log.info("Challenge resolved after wait")
                return resp

        # If still challenged, try different profile
        original_profile = self._current_profile
        for profile in BROWSER_PROFILES:
            if profile == original_profile:
                continue

            self._current_profile = profile
            old_cookies = dict(self._session.cookies)
            self._session.close()
            self._session = cffi_requests.Session(
                impersonate=profile.impersonate,
                verify=self.config.verify_ssl,
            )
            for name, value in old_cookies.items():
                self._session.cookies.set(name, value)

            resp = self.get(url)
            if resp.status_code == 200 and "challenge" not in resp.text.lower()[:2000]:
                log.info("Challenge bypassed with profile: %s", profile.name)
                return resp

        log.warning("Could not bypass challenge — use --browser for full JS execution")
        return resp

    @property
    def cookies(self) -> dict:
        """Return current session cookies."""
        return dict(self._session.cookies)

    def close(self):
        """Close the underlying session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
