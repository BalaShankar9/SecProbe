"""
StealthEngine — Swarm-level evasion and anti-detection coordination.

This module sits between the SwarmExecutor and the network layer.  Every
HTTP request the swarm makes passes through StealthEngine.pre_request()
before sending and StealthEngine.post_request() after receiving.  The
engine controls:

    - Timing: adaptive delays, jitter, burst control
    - Identity: User-Agent rotation, TLS profile cycling, proxy chains
    - Headers: realistic browser headers, Sec-CH-UA, Accept-Language
    - URL mutation: param reordering, cache busters, case randomisation
    - WAF evasion: per-WAF encoding strategies, backoff on detection
    - Behavioural mimicry: fetch static assets to simulate real browsing

Design principles:
    1. Async-first — all public methods are async, safe for concurrent use
    2. Adaptive — the engine backs off automatically on 403/429 signals
    3. Profile-driven — swap a StealthProfile to change everything at once
    4. Thread-safe — asyncio.Lock on all mutable shared state
    5. Zero external deps beyond stdlib + what SecProbe already ships

Architecture:
    StealthProfile (config)  ->  StealthEngine (runtime)
          |                             |
    STEALTH_PRESETS              RequestConfig (per-request output)
    WAF_STRATEGIES               post_request() feedback loop
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import random
import string
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional
from urllib.parse import (
    parse_qs,
    quote,
    urlencode,
    urlparse,
    urlunparse,
)

logger = logging.getLogger("secprobe.stealth")


# =====================================================================
# User-Agent Pool — 35 real-world strings
# =====================================================================

USER_AGENTS: list[str] = [
    # Chrome 120-130 — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome — Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    # Firefox 120-130 — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    # Firefox — macOS / Linux
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    # Safari 17 — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Safari — iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    # Edge 120-130 — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
]

# TLS impersonation profile identifiers (used by curl_cffi)
TLS_PROFILES: list[str] = [
    "chrome_120",
    "chrome_124",
    "chrome_125",
    "chrome_126",
    "chrome_130",
    "firefox_120",
    "firefox_124",
    "firefox_128",
    "safari_17",
    "safari_17_2",
    "edge_120",
    "edge_124",
    "edge_130",
]

# Realistic Accept-Language values for rotation
ACCEPT_LANGUAGES: list[str] = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "en-US,en;q=0.9,pt-BR;q=0.8",
    "en-US,en;q=0.5",
    "en-GB,en;q=0.9",
    "en-CA,en;q=0.9,fr-CA;q=0.8",
    "en-AU,en;q=0.9",
]

# Realistic Accept-Encoding variants
ACCEPT_ENCODINGS: list[str] = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
    "gzip, deflate, br",  # duplicated — weighted towards common value
]


# =====================================================================
# WAF-specific evasion strategies
# =====================================================================

WAF_STRATEGIES: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "tls_profiles": ["chrome_120", "chrome_124", "chrome_125", "chrome_130"],
        "min_delay": 2.0,
        "max_delay": 6.0,
        "avoid_headers": ["X-Scanner", "X-Forwarded-For", "X-Security-Test"],
        "encoding": ["double_url", "unicode"],
        "burst_size": 2,
        "burst_pause": 10.0,
        "require_sec_ch_ua": True,
        "notes": "Cloudflare inspects JA3/JA4 fingerprints heavily",
    },
    "akamai": {
        "tls_profiles": ["chrome_120", "chrome_124", "firefox_124", "firefox_128"],
        "min_delay": 3.0,
        "max_delay": 8.0,
        "require_sec_ch_ua": True,
        "encoding": ["hex", "unicode", "html_entity"],
        "burst_size": 2,
        "burst_pause": 12.0,
        "notes": "Akamai Bot Manager checks behavioural patterns",
    },
    "aws_waf": {
        "tls_profiles": ["chrome_124", "chrome_130", "firefox_128"],
        "min_delay": 1.0,
        "max_delay": 4.0,
        "randomize_everything": True,
        "encoding": ["url", "double_url"],
        "burst_size": 5,
        "burst_pause": 5.0,
        "notes": "AWS WAF is rule-based; request diversity is key",
    },
    "modsecurity": {
        "tls_profiles": ["chrome_120", "firefox_124"],
        "min_delay": 0.5,
        "max_delay": 2.0,
        "encoding": ["double_url", "unicode", "null_byte", "comment_injection"],
        "payload_splitting": True,
        "burst_size": 5,
        "burst_pause": 3.0,
        "notes": "ModSecurity CRS matches request bodies; encoding chains bypass rules",
    },
    "imperva": {
        "tls_profiles": ["safari_17", "chrome_125", "chrome_130"],
        "min_delay": 2.5,
        "max_delay": 7.0,
        "avoid_rapid_404s": True,
        "encoding": ["hex", "unicode"],
        "burst_size": 2,
        "burst_pause": 10.0,
        "notes": "Imperva Incapsula checks TLS + behavioural anomalies",
    },
    "sucuri": {
        "tls_profiles": ["chrome_120", "chrome_124"],
        "min_delay": 2.0,
        "max_delay": 5.0,
        "encoding": ["url", "unicode"],
        "burst_size": 3,
        "burst_pause": 8.0,
        "notes": "Sucuri CloudProxy; moderate detection capability",
    },
    "f5_bigip": {
        "tls_profiles": ["chrome_120", "chrome_124", "edge_120", "edge_124"],
        "min_delay": 1.0,
        "max_delay": 3.0,
        "encoding": ["double_url", "comment_injection"],
        "burst_size": 4,
        "burst_pause": 5.0,
        "notes": "F5 ASM inspects payload content; encoding chains help",
    },
    "barracuda": {
        "tls_profiles": ["chrome_120", "firefox_124"],
        "min_delay": 1.0,
        "max_delay": 3.0,
        "encoding": ["null_byte", "double_url", "unicode"],
        "burst_size": 5,
        "burst_pause": 4.0,
        "notes": "Barracuda WAF; moderate detection, weak against encoding",
    },
}


# =====================================================================
# Data classes
# =====================================================================

@dataclass
class RequestConfig:
    """Per-request evasion configuration returned by StealthEngine.pre_request()."""

    delay: float                    # Seconds to wait before sending
    user_agent: str                 # Selected User-Agent string
    proxy: str | None               # SOCKS5/HTTP proxy URL or None
    tls_profile: str | None         # curl_cffi impersonation target or None
    headers: dict[str, str]         # Full header set for the request
    url: str                        # Mutated URL (param reorder, cache busters)
    extra_pause: float = 0.0        # Additional pause for burst control

    @property
    def total_delay(self) -> float:
        """Total time to wait before sending this request."""
        return self.delay + self.extra_pause


@dataclass
class StealthProfile:
    """
    Configures how discreet the swarm operates.

    Each field directly controls an evasion dimension.  Use the preset
    profiles (ghost, ninja, shadow, blitz, normal) for common scenarios
    or build a custom profile for specific engagements.
    """

    # ── Timing ────────────────────────────────────────────────────
    min_delay: float = 0.5              # Min seconds between requests
    max_delay: float = 3.0              # Max seconds between requests
    jitter_factor: float = 0.3          # Random jitter +/- percentage
    burst_size: int = 3                 # Requests before mandatory pause
    burst_pause: float = 5.0            # Pause duration after burst (seconds)

    # ── Concurrency ───────────────────────────────────────────────
    max_concurrent_agents: int = 3      # Agents running simultaneously
    max_concurrent_requests: int = 5    # Total HTTP requests in flight

    # ── Identity rotation ─────────────────────────────────────────
    rotate_user_agent: bool = True
    rotate_interval: int = 10           # Requests before UA rotation
    user_agents: list[str] = field(default_factory=lambda: list(USER_AGENTS))

    # ── TLS fingerprinting ────────────────────────────────────────
    tls_impersonation: bool = True      # Mimic real browser TLS handshakes
    tls_profiles: list[str] = field(default_factory=lambda: list(TLS_PROFILES))
    rotate_tls_profile: bool = True

    # ── IP / Proxy rotation ───────────────────────────────────────
    proxy_chain: list[str] = field(default_factory=list)
    rotate_proxy: bool = True
    proxy_rotate_interval: int = 20     # Requests before proxy rotation

    # ── Header manipulation ───────────────────────────────────────
    randomize_accept_language: bool = True
    randomize_accept_encoding: bool = True
    add_realistic_headers: bool = True  # Referer, Origin, Sec-Fetch-* etc.

    # ── Request fingerprint evasion ───────────────────────────────
    randomize_param_order: bool = True  # Shuffle URL query parameters
    case_randomize_path: bool = False   # /Admin vs /admin for case-insensitive servers
    add_cache_busters: bool = True      # Append random query params

    # ── DNS ────────────────────────────────────────────────────────
    use_doh: bool = False               # DNS over HTTPS
    custom_resolvers: list[str] = field(default_factory=list)

    # ── Behavioural ───────────────────────────────────────────────
    mimic_human_browsing: bool = True   # Fetch CSS/JS/images between scans
    follow_robots_txt: bool = False     # Obey robots.txt (False for pentesting)

    # ── WAF evasion ───────────────────────────────────────────────
    waf_evasion_level: int = 2          # 0=none, 1=basic encoding, 2=advanced, 3=aggressive


# =====================================================================
# Preset profiles
# =====================================================================

STEALTH_PRESETS: dict[str, StealthProfile] = {
    "ghost": StealthProfile(
        min_delay=2.0,
        max_delay=8.0,
        jitter_factor=0.5,
        burst_size=2,
        burst_pause=15.0,
        max_concurrent_agents=1,
        max_concurrent_requests=1,
        rotate_interval=5,
        mimic_human_browsing=True,
        waf_evasion_level=3,
        add_cache_busters=True,
        randomize_param_order=True,
    ),
    "ninja": StealthProfile(
        min_delay=0.5,
        max_delay=2.0,
        jitter_factor=0.3,
        burst_size=5,
        burst_pause=5.0,
        max_concurrent_agents=3,
        max_concurrent_requests=5,
        rotate_interval=10,
        mimic_human_browsing=True,
        waf_evasion_level=2,
    ),
    "shadow": StealthProfile(
        min_delay=5.0,
        max_delay=30.0,
        jitter_factor=0.8,
        burst_size=1,
        burst_pause=30.0,
        max_concurrent_agents=1,
        max_concurrent_requests=1,
        rotate_interval=3,
        mimic_human_browsing=True,
        waf_evasion_level=3,
        add_cache_busters=True,
        randomize_param_order=True,
        case_randomize_path=True,
    ),
    "blitz": StealthProfile(
        min_delay=0.1,
        max_delay=0.5,
        jitter_factor=0.1,
        burst_size=20,
        burst_pause=1.0,
        max_concurrent_agents=10,
        max_concurrent_requests=20,
        rotate_interval=50,
        mimic_human_browsing=False,
        waf_evasion_level=1,
        add_cache_busters=False,
        randomize_param_order=False,
    ),
    "normal": StealthProfile(
        min_delay=0.3,
        max_delay=1.0,
        jitter_factor=0.15,
        burst_size=10,
        burst_pause=2.0,
        max_concurrent_agents=5,
        max_concurrent_requests=10,
        rotate_interval=25,
        mimic_human_browsing=False,
        waf_evasion_level=0,
        add_cache_busters=False,
        randomize_param_order=False,
        rotate_tls_profile=False,
        randomize_accept_language=False,
        randomize_accept_encoding=False,
        add_realistic_headers=False,
    ),
}


# =====================================================================
# Detection signal tracking
# =====================================================================

class _DetectionSignal(IntEnum):
    """Severity of detection signals from responses."""
    NONE = 0
    LOW = 1       # Unusual response time
    MEDIUM = 2    # 403 on a path that should exist
    HIGH = 3      # 429 rate limit
    CRITICAL = 4  # CAPTCHA / JS challenge page


@dataclass
class _RequestStats:
    """Internal bookkeeping for adaptive behaviour."""
    total_requests: int = 0
    burst_counter: int = 0
    consecutive_blocks: int = 0
    last_request_time: float = 0.0
    avg_response_time: float = 0.0
    response_time_samples: list[float] = field(default_factory=list)
    detection_signals: list[_DetectionSignal] = field(default_factory=list)
    blocked_count: int = 0
    success_count: int = 0

    @property
    def block_rate(self) -> float:
        total = self.blocked_count + self.success_count
        if total == 0:
            return 0.0
        return self.blocked_count / total

    def record_response_time(self, elapsed: float) -> None:
        self._trim_samples()
        self.response_time_samples.append(elapsed)
        if self.response_time_samples:
            self.avg_response_time = (
                sum(self.response_time_samples) / len(self.response_time_samples)
            )

    def _trim_samples(self) -> None:
        """Keep only the most recent 200 samples."""
        if len(self.response_time_samples) >= 200:
            self.response_time_samples = self.response_time_samples[-100:]
        if len(self.detection_signals) >= 200:
            self.detection_signals = self.detection_signals[-100:]


# =====================================================================
# StealthEngine
# =====================================================================

class StealthEngine:
    """
    Coordinates all stealth behaviours for the swarm.

    Every HTTP request the swarm sends passes through this engine:

        config = await engine.pre_request(url)
        # ... send request using config.headers, config.proxy, etc ...
        await engine.post_request(url, status_code, response_time)

    The engine is fully async and safe for concurrent use by multiple
    agents.  All mutable state is guarded by an asyncio.Lock.
    """

    def __init__(self, profile: StealthProfile | None = None) -> None:
        self._profile: StealthProfile = profile or STEALTH_PRESETS["ninja"]
        self._stats = _RequestStats()

        # Rotation indices
        self._ua_index: int = random.randint(0, max(len(self._profile.user_agents) - 1, 0))
        self._proxy_index: int = 0
        self._tls_index: int = random.randint(0, max(len(self._profile.tls_profiles) - 1, 0))

        # Current active identities
        self._current_ua: str = self._pick_ua()
        self._current_proxy: str | None = self._pick_proxy()
        self._current_tls: str | None = self._pick_tls()

        # WAF adaptation state
        self._detected_waf: str | None = None
        self._waf_overrides: dict[str, Any] = {}

        # Delay multiplier — raised on detection signals, decayed on success
        self._delay_multiplier: float = 1.0

        # Concurrency controls (exposed for executor to use)
        self.agent_semaphore: asyncio.Semaphore = asyncio.Semaphore(
            self._profile.max_concurrent_agents,
        )
        self.request_semaphore: asyncio.Semaphore = asyncio.Semaphore(
            self._profile.max_concurrent_requests,
        )

        # Async lock for all mutable state mutations
        self._lock: asyncio.Lock = asyncio.Lock()

        logger.info(
            "StealthEngine initialised — profile concurrency=%d/%d, "
            "delay=%.1f-%.1fs, waf_level=%d",
            self._profile.max_concurrent_agents,
            self._profile.max_concurrent_requests,
            self._profile.min_delay,
            self._profile.max_delay,
            self._profile.waf_evasion_level,
        )

    # ── Properties ────────────────────────────────────────────────

    @property
    def profile(self) -> StealthProfile:
        return self._profile

    @property
    def request_count(self) -> int:
        return self._stats.total_requests

    @property
    def block_rate(self) -> float:
        return self._stats.block_rate

    @property
    def detected_waf(self) -> str | None:
        return self._detected_waf

    @property
    def delay_multiplier(self) -> float:
        return self._delay_multiplier

    # ── Core API ──────────────────────────────────────────────────

    async def pre_request(self, url: str) -> RequestConfig:
        """
        Called before every HTTP request.

        Returns a RequestConfig containing the delay to wait, the
        User-Agent to use, proxy, TLS profile, full header dict, and
        the (possibly mutated) URL.  The caller MUST honour the delay.
        """
        async with self._lock:
            self._stats.total_requests += 1
            self._stats.burst_counter += 1
            request_num = self._stats.total_requests

            # 1. Calculate delay
            delay = self._calculate_delay()

            # 2. Burst control
            extra_pause = 0.0
            if self._stats.burst_counter >= self._profile.burst_size:
                extra_pause = self._profile.burst_pause * self._delay_multiplier
                self._stats.burst_counter = 0
                logger.debug(
                    "Burst limit reached (%d), adding %.1fs pause",
                    self._profile.burst_size, extra_pause,
                )

            # 3. Rotate User-Agent if needed
            if (
                self._profile.rotate_user_agent
                and request_num % self._profile.rotate_interval == 0
            ):
                self._ua_index = (self._ua_index + 1) % len(self._profile.user_agents)
                self._current_ua = self._profile.user_agents[self._ua_index]
                logger.debug("Rotated User-Agent [%d]: %s", self._ua_index, self._current_ua[:60])

            # 4. Rotate proxy if needed
            if (
                self._profile.rotate_proxy
                and self._profile.proxy_chain
                and request_num % self._profile.proxy_rotate_interval == 0
            ):
                self._proxy_index = (self._proxy_index + 1) % len(self._profile.proxy_chain)
                self._current_proxy = self._profile.proxy_chain[self._proxy_index]
                logger.debug("Rotated proxy [%d]: %s", self._proxy_index, self._current_proxy)

            # 5. Rotate TLS profile if needed
            if (
                self._profile.rotate_tls_profile
                and self._profile.tls_profiles
                and request_num % self._profile.rotate_interval == 0
            ):
                self._tls_index = (self._tls_index + 1) % len(self._profile.tls_profiles)
                self._current_tls = self._profile.tls_profiles[self._tls_index]
                logger.debug("Rotated TLS profile [%d]: %s", self._tls_index, self._current_tls)

            # 6. Build headers
            headers = self._build_headers(url)

            # 7. Mutate URL
            mutated_url = self.mutate_url(url)

            self._stats.last_request_time = time.monotonic()

        return RequestConfig(
            delay=delay,
            user_agent=self._current_ua,
            proxy=self._current_proxy,
            tls_profile=self._current_tls,
            headers=headers,
            url=mutated_url,
            extra_pause=extra_pause,
        )

    async def post_request(
        self,
        url: str,
        status_code: int,
        response_time: float,
    ) -> None:
        """
        Called after every HTTP request.

        Analyses the response for detection signals and adapts timing,
        identity rotation, and evasion parameters accordingly.
        """
        async with self._lock:
            self._stats.record_response_time(response_time)
            signal = self._classify_signal(status_code, response_time)
            self._stats.detection_signals.append(signal)

            if signal >= _DetectionSignal.HIGH:
                # Blocked — increase delays, rotate identity
                self._stats.blocked_count += 1
                self._stats.consecutive_blocks += 1
                self._handle_block(status_code)
            else:
                self._stats.success_count += 1
                self._stats.consecutive_blocks = 0
                # Gradually decay the delay multiplier on success
                if self._delay_multiplier > 1.0:
                    self._delay_multiplier = max(1.0, self._delay_multiplier * 0.97)

            if signal >= _DetectionSignal.MEDIUM:
                logger.warning(
                    "Detection signal %s for %s (HTTP %d, %.2fs)",
                    signal.name, url, status_code, response_time,
                )

    def get_headers(self, url: str | None = None) -> dict[str, str]:
        """
        Generate realistic browser headers.

        Can be called synchronously when a full pre_request() cycle is
        not needed.  Uses the current identity state.
        """
        return self._build_headers(url or "https://example.com")

    def mutate_url(self, url: str) -> str:
        """
        Apply URL-level evasion techniques.

        - Randomise query parameter order
        - Add cache-buster parameter
        - Optionally randomise path casing
        """
        parsed = urlparse(url)

        # Path case randomisation
        path = parsed.path
        if self._profile.case_randomize_path and path and len(path) > 1:
            path = self._randomize_case(path)

        # Parse and reorder query parameters
        query = parsed.query
        if query:
            params = parse_qs(query, keep_blank_values=True)
            if self._profile.randomize_param_order:
                items = list(params.items())
                random.shuffle(items)
                flat: list[tuple[str, str]] = []
                for key, values in items:
                    for val in values:
                        flat.append((key, val))
                query = urlencode(flat)
            else:
                # Rebuild as-is (preserves original encoding)
                flat = []
                for key, values in params.items():
                    for val in values:
                        flat.append((key, val))
                query = urlencode(flat)

        # Cache buster
        if self._profile.add_cache_busters:
            buster_key = "_" + "".join(random.choices(string.ascii_lowercase, k=3))
            buster_val = hashlib.md5(
                f"{time.monotonic()}{random.random()}".encode()
            ).hexdigest()[:8]
            separator = "&" if query else ""
            query = f"{query}{separator}{buster_key}={buster_val}"

        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            query,
            parsed.fragment,
        ))

    def adapt_to_waf(self, waf_name: str) -> None:
        """
        Adjust evasion techniques based on a detected WAF.

        Looks up the WAF in WAF_STRATEGIES and applies timing, TLS,
        and encoding overrides.  Can be called multiple times — later
        calls update/merge, they do not reset.
        """
        waf_key = waf_name.lower().replace(" ", "_").replace("-", "_")
        strategy = WAF_STRATEGIES.get(waf_key)

        if strategy is None:
            logger.info("No specific strategy for WAF '%s' — using profile defaults", waf_name)
            self._detected_waf = waf_key
            return

        self._detected_waf = waf_key
        self._waf_overrides = dict(strategy)

        # Apply timing overrides
        waf_min_delay = strategy.get("min_delay")
        waf_max_delay = strategy.get("max_delay")
        if waf_min_delay and waf_min_delay > self._profile.min_delay:
            self._profile.min_delay = waf_min_delay
            logger.info("WAF %s: raised min_delay to %.1fs", waf_key, waf_min_delay)
        if waf_max_delay and waf_max_delay > self._profile.max_delay:
            self._profile.max_delay = waf_max_delay
            logger.info("WAF %s: raised max_delay to %.1fs", waf_key, waf_max_delay)

        # Apply TLS profile restriction
        waf_tls = strategy.get("tls_profiles")
        if waf_tls:
            self._profile.tls_profiles = list(waf_tls)
            self._tls_index = 0
            self._current_tls = self._profile.tls_profiles[0]
            logger.info("WAF %s: restricted TLS profiles to %s", waf_key, waf_tls)

        # Apply burst overrides
        waf_burst = strategy.get("burst_size")
        waf_burst_pause = strategy.get("burst_pause")
        if waf_burst is not None:
            self._profile.burst_size = waf_burst
        if waf_burst_pause is not None:
            self._profile.burst_pause = waf_burst_pause

        logger.info(
            "Adapted to WAF '%s' — delay=%.1f-%.1fs, burst=%d/%.1fs, tls=%s",
            waf_key,
            self._profile.min_delay,
            self._profile.max_delay,
            self._profile.burst_size,
            self._profile.burst_pause,
            self._profile.tls_profiles[:3],
        )

    async def mimic_browsing(self, base_url: str, client: Any) -> None:
        """
        Fetch static resources to simulate real browser behaviour.

        Parses the page body for CSS/JS/image references and fetches
        2-4 of them with realistic timing.  This makes the traffic
        pattern look like a real user browsing rather than a scanner
        hitting endpoints sequentially.
        """
        if not self._profile.mimic_human_browsing:
            return

        import re as _re
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Try to get the page content for resource discovery
        body = ""
        try:
            if hasattr(client, "get"):
                resp = await self._async_client_get(client, base_url)
                if resp is not None:
                    body = resp if isinstance(resp, str) else getattr(resp, "text", "")
        except Exception:
            logger.debug("mimic_browsing: could not fetch %s", base_url)
            return

        if not body:
            return

        # Extract resource URLs
        resource_urls: list[str] = []

        # CSS
        for match in _re.finditer(r'href=["\']([^"\']+\.css[^"\']*)["\']', body[:50000]):
            resource_urls.append(match.group(1))

        # JS
        for match in _re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', body[:50000]):
            resource_urls.append(match.group(1))

        # Images (limit to avoid excessive requests)
        for match in _re.finditer(
            r'src=["\']([^"\']+\.(?:png|jpg|jpeg|gif|svg|webp|ico)[^"\']*)["\']',
            body[:50000],
        ):
            resource_urls.append(match.group(1))

        if not resource_urls:
            return

        # Normalise URLs
        normalised: list[str] = []
        for rurl in resource_urls:
            if rurl.startswith("//"):
                rurl = f"{parsed.scheme}:{rurl}"
            elif rurl.startswith("/"):
                rurl = f"{origin}{rurl}"
            elif not rurl.startswith("http"):
                rurl = f"{origin}/{rurl}"
            normalised.append(rurl)

        # Fetch 2-4 random resources with realistic delays
        sample_size = min(random.randint(2, 4), len(normalised))
        selected = random.sample(normalised, sample_size)

        for rurl in selected:
            try:
                # Small delay between resource fetches (50-300ms)
                await asyncio.sleep(random.uniform(0.05, 0.3))
                await self._async_client_get(client, rurl)
                logger.debug("mimic_browsing: fetched %s", rurl[:80])
            except Exception:
                pass  # Resource fetch failures are expected and harmless

    def get_encoding_strategies(self) -> list[str]:
        """
        Return the active payload encoding strategies based on WAF and
        evasion level.
        """
        level = self._profile.waf_evasion_level

        if level <= 0:
            return []

        # Base strategies by level
        strategies: list[str] = []
        if level >= 1:
            strategies.extend(["url"])
        if level >= 2:
            strategies.extend(["double_url", "unicode"])
        if level >= 3:
            strategies.extend(["hex", "html_entity", "null_byte", "comment_injection"])

        # WAF-specific overrides take precedence
        if self._waf_overrides:
            waf_encodings = self._waf_overrides.get("encoding")
            if waf_encodings:
                strategies = list(waf_encodings)

        return strategies

    def get_status_summary(self) -> dict[str, Any]:
        """Return a diagnostic summary of the engine's current state."""
        return {
            "total_requests": self._stats.total_requests,
            "success_count": self._stats.success_count,
            "blocked_count": self._stats.blocked_count,
            "block_rate": round(self._stats.block_rate, 4),
            "delay_multiplier": round(self._delay_multiplier, 2),
            "consecutive_blocks": self._stats.consecutive_blocks,
            "avg_response_time": round(self._stats.avg_response_time, 3),
            "detected_waf": self._detected_waf,
            "current_ua": self._current_ua[:60] + "..." if len(self._current_ua) > 60 else self._current_ua,
            "current_tls": self._current_tls,
            "current_proxy": self._current_proxy,
            "profile_delays": f"{self._profile.min_delay:.1f}-{self._profile.max_delay:.1f}s",
            "effective_delays": (
                f"{self._profile.min_delay * self._delay_multiplier:.1f}-"
                f"{self._profile.max_delay * self._delay_multiplier:.1f}s"
            ),
        }

    # ── Internal helpers ──────────────────────────────────────────

    def _calculate_delay(self) -> float:
        """
        Calculate the delay for the next request.

        Uses uniform random between min_delay and max_delay, applies
        jitter, and scales by the adaptive delay_multiplier.
        """
        base = random.uniform(self._profile.min_delay, self._profile.max_delay)

        # Apply jitter
        jitter_range = base * self._profile.jitter_factor
        jitter = random.uniform(-jitter_range, jitter_range)
        base = max(0.01, base + jitter)

        # Apply adaptive multiplier
        return base * self._delay_multiplier

    def _classify_signal(self, status_code: int, response_time: float) -> _DetectionSignal:
        """Classify a response as a detection signal."""
        # Hard blocks
        if status_code == 429:
            return _DetectionSignal.HIGH
        if status_code == 403:
            return _DetectionSignal.MEDIUM
        if status_code in (406, 418, 503):
            # 406 Not Acceptable, 418 I'm a teapot (used by some WAFs), 503 often WAF
            return _DetectionSignal.MEDIUM

        # Response time anomaly — if it's 3x the average, WAF may be inspecting
        if (
            self._stats.avg_response_time > 0
            and response_time > self._stats.avg_response_time * 3.0
            and response_time > 2.0
        ):
            return _DetectionSignal.LOW

        return _DetectionSignal.NONE

    def _handle_block(self, status_code: int) -> None:
        """
        React to a detected block.

        Escalates delay multiplier and rotates identity components.
        Uses exponential backoff capped at 10x.
        """
        # Exponential backoff on consecutive blocks
        self._delay_multiplier = min(
            10.0,
            self._delay_multiplier * (1.5 + 0.5 * min(self._stats.consecutive_blocks, 5)),
        )

        # Force identity rotation
        if self._profile.user_agents:
            self._ua_index = random.randint(0, len(self._profile.user_agents) - 1)
            self._current_ua = self._profile.user_agents[self._ua_index]

        if self._profile.tls_profiles:
            self._tls_index = random.randint(0, len(self._profile.tls_profiles) - 1)
            self._current_tls = self._profile.tls_profiles[self._tls_index]

        if self._profile.proxy_chain:
            self._proxy_index = (self._proxy_index + 1) % len(self._profile.proxy_chain)
            self._current_proxy = self._profile.proxy_chain[self._proxy_index]

        # Reset burst counter to trigger an immediate pause
        self._stats.burst_counter = self._profile.burst_size

        logger.warning(
            "Block detected (HTTP %d) — delay_multiplier=%.1fx, "
            "rotated UA/TLS/proxy, consecutive=%d",
            status_code,
            self._delay_multiplier,
            self._stats.consecutive_blocks,
        )

    def _build_headers(self, url: str) -> dict[str, str]:
        """
        Generate a complete, realistic set of browser headers.

        Adapts headers based on the current User-Agent (Chrome vs Firefox
        vs Safari send different header sets), evasion level, and any
        WAF-specific overrides.
        """
        ua = self._current_ua
        is_chrome = "Chrome" in ua and "Edg" not in ua
        is_firefox = "Firefox" in ua
        is_safari = "Safari" in ua and "Chrome" not in ua
        is_edge = "Edg" in ua

        headers: dict[str, str] = {
            "User-Agent": ua,
        }

        # Accept header
        if is_firefox:
            headers["Accept"] = (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            )
        else:
            headers["Accept"] = (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            )

        # Accept-Language
        if self._profile.randomize_accept_language:
            headers["Accept-Language"] = random.choice(ACCEPT_LANGUAGES)
        else:
            headers["Accept-Language"] = "en-US,en;q=0.9"

        # Accept-Encoding
        if self._profile.randomize_accept_encoding:
            headers["Accept-Encoding"] = random.choice(ACCEPT_ENCODINGS)
        else:
            headers["Accept-Encoding"] = "gzip, deflate, br"

        # Connection
        headers["Connection"] = "keep-alive"
        headers["Upgrade-Insecure-Requests"] = "1"

        # Sec-Fetch headers (Chrome/Edge send these, Firefox sends some, Safari does not)
        if self._profile.add_realistic_headers:
            if is_chrome or is_edge:
                headers["Sec-Fetch-Dest"] = "document"
                headers["Sec-Fetch-Mode"] = "navigate"
                headers["Sec-Fetch-Site"] = "none"
                headers["Sec-Fetch-User"] = "?1"
                headers["DNT"] = "1"

                # Client Hints
                chrome_version = self._extract_version(ua, "Chrome")
                if is_edge:
                    edge_version = self._extract_version(ua, "Edg")
                    headers["Sec-CH-UA"] = (
                        f'"Chromium";v="{chrome_version}", '
                        f'"Microsoft Edge";v="{edge_version}", '
                        f'"Not-A.Brand";v="99"'
                    )
                else:
                    headers["Sec-CH-UA"] = (
                        f'"Chromium";v="{chrome_version}", '
                        f'"Google Chrome";v="{chrome_version}", '
                        f'"Not-A.Brand";v="99"'
                    )
                headers["Sec-CH-UA-Mobile"] = "?0"

                # Platform detection from UA
                if "Windows" in ua:
                    headers["Sec-CH-UA-Platform"] = '"Windows"'
                elif "Macintosh" in ua or "Mac OS" in ua:
                    headers["Sec-CH-UA-Platform"] = '"macOS"'
                elif "Linux" in ua:
                    headers["Sec-CH-UA-Platform"] = '"Linux"'

            elif is_firefox:
                headers["Sec-Fetch-Dest"] = "document"
                headers["Sec-Fetch-Mode"] = "navigate"
                headers["Sec-Fetch-Site"] = "none"
                headers["Sec-Fetch-User"] = "?1"
                headers["DNT"] = "1"
                # Firefox does NOT send Sec-CH-UA

            # Safari sends minimal security headers
            elif is_safari:
                headers["DNT"] = "1"

        # WAF-specific header filtering
        if self._waf_overrides:
            avoid = self._waf_overrides.get("avoid_headers", [])
            for hdr in avoid:
                headers.pop(hdr, None)

            # Some WAFs require Client Hints
            if self._waf_overrides.get("require_sec_ch_ua") and "Sec-CH-UA" not in headers:
                headers["Sec-CH-UA"] = (
                    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'
                )
                headers["Sec-CH-UA-Mobile"] = "?0"
                headers["Sec-CH-UA-Platform"] = '"Windows"'

        return headers

    def _pick_ua(self) -> str:
        """Select an initial User-Agent."""
        agents = self._profile.user_agents
        if not agents:
            return USER_AGENTS[0]
        return agents[self._ua_index % len(agents)]

    def _pick_proxy(self) -> str | None:
        """Select an initial proxy."""
        chain = self._profile.proxy_chain
        if not chain:
            return None
        return chain[self._proxy_index % len(chain)]

    def _pick_tls(self) -> str | None:
        """Select an initial TLS profile."""
        if not self._profile.tls_impersonation:
            return None
        profiles = self._profile.tls_profiles
        if not profiles:
            return None
        return profiles[self._tls_index % len(profiles)]

    @staticmethod
    def _extract_version(ua: str, browser: str) -> str:
        """Extract the major version number for a browser from a UA string."""
        try:
            idx = ua.index(browser + "/")
            version_start = idx + len(browser) + 1
            dot = ua.index(".", version_start)
            return ua[version_start:dot]
        except (ValueError, IndexError):
            return "124"  # Safe fallback

    @staticmethod
    def _randomize_case(path: str) -> str:
        """
        Randomly toggle the case of alphabetic characters in a URL path.

        Preserves the leading slash and file extensions.  Only touches
        the path segment characters to avoid breaking URL structure.
        """
        if not path or path == "/":
            return path

        # Split off leading slash
        parts = path.split("/")
        result: list[str] = []
        for part in parts:
            if not part:
                result.append(part)
                continue
            # Don't randomise file extensions
            if "." in part:
                name, ext = part.rsplit(".", 1)
                name = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in name
                )
                result.append(f"{name}.{ext}")
            else:
                result.append(
                    "".join(
                        c.upper() if random.random() > 0.5 else c.lower()
                        for c in part
                    )
                )
        return "/".join(result)

    @staticmethod
    async def _async_client_get(client: Any, url: str) -> Any:
        """
        Dispatch a GET request to whatever client object was provided.

        Handles both async (httpx.AsyncClient) and sync (requests.Session,
        StealthClient) clients transparently.
        """
        if hasattr(client, "get"):
            result = client.get(url)
            # If the client returns a coroutine, await it
            if asyncio.iscoroutine(result):
                return await result
            return result
        if hasattr(client, "request"):
            result = client.request("GET", url)
            if asyncio.iscoroutine(result):
                return await result
            return result
        return None

    # ── Class methods ─────────────────────────────────────────────

    @classmethod
    def from_preset(cls, name: str) -> StealthEngine:
        """
        Create a StealthEngine from a named preset.

        Available presets: ghost, ninja, shadow, blitz, normal.

        Raises KeyError if the preset name is not recognised.
        """
        if name not in STEALTH_PRESETS:
            available = ", ".join(sorted(STEALTH_PRESETS))
            raise KeyError(
                f"Unknown stealth preset '{name}'. Available: {available}"
            )
        profile = STEALTH_PRESETS[name]
        logger.info("Creating StealthEngine from preset '%s'", name)
        return cls(profile=profile)

    @classmethod
    def for_waf(cls, waf_name: str, base_preset: str = "ninja") -> StealthEngine:
        """
        Create a StealthEngine pre-configured for a specific WAF.

        Starts from the base_preset and immediately applies WAF-specific
        adaptations.
        """
        engine = cls.from_preset(base_preset)
        engine.adapt_to_waf(waf_name)
        return engine

    def __repr__(self) -> str:
        return (
            f"StealthEngine("
            f"requests={self._stats.total_requests}, "
            f"blocks={self._stats.blocked_count}, "
            f"multiplier={self._delay_multiplier:.1f}x, "
            f"waf={self._detected_waf!r})"
        )
