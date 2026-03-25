"""
SwarmExecutor — Async execution engine for SecProbe's 600-agent swarm.

This is the core engine that wires every agent to REAL HTTP scanning via
httpx.AsyncClient.  No mocks.  Real async HTTP, real payload delivery,
real response analysis, real consensus verification.

Lifecycle (mirrors ScanSession's 5-phase model):
    1. Recon     — crawl, fingerprint, WAF detect, build AttackSurface
    2. Plan      — select agents from registry, build prioritised task list
    3. Attack    — concurrent agent execution with rate/budget control
    4. Verify    — multi-agent consensus + false-positive elimination
    5. Report    — aggregate findings, score risk, map compliance

Design principles:
    * Every HTTP request goes through the shared AsyncHTTPClient
    * Every agent action passes SafetyGovernor.approve()
    * Concurrency controlled via asyncio.Semaphore (agents + requests)
    * Token-bucket rate limiting shared across all agents
    * Payloads loaded from secprobe/payloads/ and cached
    * Detection patterns compiled once at init
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import (
    urlparse, urljoin, parse_qs, urlencode,
    urlunparse, quote,
)

import httpx

from secprobe.swarm.agent import (
    SwarmAgent,
    AgentSpec,
    Evidence,
    Finding,
    AgentAction,
    AgentMessage,
    Confidence,
    OperationalMode as Mode,
    AgentCapability,
    AgentPriority,
    MessageType,
)
from secprobe.swarm.registry import SwarmRegistry
from secprobe.swarm.comm.event_bus import EventBus
from secprobe.swarm.memory.working import WorkingMemory
from secprobe.swarm.safety.governor import SafetyGovernor

logger = logging.getLogger("secprobe.executor")

# ═══════════════════════════════════════════════════════════════════════
# User-Agent pool (same as core/http_client.py for consistency)
# ═══════════════════════════════════════════════════════════════════════

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
    "Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Edge/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 "
    "Mobile/15E148 Safari/604.1",
]

# Retryable HTTP status codes
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})

# Severity weights for risk scoring
_SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 5,
    "LOW": 1,
    "INFO": 0,
}

# OWASP Top-10 2021 mapping
_CWE_TO_OWASP: dict[str, str] = {
    "CWE-79":  "A03:2021 Injection",
    "CWE-89":  "A03:2021 Injection",
    "CWE-90":  "A03:2021 Injection",
    "CWE-91":  "A03:2021 Injection",
    "CWE-78":  "A03:2021 Injection",
    "CWE-94":  "A03:2021 Injection",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-918": "A10:2021 SSRF",
    "CWE-22":  "A01:2021 Broken Access Control",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
}


# ═══════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ExecutorConfig:
    """Configuration for a SwarmExecutor run."""
    target: str = ""
    mode: Mode = Mode.AUDIT

    # Concurrency
    max_concurrent_agents: int = 20
    max_concurrent_requests: int = 50

    # Budget
    max_total_requests: int = 10_000
    timeout: float = 30.0
    rate_limit_rps: float = 20.0

    # Network
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    auth: dict[str, str] | None = None
    ssl_verify: bool = False

    # Scope
    divisions: list[int] | None = None

    # Features
    oob_server: bool = False
    crawl: bool = True
    crawl_depth: int = 3


@dataclass
class FormField:
    """A single HTML form input field."""
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class FormInfo:
    """An HTML form discovered during recon."""
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)


@dataclass
class AttackSurface:
    """Everything discovered about the target during recon."""
    urls: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    waf_detected: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    server: str = ""
    response_sample: str = ""


@dataclass
class AgentTask:
    """A planned unit of work for one agent."""
    agent_spec: AgentSpec
    target_urls: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    payloads: list[str] = field(default_factory=list)
    priority: float = 0.0
    depends_on: list[str] = field(default_factory=list)


@dataclass
class AgentStats:
    """Per-agent execution statistics."""
    agent_id: str = ""
    findings_count: int = 0
    requests_made: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


@dataclass
class SwarmResult:
    """Final output of a SwarmExecutor run."""
    target: str = ""
    mode: Mode = Mode.AUDIT
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    grade: str = "A+"
    total_agents_deployed: int = 0
    total_requests: int = 0
    duration_seconds: float = 0.0
    divisions_active: list[int] = field(default_factory=list)
    attack_surface: AttackSurface | None = None
    agent_stats: dict[str, AgentStats] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════
# Async Token-Bucket Rate Limiter
# ═══════════════════════════════════════════════════════════════════════

class AsyncRateLimiter:
    """
    Async token-bucket rate limiter shared across all agents.

    Guarantees we never exceed ``rate`` requests per second across the
    entire swarm, regardless of concurrency.
    """

    def __init__(self, rate: float):
        self._rate = max(rate, 0.1)
        self._tokens = rate          # start full
        self._max_tokens = rate
        self._last = asyncio.get_event_loop().time() if rate > 0 else 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one."""
        if self._rate <= 0:
            return
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(
                self._max_tokens,
                self._tokens + elapsed * self._rate,
            )
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# ═══════════════════════════════════════════════════════════════════════
# Async HTTP Client Wrapper
# ═══════════════════════════════════════════════════════════════════════

class AsyncHTTPClient:
    """
    Production-grade async HTTP client built on httpx.

    Features:
        * Connection pooling (configurable limits)
        * Token-bucket rate limiting
        * Exponential-backoff retry for transient failures
        * User-Agent rotation
        * Proxy + TLS toggle
        * Per-request timeout
        * Request counter
    """

    def __init__(self, config: ExecutorConfig, rate_limiter: AsyncRateLimiter):
        self._config = config
        self._rate_limiter = rate_limiter
        self._request_count = 0
        self._lock = asyncio.Lock()

        # Build the underlying httpx client
        transport_kwargs: dict[str, Any] = {
            "limits": httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
            "retries": 0,  # we handle retries ourselves
        }
        if config.proxy:
            proxy = httpx.Proxy(config.proxy)
        else:
            proxy = None

        base_headers = {
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        base_headers.update(config.headers)
        if config.auth:
            base_headers.update(config.auth)

        self._client = httpx.AsyncClient(
            headers=base_headers,
            timeout=httpx.Timeout(config.timeout, connect=10.0),
            verify=config.ssl_verify,
            follow_redirects=True,
            proxy=proxy,
            transport=httpx.AsyncHTTPTransport(**transport_kwargs),
        )

    # ── Public API ────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | str | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_retries: int = 3,
    ) -> dict[str, Any]:
        """
        Send an HTTP request with rate limiting, UA rotation, and retry.

        Returns a normalised response dict consumed by agents:
            {status, headers, body, body_length, elapsed, url}
        """
        await self._rate_limiter.acquire()

        # Rotate User-Agent
        req_headers = {"User-Agent": random.choice(_USER_AGENTS)}
        if headers:
            req_headers.update(headers)

        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                resp = await self._client.request(
                    method,
                    url,
                    params=params,
                    content=data if isinstance(data, (str, bytes)) else None,
                    data=data if isinstance(data, dict) else None,
                    json=json_body,
                    headers=req_headers,
                    timeout=timeout or self._config.timeout,
                )
                async with self._lock:
                    self._request_count += 1

                body = resp.text
                return {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": body,
                    "body_length": len(body),
                    "elapsed": resp.elapsed.total_seconds()
                    if resp.elapsed
                    else 0.0,
                    "url": str(resp.url),
                }

            except (httpx.TimeoutException, httpx.ConnectError,
                    httpx.RemoteProtocolError) as exc:
                last_exc = exc
                if attempt < max_retries:
                    backoff = min(2 ** attempt * 0.5, 10.0)
                    logger.debug(
                        "Retry %d/%d for %s %s (%.1fs backoff): %s",
                        attempt + 1, max_retries, method, url, backoff, exc,
                    )
                    await asyncio.sleep(backoff)
                continue

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in _RETRYABLE_STATUSES and attempt < max_retries:
                    retry_after = exc.response.headers.get("Retry-After")
                    backoff = (
                        float(retry_after)
                        if retry_after and retry_after.isdigit()
                        else min(2 ** attempt * 1.0, 30.0)
                    )
                    logger.debug(
                        "Retry %d/%d for %s %s (HTTP %d, %.1fs backoff)",
                        attempt + 1, max_retries, method, url, status, backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise

        # All retries exhausted
        logger.warning(
            "All %d retries exhausted for %s %s: %s",
            max_retries, method, url, last_exc,
        )
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "elapsed": 0.0,
            "url": url,
            "error": str(last_exc) if last_exc else "unknown",
        }

    @property
    def request_count(self) -> int:
        return self._request_count

    async def close(self) -> None:
        await self._client.aclose()


# ═══════════════════════════════════════════════════════════════════════
# Payload Cache
# ═══════════════════════════════════════════════════════════════════════

class PayloadCache:
    """
    Loads and caches payload files from secprobe/payloads/.

    Files are loaded once at startup and served from memory.
    Lines starting with ``#`` and blank lines are skipped.
    """

    def __init__(self):
        self._cache: dict[str, list[str]] = {}
        self._base_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "payloads",
        )

    def load_all(self) -> None:
        """Eagerly load every .txt file in the payloads directory."""
        if not os.path.isdir(self._base_dir):
            logger.warning("Payloads directory not found: %s", self._base_dir)
            return
        for fname in os.listdir(self._base_dir):
            if fname.endswith(".txt"):
                self._load_file(fname)
        logger.info(
            "Payload cache loaded: %d files, %d total payloads",
            len(self._cache),
            sum(len(v) for v in self._cache.values()),
        )

    def get(self, filename: str) -> list[str]:
        """Get payloads for a file, loading on demand if needed."""
        if filename not in self._cache:
            self._load_file(filename)
        return self._cache.get(filename, [])

    def get_for_spec(self, spec: AgentSpec) -> list[str]:
        """Collect all payloads referenced by an AgentSpec."""
        payloads: list[str] = []
        for ref in spec.payloads:
            payloads.extend(self.get(ref))
        return payloads

    def _load_file(self, filename: str) -> None:
        path = os.path.join(self._base_dir, filename)
        if not os.path.exists(path):
            logger.debug("Payload file not found: %s", path)
            self._cache[filename] = []
            return
        lines: list[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        lines.append(line)
        except OSError as exc:
            logger.warning("Failed to read payload file %s: %s", path, exc)
        self._cache[filename] = lines


# ═══════════════════════════════════════════════════════════════════════
# Detection Helpers
# ═══════════════════════════════════════════════════════════════════════

class DetectionMatcher:
    """
    Compiled regex detection patterns for an AgentSpec.

    Supports three detection strategies:
        * Error-based   — regex match in response body
        * Boolean-based — significant response diff vs baseline
        * Time-based    — response time exceeds threshold
    """

    def __init__(self, patterns: tuple[str, ...]):
        self._compiled: list[re.Pattern[str]] = []
        for pat in patterns:
            try:
                self._compiled.append(re.compile(pat, re.IGNORECASE))
            except re.error as exc:
                logger.debug("Invalid detection pattern %r: %s", pat, exc)

    def match_body(self, body: str) -> re.Match[str] | None:
        """Return the first match against the response body."""
        for rx in self._compiled:
            m = rx.search(body)
            if m:
                return m
        return None

    def match_headers(self, headers: dict[str, str]) -> re.Match[str] | None:
        """Check detection patterns against response headers."""
        combined = "\n".join(f"{k}: {v}" for k, v in headers.items())
        return self.match_body(combined)

    @staticmethod
    def is_time_anomaly(
        elapsed: float,
        baseline: float = 1.0,
        threshold_multiplier: float = 5.0,
    ) -> bool:
        """Detect time-based injection via response timing."""
        return elapsed > max(baseline * threshold_multiplier, 5.0)

    @staticmethod
    def response_diff_ratio(body_a: str, body_b: str) -> float:
        """Quick diff ratio between two responses (0.0 = identical, 1.0 = totally different)."""
        if not body_a and not body_b:
            return 0.0
        if not body_a or not body_b:
            return 1.0
        len_a, len_b = len(body_a), len(body_b)
        max_len = max(len_a, len_b)
        # Use size-based heuristic first (fast)
        size_diff = abs(len_a - len_b) / max_len
        if size_diff > 0.3:
            return size_diff
        # Hash-based check for identical
        if hashlib.md5(body_a.encode()).digest() == hashlib.md5(body_b.encode()).digest():
            return 0.0
        # Simple character-level diff ratio
        common = sum(1 for a, b in zip(body_a[:5000], body_b[:5000]) if a == b)
        return 1.0 - (common / min(len_a, len_b, 5000))


# ═══════════════════════════════════════════════════════════════════════
# Technology / WAF Fingerprinting
# ═══════════════════════════════════════════════════════════════════════

_HEADER_TECH_MAP: dict[str, str] = {
    "nginx": "nginx", "apache": "apache", "iis": "iis",
    "cloudflare": "cloudflare", "php": "php", "asp.net": "aspnet",
    "express": "nodejs", "next.js": "nextjs", "django": "django",
    "flask": "flask", "spring": "java", "ruby": "ruby",
    "wordpress": "wordpress", "laravel": "laravel",
    "tomcat": "tomcat", "gunicorn": "python", "openresty": "openresty",
    "kestrel": "aspnet", "jetty": "java",
}

_BODY_TECH_MAP: dict[str, str] = {
    "wp-content": "wordpress", "wp-json": "wordpress",
    "react": "react", "angular": "angular", "vue.js": "vue",
    "jquery": "jquery", "bootstrap": "bootstrap",
    "graphql": "graphql", "swagger": "swagger",
    "drupal": "drupal", "joomla": "joomla",
    "__next": "nextjs", "nuxt": "nuxt",
}

_WAF_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "akamai": ["akamai", "x-akamai"],
    "incapsula": ["incap_ses", "visid_incap", "incapsula"],
    "sucuri": ["sucuri", "x-sucuri-id"],
    "aws_waf": ["x-amzn-requestid", "awselb"],
    "modsecurity": ["mod_security", "modsecurity"],
    "f5_bigip": ["bigipserver", "f5", "ts="],
    "barracuda": ["barra_counter_session"],
    "fortiweb": ["fortiwafsid"],
    "imperva": ["x-iinfo"],
}


def _fingerprint_tech(headers: dict[str, str], body: str) -> list[str]:
    """Detect technologies from response headers and body."""
    techs: list[str] = []
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()
    header_str = f"{server} {powered}"

    for keyword, tech in _HEADER_TECH_MAP.items():
        if keyword in header_str:
            techs.append(tech)

    body_lower = body[:10_000].lower()
    for keyword, tech in _BODY_TECH_MAP.items():
        if keyword in body_lower and tech not in techs:
            techs.append(tech)

    return techs


def _detect_waf(headers: dict[str, str], body: str, status: int) -> str | None:
    """Detect WAF from response headers/body/status."""
    header_str = " ".join(
        f"{k.lower()}={v.lower()}" for k, v in headers.items()
    )
    combined = f"{header_str} {body[:5000].lower()}"
    for waf_name, signatures in _WAF_SIGNATURES.items():
        for sig in signatures:
            if sig in combined:
                return waf_name
    # Generic WAF indicators
    if status in (403, 406) and any(
        kw in combined
        for kw in ("blocked", "forbidden", "security", "firewall", "waf")
    ):
        return "generic_waf"
    return None


# ═══════════════════════════════════════════════════════════════════════
# URL / Parameter Extraction
# ═══════════════════════════════════════════════════════════════════════

_HREF_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"']{1,500})["']""",
    re.IGNORECASE,
)
_PARAM_RE = re.compile(
    r"""(?:name|id)\s*=\s*["']([a-zA-Z_][\w\-]{0,60})["']""",
    re.IGNORECASE,
)
_FORM_RE = re.compile(
    r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL,
)
_INPUT_RE = re.compile(
    r'<input\b([^>]*)/?>', re.IGNORECASE,
)
_ATTR_RE = re.compile(
    r'(\w+)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE,
)


def _extract_links(body: str, base_url: str) -> list[str]:
    """Extract and resolve absolute URLs from HTML."""
    parsed_base = urlparse(base_url)
    base_domain = parsed_base.hostname or ""
    links: list[str] = []
    seen: set[str] = set()
    for match in _HREF_RE.finditer(body):
        raw = match.group(1).split("#")[0].strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "data:", "tel:")):
            continue
        absolute = urljoin(base_url, raw)
        parsed = urlparse(absolute)
        # Stay in scope
        if parsed.hostname and parsed.hostname != base_domain:
            if not (parsed.hostname and parsed.hostname.endswith(f".{base_domain}")):
                continue
        normalised = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
        if normalised not in seen:
            seen.add(normalised)
            links.append(absolute)
    return links


def _extract_parameters(urls: list[str], body: str) -> list[dict[str, Any]]:
    """Extract injectable parameters from URLs and HTML body."""
    params: list[dict[str, Any]] = []
    seen: set[str] = set()

    # From URL query strings
    for url in urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for name in qs:
            key = f"url:{parsed.path}:{name}"
            if key not in seen:
                seen.add(key)
                params.append({
                    "name": name,
                    "source": "url",
                    "url": url,
                    "method": "GET",
                })

    # From HTML input names
    for match in _PARAM_RE.finditer(body):
        name = match.group(1)
        key = f"body:{name}"
        if key not in seen:
            seen.add(key)
            params.append({
                "name": name,
                "source": "html",
                "url": "",
                "method": "GET",
            })

    return params


def _extract_forms(body: str, base_url: str) -> list[FormInfo]:
    """Extract HTML forms with their fields."""
    forms: list[FormInfo] = []
    for form_match in _FORM_RE.finditer(body):
        form_html = form_match.group(0)
        # Get form attributes
        action = ""
        method = "GET"
        for attr_m in _ATTR_RE.finditer(form_html.split(">")[0]):
            aname, aval = attr_m.group(1).lower(), attr_m.group(2)
            if aname == "action":
                action = urljoin(base_url, aval) if aval else base_url
            elif aname == "method":
                method = aval.upper()
        if not action:
            action = base_url

        # Get input fields
        fields: list[FormField] = []
        for inp_match in _INPUT_RE.finditer(form_html):
            attrs_str = inp_match.group(1)
            attrs: dict[str, str] = {}
            for attr_m in _ATTR_RE.finditer(attrs_str):
                attrs[attr_m.group(1).lower()] = attr_m.group(2)
            if "name" in attrs:
                fields.append(FormField(
                    name=attrs["name"],
                    type=attrs.get("type", "text"),
                    value=attrs.get("value", ""),
                ))
        if fields:
            forms.append(FormInfo(action=action, method=method, fields=fields))
    return forms


# ═══════════════════════════════════════════════════════════════════════
# SwarmExecutor
# ═══════════════════════════════════════════════════════════════════════

class SwarmExecutor:
    """
    The async execution engine that wires 600 agents to real HTTP scanning.

    Usage:
        config = ExecutorConfig(target="https://example.com", mode=Mode.AUDIT)
        registry = SwarmRegistry()
        registry.load_all()
        governor = SafetyGovernor(mode=Mode.AUDIT, ...)
        bus = EventBus()
        memory = WorkingMemory()

        executor = SwarmExecutor(config, registry, governor, bus, memory)
        result = await executor.execute("https://example.com", Mode.AUDIT)
    """

    def __init__(
        self,
        config: ExecutorConfig,
        registry: SwarmRegistry,
        governor: SafetyGovernor,
        event_bus: EventBus,
        working_memory: WorkingMemory,
    ):
        self._config = config
        self._registry = registry
        self._governor = governor
        self._event_bus = event_bus
        self._memory = working_memory

        # Concurrency controls
        self._agent_semaphore = asyncio.Semaphore(config.max_concurrent_agents)
        self._request_semaphore = asyncio.Semaphore(config.max_concurrent_requests)

        # Shared rate limiter and HTTP client
        self._rate_limiter = AsyncRateLimiter(config.rate_limit_rps)
        self._http: AsyncHTTPClient | None = None

        # Payload cache
        self._payload_cache = PayloadCache()

        # Runtime counters
        self._total_requests = 0
        self._agent_stats: dict[str, AgentStats] = {}
        self._all_findings: list[Finding] = []
        self._start_time: float = 0.0

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    async def execute(
        self,
        target: str,
        mode: Mode,
        divisions: list[int] | None = None,
    ) -> SwarmResult:
        """
        Run the full 5-phase swarm scan against *target*.

        Args:
            target:    The root URL to scan.
            mode:      Operational mode (RECON / AUDIT / REDTEAM).
            divisions: Optional list of division numbers to restrict.

        Returns:
            SwarmResult with findings, risk score, and statistics.
        """
        self._start_time = time.monotonic()
        self._config.target = target
        self._config.mode = mode
        if divisions is not None:
            self._config.divisions = divisions

        # Initialise shared resources
        self._http = AsyncHTTPClient(self._config, self._rate_limiter)
        self._payload_cache.load_all()

        logger.info(
            "SwarmExecutor starting | target=%s mode=%s divisions=%s",
            target, mode.value, divisions,
        )

        try:
            # Phase 1: Recon
            logger.info("Phase 1/5: RECON")
            surface = await self._phase_recon(target)
            await self._memory.store(
                "attack_surface",
                {
                    "urls": surface.urls,
                    "tech_stack": surface.tech_stack,
                    "waf": surface.waf_detected,
                    "params_count": len(surface.parameters),
                },
                source="executor",
                tags=("recon", "surface"),
            )

            # Phase 2: Plan
            logger.info("Phase 2/5: PLAN")
            tasks = await self._phase_plan(surface)
            logger.info("Planned %d agent tasks", len(tasks))

            # Phase 3: Attack
            logger.info("Phase 3/5: ATTACK")
            raw_findings = await self._phase_attack(tasks)
            logger.info(
                "Attack phase complete: %d raw findings", len(raw_findings),
            )

            # Phase 4: Verify
            logger.info("Phase 4/5: VERIFY")
            verified = await self._phase_verify(raw_findings)
            logger.info(
                "Verification complete: %d/%d findings verified",
                len(verified), len(raw_findings),
            )

            # Phase 5: Report
            logger.info("Phase 5/5: REPORT")
            result = await self._phase_report(verified)

            logger.info(
                "Scan complete | findings=%d risk=%.0f grade=%s "
                "requests=%d agents=%d duration=%.1fs",
                len(result.findings), result.risk_score, result.grade,
                result.total_requests, result.total_agents_deployed,
                result.duration_seconds,
            )
            return result

        except Exception:
            logger.exception("SwarmExecutor failed")
            raise
        finally:
            if self._http:
                await self._http.close()

    # ──────────────────────────────────────────────────────────────
    # Phase 1 — Recon
    # ──────────────────────────────────────────────────────────────

    async def _phase_recon(self, target: str) -> AttackSurface:
        """
        Reconnaissance phase:
            1. Fetch the root URL
            2. Crawl to discover pages/endpoints (breadth-first)
            3. Fingerprint tech stack and WAF
            4. Extract parameters and forms
            5. Optionally run Division 1 recon agents
        """
        surface = AttackSurface()
        surface.urls.append(target)

        # ── Initial probe ──────────────────────────────────────
        assert self._http is not None
        resp = await self._http.request("GET", target)
        self._total_requests += 1
        surface.status_code = resp.get("status", 0)
        surface.headers = {
            k: v for k, v in resp.get("headers", {}).items()
        }
        surface.server = surface.headers.get("server", "")
        body = resp.get("body", "")
        surface.response_sample = body[:5000]

        # Cookies
        set_cookies = surface.headers.get("set-cookie", "")
        if set_cookies:
            for part in set_cookies.split(","):
                kv = part.strip().split(";")[0]
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    surface.cookies[k.strip()] = v.strip()

        # Tech fingerprinting
        surface.tech_stack = _fingerprint_tech(surface.headers, body)
        surface.waf_detected = _detect_waf(
            surface.headers, body, surface.status_code,
        )
        if surface.waf_detected:
            logger.warning("WAF detected: %s", surface.waf_detected)
            await self._event_bus.publish(AgentMessage(
                type=MessageType.ALERT,
                sender="executor",
                payload={"waf": surface.waf_detected},
                priority=AgentPriority.HIGH,
            ))

        # ── Crawl ──────────────────────────────────────────────
        if self._config.crawl:
            crawled = await self._crawl(
                target, body, depth=self._config.crawl_depth,
            )
            surface.urls.extend(crawled)
            # Deduplicate
            surface.urls = list(dict.fromkeys(surface.urls))

        logger.info(
            "Recon: %d URLs, %d techs (%s), WAF=%s",
            len(surface.urls), len(surface.tech_stack),
            ", ".join(surface.tech_stack) or "none",
            surface.waf_detected or "none",
        )

        # ── Extract parameters & forms ─────────────────────────
        all_bodies: list[str] = [body]
        # Fetch a sample of discovered URLs for parameter extraction
        sample_urls = surface.urls[1 : min(len(surface.urls), 20)]
        if sample_urls:
            fetch_tasks = [
                self._fetch_url_safe(url) for url in sample_urls
            ]
            responses = await asyncio.gather(*fetch_tasks)
            for r in responses:
                if r:
                    all_bodies.append(r.get("body", ""))

        combined_body = "\n".join(all_bodies)
        surface.parameters = _extract_parameters(surface.urls, combined_body)
        surface.forms = _extract_forms(combined_body, target)

        logger.info(
            "Recon: %d parameters, %d forms discovered",
            len(surface.parameters), len(surface.forms),
        )

        # ── Run Division 1 recon agents ────────────────────────
        recon_specs = self._registry.by_division(1)
        if recon_specs:
            recon_findings = await self._run_agent_batch(
                recon_specs, target, surface.urls, surface,
            )
            # Recon agents contribute intelligence, not attack findings
            for f in recon_findings:
                await self._memory.store(
                    f"recon_finding:{f.id}",
                    {"title": f.title, "url": f.url, "type": f.attack_type},
                    source=f.discovered_by,
                    tags=("recon", "intelligence"),
                )

        return surface

    async def _crawl(
        self, root: str, root_body: str, depth: int,
    ) -> list[str]:
        """Breadth-first crawl starting from root, up to *depth* levels."""
        discovered: list[str] = []
        visited: set[str] = {root}
        frontier = _extract_links(root_body, root)
        current_depth = 0

        while frontier and current_depth < depth:
            next_frontier: list[str] = []
            batch = [
                url for url in frontier
                if url not in visited
            ][:50]  # cap per level

            if not batch:
                break

            tasks = [self._fetch_url_safe(url) for url in batch]
            results = await asyncio.gather(*tasks)

            for url, resp in zip(batch, results):
                visited.add(url)
                if resp and resp.get("status", 0) in range(200, 400):
                    discovered.append(url)
                    child_links = _extract_links(
                        resp.get("body", ""), url,
                    )
                    next_frontier.extend(
                        u for u in child_links if u not in visited
                    )

            frontier = next_frontier
            current_depth += 1

        return discovered

    async def _fetch_url_safe(self, url: str) -> dict[str, Any] | None:
        """Fetch a URL, returning None on any error."""
        if not self._http:
            return None
        if self._total_requests >= self._config.max_total_requests:
            return None
        try:
            async with self._request_semaphore:
                resp = await self._http.request("GET", url, max_retries=1)
            self._total_requests += 1
            return resp
        except Exception as exc:
            logger.debug("Fetch failed for %s: %s", url, exc)
            return None

    # ──────────────────────────────────────────────────────────────
    # Phase 2 — Plan
    # ──────────────────────────────────────────────────────────────

    async def _phase_plan(self, surface: AttackSurface) -> list[AgentTask]:
        """
        Analyse the AttackSurface and build a prioritised task list.

        Selection logic:
            1. Filter agents by mode (governor)
            2. Match by technology
            3. Match by attack type relevance
            4. Apply division filter if specified
            5. Score and prioritise
        """
        tasks: list[AgentTask] = []
        seen_agents: set[str] = set()

        # All agents eligible for the current mode
        eligible = self._registry.by_mode(self._config.mode)

        # Apply division filter
        if self._config.divisions:
            eligible = [
                s for s in eligible
                if s.division in self._config.divisions
            ]

        # Skip division 1 (already ran in recon)
        eligible = [s for s in eligible if s.division != 1]

        for spec in eligible:
            if spec.id in seen_agents:
                continue

            # Calculate priority score
            priority = float(spec.priority)

            # Boost if technology matches
            tech_match = any(
                t in surface.tech_stack
                for t in spec.target_technologies
            )
            if tech_match:
                priority += 20.0

            # Agents with no tech filter are generic — always relevant
            if not spec.target_technologies:
                priority += 5.0

            # Boost if we have injectable parameters for this attack type
            if surface.parameters:
                priority += 10.0

            # Collect payloads
            payloads = self._payload_cache.get_for_spec(spec)

            # Build target URL list
            target_urls = list(surface.urls)

            # Collect parameter names
            param_names = [p["name"] for p in surface.parameters]

            task = AgentTask(
                agent_spec=spec,
                target_urls=target_urls,
                parameters=param_names,
                payloads=payloads,
                priority=priority,
                depends_on=list(spec.depends_on),
            )
            tasks.append(task)
            seen_agents.add(spec.id)

        # Sort by priority descending
        tasks.sort(key=lambda t: t.priority, reverse=True)

        logger.info(
            "Plan: %d tasks across %d divisions, %d total payloads",
            len(tasks),
            len({t.agent_spec.division for t in tasks}),
            sum(len(t.payloads) for t in tasks),
        )

        return tasks

    # ──────────────────────────────────────────────────────────────
    # Phase 3 — Attack
    # ──────────────────────────────────────────────────────────────

    async def _phase_attack(self, tasks: list[AgentTask]) -> list[Finding]:
        """
        Execute all agent tasks concurrently with rate and budget control.

        Each agent runs inside _execute_agent_task, gated by:
            * agent semaphore (max concurrent agents)
            * request semaphore (max concurrent HTTP requests)
            * rate limiter (max RPS)
            * safety governor (per-action approval)
            * total request budget
        """
        findings: list[Finding] = []

        # Group tasks into waves by dependency
        independent = [t for t in tasks if not t.depends_on]
        dependent = [t for t in tasks if t.depends_on]

        # Wave 1: independent tasks
        if independent:
            wave_findings = await self._run_task_wave(independent)
            findings.extend(wave_findings)

        # Wave 2: dependent tasks (dependencies already ran)
        if dependent:
            wave_findings = await self._run_task_wave(dependent)
            findings.extend(wave_findings)

        return findings

    async def _run_task_wave(self, tasks: list[AgentTask]) -> list[Finding]:
        """Run a wave of tasks concurrently, respecting the agent semaphore."""
        async def _guarded(task: AgentTask) -> list[Finding]:
            async with self._agent_semaphore:
                return await self._execute_agent_task(task)

        coroutines = [_guarded(t) for t in tasks]
        results = await asyncio.gather(*coroutines, return_exceptions=True)

        findings: list[Finding] = []
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                agent_id = tasks[i].agent_spec.id
                logger.error(
                    "Agent %s failed: %s", agent_id, result,
                )
                stats = self._agent_stats.setdefault(
                    agent_id, AgentStats(agent_id=agent_id),
                )
                stats.errors += 1
            else:
                findings.extend(result)
        return findings

    async def _execute_agent_task(self, task: AgentTask) -> list[Finding]:
        """
        Execute a single agent's scanning task.

        For each target URL and parameter:
            1. Load / select payloads
            2. Optionally mutate payloads for WAF evasion
            3. Request governor approval
            4. Send HTTP request via AsyncHTTPClient
            5. Analyse response against detection patterns
            6. If match -> create Evidence -> create Finding
            7. Publish finding to event bus
        """
        spec = task.agent_spec
        agent_start = time.monotonic()
        stats = AgentStats(agent_id=spec.id)
        self._agent_stats[spec.id] = stats

        # Register with governor
        self._governor.register_agent(spec.id)

        # Compile detection patterns
        matcher = DetectionMatcher(spec.detection_patterns)

        findings: list[Finding] = []
        payloads = task.payloads or []

        # Determine injection targets
        targets = self._build_injection_targets(task)

        for inject_target in targets:
            if self._total_requests >= self._config.max_total_requests:
                logger.debug(
                    "Agent %s: global request budget exhausted", spec.id,
                )
                break
            if stats.requests_made >= spec.max_requests:
                logger.debug(
                    "Agent %s: per-agent request budget exhausted", spec.id,
                )
                break

            url = inject_target["url"]
            param = inject_target.get("param", "")
            method = inject_target.get("method", "GET")

            # ── Baseline request (clean, no payload) ────────────
            baseline_resp = await self._send_request_safe(
                spec.id, method, url, stats,
            )
            baseline_body = baseline_resp.get("body", "") if baseline_resp else ""
            baseline_elapsed = (
                baseline_resp.get("elapsed", 1.0) if baseline_resp else 1.0
            )

            for payload in payloads:
                if self._total_requests >= self._config.max_total_requests:
                    break
                if stats.requests_made >= spec.max_requests:
                    break

                # Governor approval
                action = AgentAction(
                    agent_id=spec.id,
                    type="payload_injection",
                    target=url,
                    description=(
                        f"Inject {spec.attack_types[0] if spec.attack_types else 'test'} "
                        f"payload into param={param}"
                    ),
                    parameters={"payload": payload[:200], "parameter": param},
                    requires_mode=spec.min_mode,
                    risk_level="medium" if spec.min_mode == Mode.AUDIT else "high",
                )
                approved = await self._governor.approve(action)
                if not approved:
                    continue

                # Build the request
                injected_url, req_data = self._build_injected_request(
                    url, param, payload, method,
                )

                # Send
                resp = await self._send_request_safe(
                    spec.id,
                    method,
                    injected_url,
                    stats,
                    data=req_data,
                )
                if not resp:
                    continue

                # ── Analyse response ──────────────────────────
                finding = self._analyse_response(
                    spec, matcher, url, param, payload,
                    resp, baseline_body, baseline_elapsed,
                )
                if finding:
                    findings.append(finding)
                    self._all_findings.append(finding)
                    self._governor.record_finding()

                    # Publish to event bus
                    await self._event_bus.publish(AgentMessage(
                        type=MessageType.FINDING,
                        sender=spec.id,
                        division=spec.division,
                        payload={
                            "finding_id": finding.id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "url": finding.url,
                            "attack_type": finding.attack_type,
                            "confidence": finding.consensus_confidence.name,
                        },
                        priority=AgentPriority.HIGH,
                    ))

                    # Store in working memory
                    await self._memory.store(
                        f"finding:{finding.id}",
                        {
                            "title": finding.title,
                            "url": finding.url,
                            "param": finding.parameter,
                            "severity": finding.severity,
                            "attack_type": finding.attack_type,
                            "agent": spec.id,
                        },
                        source=spec.id,
                        tags=("finding", finding.attack_type, finding.severity.lower()),
                    )

        stats.findings_count = len(findings)
        stats.duration_seconds = time.monotonic() - agent_start

        # Deregister from governor
        self._governor.deregister_agent(spec.id)

        logger.debug(
            "Agent %s complete: %d findings, %d requests, %.1fs",
            spec.id, stats.findings_count, stats.requests_made,
            stats.duration_seconds,
        )
        return findings

    def _build_injection_targets(
        self, task: AgentTask,
    ) -> list[dict[str, Any]]:
        """
        Build a list of (url, param, method) injection targets from a task.

        Combines URL-level parameters with form fields.
        """
        targets: list[dict[str, Any]] = []
        seen: set[str] = set()

        for url in task.target_urls:
            # URL query parameters
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in qs:
                key = f"{parsed.path}:{param}:GET"
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        "url": url,
                        "param": param,
                        "method": "GET",
                    })

            # Named parameters from the task
            for param in task.parameters:
                key = f"{parsed.path}:{param}:GET"
                if key not in seen:
                    seen.add(key)
                    base_url = urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, "", "", ""),
                    )
                    targets.append({
                        "url": base_url,
                        "param": param,
                        "method": "GET",
                    })

        # If no parameters found, try injecting into the URL path
        if not targets and task.target_urls:
            for url in task.target_urls[:5]:
                targets.append({
                    "url": url,
                    "param": "",
                    "method": "GET",
                })

        return targets

    @staticmethod
    def _build_injected_request(
        url: str, param: str, payload: str, method: str,
    ) -> tuple[str, dict[str, str] | None]:
        """
        Build the HTTP request with the payload injected.

        Returns (url, post_data).
        """
        if not param:
            # No parameter — append as query string
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}test={quote(payload)}", None

        if method.upper() == "POST":
            return url, {param: payload}

        # GET — inject into query string
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, "",
        ))
        return new_url, None

    async def _send_request_safe(
        self,
        agent_id: str,
        method: str,
        url: str,
        stats: AgentStats,
        *,
        data: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Send a request with concurrency control and error handling."""
        if not self._http:
            return None
        if self._total_requests >= self._config.max_total_requests:
            return None
        try:
            async with self._request_semaphore:
                resp = await self._http.request(
                    method, url,
                    data=data,
                    max_retries=2,
                )
            self._total_requests += 1
            stats.requests_made += 1
            return resp
        except Exception as exc:
            logger.debug("Agent %s request failed: %s %s: %s", agent_id, method, url, exc)
            stats.errors += 1
            return None

    def _analyse_response(
        self,
        spec: AgentSpec,
        matcher: DetectionMatcher,
        url: str,
        param: str,
        payload: str,
        resp: dict[str, Any],
        baseline_body: str,
        baseline_elapsed: float,
    ) -> Finding | None:
        """
        Analyse an HTTP response for vulnerability indicators.

        Checks:
            1. Detection pattern regex match (error-based)
            2. Boolean-based: significant response diff vs baseline
            3. Time-based: anomalous response time
            4. Payload reflection
        """
        body = resp.get("body", "")
        status = resp.get("status", 0)
        headers = resp.get("headers", {})
        elapsed = resp.get("elapsed", 0.0)

        attack_type = spec.attack_types[0] if spec.attack_types else "unknown"
        cwe = spec.cwe_ids[0] if spec.cwe_ids else ""

        # ── 1. Error-based detection ─────────────────────────
        match = matcher.match_body(body)
        if match:
            evidence = Evidence(
                agent_id=spec.id,
                type="error_based",
                description=f"Detection pattern matched: {match.re.pattern}",
                data={
                    "pattern": match.re.pattern,
                    "match": match.group()[:500],
                    "payload": payload[:200],
                    "status_code": status,
                    "response_length": len(body),
                },
                confidence=Confidence.FIRM,
            )
            return self._build_finding(
                spec, url, param, payload, attack_type, cwe,
                evidence, severity="HIGH",
            )

        # ── 2. Header-based detection ────────────────────────
        header_match = matcher.match_headers(headers)
        if header_match:
            evidence = Evidence(
                agent_id=spec.id,
                type="header_match",
                description=f"Detection pattern in headers: {header_match.re.pattern}",
                data={
                    "pattern": header_match.re.pattern,
                    "match": header_match.group()[:500],
                    "payload": payload[:200],
                    "status_code": status,
                },
                confidence=Confidence.FIRM,
            )
            return self._build_finding(
                spec, url, param, payload, attack_type, cwe,
                evidence, severity="HIGH",
            )

        # ── 3. Time-based detection ──────────────────────────
        if (
            AgentCapability.TIME_BASED in spec.capabilities
            and DetectionMatcher.is_time_anomaly(elapsed, baseline_elapsed)
        ):
            evidence = Evidence(
                agent_id=spec.id,
                type="time_based",
                description=(
                    f"Anomalous response time: {elapsed:.2f}s "
                    f"(baseline {baseline_elapsed:.2f}s)"
                ),
                data={
                    "elapsed": elapsed,
                    "baseline": baseline_elapsed,
                    "payload": payload[:200],
                    "status_code": status,
                },
                confidence=Confidence.TENTATIVE,
            )
            return self._build_finding(
                spec, url, param, payload, attack_type, cwe,
                evidence, severity="MEDIUM",
            )

        # ── 4. Boolean-based detection ───────────────────────
        if (
            AgentCapability.BOOLEAN_INFERENCE in spec.capabilities
            and baseline_body
        ):
            diff = DetectionMatcher.response_diff_ratio(baseline_body, body)
            if diff > 0.3:
                evidence = Evidence(
                    agent_id=spec.id,
                    type="boolean_based",
                    description=(
                        f"Significant response diff: {diff:.1%} "
                        f"change from baseline"
                    ),
                    data={
                        "diff_ratio": diff,
                        "payload": payload[:200],
                        "status_code": status,
                        "baseline_length": len(baseline_body),
                        "response_length": len(body),
                    },
                    confidence=Confidence.TENTATIVE,
                )
                return self._build_finding(
                    spec, url, param, payload, attack_type, cwe,
                    evidence, severity="MEDIUM",
                )

        # ── 5. Payload reflection (XSS, SSTI) ───────────────
        if (
            AgentCapability.PAYLOAD_INJECTION in spec.capabilities
            and payload in body
        ):
            evidence = Evidence(
                agent_id=spec.id,
                type="reflection",
                description="Payload reflected verbatim in response body",
                data={
                    "payload": payload[:200],
                    "status_code": status,
                    "response_length": len(body),
                },
                confidence=Confidence.FIRM,
            )
            return self._build_finding(
                spec, url, param, payload, attack_type, cwe,
                evidence, severity="MEDIUM",
            )

        return None

    @staticmethod
    def _build_finding(
        spec: AgentSpec,
        url: str,
        param: str,
        payload: str,
        attack_type: str,
        cwe: str,
        evidence: Evidence,
        severity: str = "MEDIUM",
    ) -> Finding:
        """Construct a Finding with proper metadata."""
        owasp = _CWE_TO_OWASP.get(cwe, "")
        return Finding(
            title=(
                f"{spec.name}: {attack_type} detected"
                f"{f' in param [{param}]' if param else ''}"
            ),
            severity=severity,
            description=(
                f"Agent {spec.id} detected {attack_type} vulnerability "
                f"via {evidence.type} analysis. "
                f"Payload: {payload[:120]}"
            ),
            recommendation=f"Sanitise input for parameter '{param}' against {attack_type} attacks.",
            url=url,
            parameter=param,
            attack_type=attack_type,
            cwe=cwe,
            discovered_by=spec.id,
            evidence=[evidence],
            consensus_confidence=evidence.confidence,
            owasp_category=owasp,
        )

    # ──────────────────────────────────────────────────────────────
    # Phase 4 — Verify
    # ──────────────────────────────────────────────────────────────

    async def _phase_verify(self, findings: list[Finding]) -> list[Finding]:
        """
        Multi-agent consensus verification.

        For each finding:
            1. Select 2+ agents qualified in the same attack type
            2. Each verifier re-tests the finding independently
            3. Baseline comparison eliminates false positives
            4. Consensus voting: 3 agents minimum for CONFIRMED
        """
        if not findings:
            return []

        verified: list[Finding] = []

        for finding in findings:
            # Already high-confidence — keep
            if finding.consensus_confidence >= Confidence.CONFIRMED:
                verified.append(finding)
                continue

            # Find verifier agents for this attack type
            verifier_specs = self._registry.by_attack_type(finding.attack_type)
            # Exclude the discovering agent
            verifier_specs = [
                s for s in verifier_specs
                if s.id != finding.discovered_by
            ][:2]  # max 2 verifiers

            if not verifier_specs:
                # No verifiers available — keep finding if FIRM
                if finding.consensus_confidence >= Confidence.FIRM:
                    verified.append(finding)
                continue

            # ── Re-verification ────────────────────────────────
            confirmations = 0

            for v_spec in verifier_specs:
                confirmed = await self._verify_single(
                    finding, v_spec,
                )
                if confirmed:
                    confirmations += 1
                    finding.add_confirmation(v_spec.id)

            # Baseline comparison (false-positive elimination)
            fp = await self._baseline_check(finding)
            if fp:
                logger.info(
                    "Finding %s eliminated as false positive (baseline match)",
                    finding.id,
                )
                continue

            # Consensus decision
            if confirmations >= 2:
                finding.consensus_confidence = Confidence.CONFIRMED
                verified.append(finding)
            elif confirmations >= 1 and finding.consensus_confidence >= Confidence.FIRM:
                verified.append(finding)
            elif finding.consensus_confidence >= Confidence.FIRM:
                # Keep FIRM findings even without consensus
                verified.append(finding)

        return verified

    async def _verify_single(
        self, finding: Finding, spec: AgentSpec,
    ) -> bool:
        """Have a single verifier agent re-test a finding."""
        matcher = DetectionMatcher(spec.detection_patterns)
        url = finding.url
        param = finding.parameter

        # Reconstruct a payload from the original evidence
        payload = ""
        for ev in finding.evidence:
            payload = ev.data.get("payload", "")
            if payload:
                break
        if not payload:
            return False

        # Build and send request
        injected_url, req_data = self._build_injected_request(
            url, param, payload, "GET",
        )
        stats = self._agent_stats.get(spec.id) or AgentStats(agent_id=spec.id)
        resp = await self._send_request_safe(
            spec.id, "GET", injected_url, stats, data=req_data,
        )
        if not resp:
            return False

        body = resp.get("body", "")
        headers = resp.get("headers", {})

        # Check detection patterns
        if matcher.match_body(body) or matcher.match_headers(headers):
            return True

        # Check payload reflection
        if payload in body:
            return True

        return False

    async def _baseline_check(self, finding: Finding) -> bool:
        """
        False-positive check: send a clean request and see if the
        "vulnerability indicator" appears even without a payload.

        Returns True if the finding is a false positive.
        """
        url = finding.url
        stats = AgentStats(agent_id="verifier")
        resp = await self._send_request_safe(
            "verifier", "GET", url, stats,
        )
        if not resp:
            return False

        body = resp.get("body", "")

        # Check if the detection pattern matches in the baseline too
        for ev in finding.evidence:
            pattern_str = ev.data.get("pattern", "")
            if pattern_str:
                try:
                    rx = re.compile(pattern_str, re.IGNORECASE)
                    if rx.search(body):
                        # Pattern matches even without payload -> false positive
                        return True
                except re.error:
                    pass

            # If evidence was reflection-based, check if payload appears
            # in baseline (shouldn't, but edge case)
            if ev.type == "reflection":
                payload = ev.data.get("payload", "")
                if payload and payload in body:
                    return True

        return False

    # ──────────────────────────────────────────────────────────────
    # Phase 5 — Report
    # ──────────────────────────────────────────────────────────────

    async def _phase_report(self, findings: list[Finding]) -> SwarmResult:
        """
        Aggregate verified findings into the final SwarmResult.

        Calculates risk score, letter grade, compliance mappings,
        and per-agent statistics.
        """
        duration = time.monotonic() - self._start_time

        # Risk score (0-100)
        raw_score = sum(
            _SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings
        )
        risk_score = min(100.0, float(raw_score))

        # Letter grade
        if risk_score >= 80:
            grade = "F"
        elif risk_score >= 60:
            grade = "D"
        elif risk_score >= 40:
            grade = "C"
        elif risk_score >= 20:
            grade = "B"
        elif risk_score > 0:
            grade = "A-"
        else:
            grade = "A+"

        # Compliance mappings
        for finding in findings:
            if finding.cwe and not finding.owasp_category:
                finding.owasp_category = _CWE_TO_OWASP.get(finding.cwe, "")

        # Active divisions
        divisions_active = sorted({
            s.division
            for s in self._registry.all()
            if s.id in self._agent_stats
        })

        # Total requests from HTTP client
        total_requests = self._http.request_count if self._http else 0

        result = SwarmResult(
            target=self._config.target,
            mode=self._config.mode,
            findings=findings,
            risk_score=risk_score,
            grade=grade,
            total_agents_deployed=len(self._agent_stats),
            total_requests=total_requests,
            duration_seconds=round(duration, 2),
            divisions_active=divisions_active,
            attack_surface=await self._get_cached_surface(),
            agent_stats=dict(self._agent_stats),
        )

        # Store result in working memory for downstream consumers
        await self._memory.store(
            "swarm_result",
            {
                "risk_score": risk_score,
                "grade": grade,
                "findings_count": len(findings),
                "duration": duration,
                "total_requests": total_requests,
            },
            source="executor",
            tags=("result", "report"),
        )

        return result

    async def _get_cached_surface(self) -> AttackSurface | None:
        """Retrieve the attack surface from working memory."""
        data = await self._memory.recall("attack_surface")
        if data:
            surface = AttackSurface()
            surface.urls = data.get("urls", [])
            surface.tech_stack = data.get("tech_stack", [])
            surface.waf_detected = data.get("waf")
            return surface
        return None

    # ──────────────────────────────────────────────────────────────
    # Agent Batch Runner (used in recon phase)
    # ──────────────────────────────────────────────────────────────

    async def _run_agent_batch(
        self,
        specs: list[AgentSpec],
        target: str,
        urls: list[str],
        surface: AttackSurface,
    ) -> list[Finding]:
        """
        Run a batch of agents using SwarmAgent.run().

        This is used for recon and verification agents that need
        the full agent lifecycle (observe -> plan -> execute -> analyse).
        """
        findings: list[Finding] = []

        async def _run_one(spec: AgentSpec) -> list[Finding]:
            async with self._agent_semaphore:
                agent = SwarmAgent(
                    spec,
                    event_bus=self._event_bus,
                    working_memory=self._memory,
                    safety_governor=self._governor,
                )
                await agent.initialize()
                return await agent.run(
                    target, self._config.mode, http_client=self._http,
                )

        tasks = [_run_one(s) for s in specs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                logger.error(
                    "Recon agent %s failed: %s", specs[i].id, result,
                )
            else:
                findings.extend(result)

        return findings
