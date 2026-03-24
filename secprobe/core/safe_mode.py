"""
Safe Mode & Scan Policy — Responsible scanning controls.

This module enforces responsible scanning behaviour by providing:

1. ScanPolicy     — Configurable scanning rules (rate limits, scope, depth)
2. PolicyPreset   — Pre-built profiles: STEALTH, SAFE, NORMAL, AGGRESSIVE
3. RequestBudget  — Hard limit on total requests per scan
4. ScopeEnforcer  — Only test URLs within the authorized target scope
5. SafetyGuard    — Block destructive/dangerous operations in safe mode
6. ScanThrottle   — Adaptive rate control that backs off on errors

Why this matters:
  - Real security tools MUST have controls to prevent accidental DoS
  - Bug bounty programs have strict scope rules — violating them = ban
  - Pentests require evidence of responsible testing
  - Safe mode lets users scan production without fear
"""

from __future__ import annotations

import re
import time
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
from urllib.parse import urlparse

from secprobe.core.logger import get_logger

log = get_logger("safe_mode")


# ═══════════════════════════════════════════════════════════════════════
# Policy Presets
# ═══════════════════════════════════════════════════════════════════════

class PolicyPreset(Enum):
    """Pre-built scanning profiles."""
    STEALTH = auto()      # Minimal footprint, passive-only, very slow
    SAFE = auto()         # Non-destructive, rate-limited, careful
    NORMAL = auto()       # Standard scanning — balanced speed/safety
    AGGRESSIVE = auto()   # Full speed, all tests, time-based included
    CUSTOM = auto()       # User-defined

    @property
    def description(self) -> str:
        return {
            PolicyPreset.STEALTH: "Minimal footprint — passive checks only, 1 req/2s",
            PolicyPreset.SAFE: "Non-destructive — no write operations, 2 req/s, strict scope",
            PolicyPreset.NORMAL: "Balanced — all scanner types, 10 req/s, standard scope",
            PolicyPreset.AGGRESSIVE: "Full power — all tests including time-based, unlimited rate",
            PolicyPreset.CUSTOM: "User-defined policy",
        }.get(self, "Unknown")


# ═══════════════════════════════════════════════════════════════════════
# Scan Policy — Central configuration for scan behaviour
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ScanPolicy:
    """
    Configurable scanning rules that control scan behavior.

    Usage:
        policy = ScanPolicy.from_preset(PolicyPreset.SAFE)
        policy = ScanPolicy(max_requests_per_second=5, allow_destructive=False)
    """

    # ── Rate Limiting ─────────────────────────────────────────────
    max_requests_per_second: float = 10.0
    max_requests_total: int = 0       # 0 = unlimited
    max_scan_duration: float = 0.0    # Seconds, 0 = unlimited
    request_delay_ms: int = 0         # Minimum delay between requests

    # ── Scope Control ─────────────────────────────────────────────
    allowed_domains: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)  # Path prefixes
    blocked_paths: list[str] = field(default_factory=lambda: [
        "/admin", "/administrator", "/logout", "/signout", "/sign-out",
        "/delete", "/remove", "/destroy", "/drop", "/reset",
        "/api/v*/admin", "/wp-admin", "/phpmyadmin",
    ])
    blocked_extensions: list[str] = field(default_factory=lambda: [
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".mp4", ".mp3", ".avi", ".mov", ".wav",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
        ".exe", ".dll", ".so", ".bin",
    ])

    # ── Safety Controls ───────────────────────────────────────────
    allow_destructive: bool = True    # Allow PUT/DELETE/write operations
    allow_time_based: bool = True     # Allow time-based blind injection
    allow_file_upload: bool = True    # Allow file upload tests
    allow_oob: bool = True            # Allow out-of-band callbacks
    allow_deserialization: bool = True # Allow deserialization tests
    max_payload_size: int = 10_000    # Max bytes per payload
    max_redirects: int = 10           # Max redirect chain length
    max_response_size: int = 10_000_000  # 10 MB max response
    respect_robots_txt: bool = False

    # ── Scanner Controls ──────────────────────────────────────────
    enabled_scanners: list[str] = field(default_factory=list)  # Empty = all
    disabled_scanners: list[str] = field(default_factory=list)
    passive_only: bool = False        # Only run passive scanners
    max_params_per_url: int = 50      # Skip URLs with too many params
    max_urls_per_scan: int = 0        # 0 = unlimited
    max_depth: int = 10               # Max crawl depth

    # ── Error Handling ────────────────────────────────────────────
    stop_on_error_count: int = 0      # 0 = never stop
    backoff_on_429: bool = True       # Exponential backoff on rate limiting
    backoff_on_5xx: bool = True       # Slow down on server errors

    # ── Reporting ─────────────────────────────────────────────────
    min_confidence: str = "TENTATIVE"  # Minimum confidence to report
    deduplicate: bool = True

    # ── Preset ────────────────────────────────────────────────────
    preset: PolicyPreset = PolicyPreset.NORMAL

    @classmethod
    def from_preset(cls, preset: PolicyPreset) -> ScanPolicy:
        """Create a policy from a preset profile."""
        if preset == PolicyPreset.STEALTH:
            return cls(
                max_requests_per_second=0.5,
                max_requests_total=500,
                request_delay_ms=2000,
                allow_destructive=False,
                allow_time_based=False,
                allow_file_upload=False,
                allow_oob=False,
                allow_deserialization=False,
                passive_only=True,
                respect_robots_txt=True,
                max_depth=2,
                max_urls_per_scan=50,
                backoff_on_429=True,
                backoff_on_5xx=True,
                min_confidence="FIRM",
                preset=PolicyPreset.STEALTH,
            )
        elif preset == PolicyPreset.SAFE:
            return cls(
                max_requests_per_second=2.0,
                max_requests_total=5000,
                request_delay_ms=500,
                allow_destructive=False,
                allow_time_based=False,
                allow_file_upload=False,
                allow_oob=True,
                allow_deserialization=False,
                passive_only=False,
                respect_robots_txt=True,
                max_depth=5,
                max_urls_per_scan=200,
                backoff_on_429=True,
                backoff_on_5xx=True,
                min_confidence="FIRM",
                preset=PolicyPreset.SAFE,
            )
        elif preset == PolicyPreset.AGGRESSIVE:
            return cls(
                max_requests_per_second=0.0,  # Unlimited
                max_requests_total=0,
                request_delay_ms=0,
                allow_destructive=True,
                allow_time_based=True,
                allow_file_upload=True,
                allow_oob=True,
                allow_deserialization=True,
                passive_only=False,
                respect_robots_txt=False,
                max_depth=15,
                max_urls_per_scan=0,
                max_payload_size=100_000_000,  # Effectively unlimited
                stop_on_error_count=0,
                backoff_on_429=False,
                backoff_on_5xx=False,
                min_confidence="TENTATIVE",
                preset=PolicyPreset.AGGRESSIVE,
            )
        else:
            return cls(preset=PolicyPreset.NORMAL)

    def is_scanner_allowed(self, scanner_name: str) -> bool:
        """Check if a scanner is allowed by this policy."""
        if self.disabled_scanners and scanner_name.lower() in [
            s.lower() for s in self.disabled_scanners
        ]:
            return False
        if self.enabled_scanners:
            return scanner_name.lower() in [s.lower() for s in self.enabled_scanners]
        return True

    def to_dict(self) -> dict:
        return {
            "preset": self.preset.name,
            "max_requests_per_second": self.max_requests_per_second,
            "max_requests_total": self.max_requests_total,
            "allow_destructive": self.allow_destructive,
            "allow_time_based": self.allow_time_based,
            "passive_only": self.passive_only,
            "allowed_domains": self.allowed_domains,
            "blocked_paths": self.blocked_paths,
            "min_confidence": self.min_confidence,
        }


# ═══════════════════════════════════════════════════════════════════════
# Request Budget — Hard limit on scan requests
# ═══════════════════════════════════════════════════════════════════════

class RequestBudget:
    """
    Thread-safe request budget tracker.

    Enforces hard limits on total requests to prevent runaway scans.
    """

    def __init__(self, max_requests: int = 0, max_duration: float = 0.0):
        self._max_requests = max_requests
        self._max_duration = max_duration
        self._count = 0
        self._start_time = time.monotonic()
        self._lock = threading.Lock()
        self._scanner_counts: dict[str, int] = {}

    @property
    def requests_made(self) -> int:
        return self._count

    @property
    def requests_remaining(self) -> int:
        if self._max_requests <= 0:
            return 999_999
        return max(0, self._max_requests - self._count)

    @property
    def time_elapsed(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def time_remaining(self) -> float:
        if self._max_duration <= 0:
            return float("inf")
        return max(0.0, self._max_duration - self.time_elapsed)

    @property
    def is_exhausted(self) -> bool:
        """True if budget is exceeded."""
        if self._max_requests > 0 and self._count >= self._max_requests:
            return True
        if self._max_duration > 0 and self.time_elapsed >= self._max_duration:
            return True
        return False

    @property
    def utilization(self) -> float:
        """Fraction of budget used (0.0 to 1.0)."""
        if self._max_requests <= 0:
            return 0.0
        return min(1.0, self._count / self._max_requests)

    @property
    def scanner_breakdown(self) -> dict[str, int]:
        """Request count per scanner."""
        return dict(self._scanner_counts)

    def consume(self, scanner_name: str = "", count: int = 1) -> bool:
        """
        Consume request(s) from the budget.

        Returns True if budget allows, False if exhausted.
        """
        with self._lock:
            if self.is_exhausted:
                return False
            self._count += count
            if scanner_name:
                self._scanner_counts[scanner_name] = (
                    self._scanner_counts.get(scanner_name, 0) + count
                )
            return True

    def reset(self):
        """Reset the budget counter."""
        with self._lock:
            self._count = 0
            self._start_time = time.monotonic()
            self._scanner_counts.clear()

    def summary(self) -> dict:
        return {
            "requests_made": self._count,
            "max_requests": self._max_requests,
            "time_elapsed": round(self.time_elapsed, 2),
            "max_duration": self._max_duration,
            "is_exhausted": self.is_exhausted,
            "utilization": round(self.utilization, 3),
            "scanner_breakdown": self.scanner_breakdown,
        }


# ═══════════════════════════════════════════════════════════════════════
# Scope Enforcer — Ensure scans stay within authorized boundaries
# ═══════════════════════════════════════════════════════════════════════

class ScopeEnforcer:
    """
    Enforces URL scope to prevent scanning unauthorized targets.

    This is critical for:
      - Bug bounty programs with strict scope definitions
      - Penetration tests with defined boundaries
      - Preventing accidental cross-domain scanning
    """

    def __init__(self, policy: ScanPolicy, target_url: str = ""):
        self.policy = policy
        self._target_parsed = urlparse(target_url) if target_url else None

        # Auto-add target domain to allowed list
        self._allowed_domains: set[str] = set()
        if self._target_parsed and self._target_parsed.netloc:
            self._allowed_domains.add(self._target_parsed.netloc.lower())
        for d in policy.allowed_domains:
            self._allowed_domains.add(d.lower())

        # Compile blocked path patterns
        self._blocked_patterns = []
        for path in policy.blocked_paths:
            # Convert glob-like patterns to regex
            pattern = path.replace("*", "[^/]+")
            self._blocked_patterns.append(re.compile(pattern, re.IGNORECASE))

        # Stats
        self._allowed_count = 0
        self._blocked_count = 0
        self._blocked_reasons: dict[str, int] = {}

    @property
    def allowed_count(self) -> int:
        return self._allowed_count

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    def is_in_scope(self, url: str) -> tuple[bool, str]:
        """
        Check if a URL is within the authorized scan scope.

        Returns:
            (is_allowed, reason) — reason explains why it was blocked
        """
        try:
            parsed = urlparse(url)
        except Exception:
            self._block("invalid_url")
            return False, "Invalid URL"

        # Check domain scope
        domain = parsed.netloc.lower()
        if self._allowed_domains and domain not in self._allowed_domains:
            # Check wildcard subdomains
            allowed = False
            for d in self._allowed_domains:
                if d.startswith("*.") and domain.endswith(d[1:]):
                    allowed = True
                    break
                if domain == d:
                    allowed = True
                    break
            if not allowed:
                self._block("domain_out_of_scope")
                return False, f"Domain '{domain}' not in scope"

        # Check blocked paths
        path = parsed.path.lower()
        for pattern in self._blocked_patterns:
            if pattern.search(path):
                self._block("blocked_path")
                return False, f"Path matches blocked pattern: {path}"

        # Check allowed path prefixes (if configured)
        if self.policy.allowed_paths:
            if not any(path.startswith(p.lower()) for p in self.policy.allowed_paths):
                self._block("path_not_in_scope")
                return False, f"Path not in allowed prefixes: {path}"

        # Check blocked extensions
        for ext in self.policy.blocked_extensions:
            if path.endswith(ext.lower()):
                self._block("blocked_extension")
                return False, f"File extension blocked: {ext}"

        self._allowed_count += 1
        return True, ""

    def _block(self, reason: str):
        self._blocked_count += 1
        self._blocked_reasons[reason] = self._blocked_reasons.get(reason, 0) + 1

    def summary(self) -> dict:
        return {
            "allowed_domains": sorted(self._allowed_domains),
            "allowed": self._allowed_count,
            "blocked": self._blocked_count,
            "blocked_reasons": self._blocked_reasons,
        }


# ═══════════════════════════════════════════════════════════════════════
# Safety Guard — Block dangerous operations
# ═══════════════════════════════════════════════════════════════════════

class SafetyGuard:
    """
    Safety guard that blocks dangerous operations based on scan policy.

    Acts as a gatekeeper for operations that could be destructive.
    """

    def __init__(self, policy: ScanPolicy):
        self.policy = policy
        self._violations: list[dict] = []

    @property
    def violations(self) -> list[dict]:
        return list(self._violations)

    @property
    def violation_count(self) -> int:
        return len(self._violations)

    def check_method(self, method: str, url: str = "") -> tuple[bool, str]:
        """Check if an HTTP method is allowed."""
        destructive_methods = {"PUT", "DELETE", "PATCH"}
        if method.upper() in destructive_methods and not self.policy.allow_destructive:
            self._record_violation("destructive_method", method, url)
            return False, f"{method} blocked — destructive operations disabled"
        return True, ""

    def check_scanner_type(self, scanner_name: str) -> tuple[bool, str]:
        """Check if a scanner type is allowed by policy."""
        # Map scanner names to policy flags
        restrictions = {
            "time_based": self.policy.allow_time_based,
            "blind_sqli": self.policy.allow_time_based,
            "upload": self.policy.allow_file_upload,
            "file_upload": self.policy.allow_file_upload,
            "deserialization": self.policy.allow_deserialization,
            "oob": self.policy.allow_oob,
            "ssrf": self.policy.allow_oob,
        }

        scanner_lower = scanner_name.lower()
        for keyword, allowed in restrictions.items():
            if keyword in scanner_lower and not allowed:
                self._record_violation("scanner_blocked", scanner_name, "")
                return False, f"{scanner_name} blocked by policy"

        if self.policy.passive_only:
            passive_scanners = {
                "header", "cookie", "ssl", "passive", "tech",
                "cors", "csp", "security_headers",
            }
            if not any(p in scanner_lower for p in passive_scanners):
                self._record_violation("active_blocked", scanner_name, "")
                return False, f"{scanner_name} blocked — passive-only mode"

        return True, ""

    def check_payload_size(self, payload: str) -> tuple[bool, str]:
        """Check if a payload exceeds the size limit."""
        size = len(payload.encode("utf-8", errors="replace"))
        if size > self.policy.max_payload_size:
            self._record_violation("payload_too_large", str(size), "")
            return False, f"Payload size {size} exceeds limit {self.policy.max_payload_size}"
        return True, ""

    def _record_violation(self, violation_type: str, detail: str, url: str):
        self._violations.append({
            "type": violation_type,
            "detail": detail,
            "url": url,
            "timestamp": time.time(),
        })
        log.info("Safety violation: %s — %s", violation_type, detail)

    def summary(self) -> dict:
        return {
            "violations": self.violation_count,
            "policy_preset": self.policy.preset.name,
            "allow_destructive": self.policy.allow_destructive,
            "allow_time_based": self.policy.allow_time_based,
            "passive_only": self.policy.passive_only,
        }


# ═══════════════════════════════════════════════════════════════════════
# Scan Throttle — Adaptive rate control
# ═══════════════════════════════════════════════════════════════════════

class ScanThrottle:
    """
    Adaptive rate controller that responds to server feedback.

    Automatically slows down when:
      - Receiving 429 (Rate Limited) responses
      - Receiving 5xx (Server Error) responses
      - Connection timeouts increase
      - WAF blocks are detected

    Automatically speeds up when:
      - Consistent 2xx responses
      - Low latency responses
      - No blocks for a sustained period
    """

    def __init__(self, policy: ScanPolicy):
        self.policy = policy
        self._base_rate = policy.max_requests_per_second or 100.0
        self._current_rate = self._base_rate
        self._min_rate = 0.1   # Never slower than 1 request per 10 seconds
        self._lock = threading.Lock()

        # Tracking
        self._consecutive_429 = 0
        self._consecutive_5xx = 0
        self._consecutive_ok = 0
        self._total_requests = 0
        self._total_blocks = 0
        self._last_request_time = 0.0

    @property
    def current_rate(self) -> float:
        """Current requests per second."""
        return self._current_rate

    @property
    def current_delay(self) -> float:
        """Current delay between requests in seconds."""
        if self._current_rate <= 0:
            return 0.0
        return 1.0 / self._current_rate

    @property
    def is_throttled(self) -> bool:
        """Whether rate is currently reduced from baseline."""
        return self._current_rate < self._base_rate * 0.9

    def wait(self):
        """Wait the appropriate amount of time before the next request."""
        if self._current_rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / self._current_rate
            elapsed = now - self._last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_request_time = time.monotonic()
            self._total_requests += 1

    def record_response(self, status_code: int, was_blocked: bool = False):
        """Record a response and adjust rate accordingly."""
        with self._lock:
            if was_blocked or status_code == 429:
                self._consecutive_429 += 1
                self._consecutive_ok = 0
                self._total_blocks += 1
                if self.policy.backoff_on_429:
                    # Exponential backoff: halve rate each consecutive 429
                    factor = 0.5 ** min(self._consecutive_429, 5)
                    self._current_rate = max(
                        self._min_rate, self._base_rate * factor
                    )
                    log.info("Throttle: rate reduced to %.2f req/s (429 backoff)",
                             self._current_rate)

            elif 500 <= status_code < 600:
                self._consecutive_5xx += 1
                self._consecutive_ok = 0
                if self.policy.backoff_on_5xx and self._consecutive_5xx >= 3:
                    self._current_rate = max(
                        self._min_rate, self._current_rate * 0.7
                    )
                    log.info("Throttle: rate reduced to %.2f req/s (5xx backoff)",
                             self._current_rate)

            elif 200 <= status_code < 400:
                self._consecutive_ok += 1
                self._consecutive_429 = 0
                self._consecutive_5xx = 0
                # Gradually recover rate after 10 consecutive successes
                if self._consecutive_ok >= 10 and self._current_rate < self._base_rate:
                    self._current_rate = min(
                        self._base_rate, self._current_rate * 1.2
                    )

    def reset(self):
        """Reset throttle to base rate."""
        with self._lock:
            self._current_rate = self._base_rate
            self._consecutive_429 = 0
            self._consecutive_5xx = 0
            self._consecutive_ok = 0

    def summary(self) -> dict:
        return {
            "base_rate": self._base_rate,
            "current_rate": round(self._current_rate, 2),
            "is_throttled": self.is_throttled,
            "total_requests": self._total_requests,
            "total_blocks": self._total_blocks,
        }


# ═══════════════════════════════════════════════════════════════════════
# SafeMode Facade — Unified safety layer
# ═══════════════════════════════════════════════════════════════════════

class SafeMode:
    """
    Unified facade for all safety controls.

    Usage:
        safe = SafeMode.from_preset(PolicyPreset.SAFE, target_url="https://example.com")

        # Before every request:
        if not safe.can_request("https://example.com/api", scanner="xss"):
            return  # Blocked

        safe.throttle.wait()
        response = client.get(url)
        safe.record_response(response.status_code)
    """

    def __init__(self, policy: ScanPolicy, target_url: str = ""):
        self.policy = policy
        self.budget = RequestBudget(
            max_requests=policy.max_requests_total,
            max_duration=policy.max_scan_duration,
        )
        self.scope = ScopeEnforcer(policy, target_url)
        self.guard = SafetyGuard(policy)
        self.throttle = ScanThrottle(policy)

    @classmethod
    def from_preset(cls, preset: PolicyPreset, target_url: str = "") -> SafeMode:
        """Create a SafeMode from a preset."""
        policy = ScanPolicy.from_preset(preset)
        return cls(policy, target_url)

    def can_request(self, url: str, method: str = "GET",
                    scanner: str = "", payload: str = "") -> tuple[bool, str]:
        """
        Check ALL safety conditions before making a request.

        Returns (allowed, reason).
        """
        # Budget check
        if self.budget.is_exhausted:
            return False, "Request budget exhausted"

        # Scope check
        in_scope, reason = self.scope.is_in_scope(url)
        if not in_scope:
            return False, reason

        # Method check
        allowed, reason = self.guard.check_method(method, url)
        if not allowed:
            return False, reason

        # Scanner check
        if scanner:
            allowed, reason = self.guard.check_scanner_type(scanner)
            if not allowed:
                return False, reason

        # Payload size check
        if payload:
            allowed, reason = self.guard.check_payload_size(payload)
            if not allowed:
                return False, reason

        # Consume budget
        self.budget.consume(scanner)
        return True, ""

    def record_response(self, status_code: int, was_blocked: bool = False):
        """Record a response for adaptive throttling."""
        self.throttle.record_response(status_code, was_blocked)

    @property
    def is_active(self) -> bool:
        """Whether safety controls are enabled (not AGGRESSIVE/unlimited)."""
        return self.policy.preset != PolicyPreset.AGGRESSIVE

    def summary(self) -> dict:
        """Full summary of safety state."""
        return {
            "policy": self.policy.to_dict(),
            "budget": self.budget.summary(),
            "scope": self.scope.summary(),
            "safety": self.guard.summary(),
            "throttle": self.throttle.summary(),
        }
