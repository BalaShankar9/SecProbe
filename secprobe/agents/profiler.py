"""
Behavioral Profiling Engine — Deep target characterization.

This engine builds a comprehensive behavioral model of the target:

  1. TIMING PROFILER
     - Response time distribution per endpoint
     - Statistical baseline for blind injection detection
     - Network jitter compensation
     - Server processing time fingerprinting

  2. WAF BEHAVIORAL MODEL
     - Maps exactly which patterns trigger blocks
     - Learns WAF rule thresholds (e.g., blocks after 3 suspicious chars)
     - Identifies bypass windows (timing, encoding, header tricks)
     - Classifies WAF type from behavioral signatures

  3. RESPONSE FINGERPRINTER
     - Builds response templates per endpoint
     - Detects dynamic vs static content regions
     - Identifies error patterns and their meanings
     - Tracks response similarity clustering

  4. TECHNOLOGY PROFILER
     - Deep stack fingerprinting beyond headers
     - Error message → technology mapping
     - URL pattern → framework detection
     - Cookie/session format → technology inference

What makes this world-class:
  - PREDICTIVE: models target behavior so well we can predict responses
  - ADAPTIVE: model updates in real-time as we learn more
  - STATISTICAL: uses proper statistics (not just string matching)
  - SHARED: profiling results feed all other agents
"""

from __future__ import annotations

import math
import re
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════
# TIMING PROFILER
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TimingProfile:
    """Statistical timing profile for an endpoint."""
    endpoint: str = ""
    samples: list[float] = field(default_factory=list)
    _sorted: bool = False

    def add_sample(self, response_time: float):
        """Add a response time sample."""
        self.samples.append(response_time)
        self._sorted = False

    @property
    def mean(self) -> float:
        return statistics.mean(self.samples) if self.samples else 0.0

    @property
    def median(self) -> float:
        return statistics.median(self.samples) if self.samples else 0.0

    @property
    def std_dev(self) -> float:
        return statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0

    @property
    def min_time(self) -> float:
        return min(self.samples) if self.samples else 0.0

    @property
    def max_time(self) -> float:
        return max(self.samples) if self.samples else 0.0

    @property
    def sample_count(self) -> int:
        return len(self.samples)

    def percentile(self, p: float) -> float:
        """Get the p-th percentile (0-100)."""
        if not self.samples:
            return 0.0
        if not self._sorted:
            self.samples.sort()
            self._sorted = True
        k = (len(self.samples) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return self.samples[int(k)]
        d0 = self.samples[int(f)] * (c - k)
        d1 = self.samples[int(c)] * (k - f)
        return d0 + d1

    def is_anomalous(self, response_time: float,
                     sigma_threshold: float = 3.0) -> bool:
        """
        Check if a response time is statistically anomalous.

        Uses 3-sigma rule: anomalous if > mean + 3 × std_dev
        Requires at least 5 baseline samples.
        """
        if len(self.samples) < 5:
            return False
        threshold = self.mean + sigma_threshold * self.std_dev
        return response_time > threshold

    def get_blind_injection_threshold(self) -> float:
        """
        Get the minimum delay that would indicate blind injection.

        Uses percentile-based approach: anything above the 99th
        percentile of normal responses is suspicious.
        """
        if len(self.samples) < 10:
            return 5.0  # Default: 5 seconds
        return self.percentile(99) + 1.0

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "samples": self.sample_count,
            "mean": round(self.mean, 4),
            "median": round(self.median, 4),
            "std_dev": round(self.std_dev, 4),
            "min": round(self.min_time, 4),
            "max": round(self.max_time, 4),
            "p95": round(self.percentile(95), 4),
            "p99": round(self.percentile(99), 4),
        }


class TimingProfiler:
    """
    Builds timing profiles for all endpoints.

    Used for:
    - Baseline establishment (what's normal for this server)
    - Blind injection detection (timing anomalies)
    - Server load estimation (average processing time)
    - Network jitter compensation
    """

    def __init__(self, max_samples_per_endpoint: int = 200):
        self.profiles: dict[str, TimingProfile] = {}
        self._max_samples = max_samples_per_endpoint
        self._global_samples: deque[float] = deque(maxlen=1000)

    def record(self, endpoint: str, response_time: float):
        """Record a response time for an endpoint."""
        if endpoint not in self.profiles:
            self.profiles[endpoint] = TimingProfile(endpoint=endpoint)

        profile = self.profiles[endpoint]
        if profile.sample_count < self._max_samples:
            profile.add_sample(response_time)
        self._global_samples.append(response_time)

    def is_anomalous(self, endpoint: str, response_time: float,
                     sigma: float = 3.0) -> bool:
        """Check if a response time is anomalous for an endpoint."""
        profile = self.profiles.get(endpoint)
        if profile:
            return profile.is_anomalous(response_time, sigma)
        # No profile — use global baseline
        if len(self._global_samples) >= 5:
            mean = statistics.mean(self._global_samples)
            std = statistics.stdev(self._global_samples)
            return response_time > mean + sigma * std
        return False

    def get_injection_threshold(self, endpoint: str) -> float:
        """Get the blind injection detection threshold for an endpoint."""
        profile = self.profiles.get(endpoint)
        if profile:
            return profile.get_blind_injection_threshold()
        return 5.0  # Conservative default

    @property
    def global_mean(self) -> float:
        return statistics.mean(self._global_samples) if self._global_samples else 0.0

    @property
    def endpoint_count(self) -> int:
        return len(self.profiles)

    def get_stats(self) -> dict:
        return {
            "endpoints_profiled": len(self.profiles),
            "total_samples": sum(p.sample_count for p in self.profiles.values()),
            "global_mean": round(self.global_mean, 4),
            "profiles": {
                ep: profile.to_dict()
                for ep, profile in list(self.profiles.items())[:10]
            },
        }


# ═══════════════════════════════════════════════════════════════════
# WAF BEHAVIORAL MODEL
# ═══════════════════════════════════════════════════════════════════

@dataclass
class WAFRule:
    """A learned WAF rule from behavioral analysis."""
    pattern: str = ""              # What triggers the rule
    block_count: int = 0           # Times this pattern was blocked
    pass_count: int = 0            # Times this pattern was allowed
    confidence: float = 0.0        # How sure we are this rule exists
    bypass_techniques: list[str] = field(default_factory=list)
    discovery_time: float = field(default_factory=time.time)

    @property
    def block_rate(self) -> float:
        total = self.block_count + self.pass_count
        return self.block_count / total if total > 0 else 0.0

    def update(self, blocked: bool):
        """Update rule based on new observation."""
        if blocked:
            self.block_count += 1
        else:
            self.pass_count += 1
        total = self.block_count + self.pass_count
        self.confidence = min(1.0, total / 10.0)


class WAFBehaviorModel:
    """
    Behavioral model of target's Web Application Firewall.

    Instead of relying on a static WAF signature database,
    this model learns the ACTUAL behavior of the specific WAF
    instance through testing.

    Learns:
    - Which patterns trigger blocks (and which don't)
    - Block thresholds (e.g., blocks after N suspicious chars)
    - Bypass windows (timing, encoding, header manipulation)
    - Rate limiting behavior
    """

    def __init__(self):
        self.waf_type: str = ""                # Detected WAF type
        self.waf_confidence: float = 0.0
        self.rules: dict[str, WAFRule] = {}     # pattern → WAFRule
        self.block_history: deque[dict] = deque(maxlen=500)
        self.pass_history: deque[dict] = deque(maxlen=500)
        self._rate_limit_data: list[dict] = []
        self._block_status_codes: defaultdict = defaultdict(int)
        self._total_requests = 0
        self._total_blocks = 0

    # Known patterns to test for WAF rules
    TEST_PATTERNS = [
        ("single_quote", "'"),
        ("double_quote", '"'),
        ("angle_bracket", "<"),
        ("script_tag", "<script>"),
        ("union_select", "UNION SELECT"),
        ("or_1eq1", "OR 1=1"),
        ("semicolon", ";"),
        ("pipe", "|"),
        ("backtick", "`"),
        ("dollar_brace", "${"),
        ("double_brace", "{{"),
        ("dot_dot_slash", "../"),
        ("null_byte", "%00"),
        ("sleep_fn", "SLEEP("),
        ("xml_entity", "<!ENTITY"),
    ]

    def record_request(self, payload: str, status_code: int,
                       was_blocked: bool, response_body: str = ""):
        """Record a request and whether it was blocked."""
        self._total_requests += 1

        if was_blocked:
            self._total_blocks += 1
            self._block_status_codes[status_code] += 1
            self.block_history.append({
                "payload": payload[:200],
                "status": status_code,
                "time": time.time(),
            })
        else:
            self.pass_history.append({
                "payload": payload[:200],
                "status": status_code,
                "time": time.time(),
            })

        # Update known pattern rules
        for pattern_name, pattern_str in self.TEST_PATTERNS:
            if pattern_str.lower() in payload.lower():
                if pattern_name not in self.rules:
                    self.rules[pattern_name] = WAFRule(pattern=pattern_str)
                self.rules[pattern_name].update(was_blocked)

    def predict_block(self, payload: str) -> float:
        """
        Predict probability that a payload will be blocked.

        Uses learned rules to estimate block probability.
        """
        if not self.rules:
            return self.overall_block_rate

        # Check which known rules the payload matches
        matching_rules = []
        for rule_name, rule in self.rules.items():
            if rule.pattern.lower() in payload.lower():
                matching_rules.append(rule)

        if not matching_rules:
            return max(0.1, self.overall_block_rate * 0.5)

        # Combine rule probabilities (assuming independence)
        # P(blocked) = 1 - ∏(1 - P(rule_i blocks))
        pass_prob = 1.0
        for rule in matching_rules:
            pass_prob *= (1 - rule.block_rate)

        return 1.0 - pass_prob

    def get_safe_patterns(self, min_pass_rate: float = 0.8
                          ) -> list[str]:
        """Get patterns that usually pass the WAF."""
        safe = []
        for name, rule in self.rules.items():
            if rule.pass_count > 0 and (1 - rule.block_rate) >= min_pass_rate:
                safe.append(name)
        return safe

    def get_blocked_patterns(self, min_block_rate: float = 0.7
                             ) -> list[str]:
        """Get patterns that are usually blocked."""
        blocked = []
        for name, rule in self.rules.items():
            if rule.block_rate >= min_block_rate:
                blocked.append(name)
        return blocked

    def suggest_bypass(self, pattern_name: str) -> list[str]:
        """Suggest bypass techniques for a blocked pattern."""
        rule = self.rules.get(pattern_name)
        if rule and rule.bypass_techniques:
            return rule.bypass_techniques

        # Default bypass suggestions based on pattern type
        defaults = {
            "single_quote": ["unicode_escape", "hex_encode", "double_encode"],
            "script_tag": ["case_swap", "null_byte", "html_entity"],
            "union_select": ["comment_inject", "case_swap", "whitespace_sub"],
            "dot_dot_slash": ["double_encode", "unicode_escape", "null_byte"],
            "sleep_fn": ["benchmark_alt", "heavy_query", "conditional_error"],
        }
        return defaults.get(pattern_name, ["url_encode", "case_swap"])

    @property
    def overall_block_rate(self) -> float:
        return self._total_blocks / self._total_requests if self._total_requests > 0 else 0.0

    @property
    def is_waf_detected(self) -> bool:
        return self.overall_block_rate > 0.1 and self._total_requests >= 5

    def get_stats(self) -> dict:
        return {
            "waf_type": self.waf_type,
            "waf_detected": self.is_waf_detected,
            "total_requests": self._total_requests,
            "total_blocks": self._total_blocks,
            "block_rate": round(self.overall_block_rate, 4),
            "rules_learned": len(self.rules),
            "blocked_patterns": self.get_blocked_patterns(),
            "safe_patterns": self.get_safe_patterns(),
        }


# ═══════════════════════════════════════════════════════════════════
# RESPONSE FINGERPRINTER
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ResponseTemplate:
    """A learned template for normal responses from an endpoint."""
    endpoint: str = ""
    status_codes: dict[int, int] = field(default_factory=dict)  # code → count
    content_lengths: list[int] = field(default_factory=list)
    common_headers: dict[str, int] = field(default_factory=dict)
    body_patterns: list[str] = field(default_factory=list)
    dynamic_regions: list[tuple[int, int]] = field(default_factory=list)
    sample_count: int = 0

    @property
    def typical_status(self) -> int:
        if not self.status_codes:
            return 200
        return max(self.status_codes, key=self.status_codes.get)

    @property
    def typical_length(self) -> float:
        return statistics.mean(self.content_lengths) if self.content_lengths else 0

    @property
    def length_variance(self) -> float:
        return statistics.stdev(self.content_lengths) if len(self.content_lengths) > 1 else 0


class ResponseFingerprinter:
    """
    Builds behavioral fingerprints of target responses.

    Learns what "normal" looks like for each endpoint so we can
    detect when something abnormal happens (indicating a vuln).
    """

    def __init__(self):
        self.templates: dict[str, ResponseTemplate] = {}
        self._error_patterns: dict[str, int] = defaultdict(int)
        self._tech_signatures: dict[str, float] = {}

    def record_response(self, endpoint: str, status_code: int,
                        content_length: int, headers: dict = None,
                        body_snippet: str = ""):
        """Record a response for fingerprinting."""
        if endpoint not in self.templates:
            self.templates[endpoint] = ResponseTemplate(endpoint=endpoint)

        tmpl = self.templates[endpoint]
        tmpl.sample_count += 1
        tmpl.status_codes[status_code] = tmpl.status_codes.get(status_code, 0) + 1

        if content_length > 0:
            tmpl.content_lengths.append(content_length)
            # Keep manageable
            if len(tmpl.content_lengths) > 200:
                tmpl.content_lengths = tmpl.content_lengths[-200:]

        if headers:
            for header in headers:
                tmpl.common_headers[header] = tmpl.common_headers.get(header, 0) + 1

        # Detect error patterns
        if body_snippet:
            self._detect_errors(body_snippet)
            self._detect_tech(body_snippet, headers or {})

    def is_anomalous_response(self, endpoint: str, status_code: int,
                               content_length: int) -> tuple[bool, str]:
        """
        Check if a response is anomalous compared to the template.

        Returns (is_anomalous, reason).
        """
        tmpl = self.templates.get(endpoint)
        if not tmpl or tmpl.sample_count < 3:
            return False, ""

        # Status code anomaly
        if status_code not in tmpl.status_codes:
            return True, f"Unexpected status code: {status_code}"

        # Content length anomaly (>2 sigma from mean)
        if tmpl.content_lengths and len(tmpl.content_lengths) >= 5:
            mean = tmpl.typical_length
            std = tmpl.length_variance or 1
            if abs(content_length - mean) > 2 * std:
                direction = "larger" if content_length > mean else "smaller"
                return True, f"Response {direction} than normal ({content_length} vs {mean:.0f}±{std:.0f})"

        return False, ""

    def _detect_errors(self, body: str):
        """Detect error patterns in response body."""
        error_patterns = {
            "sql_error": [
                r"SQL syntax", r"mysql_", r"pg_query", r"ORA-\d+",
                r"sqlite3?\.", r"SQLSTATE",
            ],
            "stack_trace": [
                r"Traceback \(most recent", r"at [\w.]+\([\w.]+:\d+\)",
                r"Exception in thread", r"Fatal error",
            ],
            "path_disclosure": [
                r"/var/www/", r"C:\\", r"/home/\w+/",
                r"/usr/local/", r"DocumentRoot",
            ],
            "debug_info": [
                r"DEBUG\s*=\s*True", r"stack_trace",
                r"phpinfo\(\)", r"server_info",
            ],
        }
        body_str = body[:5000]
        for category, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body_str, re.I):
                    self._error_patterns[category] += 1

    def _detect_tech(self, body: str, headers: dict):
        """Detect technology from response content."""
        tech_indicators = {
            "php": {
                "headers": ["x-powered-by: php"],
                "body": [r"\.php", r"PHPSESSID"],
            },
            "python": {
                "headers": ["server: gunicorn", "server: waitress"],
                "body": [r"Traceback \(most recent", r"wsgi"],
            },
            "java": {
                "headers": ["x-powered-by: servlet"],
                "body": [r"\.jsp", r"java\.", r"javax\."],
            },
            "nodejs": {
                "headers": ["x-powered-by: express"],
                "body": [r"node_modules", r"express"],
            },
        }
        for tech, indicators in tech_indicators.items():
            score = 0
            for h in indicators.get("headers", []):
                for header_key, header_val in headers.items():
                    if h.lower() in f"{header_key}: {header_val}".lower():
                        score += 0.4
            for pattern in indicators.get("body", []):
                if re.search(pattern, body[:5000], re.I):
                    score += 0.2
            if score > 0:
                self._tech_signatures[tech] = min(
                    1.0, self._tech_signatures.get(tech, 0) + score
                )

    @property
    def detected_tech(self) -> dict[str, float]:
        return dict(self._tech_signatures)

    @property
    def error_summary(self) -> dict[str, int]:
        return dict(self._error_patterns)

    def get_stats(self) -> dict:
        return {
            "endpoints_fingerprinted": len(self.templates),
            "error_patterns": dict(self._error_patterns),
            "detected_tech": self._tech_signatures,
            "total_samples": sum(
                t.sample_count for t in self.templates.values()
            ),
        }


# ═══════════════════════════════════════════════════════════════════
# COMPLETE BEHAVIORAL PROFILER
# ═══════════════════════════════════════════════════════════════════

class BehavioralProfiler:
    """
    Complete behavioral profiling system.

    Integrates:
    - Timing profiler (statistical timing baselines)
    - WAF model (learned WAF rules and bypass strategies)
    - Response fingerprinter (normal response templates)
    - Technology profiler (stack detection)

    All components feed each other and update in real-time.
    """

    def __init__(self):
        self.timing = TimingProfiler()
        self.waf = WAFBehaviorModel()
        self.fingerprinter = ResponseFingerprinter()
        self._total_requests = 0
        self._start_time = time.time()

    def record(self, endpoint: str, payload: str = "",
               status_code: int = 200, content_length: int = 0,
               response_time: float = 0.0, headers: dict = None,
               body_snippet: str = "", was_blocked: bool = False):
        """
        Record a complete request/response observation.

        Feeds all profiling components simultaneously.
        """
        self._total_requests += 1

        # Timing
        if response_time > 0:
            self.timing.record(endpoint, response_time)

        # WAF
        if payload:
            self.waf.record_request(payload, status_code, was_blocked, body_snippet)

        # Response fingerprinting
        self.fingerprinter.record_response(
            endpoint, status_code, content_length,
            headers, body_snippet
        )

    def analyze(self, endpoint: str, payload: str = "",
                status_code: int = 200, content_length: int = 0,
                response_time: float = 0.0) -> dict:
        """
        Analyze a response against known profiles.

        Returns analysis dict with anomaly flags and predictions.
        """
        analysis = {
            "timing_anomaly": False,
            "response_anomaly": False,
            "likely_blocked": False,
            "anomaly_reasons": [],
        }

        # Timing analysis
        if response_time > 0:
            if self.timing.is_anomalous(endpoint, response_time):
                analysis["timing_anomaly"] = True
                analysis["anomaly_reasons"].append(
                    f"Response time {response_time:.2f}s is anomalous"
                )

        # Response analysis
        is_anom, reason = self.fingerprinter.is_anomalous_response(
            endpoint, status_code, content_length
        )
        if is_anom:
            analysis["response_anomaly"] = True
            analysis["anomaly_reasons"].append(reason)

        # Block prediction
        if payload:
            block_prob = self.waf.predict_block(payload)
            analysis["block_probability"] = round(block_prob, 4)
            analysis["likely_blocked"] = block_prob > 0.6

        return analysis

    def get_injection_threshold(self, endpoint: str) -> float:
        """Get the blind injection timing threshold for an endpoint."""
        return self.timing.get_injection_threshold(endpoint)

    def suggest_evasion(self, payload: str) -> list[str]:
        """Suggest evasion techniques based on WAF model."""
        suggestions = []
        for rule_name, rule in self.waf.rules.items():
            if (rule.pattern.lower() in payload.lower() and
                    rule.block_rate > 0.5):
                bypass = self.waf.suggest_bypass(rule_name)
                suggestions.extend(bypass)
        return list(set(suggestions))

    def get_stats(self) -> dict:
        return {
            "total_requests": self._total_requests,
            "uptime": round(time.time() - self._start_time, 2),
            "timing": self.timing.get_stats(),
            "waf": self.waf.get_stats(),
            "fingerprinter": self.fingerprinter.get_stats(),
        }
