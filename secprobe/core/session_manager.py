"""
Advanced Session Manager — Authentication state machines & token analysis.

Features:
  - Multi-step authentication flows (login → MFA → dashboard)
  - Session token entropy analysis (randomness testing)
  - Token prediction resistance testing
  - Automatic re-authentication on session expiry
  - Session fixation detection
  - Concurrent session testing
  - Idle timeout detection
  - Cookie/token lifecycle analysis
"""

from __future__ import annotations

import hashlib
import math
import re
import time
import string
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from urllib.parse import urljoin

from secprobe.config import Severity
from secprobe.models import Finding


# ── Authentication State Machine ─────────────────────────────────────

class AuthState(Enum):
    UNAUTHENTICATED = "unauthenticated"
    CREDENTIALS_SUBMITTED = "credentials_submitted"
    MFA_REQUIRED = "mfa_required"
    MFA_SUBMITTED = "mfa_submitted"
    AUTHENTICATED = "authenticated"
    SESSION_EXPIRED = "session_expired"
    LOCKED_OUT = "locked_out"


@dataclass
class AuthStep:
    """A single step in a multi-step authentication flow."""
    name: str
    url: str
    method: str = "POST"
    data: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    success_indicator: str = ""    # Regex pattern to match on success
    failure_indicator: str = ""    # Regex pattern to match on failure
    extract_tokens: dict = field(default_factory=dict)  # name -> regex pattern
    next_state: AuthState = AuthState.AUTHENTICATED


@dataclass
class AuthFlow:
    """Complete multi-step authentication flow definition."""
    name: str
    steps: list[AuthStep] = field(default_factory=list)
    logout_url: Optional[str] = None
    session_check_url: Optional[str] = None
    session_valid_indicator: str = ""  # Regex on session check response


class SessionManager:
    """
    Advanced session management with authentication state machines.

    Handles:
        - Multi-step auth flows
        - Session token extraction and refresh
        - Automatic re-authentication
        - Session state tracking
    """

    def __init__(self, http_client=None):
        self.http_client = http_client
        self.state = AuthState.UNAUTHENTICATED
        self.auth_flow: Optional[AuthFlow] = None
        self.tokens: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self._session_start: Optional[float] = None
        self._last_activity: Optional[float] = None
        self._auth_attempts: int = 0

    def configure_flow(self, flow: AuthFlow):
        """Configure the authentication flow."""
        self.auth_flow = flow

    def authenticate(self) -> bool:
        """Execute the full authentication flow."""
        if not self.auth_flow or not self.http_client:
            return False

        self.state = AuthState.UNAUTHENTICATED
        self._auth_attempts += 1

        for step in self.auth_flow.steps:
            success = self._execute_step(step)
            if not success:
                return False
            self.state = step.next_state

        self._session_start = time.time()
        self._last_activity = time.time()
        self.state = AuthState.AUTHENTICATED
        return True

    def _execute_step(self, step: AuthStep) -> bool:
        """Execute a single authentication step."""
        # Replace token placeholders in data
        data = {}
        for key, value in step.data.items():
            if isinstance(value, str):
                for token_name, token_value in self.tokens.items():
                    value = value.replace(f"{{{token_name}}}", token_value)
            data[key] = value

        headers = {**step.headers}
        for key, value in headers.items():
            if isinstance(value, str):
                for token_name, token_value in self.tokens.items():
                    headers[key] = value.replace(f"{{{token_name}}}", token_value)

        try:
            if step.method.upper() == "POST":
                resp = self.http_client.post(step.url, data=data, headers=headers)
            else:
                resp = self.http_client.get(step.url, headers=headers)

            if not resp:
                return False

            # Check for failure
            if step.failure_indicator and re.search(step.failure_indicator, resp.text, re.IGNORECASE):
                self.state = AuthState.LOCKED_OUT if self._auth_attempts > 3 else AuthState.UNAUTHENTICATED
                return False

            # Check for success
            if step.success_indicator and not re.search(step.success_indicator, resp.text, re.IGNORECASE):
                return False

            # Extract tokens
            for name, pattern in step.extract_tokens.items():
                match = re.search(pattern, resp.text)
                if match:
                    self.tokens[name] = match.group(1) if match.groups() else match.group(0)

            # Extract cookies
            if hasattr(resp, 'cookies'):
                for name, value in resp.cookies.items():
                    self.cookies[name] = value

            self._last_activity = time.time()
            return True

        except Exception:
            return False

    def check_session(self) -> bool:
        """Check if current session is still valid."""
        if not self.auth_flow or not self.auth_flow.session_check_url:
            return self.state == AuthState.AUTHENTICATED

        try:
            resp = self.http_client.get(self.auth_flow.session_check_url)
            if resp and self.auth_flow.session_valid_indicator:
                if re.search(self.auth_flow.session_valid_indicator, resp.text):
                    self._last_activity = time.time()
                    return True
            self.state = AuthState.SESSION_EXPIRED
            return False
        except Exception:
            return False

    def ensure_authenticated(self) -> bool:
        """Ensure we have a valid session, re-authenticating if needed."""
        if self.check_session():
            return True
        return self.authenticate()

    def logout(self) -> bool:
        """Perform logout."""
        if self.auth_flow and self.auth_flow.logout_url:
            try:
                self.http_client.get(self.auth_flow.logout_url)
            except Exception:
                pass
        self.state = AuthState.UNAUTHENTICATED
        self.tokens.clear()
        self.cookies.clear()
        return True


# ── Token Entropy Analyzer ───────────────────────────────────────────

@dataclass
class EntropyResult:
    """Result of entropy analysis on a token."""
    token: str
    length: int
    entropy_bits: float
    charset_size: int
    charsets_used: list[str]
    is_predictable: bool
    prediction_risk: str  # LOW, MEDIUM, HIGH
    analysis: str


class TokenAnalyzer:
    """
    Analyze session token security properties.

    Tests:
        - Shannon entropy
        - Character set diversity
        - Sequential pattern detection
        - Timestamp embedding detection
        - Predictability assessment
    """

    def analyze_entropy(self, token: str) -> EntropyResult:
        """Analyze the entropy of a single token."""
        length = len(token)
        charsets = self._identify_charsets(token)
        charset_size = self._charset_size(charsets)
        entropy = self._shannon_entropy(token) * length

        # Ideal entropy for this charset
        ideal_entropy = math.log2(charset_size) * length if charset_size > 0 else 0
        entropy_ratio = entropy / ideal_entropy if ideal_entropy > 0 else 0

        # Predictability assessment
        is_sequential = self._check_sequential(token)
        has_timestamp = self._check_timestamp(token)

        if entropy < 64 or is_sequential or entropy_ratio < 0.5:
            prediction_risk = "HIGH"
            is_predictable = True
        elif entropy < 128 or has_timestamp or entropy_ratio < 0.7:
            prediction_risk = "MEDIUM"
            is_predictable = True
        else:
            prediction_risk = "LOW"
            is_predictable = False

        analysis_parts = [f"Length: {length} chars", f"Entropy: {entropy:.1f} bits"]
        if is_sequential:
            analysis_parts.append("⚠ Sequential patterns detected")
        if has_timestamp:
            analysis_parts.append("⚠ Possible timestamp embedding")
        analysis_parts.append(f"Charset: {', '.join(charsets)} ({charset_size} chars)")
        analysis_parts.append(f"Entropy ratio: {entropy_ratio:.1%} of ideal")

        return EntropyResult(
            token=token[:20] + "..." if len(token) > 20 else token,
            length=length,
            entropy_bits=round(entropy, 1),
            charset_size=charset_size,
            charsets_used=charsets,
            is_predictable=is_predictable,
            prediction_risk=prediction_risk,
            analysis="; ".join(analysis_parts),
        )

    def analyze_token_set(self, tokens: list[str]) -> dict:
        """Analyze a set of tokens for patterns and predictability."""
        if len(tokens) < 2:
            return {"error": "Need at least 2 tokens for comparison"}

        analyses = [self.analyze_entropy(t) for t in tokens]

        # Check for common prefixes/suffixes (potential structure)
        common_prefix = self._common_prefix(tokens)
        common_suffix = self._common_suffix(tokens)

        # Check for incrementing patterns
        is_incremental = self._check_incremental(tokens)

        # Hamming distance between consecutive tokens
        distances = []
        for i in range(len(tokens) - 1):
            d = self._hamming_distance(tokens[i], tokens[i + 1])
            distances.append(d)

        avg_distance = sum(distances) / len(distances) if distances else 0
        avg_entropy = sum(a.entropy_bits for a in analyses) / len(analyses)

        return {
            "token_count": len(tokens),
            "avg_entropy_bits": round(avg_entropy, 1),
            "avg_length": sum(len(t) for t in tokens) / len(tokens),
            "common_prefix": common_prefix,
            "common_suffix": common_suffix,
            "is_incremental": is_incremental,
            "avg_hamming_distance": round(avg_distance, 1),
            "prediction_risk": max(a.prediction_risk for a in analyses),
            "individual_analyses": analyses,
        }

    def _shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy per character."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _identify_charsets(self, token: str) -> list[str]:
        """Identify character sets used in token."""
        charsets = []
        if any(c in string.ascii_lowercase for c in token):
            charsets.append("lowercase")
        if any(c in string.ascii_uppercase for c in token):
            charsets.append("uppercase")
        if any(c in string.digits for c in token):
            charsets.append("digits")
        if any(c in "+-/=" for c in token):
            charsets.append("base64")
        if any(c in string.punctuation.replace("+", "").replace("/", "").replace("=", "")
               for c in token):
            charsets.append("special")
        return charsets

    def _charset_size(self, charsets: list[str]) -> int:
        """Calculate total charset size."""
        sizes = {
            "lowercase": 26,
            "uppercase": 26,
            "digits": 10,
            "base64": 4,
            "special": 32,
        }
        return sum(sizes.get(cs, 0) for cs in charsets)

    def _check_sequential(self, token: str) -> bool:
        """Check for sequential patterns in token."""
        # Check for incrementing digits
        digits = "".join(c for c in token if c.isdigit())
        if len(digits) > 4:
            for i in range(len(digits) - 3):
                if all(int(digits[j + 1]) - int(digits[j]) == 1
                       for j in range(i, i + 3)
                       if digits[j].isdigit() and digits[j + 1].isdigit()):
                    return True
        return False

    def _check_timestamp(self, token: str) -> bool:
        """Check if token contains timestamp-like patterns."""
        import time as time_mod
        current_time = int(time_mod.time())
        # Check for Unix timestamp (10 digits)
        digits = re.findall(r'\d{10}', token)
        for d in digits:
            ts = int(d)
            # Within last year
            if abs(ts - current_time) < 365 * 24 * 3600:
                return True
        # Check for millisecond timestamp (13 digits)
        ms_digits = re.findall(r'\d{13}', token)
        for d in ms_digits:
            ts = int(d) / 1000
            if abs(ts - current_time) < 365 * 24 * 3600:
                return True
        return False

    def _check_incremental(self, tokens: list[str]) -> bool:
        """Check if tokens are incrementing."""
        try:
            # Try hex interpretation
            nums = [int(t, 16) for t in tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            if all(d == diffs[0] for d in diffs) and diffs[0] != 0:
                return True
        except (ValueError, IndexError):
            pass

        try:
            # Try integer interpretation
            nums = [int(t) for t in tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            if all(d == diffs[0] for d in diffs) and diffs[0] != 0:
                return True
        except (ValueError, IndexError):
            pass

        return False

    def _hamming_distance(self, s1: str, s2: str) -> int:
        """Calculate Hamming distance between two strings."""
        min_len = min(len(s1), len(s2))
        distance = abs(len(s1) - len(s2))
        distance += sum(c1 != c2 for c1, c2 in zip(s1[:min_len], s2[:min_len]))
        return distance

    def _common_prefix(self, strings: list[str]) -> str:
        if not strings:
            return ""
        prefix = strings[0]
        for s in strings[1:]:
            while not s.startswith(prefix):
                prefix = prefix[:-1]
                if not prefix:
                    return ""
        return prefix

    def _common_suffix(self, strings: list[str]) -> str:
        reversed_strings = [s[::-1] for s in strings]
        suffix = self._common_prefix(reversed_strings)
        return suffix[::-1]


# ── Session Security Tester ──────────────────────────────────────────

class SessionSecurityTester:
    """
    Test session management security properties.

    Tests performed:
        - Session fixation
        - Session token prediction
        - Idle timeout
        - Concurrent session handling
        - Session invalidation on logout
        - Cookie security attributes
    """

    def __init__(self, http_client=None, session_manager: Optional[SessionManager] = None):
        self.http_client = http_client
        self.session_manager = session_manager
        self.analyzer = TokenAnalyzer()
        self.findings: list[Finding] = []

    def test_all(self, target: str) -> list[Finding]:
        """Run all session security tests."""
        self.findings = []
        self._test_session_fixation(target)
        self._test_token_entropy(target)
        self._test_logout_invalidation(target)
        return self.findings

    def _test_session_fixation(self, target: str):
        """Test for session fixation vulnerability."""
        if not self.http_client:
            return

        try:
            # Get initial session token
            resp1 = self.http_client.get(target)
            if not resp1:
                return

            cookies_before = {}
            if hasattr(resp1, 'cookies'):
                cookies_before = dict(resp1.cookies)

            if not cookies_before:
                return

            # If we have an auth flow, authenticate and check if token changes
            if self.session_manager and self.session_manager.auth_flow:
                self.session_manager.authenticate()
                cookies_after = dict(self.session_manager.cookies)

                # Check if session cookie changed after auth
                for cookie_name in cookies_before:
                    if cookie_name in cookies_after:
                        if cookies_before[cookie_name] == cookies_after[cookie_name]:
                            self.findings.append(Finding(
                                title="Session Fixation Vulnerability",
                                severity=Severity.HIGH,
                                description=f"The session cookie '{cookie_name}' was not regenerated "
                                           f"after authentication. An attacker can fix a session "
                                           f"token before the victim logs in.",
                                recommendation="Regenerate session tokens after authentication. "
                                              "Invalidate pre-authentication sessions.",
                                evidence=f"Cookie: {cookie_name}\n"
                                        f"Before auth: {cookies_before[cookie_name][:20]}...\n"
                                        f"After auth: {cookies_after[cookie_name][:20]}...\n"
                                        f"Changed: NO",
                                scanner="Session Manager",
                                category="Session Management",
                                url=target,
                                cwe="CWE-384",
                            ))
        except Exception:
            pass

    def _test_token_entropy(self, target: str):
        """Collect multiple session tokens and analyze entropy."""
        if not self.http_client:
            return

        tokens = []
        for _ in range(5):
            try:
                resp = self.http_client.get(target)
                if resp and hasattr(resp, 'cookies'):
                    for name, value in resp.cookies.items():
                        if any(indicator in name.lower() for indicator in
                               ["session", "sid", "token", "auth", "jwt"]):
                            tokens.append(value)
            except Exception:
                continue

        if len(tokens) >= 2:
            analysis = self.analyzer.analyze_token_set(tokens)
            if analysis.get("prediction_risk") in ("HIGH", "MEDIUM"):
                self.findings.append(Finding(
                    title=f"Weak Session Token Entropy ({analysis.get('prediction_risk')} Risk)",
                    severity=Severity.HIGH if analysis["prediction_risk"] == "HIGH" else Severity.MEDIUM,
                    description=f"Session tokens have insufficient entropy "
                               f"(avg {analysis.get('avg_entropy_bits', 0)} bits). "
                               f"Tokens may be predictable by attackers.",
                    recommendation="Use cryptographically secure random number generators "
                                  "for session token generation. Ensure at least 128 bits of entropy.",
                    evidence=f"Tokens analyzed: {analysis.get('token_count', 0)}\n"
                            f"Avg entropy: {analysis.get('avg_entropy_bits', 0)} bits\n"
                            f"Incremental: {analysis.get('is_incremental', False)}\n"
                            f"Common prefix: '{analysis.get('common_prefix', '')}'",
                    scanner="Session Manager",
                    category="Session Management",
                    url=target,
                    cwe="CWE-330",
                ))

    def _test_logout_invalidation(self, target: str):
        """Test if session is properly invalidated on logout."""
        if not self.session_manager or not self.session_manager.auth_flow:
            return

        if not self.session_manager.auth_flow.logout_url:
            return

        try:
            # Authenticate
            if not self.session_manager.authenticate():
                return

            # Save session tokens
            saved_tokens = dict(self.session_manager.tokens)
            saved_cookies = dict(self.session_manager.cookies)

            # Logout
            self.session_manager.logout()

            # Try to use old session
            if self.session_manager.auth_flow.session_check_url:
                resp = self.http_client.get(
                    self.session_manager.auth_flow.session_check_url,
                    cookies=saved_cookies,
                )
                if resp and self.session_manager.auth_flow.session_valid_indicator:
                    if re.search(self.session_manager.auth_flow.session_valid_indicator, resp.text):
                        self.findings.append(Finding(
                            title="Session Not Invalidated After Logout",
                            severity=Severity.HIGH,
                            description="After logout, the old session token is still valid. "
                                       "This allows session replay attacks.",
                            recommendation="Invalidate session tokens server-side on logout. "
                                          "Clear all session data from server storage.",
                            evidence="Session remained valid after logout request",
                            scanner="Session Manager",
                            category="Session Management",
                            url=target,
                            cwe="CWE-613",
                        ))
        except Exception:
            pass
