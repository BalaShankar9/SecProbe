"""
Finding Verification Engine — Confirm findings to eliminate false positives.

This is the #1 thing that separates professional scanners (Burp) from toys.
Every finding goes through a verification pipeline before being reported:

1. **Replay verification**: Re-send the same request — does the vuln reproduce?
2. **Variant verification**: Try a different payload for the same vuln type
3. **Negative verification**: Send a safe/escaped version — does it NOT trigger?
4. **Context verification**: Use html_parser to confirm reflection context
5. **Statistical verification**: For timing-based, run multiple rounds

Confidence escalation:
  - Single match only → TENTATIVE (might be false positive)
  - Replay confirms → FIRM (likely real)
  - Variant + Negative confirm → CONFIRMED (definitely real)

Usage:
    verifier = FindingVerifier(http_client)
    result = verifier.verify_reflection(url, param, payload, original_response)
    if result.confirmed:
        add_finding(confidence=result.confidence)
"""

from __future__ import annotations

import re
import time
import hashlib
import statistics
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, TYPE_CHECKING
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from secprobe.core.logger import get_logger

if TYPE_CHECKING:
    from secprobe.core.http_client import HTTPClient

log = get_logger("verification")


# ═══════════════════════════════════════════════════════════════════════
# Verification Result
# ═══════════════════════════════════════════════════════════════════════

class Confidence(Enum):
    """Finding confidence levels, matching Burp Suite's model."""
    NONE = 0
    TENTATIVE = 1    # Single indicator, could be FP
    FIRM = 2         # Replay confirmed OR multiple indicators
    CONFIRMED = 3    # Variant + negative test pass — real vulnerability


@dataclass
class VerificationResult:
    """Result of a verification attempt."""
    confirmed: bool = False
    confidence: Confidence = Confidence.NONE
    evidence: list[str] = field(default_factory=list)
    replay_success: bool = False
    variant_success: bool = False
    negative_success: bool = False  # True = negative test passed (safe version didn't trigger)
    context_confirmed: bool = False
    rounds_passed: int = 0
    rounds_total: int = 0
    details: dict = field(default_factory=dict)

    def escalate(self):
        """Calculate confidence from verification results."""
        if self.variant_success and self.negative_success:
            self.confidence = Confidence.CONFIRMED
            self.confirmed = True
        elif self.replay_success and (self.variant_success or self.negative_success):
            self.confidence = Confidence.CONFIRMED
            self.confirmed = True
        elif self.replay_success:
            self.confidence = Confidence.FIRM
            self.confirmed = True
        elif self.variant_success or self.context_confirmed:
            self.confidence = Confidence.FIRM
            self.confirmed = True
        else:
            self.confidence = Confidence.TENTATIVE
            self.confirmed = False


# ═══════════════════════════════════════════════════════════════════════
# Payload Variant Generator
# ═══════════════════════════════════════════════════════════════════════

class PayloadVariants:
    """
    Generate variant and negative payloads for verification.

    For each vuln type, provides:
      - variant: Different payload that should also trigger
      - negative: Escaped/safe version that should NOT trigger
    """

    @staticmethod
    def xss_variants(original: str) -> dict:
        """XSS payload variants."""
        return {
            "variants": [
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '"><img src=x onerror=alert(1)>',
                "'-alert(1)-'",
            ],
            "negatives": [
                '&lt;script&gt;alert(1)&lt;/script&gt;',  # HTML-encoded
                '<script>alert(1)</script'.replace('<', ''),  # stripped
                'scriptalert1script',  # tags removed — safe text
            ],
        }

    @staticmethod
    def sqli_variants(original: str) -> dict:
        """SQLi payload variants."""
        return {
            "variants": [
                "' OR '1'='1",
                "1' AND '1'='1'--",
                "' UNION SELECT NULL--",
                "1 OR 1=1",
            ],
            "negatives": [
                "1",                     # Clean integer — should be normal
                "normaltext",            # Safe string
                "test123",               # No SQL metacharacters
            ],
        }

    @staticmethod
    def ssti_variants(original: str) -> dict:
        """SSTI payload variants."""
        return {
            "variants": [
                "{{7*191}}",    # = 1337
                "${7*191}",     # alternate syntax
                "<%=7*191%>",   # ERB
                "#{7*191}",     # Ruby
            ],
            "negatives": [
                "7*191",        # Plain text, no template syntax
                "{{safe}}",     # Nonexistent variable
                "normaltext",
            ],
            "expected_results": {
                "{{7*191}}": "1337",
                "${7*191}": "1337",
                "<%=7*191%>": "1337",
                "#{7*191}": "1337",
            },
        }

    @staticmethod
    def cmdi_variants(original: str) -> dict:
        """Command injection variants."""
        return {
            "variants": [
                ";id",
                "|id",
                "$(id)",
                "`id`",
            ],
            "negatives": [
                "normaltext",
                "12345",
            ],
        }

    @staticmethod
    def lfi_variants(original: str) -> dict:
        """LFI payload variants."""
        return {
            "variants": [
                "../../etc/passwd",
                "....//....//etc/passwd",
                "..\\..\\etc\\passwd",
                "/etc/passwd",
            ],
            "negatives": [
                "nonexistent_file_abc123.txt",
                "index.html",
            ],
        }

    @classmethod
    def get(cls, vuln_type: str, original: str = "") -> dict:
        """Get variants for a vulnerability type."""
        generators = {
            "xss": cls.xss_variants,
            "sqli": cls.sqli_variants,
            "sql": cls.sqli_variants,
            "ssti": cls.ssti_variants,
            "template": cls.ssti_variants,
            "cmdi": cls.cmdi_variants,
            "command": cls.cmdi_variants,
            "lfi": cls.lfi_variants,
            "path": cls.lfi_variants,
        }
        for key, gen in generators.items():
            if key in vuln_type.lower():
                return gen(original)
        return {"variants": [], "negatives": []}


# ═══════════════════════════════════════════════════════════════════════
# Request Helper
# ═══════════════════════════════════════════════════════════════════════

def _inject_param(url: str, param: str, value: str) -> str:
    """Replace a query parameter value in a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode({k: v[0] for k, v in params.items()}, safe="")
    return urlunparse(parsed._replace(query=new_query))


# ═══════════════════════════════════════════════════════════════════════
# Finding Verifier — Core verification engine
# ═══════════════════════════════════════════════════════════════════════

class FindingVerifier:
    """
    Verify findings to eliminate false positives.

    This is modeled after Burp Suite's verification approach:
    1. Replay the exact attack to confirm it's reproducible
    2. Try a variant payload to confirm the vuln class
    3. Try a negative (safe) payload to confirm it doesn't false-positive
    4. For reflections: parse DOM context to confirm exploitability
    5. For timing: run statistical tests with multiple rounds
    """

    def __init__(self, http_client: HTTPClient, max_retries: int = 2):
        self.http_client = http_client
        self.max_retries = max_retries

    # ── Reflection-based verification (XSS, SSTI) ────────────────

    def verify_reflection(self, url: str, param: str, payload: str,
                          detection_fn=None,
                          vuln_type: str = "xss") -> VerificationResult:
        """
        Verify a reflection-based finding (XSS, SSTI).

        Args:
            url: Original URL with the vulnerable parameter
            param: The parameter name
            payload: The payload that triggered
            detection_fn: Callable(response_body) → bool — checks if vuln present
            vuln_type: "xss", "ssti", etc.

        Returns:
            VerificationResult with confidence level
        """
        result = VerificationResult()

        if detection_fn is None:
            detection_fn = lambda body: payload in body

        # Step 1: Replay verification
        try:
            injected_url = _inject_param(url, param, payload)
            resp = self.http_client.get(injected_url)
            if detection_fn(resp.text):
                result.replay_success = True
                result.evidence.append(f"Replay confirmed: payload reflected in response")
        except Exception as e:
            log.debug(f"Replay failed: {e}")

        # Step 2: Variant verification
        variants = PayloadVariants.get(vuln_type, payload)
        for variant in variants.get("variants", [])[:2]:
            try:
                injected_url = _inject_param(url, param, variant)
                resp = self.http_client.get(injected_url)
                expected = variants.get("expected_results", {}).get(variant)
                if expected and expected in resp.text:
                    result.variant_success = True
                    result.evidence.append(f"Variant confirmed: '{variant}' → '{expected}' in response")
                    break
                elif variant in resp.text:
                    result.variant_success = True
                    result.evidence.append(f"Variant confirmed: '{variant}' reflected in response")
                    break
            except Exception:
                continue

        # Step 3: Negative verification
        for neg in variants.get("negatives", [])[:2]:
            try:
                injected_url = _inject_param(url, param, neg)
                resp = self.http_client.get(injected_url)
                # The safe payload should NOT trigger the detection
                if not detection_fn(resp.text):
                    result.negative_success = True
                    result.evidence.append(f"Negative test passed: safe payload did not trigger")
                    break
            except Exception:
                continue

        # Step 4: Context verification (XSS-specific)
        if vuln_type == "xss" and result.replay_success:
            result.context_confirmed = self._verify_xss_context(url, param, payload)
            if result.context_confirmed:
                result.evidence.append("DOM context confirms exploitable reflection")

        result.escalate()
        return result

    def _verify_xss_context(self, url: str, param: str, payload: str) -> bool:
        """Use html_parser to verify XSS reflection is in exploitable context."""
        try:
            from secprobe.core.html_parser import HTMLDocument, ReflectionMapper, ContextType

            # Send a canary to check context
            canary = f"xsscanary{hashlib.md5(f'{url}{param}'.encode()).hexdigest()[:8]}"
            injected_url = _inject_param(url, param, canary)
            resp = self.http_client.get(injected_url)

            doc = HTMLDocument.parse(resp.text)
            reflections = ReflectionMapper.find_reflections(doc, canary)

            for ref in reflections:
                # Check if the context allows script execution
                if ref.context_type.is_executable:
                    return True
                # Unfiltered reflection in these contexts is exploitable
                if ref.context_type in (
                    ContextType.HTML_TEXT,
                    ContextType.HTML_ATTRIBUTE_UNQUOTED,
                    ContextType.SCRIPT_CODE,
                ):
                    return True
            return len(reflections) > 0
        except Exception as e:
            log.debug(f"XSS context verification failed: {e}")
            return False

    # ── Error-based verification (SQLi, XXE) ─────────────────────

    def verify_error_based(self, url: str, param: str, payload: str,
                           error_pattern: str,
                           vuln_type: str = "sqli") -> VerificationResult:
        """
        Verify an error-based finding (SQLi, XXE, CMDi).

        Args:
            url: Target URL
            param: Vulnerable parameter
            payload: Payload that triggered
            error_pattern: Regex pattern that matched the error
            vuln_type: Vulnerability type for variant selection

        Returns:
            VerificationResult with confidence level
        """
        result = VerificationResult()
        pattern = re.compile(error_pattern, re.IGNORECASE)

        # Step 1: Replay
        try:
            injected_url = _inject_param(url, param, payload)
            resp = self.http_client.get(injected_url)
            if pattern.search(resp.text):
                result.replay_success = True
                result.evidence.append("Replay confirmed: error pattern still present")
        except Exception as e:
            log.debug(f"Replay failed: {e}")

        # Step 2: Variant — try different payloads that should trigger SQL errors
        variants = PayloadVariants.get(vuln_type, payload)
        for variant in variants.get("variants", [])[:2]:
            try:
                injected_url = _inject_param(url, param, variant)
                resp = self.http_client.get(injected_url)
                if pattern.search(resp.text):
                    result.variant_success = True
                    result.evidence.append(f"Variant '{variant}' also triggers error")
                    break
            except Exception:
                continue

        # Step 3: Negative — clean value should NOT trigger error
        for neg in variants.get("negatives", [])[:2]:
            try:
                injected_url = _inject_param(url, param, neg)
                resp = self.http_client.get(injected_url)
                if not pattern.search(resp.text):
                    result.negative_success = True
                    result.evidence.append("Negative test: clean input does not trigger error")
                    break
            except Exception:
                continue

        result.escalate()
        return result

    # ── Boolean-based verification (SQLi, XPath, LDAP) ───────────

    def verify_boolean_based(self, url: str, param: str,
                             true_payload: str, false_payload: str,
                             baseline_body: str = "",
                             rounds: int = 3) -> VerificationResult:
        """
        Verify a boolean-based blind finding with multiple confirmation rounds.

        The key insight (from Burp): a single true/false pair might be coincidence.
        We need N rounds with DIFFERENT true/false pairs, all showing the same
        differential response.

        Args:
            url: Target URL
            param: Vulnerable parameter
            true_payload: Payload that evaluates to TRUE
            false_payload: Payload that evaluates to FALSE
            baseline_body: Normal response body for comparison
            rounds: Number of confirmation rounds

        Returns:
            VerificationResult with round statistics
        """
        result = VerificationResult()
        result.rounds_total = rounds

        # Generate different true/false pairs for each round
        true_false_pairs = [
            (true_payload, false_payload),
            ("' OR '1'='1", "' OR '1'='2"),
            ("' OR 2=2--", "' OR 2=3--"),
            ("1 OR 1=1", "1 OR 1=2"),
            ("' OR 'a'='a", "' OR 'a'='b"),
        ]

        for i, (tp, fp) in enumerate(true_false_pairs[:rounds]):
            try:
                true_url = _inject_param(url, param, tp)
                false_url = _inject_param(url, param, fp)

                true_resp = self.http_client.get(true_url)
                false_resp = self.http_client.get(false_url)

                # Must see a differential: true response ≠ false response
                true_hash = hashlib.md5(true_resp.text.encode(errors="replace")).hexdigest()
                false_hash = hashlib.md5(false_resp.text.encode(errors="replace")).hexdigest()

                size_diff = abs(len(true_resp.text) - len(false_resp.text))
                status_diff = true_resp.status_code != false_resp.status_code

                if true_hash != false_hash or status_diff or size_diff > 50:
                    result.rounds_passed += 1
                    result.evidence.append(
                        f"Round {i+1}: differential confirmed "
                        f"(size_diff={size_diff}, status_diff={status_diff})"
                    )
            except Exception as e:
                log.debug(f"Boolean round {i+1} failed: {e}")

        # Confidence based on rounds
        if result.rounds_passed >= rounds:
            result.confirmed = True
            result.confidence = Confidence.CONFIRMED
            result.variant_success = True
        elif result.rounds_passed >= 2:
            result.confirmed = True
            result.confidence = Confidence.FIRM
            result.replay_success = True
        elif result.rounds_passed >= 1:
            result.confidence = Confidence.TENTATIVE

        return result

    # ── Timing-based verification (Blind SQLi, CMDi) ─────────────

    def verify_timing_based(self, url: str, param: str,
                            delay_payload: str, delay_seconds: float = 5.0,
                            rounds: int = 5,
                            baseline_rounds: int = 3) -> VerificationResult:
        """
        Verify a timing-based blind finding with statistical analysis.

        Approach (modeled after Burp):
        1. Establish baseline timing (N requests with clean value)
        2. Send delay payload N times
        3. Use Mann-Whitney U / threshold analysis to confirm
        4. Account for network jitter via multiple rounds

        Args:
            url: Target URL
            param: Vulnerable parameter
            delay_payload: Payload that should cause a time delay
            delay_seconds: Expected delay in seconds
            rounds: Number of delay-payload rounds
            baseline_rounds: Number of baseline timing measurements

        Returns:
            VerificationResult with timing statistics
        """
        result = VerificationResult()
        result.rounds_total = rounds

        # Step 1: Baseline timing
        baseline_times = []
        for _ in range(baseline_rounds):
            try:
                clean_url = _inject_param(url, param, "1")
                start = time.monotonic()
                self.http_client.get(clean_url)
                elapsed = time.monotonic() - start
                baseline_times.append(elapsed)
            except Exception:
                baseline_times.append(0.0)

        if not baseline_times or max(baseline_times) == 0:
            return result

        baseline_mean = statistics.mean(baseline_times)
        baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.5

        # Threshold: baseline + expected delay - small margin
        # The delay payload should consistently be > threshold
        threshold = baseline_mean + (delay_seconds * 0.6)

        result.details["baseline_mean"] = round(baseline_mean, 3)
        result.details["baseline_stdev"] = round(baseline_stdev, 3)
        result.details["threshold"] = round(threshold, 3)

        # Step 2: Delay payload rounds
        delay_times = []
        for i in range(rounds):
            try:
                injected_url = _inject_param(url, param, delay_payload)
                start = time.monotonic()
                self.http_client.get(injected_url)
                elapsed = time.monotonic() - start
                delay_times.append(elapsed)

                if elapsed > threshold:
                    result.rounds_passed += 1
                    result.evidence.append(
                        f"Round {i+1}: {elapsed:.2f}s > threshold {threshold:.2f}s"
                    )
            except Exception as e:
                log.debug(f"Timing round {i+1} failed: {e}")

        result.details["delay_times"] = [round(t, 3) for t in delay_times]

        # Step 3: Statistical confirmation
        if delay_times:
            delay_mean = statistics.mean(delay_times)
            result.details["delay_mean"] = round(delay_mean, 3)

            # Z-score: how many stdevs above baseline mean?
            if baseline_stdev > 0:
                z_score = (delay_mean - baseline_mean) / baseline_stdev
                result.details["z_score"] = round(z_score, 2)
            else:
                z_score = float('inf') if delay_mean > baseline_mean + 1 else 0

            # Confidence from statistics
            if result.rounds_passed >= rounds and z_score > 3:
                result.confirmed = True
                result.confidence = Confidence.CONFIRMED
                result.variant_success = True
            elif result.rounds_passed >= rounds * 0.6 and z_score > 2:
                result.confirmed = True
                result.confidence = Confidence.FIRM
                result.replay_success = True
            elif result.rounds_passed >= 1:
                result.confidence = Confidence.TENTATIVE

        return result

    # ── Generic verification dispatcher ──────────────────────────

    def verify(self, url: str, param: str, payload: str,
               vuln_type: str, **kwargs) -> VerificationResult:
        """
        Auto-dispatch to the right verification method.

        Args:
            url: Target URL
            param: Vulnerable parameter
            payload: Payload that triggered
            vuln_type: One of "xss", "sqli_error", "sqli_boolean",
                       "sqli_timing", "ssti", "cmdi", "lfi", "xxe"
            **kwargs: Extra args passed to the specific verifier
        """
        vtype = vuln_type.lower()

        if "xss" in vtype or "ssti" in vtype:
            return self.verify_reflection(
                url, param, payload,
                vuln_type=vtype.split("_")[0] if "_" in vtype else vtype,
                **kwargs,
            )
        elif "error" in vtype:
            pattern = kwargs.pop("error_pattern", r"SQL syntax|mysql_|ORA-\d+|pg_query")
            return self.verify_error_based(url, param, payload, pattern, **kwargs)
        elif "boolean" in vtype or "blind" in vtype:
            false_payload = kwargs.pop("false_payload", "' AND '1'='2")
            return self.verify_boolean_based(url, param, payload, false_payload, **kwargs)
        elif "timing" in vtype or "time" in vtype:
            delay = kwargs.pop("delay_seconds", 5.0)
            return self.verify_timing_based(url, param, payload, delay, **kwargs)
        else:
            # Default: reflection check
            return self.verify_reflection(url, param, payload, vuln_type=vtype)


# ═══════════════════════════════════════════════════════════════════════
# Response Comparison Utilities
# ═══════════════════════════════════════════════════════════════════════

class ResponseComparer:
    """
    Compare responses for differential analysis.

    Used by boolean-based and blind detection to determine
    if two responses are meaningfully different.
    """

    # Patterns typically dynamic (tokens, timestamps, etc.)
    DYNAMIC_PATTERNS = [
        re.compile(r'csrf[_-]?token["\s=:]+["\']?[\w+/=-]+', re.I),
        re.compile(r'nonce["\s=:]+["\']?[\w+/=-]+', re.I),
        re.compile(r'\b\d{10,13}\b'),  # Unix timestamps
        re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    ]

    @classmethod
    def strip_dynamic(cls, text: str) -> str:
        """Remove known dynamic content for stable comparison."""
        result = text
        for pattern in cls.DYNAMIC_PATTERNS:
            result = pattern.sub("", result)
        return result

    @classmethod
    def similarity(cls, a: str, b: str) -> float:
        """Quick similarity ratio (0.0 to 1.0) using size-based heuristic."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0

        a_clean = cls.strip_dynamic(a)
        b_clean = cls.strip_dynamic(b)

        # Hash comparison for exact match
        if hashlib.md5(a_clean.encode(errors="replace")).hexdigest() == \
           hashlib.md5(b_clean.encode(errors="replace")).hexdigest():
            return 1.0

        # Size-based rough similarity
        max_len = max(len(a_clean), len(b_clean))
        if max_len == 0:
            return 1.0
        diff = abs(len(a_clean) - len(b_clean))
        size_sim = 1.0 - (diff / max_len)

        # Line-based overlap for more accuracy
        a_lines = set(a_clean.splitlines())
        b_lines = set(b_clean.splitlines())
        if a_lines or b_lines:
            common = len(a_lines & b_lines)
            total = len(a_lines | b_lines)
            line_sim = common / total if total > 0 else 1.0
        else:
            line_sim = size_sim

        return (size_sim + line_sim) / 2.0

    @classmethod
    def is_different(cls, a: str, b: str, threshold: float = 0.85) -> bool:
        """Are two responses meaningfully different?"""
        return cls.similarity(a, b) < threshold
