"""
Tests for secprobe.core.safe_mode — ScanPolicy, RequestBudget, 
ScopeEnforcer, SafetyGuard, ScanThrottle, SafeMode.
"""

import pytest
import time
from secprobe.core.safe_mode import (
    PolicyPreset,
    ScanPolicy,
    RequestBudget,
    ScopeEnforcer,
    SafetyGuard,
    ScanThrottle,
    SafeMode,
)


# ═══════════════════════════════════════════════════════════════════════
# PolicyPreset
# ═══════════════════════════════════════════════════════════════════════

class TestPolicyPreset:
    def test_all_presets_exist(self):
        assert PolicyPreset.STEALTH is not None
        assert PolicyPreset.SAFE is not None
        assert PolicyPreset.NORMAL is not None
        assert PolicyPreset.AGGRESSIVE is not None
        assert PolicyPreset.CUSTOM is not None

    def test_description(self):
        assert len(PolicyPreset.STEALTH.description) > 0
        assert len(PolicyPreset.SAFE.description) > 0


# ═══════════════════════════════════════════════════════════════════════
# ScanPolicy
# ═══════════════════════════════════════════════════════════════════════

class TestScanPolicy:
    def test_default_policy(self):
        policy = ScanPolicy()
        assert policy.max_requests_per_second == 10
        assert policy.max_payload_size == 10_000
        assert policy.max_redirects == 10

    def test_from_preset_stealth(self):
        policy = ScanPolicy.from_preset(PolicyPreset.STEALTH)
        assert policy.max_requests_per_second <= 1.0
        assert policy.passive_only is True

    def test_from_preset_safe(self):
        policy = ScanPolicy.from_preset(PolicyPreset.SAFE)
        assert policy.allow_destructive is False
        assert policy.allow_time_based is False

    def test_from_preset_normal(self):
        policy = ScanPolicy.from_preset(PolicyPreset.NORMAL)
        assert policy.max_requests_per_second == 10

    def test_from_preset_aggressive(self):
        policy = ScanPolicy.from_preset(PolicyPreset.AGGRESSIVE)
        assert policy.allow_destructive is True

    def test_blocked_paths_default(self):
        policy = ScanPolicy()
        assert len(policy.blocked_paths) > 0

    def test_blocked_extensions_default(self):
        policy = ScanPolicy()
        assert len(policy.blocked_extensions) > 0

    def test_is_scanner_allowed_enabled(self):
        policy = ScanPolicy(enabled_scanners=["sqli", "xss"])
        assert policy.is_scanner_allowed("sqli") is True
        assert policy.is_scanner_allowed("ssti") is False

    def test_is_scanner_allowed_disabled(self):
        policy = ScanPolicy(disabled_scanners=["fuzz"])
        assert policy.is_scanner_allowed("sqli") is True
        assert policy.is_scanner_allowed("fuzz") is False

    def test_is_scanner_allowed_no_filters(self):
        policy = ScanPolicy()
        assert policy.is_scanner_allowed("anything") is True

    def test_to_dict(self):
        policy = ScanPolicy()
        d = policy.to_dict()
        assert isinstance(d, dict)
        assert "max_requests_per_second" in d


# ═══════════════════════════════════════════════════════════════════════
# RequestBudget
# ═══════════════════════════════════════════════════════════════════════

class TestRequestBudget:
    def test_basic_budget(self):
        budget = RequestBudget(max_requests=100)
        assert budget.requests_remaining == 100
        assert budget.is_exhausted is False

    def test_consume(self):
        budget = RequestBudget(max_requests=10)
        assert budget.consume("sqli") is True
        assert budget.requests_made == 1
        assert budget.requests_remaining == 9

    def test_consume_exhausted(self):
        budget = RequestBudget(max_requests=2)
        assert budget.consume("sqli") is True
        assert budget.consume("sqli") is True
        assert budget.consume("sqli") is False
        assert budget.is_exhausted is True

    def test_consume_multiple(self):
        budget = RequestBudget(max_requests=10)
        assert budget.consume("sqli", count=5) is True
        assert budget.requests_made == 5

    def test_scanner_breakdown(self):
        budget = RequestBudget(max_requests=100)
        budget.consume("sqli", count=3)
        budget.consume("xss", count=5)
        breakdown = budget.scanner_breakdown
        assert breakdown["sqli"] == 3
        assert breakdown["xss"] == 5

    def test_unlimited_budget(self):
        budget = RequestBudget(max_requests=0)
        for _ in range(1000):
            assert budget.consume("test") is True

    def test_reset(self):
        budget = RequestBudget(max_requests=10)
        budget.consume("test", count=5)
        budget.reset()
        assert budget.requests_made == 0
        assert budget.requests_remaining == 10

    def test_utilization(self):
        budget = RequestBudget(max_requests=100)
        budget.consume("test", count=25)
        assert budget.utilization == pytest.approx(0.25, abs=0.01)

    def test_summary(self):
        budget = RequestBudget(max_requests=100)
        budget.consume("sqli", count=10)
        summary = budget.summary()
        assert isinstance(summary, dict)


# ═══════════════════════════════════════════════════════════════════════
# ScopeEnforcer
# ═══════════════════════════════════════════════════════════════════════

class TestScopeEnforcer:
    def test_in_scope(self):
        policy = ScanPolicy(allowed_domains=["example.com"])
        enforcer = ScopeEnforcer(policy, "http://example.com")
        allowed, reason = enforcer.is_in_scope("http://example.com/page")
        assert allowed is True

    def test_out_of_scope_domain(self):
        policy = ScanPolicy(allowed_domains=["example.com"])
        enforcer = ScopeEnforcer(policy, "http://example.com")
        allowed, reason = enforcer.is_in_scope("http://evil.com/page")
        assert allowed is False

    def test_blocked_path(self):
        policy = ScanPolicy(blocked_paths=["/admin", "/logout"])
        enforcer = ScopeEnforcer(policy, "http://example.com")
        allowed, reason = enforcer.is_in_scope("http://example.com/admin/dashboard")
        assert allowed is False

    def test_blocked_extension(self):
        policy = ScanPolicy(blocked_extensions=[".jpg", ".png"])
        enforcer = ScopeEnforcer(policy, "http://example.com")
        allowed, reason = enforcer.is_in_scope("http://example.com/image.jpg")
        assert allowed is False

    def test_auto_adds_target_domain(self):
        policy = ScanPolicy()
        enforcer = ScopeEnforcer(policy, "http://target.com")
        allowed, _ = enforcer.is_in_scope("http://target.com/page")
        assert allowed is True

    def test_allowed_count(self):
        policy = ScanPolicy()
        enforcer = ScopeEnforcer(policy, "http://example.com")
        enforcer.is_in_scope("http://example.com/a")
        enforcer.is_in_scope("http://example.com/b")
        assert enforcer.allowed_count == 2

    def test_blocked_count(self):
        policy = ScanPolicy(allowed_domains=["example.com"])
        enforcer = ScopeEnforcer(policy, "http://example.com")
        enforcer.is_in_scope("http://evil.com/x")
        assert enforcer.blocked_count >= 1

    def test_summary(self):
        policy = ScanPolicy()
        enforcer = ScopeEnforcer(policy, "http://example.com")
        enforcer.is_in_scope("http://example.com/a")
        summary = enforcer.summary()
        assert isinstance(summary, dict)


# ═══════════════════════════════════════════════════════════════════════
# SafetyGuard
# ═══════════════════════════════════════════════════════════════════════

class TestSafetyGuard:
    def test_allows_get(self):
        policy = ScanPolicy()
        guard = SafetyGuard(policy)
        allowed, _ = guard.check_method("GET", "http://example.com/page")
        assert allowed is True

    def test_blocks_delete_when_no_destructive(self):
        policy = ScanPolicy(allow_destructive=False)
        guard = SafetyGuard(policy)
        allowed, _ = guard.check_method("DELETE", "http://example.com/resource")
        assert allowed is False

    def test_allows_delete_when_destructive(self):
        policy = ScanPolicy(allow_destructive=True)
        guard = SafetyGuard(policy)
        allowed, _ = guard.check_method("DELETE", "http://example.com/resource")
        assert allowed is True

    def test_blocks_active_scanner_in_passive_mode(self):
        policy = ScanPolicy(passive_only=True)
        guard = SafetyGuard(policy)
        allowed, _ = guard.check_scanner_type("sqli")
        assert allowed is False

    def test_allows_passive_scanner_in_passive_mode(self):
        policy = ScanPolicy(passive_only=True)
        guard = SafetyGuard(policy)
        allowed, _ = guard.check_scanner_type("headers")
        assert allowed is True

    def test_payload_size_check(self):
        policy = ScanPolicy(max_payload_size=100)
        guard = SafetyGuard(policy)
        allowed, _ = guard.check_payload_size("x" * 50)
        assert allowed is True
        allowed, _ = guard.check_payload_size("x" * 200)
        assert allowed is False

    def test_violation_tracking(self):
        policy = ScanPolicy(allow_destructive=False)
        guard = SafetyGuard(policy)
        guard.check_method("DELETE", "http://example.com/x")
        assert guard.violation_count >= 1


# ═══════════════════════════════════════════════════════════════════════
# ScanThrottle
# ═══════════════════════════════════════════════════════════════════════

class TestScanThrottle:
    def _make_throttle(self, rate=10.0):
        policy = ScanPolicy(max_requests_per_second=rate, backoff_on_429=True)
        return ScanThrottle(policy)

    def test_basic_throttle(self):
        throttle = self._make_throttle(10.0)
        assert throttle.current_rate == 10.0
        assert throttle.is_throttled is False

    def test_record_429_slows_down(self):
        throttle = self._make_throttle(10.0)
        initial_rate = throttle.current_rate
        throttle.record_response(429, was_blocked=False)
        assert throttle.current_rate < initial_rate

    def test_record_success_recovers(self):
        throttle = self._make_throttle(10.0)
        # Slow down first
        throttle.record_response(429, was_blocked=False)
        slowed_rate = throttle.current_rate
        # Then send successes to recover
        for _ in range(15):
            throttle.record_response(200, was_blocked=False)
        assert throttle.current_rate >= slowed_rate

    def test_reset(self):
        throttle = self._make_throttle(10.0)
        throttle.record_response(429, was_blocked=False)
        throttle.reset()
        assert throttle.current_rate == 10.0

    def test_summary(self):
        throttle = self._make_throttle(10.0)
        summary = throttle.summary()
        assert isinstance(summary, dict)


# ═══════════════════════════════════════════════════════════════════════
# SafeMode (Unified facade)
# ═══════════════════════════════════════════════════════════════════════

class TestSafeMode:
    def test_from_preset(self):
        sm = SafeMode.from_preset(PolicyPreset.SAFE, "http://example.com")
        assert sm.is_active is True

    def test_can_request_basic(self):
        sm = SafeMode.from_preset(PolicyPreset.NORMAL, "http://example.com")
        allowed, reason = sm.can_request("http://example.com/page")
        assert allowed is True

    def test_can_request_out_of_scope(self):
        policy = ScanPolicy.from_preset(PolicyPreset.SAFE)
        policy.allowed_domains = ["example.com"]
        sm = SafeMode(policy, "http://example.com")
        allowed, reason = sm.can_request("http://evil.com/page")
        assert allowed is False

    def test_can_request_destructive_blocked(self):
        sm = SafeMode.from_preset(PolicyPreset.SAFE, "http://example.com")
        allowed, reason = sm.can_request(
            "http://example.com/api", method="DELETE"
        )
        assert allowed is False

    def test_record_response(self):
        sm = SafeMode.from_preset(PolicyPreset.NORMAL, "http://example.com")
        sm.record_response(200, was_blocked=False)
        sm.record_response(429, was_blocked=False)
        # Should not crash

    def test_summary(self):
        sm = SafeMode.from_preset(PolicyPreset.NORMAL, "http://example.com")
        sm.can_request("http://example.com/page")
        summary = sm.summary()
        assert isinstance(summary, dict)

    def test_stealth_blocks_active_scanners(self):
        sm = SafeMode.from_preset(PolicyPreset.STEALTH, "http://example.com")
        allowed, reason = sm.can_request(
            "http://example.com/page",
            scanner="sqli",
        )
        assert allowed is False

    def test_aggressive_allows_everything(self):
        sm = SafeMode.from_preset(PolicyPreset.AGGRESSIVE, "http://example.com")
        allowed, _ = sm.can_request(
            "http://example.com/api",
            method="DELETE",
            scanner="sqli",
            payload="x" * 50000,
        )
        assert allowed is True
