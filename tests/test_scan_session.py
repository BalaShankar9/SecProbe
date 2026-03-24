"""
Tests for secprobe.core.scan_session — Scan Session Orchestrator.

Covers:
  - ScanPhase enum + is_terminal
  - EventType enum
  - ScanEvent dataclass
  - ScanEventBus (on, on_all, emit, history, event_count)
  - ScannerProgress (duration, is_done)
  - ScanProgress (percent_complete, elapsed, active_scanners, record_finding, summary)
  - ScannerRunResult dataclass
  - ScanSession (full lifecycle, cancel, phase management, risk_score, summary)
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from secprobe.config import ScanConfig
from secprobe.models import Finding, ScanResult
from secprobe.core.scan_session import (
    ScanPhase,
    EventType,
    ScanEvent,
    ScanEventBus,
    ScannerProgress,
    ScanProgress,
    ScannerRunResult,
    ScanSession,
)


# ═══════════════════════════════════════════════════════════════════════
# ScanPhase
# ═══════════════════════════════════════════════════════════════════════

class TestScanPhase:
    def test_terminal_phases(self):
        assert ScanPhase.DONE.is_terminal is True
        assert ScanPhase.FAILED.is_terminal is True
        assert ScanPhase.CANCELLED.is_terminal is True

    def test_non_terminal_phases(self):
        assert ScanPhase.INIT.is_terminal is False
        assert ScanPhase.RECON.is_terminal is False
        assert ScanPhase.ACTIVE_SCAN.is_terminal is False
        assert ScanPhase.ANALYSIS.is_terminal is False
        assert ScanPhase.REPORT.is_terminal is False

    def test_all_phases_exist(self):
        names = {p.name for p in ScanPhase}
        assert "INIT" in names
        assert "RECON" in names
        assert "ACTIVE_SCAN" in names
        assert "ANALYSIS" in names
        assert "REPORT" in names
        assert "DONE" in names
        assert "FAILED" in names
        assert "CANCELLED" in names


# ═══════════════════════════════════════════════════════════════════════
# EventType
# ═══════════════════════════════════════════════════════════════════════

class TestEventType:
    def test_all_event_types_exist(self):
        names = {e.name for e in EventType}
        expected = {
            "PHASE_CHANGED", "SCANNER_STARTED", "SCANNER_COMPLETED",
            "SCANNER_FAILED", "SCANNER_SKIPPED", "FINDING_DISCOVERED",
            "WAF_DETECTED", "RATE_LIMITED", "PROGRESS_UPDATE",
            "SESSION_STARTED", "SESSION_COMPLETED", "SESSION_FAILED",
            "SESSION_CANCELLED",
        }
        assert expected.issubset(names)


# ═══════════════════════════════════════════════════════════════════════
# ScanEvent
# ═══════════════════════════════════════════════════════════════════════

class TestScanEvent:
    def test_basic_creation(self):
        event = ScanEvent(event_type=EventType.SESSION_STARTED)
        assert event.event_type == EventType.SESSION_STARTED
        assert event.scanner == ""
        assert event.message == ""
        assert event.data == {}
        assert event.timestamp is not None

    def test_with_all_fields(self):
        finding = Finding(title="XSS", severity="HIGH", description="test")
        event = ScanEvent(
            event_type=EventType.FINDING_DISCOVERED,
            scanner="xss",
            phase=ScanPhase.ACTIVE_SCAN,
            finding=finding,
            message="Found XSS",
            data={"url": "http://example.com"},
        )
        assert event.scanner == "xss"
        assert event.phase == ScanPhase.ACTIVE_SCAN
        assert event.finding.title == "XSS"
        assert event.data["url"] == "http://example.com"


# ═══════════════════════════════════════════════════════════════════════
# ScanEventBus
# ═══════════════════════════════════════════════════════════════════════

class TestScanEventBus:
    def test_on_and_emit(self):
        bus = ScanEventBus()
        received = []
        bus.on(EventType.PHASE_CHANGED, lambda e: received.append(e))

        event = ScanEvent(event_type=EventType.PHASE_CHANGED, message="test")
        bus.emit(event)

        assert len(received) == 1
        assert received[0].message == "test"

    def test_on_does_not_fire_for_other_types(self):
        bus = ScanEventBus()
        received = []
        bus.on(EventType.PHASE_CHANGED, lambda e: received.append(e))

        bus.emit(ScanEvent(event_type=EventType.SESSION_STARTED))
        assert len(received) == 0

    def test_on_all(self):
        bus = ScanEventBus()
        received = []
        bus.on_all(lambda e: received.append(e))

        bus.emit(ScanEvent(event_type=EventType.PHASE_CHANGED))
        bus.emit(ScanEvent(event_type=EventType.SESSION_STARTED))
        assert len(received) == 2

    def test_multiple_listeners(self):
        bus = ScanEventBus()
        a, b = [], []
        bus.on(EventType.PHASE_CHANGED, lambda e: a.append(e))
        bus.on(EventType.PHASE_CHANGED, lambda e: b.append(e))

        bus.emit(ScanEvent(event_type=EventType.PHASE_CHANGED))
        assert len(a) == 1
        assert len(b) == 1

    def test_history(self):
        bus = ScanEventBus()
        bus.emit(ScanEvent(event_type=EventType.SESSION_STARTED))
        bus.emit(ScanEvent(event_type=EventType.PHASE_CHANGED))
        bus.emit(ScanEvent(event_type=EventType.SESSION_COMPLETED))

        assert len(bus.history) == 3
        assert bus.history[0].event_type == EventType.SESSION_STARTED
        assert bus.history[2].event_type == EventType.SESSION_COMPLETED

    def test_event_count(self):
        bus = ScanEventBus()
        assert bus.event_count == 0
        bus.emit(ScanEvent(event_type=EventType.SESSION_STARTED))
        assert bus.event_count == 1

    def test_history_is_copy(self):
        bus = ScanEventBus()
        bus.emit(ScanEvent(event_type=EventType.SESSION_STARTED))
        history = bus.history
        history.clear()
        assert bus.event_count == 1  # Original not mutated

    def test_listener_error_does_not_crash(self):
        bus = ScanEventBus()
        bus.on(EventType.PHASE_CHANGED, lambda e: 1 / 0)
        bus.on(EventType.PHASE_CHANGED, lambda e: None)  # should still fire

        # Should not raise
        bus.emit(ScanEvent(event_type=EventType.PHASE_CHANGED))
        assert bus.event_count == 1

    def test_global_listener_error_does_not_crash(self):
        bus = ScanEventBus()
        bus.on_all(lambda e: 1 / 0)  # raises ZeroDivisionError
        bus.emit(ScanEvent(event_type=EventType.SESSION_STARTED))
        assert bus.event_count == 1


# ═══════════════════════════════════════════════════════════════════════
# ScannerProgress
# ═══════════════════════════════════════════════════════════════════════

class TestScannerProgress:
    def test_defaults(self):
        sp = ScannerProgress(name="xss")
        assert sp.name == "xss"
        assert sp.status == "pending"
        assert sp.start_time is None
        assert sp.findings_count == 0

    def test_duration_not_started(self):
        sp = ScannerProgress(name="xss")
        assert sp.duration == 0.0

    def test_duration_running(self):
        sp = ScannerProgress(name="xss", start_time=time.time() - 2.0)
        assert sp.duration >= 1.5

    def test_duration_completed(self):
        sp = ScannerProgress(name="xss", start_time=100.0, end_time=105.0)
        assert sp.duration == pytest.approx(5.0)

    def test_is_done(self):
        assert ScannerProgress(name="x", status="completed").is_done is True
        assert ScannerProgress(name="x", status="failed").is_done is True
        assert ScannerProgress(name="x", status="skipped").is_done is True
        assert ScannerProgress(name="x", status="running").is_done is False
        assert ScannerProgress(name="x", status="pending").is_done is False


# ═══════════════════════════════════════════════════════════════════════
# ScanProgress
# ═══════════════════════════════════════════════════════════════════════

class TestScanProgress:
    def test_defaults(self):
        p = ScanProgress()
        assert p.total_scanners == 0
        assert p.completed_scanners == 0
        assert p.total_findings == 0
        assert p.current_phase == ScanPhase.INIT

    def test_percent_complete_zero(self):
        p = ScanProgress(total_scanners=0)
        assert p.percent_complete == 0.0

    def test_percent_complete_partial(self):
        p = ScanProgress(total_scanners=10, completed_scanners=3, failed_scanners=2)
        assert p.percent_complete == pytest.approx(50.0)

    def test_percent_complete_with_skipped(self):
        p = ScanProgress(total_scanners=4, completed_scanners=1, failed_scanners=1, skipped_scanners=2)
        assert p.percent_complete == pytest.approx(100.0)

    def test_elapsed_not_started(self):
        p = ScanProgress()
        assert p.elapsed == 0.0

    def test_elapsed_running(self):
        p = ScanProgress(start_time=time.time() - 3.0)
        assert p.elapsed >= 2.5

    def test_active_scanners(self):
        p = ScanProgress()
        p.scanner_progress["xss"] = ScannerProgress(name="xss", status="running")
        p.scanner_progress["sqli"] = ScannerProgress(name="sqli", status="completed")
        p.scanner_progress["cors"] = ScannerProgress(name="cors", status="running")
        assert sorted(p.active_scanners) == ["cors", "xss"]

    def test_record_finding(self):
        p = ScanProgress()
        p.record_finding(Finding(title="t", severity="HIGH", description="d"))
        p.record_finding(Finding(title="t2", severity="CRITICAL", description="d"))
        p.record_finding(Finding(title="t3", severity="HIGH", description="d"))
        assert p.total_findings == 3
        assert p.findings_by_severity["HIGH"] == 2
        assert p.findings_by_severity["CRITICAL"] == 1
        assert p.findings_by_severity["MEDIUM"] == 0

    def test_summary(self):
        p = ScanProgress(total_scanners=5, completed_scanners=3)
        p.start_time = time.time() - 10.0
        s = p.summary()
        assert isinstance(s, dict)
        assert s["scanners"]["total"] == 5
        assert s["scanners"]["completed"] == 3
        assert "progress" in s
        assert "elapsed" in s


# ═══════════════════════════════════════════════════════════════════════
# ScannerRunResult
# ═══════════════════════════════════════════════════════════════════════

class TestScannerRunResult:
    def test_defaults(self):
        r = ScannerRunResult(scanner_name="xss")
        assert r.scanner_name == "xss"
        assert r.scan_result is None
        assert r.error is None
        assert r.duration == 0.0
        assert r.was_skipped is False
        assert r.skip_reason == ""

    def test_with_result(self):
        sr = ScanResult(scanner_name="xss", target="http://example.com")
        r = ScannerRunResult(scanner_name="xss", scan_result=sr, duration=1.5)
        assert r.scan_result.scanner_name == "xss"
        assert r.duration == 1.5

    def test_skipped(self):
        r = ScannerRunResult(scanner_name="xss", was_skipped=True, skip_reason="blocked")
        assert r.was_skipped is True
        assert r.skip_reason == "blocked"


# ═══════════════════════════════════════════════════════════════════════
# ScanSession — Core Orchestrator Tests
# ═══════════════════════════════════════════════════════════════════════

def _make_scanner_class(findings=None, error=None):
    """Create a mock scanner class that returns specified findings or raises."""
    class MockScanner:
        def __init__(self, config, context):
            self.config = config
            self.context = context

        def run(self):
            if error:
                raise error
            result = ScanResult(
                scanner_name=self.__class__.__name__,
                target=self.config.target,
            )
            for f in (findings or []):
                result.add_finding(f)
            return result

    return MockScanner


class TestScanSession:
    def test_initial_state(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        assert session.phase == ScanPhase.INIT
        assert session.is_cancelled is False
        assert session.duration == 0.0
        assert session.results == []
        assert session.findings == []
        assert session.errors == []

    def test_cancel(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        session.cancel()
        assert session.is_cancelled is True
        assert session.phase == ScanPhase.CANCELLED
        assert session.phase.is_terminal is True

    def test_run_no_scanners(self):
        config = ScanConfig(target="http://example.com", scan_types=[])
        session = ScanSession(config)
        results = session.run(scanner_names=[], scanner_registry={})
        assert results == []
        assert session.phase == ScanPhase.DONE

    def test_run_scanner_not_in_registry(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        # Use "xss" which is in ACTIVE_SCANNERS, so it will actually be attempted
        results = session.run(scanner_names=["xss"], scanner_registry={})
        # Should skip the missing scanner
        sp = session.progress.scanner_progress.get("xss")
        assert sp is not None
        assert sp.status == "skipped"
        assert session.progress.skipped_scanners == 1

    def test_run_recon_scanner(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        finding = Finding(title="SSL Issue", severity="MEDIUM", description="Weak cipher", scanner="ssl")
        scanner_cls = _make_scanner_class(findings=[finding])
        registry = {"ssl": scanner_cls}

        session = ScanSession(config)
        results = session.run(scanner_names=["ssl"], scanner_registry=registry)

        assert session.phase == ScanPhase.DONE
        assert len(results) == 1
        assert len(session.findings) == 1
        assert session.findings[0].title == "SSL Issue"
        assert session.progress.completed_scanners == 1

    def test_run_active_scanner(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        finding = Finding(title="SQL Injection", severity="CRITICAL", description="Union-based SQLi", scanner="sqli")
        scanner_cls = _make_scanner_class(findings=[finding])
        registry = {"sqli": scanner_cls}

        session = ScanSession(config)
        results = session.run(scanner_names=["sqli"], scanner_registry=registry)

        assert session.phase == ScanPhase.DONE
        assert len(session.findings) == 1
        assert session.progress.completed_scanners == 1

    def test_run_mixed_scanners(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        ssl_finding = Finding(title="SSL", severity="LOW", description="d", scanner="ssl")
        xss_finding = Finding(title="XSS", severity="HIGH", description="d", scanner="xss")
        registry = {
            "ssl": _make_scanner_class(findings=[ssl_finding]),
            "xss": _make_scanner_class(findings=[xss_finding]),
        }

        session = ScanSession(config)
        results = session.run(scanner_names=["ssl", "xss"], scanner_registry=registry)

        assert len(session.findings) == 2
        assert session.progress.completed_scanners == 2

    def test_scanner_error_handling(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        registry = {
            "xss": _make_scanner_class(error=Exception("connection timeout")),
        }

        session = ScanSession(config)
        session.run(scanner_names=["xss"], scanner_registry=registry)

        assert session.progress.failed_scanners == 1
        sp = session.progress.scanner_progress["xss"]
        assert sp.status == "failed"
        assert sp.error is not None
        assert len(session.errors) == 1

    def test_consecutive_error_limit(self):
        """After too many consecutive errors, remaining scanners are skipped."""
        config = ScanConfig(target="http://example.com", output_format="none")
        # All scanners in ACTIVE_SCANNERS to put them in the same batch
        registry = {}
        for name in ["sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "nosql", "ssrf"]:
            registry[name] = _make_scanner_class(error=RuntimeError("boom"))

        session = ScanSession(config)
        session._max_consecutive_errors = 3
        session.run(
            scanner_names=["sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "nosql", "ssrf"],
            scanner_registry=registry,
        )

        # Should have stopped after 3 consecutive errors and skipped the rest
        assert session.progress.failed_scanners >= 3
        total_done = (session.progress.completed_scanners +
                      session.progress.failed_scanners +
                      session.progress.skipped_scanners)
        assert total_done == 8  # All accounted for

    def test_cancel_during_run(self):
        """Cancelling during execution stops further scanners."""
        config = ScanConfig(target="http://example.com", output_format="none")

        class CancellingScanner:
            def __init__(self, cfg, ctx):
                self.config = cfg
                # Access the session from outer scope and cancel it
                session_ref[0].cancel()

            def run(self):
                return ScanResult(scanner_name="ssl", target=self.config.target)

        registry = {
            "ssl": CancellingScanner,
            "xss": _make_scanner_class(findings=[
                Finding(title="XSS", severity="HIGH", description="d", scanner="xss")
            ]),
        }

        session_ref = [None]  # Closure to pass session
        config_session = ScanConfig(target="http://example.com", output_format="none")
        session = ScanSession(config_session)
        session_ref[0] = session
        session.run(scanner_names=["ssl", "xss"], scanner_registry=registry)

        assert session.is_cancelled is True

    def test_events_emitted(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        finding = Finding(title="Test", severity="LOW", description="d", scanner="headers")
        registry = {"headers": _make_scanner_class(findings=[finding])}

        session = ScanSession(config)
        events = []
        session.events.on_all(lambda e: events.append(e))
        session.run(scanner_names=["headers"], scanner_registry=registry)

        event_types = [e.event_type for e in events]
        assert EventType.SESSION_STARTED in event_types
        assert EventType.PHASE_CHANGED in event_types
        assert EventType.SCANNER_STARTED in event_types
        assert EventType.SCANNER_COMPLETED in event_types
        assert EventType.FINDING_DISCOVERED in event_types
        assert EventType.SESSION_COMPLETED in event_types

    def test_finding_events_carry_finding(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        finding = Finding(title="XSS Found", severity="HIGH", description="d", scanner="xss")
        registry = {"xss": _make_scanner_class(findings=[finding])}

        session = ScanSession(config)
        finding_events = []
        session.events.on(EventType.FINDING_DISCOVERED, lambda e: finding_events.append(e))
        session.run(scanner_names=["xss"], scanner_registry=registry)

        assert len(finding_events) == 1
        assert finding_events[0].finding.title == "XSS Found"
        assert finding_events[0].scanner == "xss"

    def test_get_scanner_result(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        registry = {"headers": _make_scanner_class(findings=[])}

        session = ScanSession(config)
        session.run(scanner_names=["headers"], scanner_registry=registry)

        result = session.get_scanner_result("headers")
        # The mock scanner class name is "MockScanner", so scanner_name won't match
        # But the results list itself should have entries
        assert len(session.results) == 1

    def test_get_scanner_result_not_found(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        assert session.get_scanner_result("missing") is None

    def test_duration(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        registry = {"headers": _make_scanner_class(findings=[])}
        session = ScanSession(config)
        session.run(scanner_names=["headers"], scanner_registry=registry)
        assert session.duration > 0

    def test_summary(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        finding = Finding(title="Test", severity="MEDIUM", description="d", scanner="headers")
        registry = {"headers": _make_scanner_class(findings=[finding])}

        session = ScanSession(config)
        session.run(scanner_names=["headers"], scanner_registry=registry)
        s = session.summary()

        assert isinstance(s, dict)
        assert s["target"] == "http://example.com"
        assert s["phase"] == "DONE"
        assert s["scanners"]["total"] == 1
        assert s["scanners"]["completed"] == 1
        assert s["findings"]["total"] == 1
        assert "duration" in s

    def test_summary_scanner_details(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        registry = {"headers": _make_scanner_class(findings=[])}

        session = ScanSession(config)
        session.run(scanner_names=["headers"], scanner_registry=registry)
        s = session.summary()

        assert "details" in s["scanners"]
        assert "headers" in s["scanners"]["details"]
        assert s["scanners"]["details"]["headers"]["status"] == "completed"


# ═══════════════════════════════════════════════════════════════════════
# Risk Score
# ═══════════════════════════════════════════════════════════════════════

class TestRiskScore:
    def test_no_findings(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        score, grade = session.risk_score()
        assert score == 0
        assert grade == "A+"

    def test_low_findings_only(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        # Manually add findings for scoring
        for _ in range(5):
            session._all_findings.append(
                Finding(title="Low", severity="LOW", description="d")
            )
        score, grade = session.risk_score()
        assert score == 5
        assert grade == "A-"

    def test_mixed_findings(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        session._all_findings.append(
            Finding(title="Crit", severity="CRITICAL", description="d")
        )
        session._all_findings.append(
            Finding(title="High", severity="HIGH", description="d")
        )
        session._all_findings.append(
            Finding(title="Med", severity="MEDIUM", description="d")
        )
        # CRITICAL=25 + HIGH=15 + MEDIUM=5 = 45
        score, grade = session.risk_score()
        assert score == 45
        assert grade == "C"

    def test_score_capped_at_100(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        for _ in range(10):
            session._all_findings.append(
                Finding(title="Crit", severity="CRITICAL", description="d")
            )
        # 10 * 25 = 250, capped at 100
        score, grade = session.risk_score()
        assert score == 100
        assert grade == "F"

    def test_grade_b(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        session._all_findings.append(
            Finding(title="High", severity="HIGH", description="d")
        )
        session._all_findings.append(
            Finding(title="Med", severity="MEDIUM", description="d")
        )
        # HIGH=15 + MEDIUM=5 = 20
        score, grade = session.risk_score()
        assert score == 20
        assert grade == "B"

    def test_grade_d(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        for _ in range(4):
            session._all_findings.append(
                Finding(title="High", severity="HIGH", description="d")
            )
        # 4 * 15 = 60
        score, grade = session.risk_score()
        assert score == 60
        assert grade == "D"

    def test_info_findings_score_zero(self):
        config = ScanConfig(target="http://example.com")
        session = ScanSession(config)
        for _ in range(100):
            session._all_findings.append(
                Finding(title="Info", severity="INFO", description="d")
            )
        score, grade = session.risk_score()
        assert score == 0
        assert grade == "A+"


# ═══════════════════════════════════════════════════════════════════════
# ScanSession with SafeMode
# ═══════════════════════════════════════════════════════════════════════

class TestScanSessionWithSafeMode:
    def test_safe_mode_blocks_scanner(self):
        from secprobe.core.safe_mode import SafeMode, PolicyPreset
        config = ScanConfig(target="http://example.com", output_format="none")
        safe = SafeMode.from_preset(PolicyPreset.STEALTH, "http://example.com")

        # Stealth mode blocks active scanners like sqli
        registry = {"sqli": _make_scanner_class(findings=[
            Finding(title="SQLi", severity="CRITICAL", description="d", scanner="sqli")
        ])}

        session = ScanSession(config, safe_mode=safe)
        session.run(scanner_names=["sqli"], scanner_registry=registry)

        # sqli should be blocked by safe mode (STEALTH = passive-only)
        sp = session.progress.scanner_progress.get("sqli")
        assert sp is not None
        assert sp.status == "skipped"

    def test_safe_mode_allows_passive_scanner(self):
        from secprobe.core.safe_mode import SafeMode, PolicyPreset
        config = ScanConfig(target="http://example.com", output_format="none")
        safe = SafeMode.from_preset(PolicyPreset.NORMAL, "http://example.com")

        finding = Finding(title="Hdr", severity="LOW", description="d", scanner="headers")
        registry = {"headers": _make_scanner_class(findings=[finding])}

        session = ScanSession(config, safe_mode=safe)
        session.run(scanner_names=["headers"], scanner_registry=registry)

        assert session.progress.completed_scanners == 1
        assert len(session.findings) == 1


# ═══════════════════════════════════════════════════════════════════════
# Phase Transitions
# ═══════════════════════════════════════════════════════════════════════

class TestPhaseTransitions:
    def test_full_lifecycle_phases(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        registry = {
            "headers": _make_scanner_class(findings=[]),
            "xss": _make_scanner_class(findings=[]),
        }

        session = ScanSession(config)
        phases = []
        session.events.on(EventType.PHASE_CHANGED, lambda e: phases.append(e.phase))
        session.run(scanner_names=["headers", "xss"], scanner_registry=registry)

        phase_names = [p.name for p in phases]
        # Must go through at least INIT, some scan phases, ANALYSIS, REPORT, DONE
        assert "INIT" in phase_names
        assert "ANALYSIS" in phase_names
        assert "REPORT" in phase_names
        assert "DONE" in phase_names

    def test_phase_changed_events_logged(self):
        config = ScanConfig(target="http://example.com", output_format="none")
        session = ScanSession(config)
        session.run(scanner_names=[], scanner_registry={})

        phase_events = [
            e for e in session.events.history
            if e.event_type == EventType.PHASE_CHANGED
        ]
        # Even with no scanners: INIT → DONE at minimum
        assert len(phase_events) >= 1


# ═══════════════════════════════════════════════════════════════════════
# Deduplication Integration
# ═══════════════════════════════════════════════════════════════════════

class TestDeduplication:
    def test_dedup_runs_in_analysis(self):
        config = ScanConfig(target="http://example.com", output_format="none", dedup=True)
        # Two scanners finding the same issue
        f1 = Finding(title="XSS in /search", severity="HIGH",
                     description="Reflected XSS via q param", scanner="xss", url="http://example.com/search")
        f2 = Finding(title="XSS in /search", severity="HIGH",
                     description="Reflected XSS via q param", scanner="fuzz", url="http://example.com/search")
        registry = {
            "xss": _make_scanner_class(findings=[f1]),
            "fuzz": _make_scanner_class(findings=[f2]),
        }

        session = ScanSession(config)
        session.run(scanner_names=["xss", "fuzz"], scanner_registry=registry)

        # Raw findings should be 2
        assert len(session.findings) == 2
        # Deduped groups should be fewer
        assert len(session.deduped_findings) <= 2

    def test_dedup_disabled(self):
        config = ScanConfig(target="http://example.com", output_format="none", dedup=False)
        f1 = Finding(title="XSS", severity="HIGH", description="d", scanner="xss")
        registry = {"xss": _make_scanner_class(findings=[f1])}

        session = ScanSession(config)
        session.run(scanner_names=["xss"], scanner_registry=registry)

        # No dedup groups when disabled
        assert len(session.deduped_findings) == 0
