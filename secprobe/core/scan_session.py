"""
Scan Session Orchestrator — Full lifecycle management for a security scan.

This module manages the entire scan lifecycle from initialization through
reporting, handling:

1. ScanPhase          — Enum of scan lifecycle phases
2. ScanProgress       — Real-time progress tracking per scanner
3. ScanEvent          — Typed events for hooks and logging
4. ScanEventBus       — Pub/sub event distribution
5. ScanSession        — The main orchestrator

Scan phases:
  INIT → RECON → ACTIVE_SCAN → ANALYSIS → REPORT → DONE

Architecture:
  ScanSession ties together ScanConfig, ScanContext, SafeMode,
  FindingDeduplicator, and ReportGenerator into a single coordinated run.
  Each scanner runs in its phase, findings are aggregated and deduped,
  and a final report is produced.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Callable, Optional, Any

from secprobe.config import ScanConfig
from secprobe.models import Finding, ScanResult
from secprobe.analysis.dedup import FindingDeduplicator, FindingGroup
from secprobe.core.exceptions import (
    SecProbeError,
    ScannerError,
    ScanTimeoutError,
    TargetUnreachableError,
    WAFBlockedError,
)
from secprobe.core.logger import get_logger

log = get_logger("scan_session")


# ═══════════════════════════════════════════════════════════════════════
# Scan Phase
# ═══════════════════════════════════════════════════════════════════════

class ScanPhase(Enum):
    """Lifecycle phases of a scan session."""
    INIT = auto()
    RECON = auto()
    ACTIVE_SCAN = auto()
    ANALYSIS = auto()
    REPORT = auto()
    DONE = auto()
    FAILED = auto()
    CANCELLED = auto()

    @property
    def is_terminal(self) -> bool:
        return self in (ScanPhase.DONE, ScanPhase.FAILED, ScanPhase.CANCELLED)


# ═══════════════════════════════════════════════════════════════════════
# Scan Events — Typed event system for hooks/logging
# ═══════════════════════════════════════════════════════════════════════

class EventType(Enum):
    """Types of scan events."""
    PHASE_CHANGED = auto()
    SCANNER_STARTED = auto()
    SCANNER_COMPLETED = auto()
    SCANNER_FAILED = auto()
    SCANNER_SKIPPED = auto()
    FINDING_DISCOVERED = auto()
    WAF_DETECTED = auto()
    RATE_LIMITED = auto()
    PROGRESS_UPDATE = auto()
    SESSION_STARTED = auto()
    SESSION_COMPLETED = auto()
    SESSION_FAILED = auto()
    SESSION_CANCELLED = auto()


@dataclass
class ScanEvent:
    """A typed event emitted during scanning."""
    event_type: EventType
    timestamp: datetime = field(default_factory=datetime.now)
    scanner: str = ""
    phase: Optional[ScanPhase] = None
    finding: Optional[Finding] = None
    message: str = ""
    data: dict = field(default_factory=dict)


class ScanEventBus:
    """Simple pub/sub event distribution."""

    def __init__(self):
        self._listeners: dict[EventType, list[Callable[[ScanEvent], None]]] = {}
        self._global_listeners: list[Callable[[ScanEvent], None]] = []
        self._history: list[ScanEvent] = []

    def on(self, event_type: EventType, callback: Callable[[ScanEvent], None]):
        """Subscribe to a specific event type."""
        self._listeners.setdefault(event_type, []).append(callback)

    def on_all(self, callback: Callable[[ScanEvent], None]):
        """Subscribe to all events."""
        self._global_listeners.append(callback)

    def emit(self, event: ScanEvent):
        """Emit an event to all interested listeners."""
        self._history.append(event)

        for cb in self._global_listeners:
            try:
                cb(event)
            except Exception as e:
                log.warning(f"Event listener error: {e}")

        for cb in self._listeners.get(event.event_type, []):
            try:
                cb(event)
            except Exception as e:
                log.warning(f"Event listener error: {e}")

    @property
    def history(self) -> list[ScanEvent]:
        return list(self._history)

    @property
    def event_count(self) -> int:
        return len(self._history)


# ═══════════════════════════════════════════════════════════════════════
# Progress Tracking — Real-time scan progress
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ScannerProgress:
    """Progress state of a single scanner."""
    name: str
    status: str = "pending"   # pending | running | completed | failed | skipped
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    findings_count: int = 0
    error: Optional[str] = None
    requests_made: int = 0

    @property
    def duration(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def is_done(self) -> bool:
        return self.status in ("completed", "failed", "skipped")


@dataclass
class ScanProgress:
    """Aggregate progress for the entire scan."""
    total_scanners: int = 0
    completed_scanners: int = 0
    failed_scanners: int = 0
    skipped_scanners: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )
    scanner_progress: dict[str, ScannerProgress] = field(default_factory=dict)
    start_time: Optional[float] = None
    current_phase: ScanPhase = ScanPhase.INIT

    @property
    def percent_complete(self) -> float:
        if self.total_scanners == 0:
            return 0.0
        done = self.completed_scanners + self.failed_scanners + self.skipped_scanners
        return min(100.0, (done / self.total_scanners) * 100)

    @property
    def elapsed(self) -> float:
        if self.start_time is None:
            return 0.0
        return time.time() - self.start_time

    @property
    def active_scanners(self) -> list[str]:
        return [
            name for name, sp in self.scanner_progress.items()
            if sp.status == "running"
        ]

    def record_finding(self, finding: Finding):
        self.total_findings += 1
        sev = finding.severity
        if sev in self.findings_by_severity:
            self.findings_by_severity[sev] += 1

    def summary(self) -> dict[str, Any]:
        return {
            "phase": self.current_phase.name,
            "progress": f"{self.percent_complete:.0f}%",
            "elapsed": f"{self.elapsed:.1f}s",
            "scanners": {
                "total": self.total_scanners,
                "completed": self.completed_scanners,
                "failed": self.failed_scanners,
                "skipped": self.skipped_scanners,
            },
            "findings": {
                "total": self.total_findings,
                **self.findings_by_severity,
            },
        }


# ═══════════════════════════════════════════════════════════════════════
# Scanner Run Result — Internal result for a single scanner run
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ScannerRunResult:
    """Result from running a single scanner."""
    scanner_name: str
    scan_result: Optional[ScanResult] = None
    error: Optional[str] = None
    duration: float = 0.0
    was_skipped: bool = False
    skip_reason: str = ""


# ═══════════════════════════════════════════════════════════════════════
# Scan Session — The main orchestrator
# ═══════════════════════════════════════════════════════════════════════

class ScanSession:
    """
    Full lifecycle scan orchestrator.

    Manages phases, runs scanners, aggregates findings, deduplicates,
    and generates reports.

    Usage:
        session = ScanSession(config, context)
        session.events.on(EventType.FINDING_DISCOVERED, my_handler)
        results = session.run(scanner_names=["sqli", "xss", "headers"])
        print(session.progress.summary())
    """

    # Scanner categories for phase ordering
    RECON_SCANNERS = {"ports", "dns", "tech", "ssl", "headers", "cookies", "wafid",
                      "email", "passive", "js"}
    ACTIVE_SCANNERS = {"sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "nosql",
                       "ssrf", "redirect", "jwt", "csrf", "smuggling", "api",
                       "graphql", "websocket", "upload", "deser", "oauth",
                       "race", "ldap", "xpath", "crlf", "hpp", "hostheader",
                       "domxss", "idor", "bizlogic", "prototype", "cloud",
                       "fuzz", "cors", "cve", "takeover", "dirs"}

    def __init__(self, config: ScanConfig, context=None, safe_mode=None):
        """
        Initialize a scan session.

        Args:
            config: Scan configuration
            context: ScanContext DI container (optional)
            safe_mode: SafeMode instance (optional)
        """
        self.config = config
        self.context = context
        self.safe_mode = safe_mode

        # State
        self._phase = ScanPhase.INIT
        self._cancelled = False
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._scan_results: list[ScanResult] = []
        self._all_findings: list[Finding] = []
        self._deduped_groups: list[FindingGroup] = []

        # Subsystems
        self.events = ScanEventBus()
        self.progress = ScanProgress()
        self.deduplicator = FindingDeduplicator(
            similarity_threshold=0.75
        )

        # Error tracking
        self._errors: list[dict] = []
        self._consecutive_errors = 0
        self._max_consecutive_errors = 5

    # ── Phase Management ──────────────────────────────────────────

    @property
    def phase(self) -> ScanPhase:
        return self._phase

    def _set_phase(self, phase: ScanPhase):
        old = self._phase
        self._phase = phase
        self.progress.current_phase = phase
        self.events.emit(ScanEvent(
            event_type=EventType.PHASE_CHANGED,
            phase=phase,
            message=f"Phase: {old.name} → {phase.name}",
        ))
        log.info(f"Phase transition: {old.name} → {phase.name}")

    # ── Cancel Support ────────────────────────────────────────────

    def cancel(self):
        """Cancel the scan session."""
        self._cancelled = True
        self._set_phase(ScanPhase.CANCELLED)
        self.events.emit(ScanEvent(
            event_type=EventType.SESSION_CANCELLED,
            message="Scan cancelled by user",
        ))

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    # ── Run Orchestration ─────────────────────────────────────────

    def run(self, scanner_names: Optional[list[str]] = None,
            scanner_registry: Optional[dict] = None) -> list[ScanResult]:
        """
        Run the full scan lifecycle.

        Args:
            scanner_names: Which scanners to run (None = all from config)
            scanner_registry: SCANNER_REGISTRY dict mapping name→class

        Returns:
            List of ScanResult objects
        """
        self._start_time = time.time()
        self.progress.start_time = self._start_time

        self.events.emit(ScanEvent(
            event_type=EventType.SESSION_STARTED,
            message=f"Scan started for {self.config.target}",
        ))

        try:
            # ── INIT ──
            self._set_phase(ScanPhase.INIT)
            scanners_to_run = self._resolve_scanners(scanner_names, scanner_registry)
            self.progress.total_scanners = len(scanners_to_run)

            if not scanners_to_run:
                log.warning("No scanners to run")
                self._set_phase(ScanPhase.DONE)
                return []

            # Initialize progress tracking
            for name in scanners_to_run:
                self.progress.scanner_progress[name] = ScannerProgress(name=name)

            # ── RECON PHASE ──
            recon = [s for s in scanners_to_run if s in self.RECON_SCANNERS]
            if recon:
                self._set_phase(ScanPhase.RECON)
                self._run_scanner_batch(recon, scanner_registry or {})

            if self._cancelled:
                return self._finalize()

            # ── ENHANCED DISCOVERY: JS analysis + API brute-force ──
            try:
                from secprobe.core.discovery_engine import DiscoveryEngine, DiscoveryConfig
                import asyncio
                discovery_config = DiscoveryConfig(
                    target=self.config.target,
                    enable_html_crawl=False,  # Already crawled above
                    enable_js_analysis=True,
                    enable_api_brute=True,
                    enable_browser=False,
                    crawl_depth=getattr(self.config, 'crawl_depth', 3),
                    max_api_probes=200,  # Conservative for session
                )
                engine = DiscoveryEngine(discovery_config)
                http_client = self.context.http_client
                discovered = asyncio.run(engine.discover(http_client))

                # Merge with existing attack surface
                if self.context and hasattr(self.context, 'attack_surface') and self.context.attack_surface:
                    self.context.attack_surface.urls.update(discovered.urls)
                    for ep in discovered.endpoints:
                        key = f"{ep.method}:{ep.url}"
                        existing_keys = {f"{e.method}:{e.url}" for e in self.context.attack_surface.endpoints}
                        if key not in existing_keys:
                            self.context.attack_surface.endpoints.append(ep)
                    self.context.attack_surface.parameters.update(discovered.parameters)
                elif self.context:
                    self.context.attack_surface = discovered

                log.info("Discovery engine: +%d URLs, +%d endpoints", len(discovered.urls), len(discovered.endpoints))
            except Exception:
                log.warning("Discovery engine failed, continuing with existing surface", exc_info=True)

            if self._cancelled:
                return self._finalize()

            # ── ACTIVE SCAN PHASE ──
            active = [s for s in scanners_to_run if s in self.ACTIVE_SCANNERS]
            if active:
                self._set_phase(ScanPhase.ACTIVE_SCAN)
                self._run_scanner_batch(active, scanner_registry or {})

            if self._cancelled:
                return self._finalize()

            # ── ANALYSIS PHASE ──
            self._set_phase(ScanPhase.ANALYSIS)
            self._run_analysis()

            # ── REPORT PHASE ──
            self._set_phase(ScanPhase.REPORT)
            self._generate_report()

            # ── DONE ──
            self._set_phase(ScanPhase.DONE)
            self.events.emit(ScanEvent(
                event_type=EventType.SESSION_COMPLETED,
                message=f"Scan completed: {self.progress.total_findings} findings",
                data=self.progress.summary(),
            ))

        except TargetUnreachableError as e:
            self._set_phase(ScanPhase.FAILED)
            self._errors.append({"type": "target_unreachable", "message": str(e)})
            self.events.emit(ScanEvent(
                event_type=EventType.SESSION_FAILED,
                message=str(e),
            ))
        except Exception as e:
            self._set_phase(ScanPhase.FAILED)
            self._errors.append({"type": "unexpected", "message": str(e),
                                 "traceback": traceback.format_exc()})
            self.events.emit(ScanEvent(
                event_type=EventType.SESSION_FAILED,
                message=f"Unexpected error: {e}",
            ))
            log.error(f"Session failed: {e}")

        self._end_time = time.time()
        return self._finalize()

    # ── Scanner Resolution ────────────────────────────────────────

    def _resolve_scanners(self, names: Optional[list[str]],
                          registry: Optional[dict]) -> list[str]:
        """Determine which scanners to run."""
        if names:
            return names

        # From config scan_types
        if self.config.scan_types and "all" not in self.config.scan_types:
            return self.config.scan_types

        # All registered scanners
        if registry:
            return list(registry.keys())

        return []

    # ── Scanner Execution ─────────────────────────────────────────

    def _run_scanner_batch(self, scanner_names: list[str], registry: dict):
        """Run a batch of scanners sequentially."""
        for name in scanner_names:
            if self._cancelled:
                break

            if self._consecutive_errors >= self._max_consecutive_errors:
                log.error(f"Too many consecutive errors ({self._consecutive_errors}), stopping")
                remaining = [n for n in scanner_names if n not in
                             [s for s, sp in self.progress.scanner_progress.items() if sp.is_done]]
                for r in remaining:
                    self._skip_scanner(r, "Too many consecutive errors")
                break

            result = self._run_single_scanner(name, registry)

            if result.error:
                self._consecutive_errors += 1
            else:
                self._consecutive_errors = 0

    def _run_single_scanner(self, name: str, registry: dict) -> ScannerRunResult:
        """Run a single scanner and return its result."""
        sp = self.progress.scanner_progress.get(name)
        if sp is None:
            sp = ScannerProgress(name=name)
            self.progress.scanner_progress[name] = sp

        # Check if scanner class exists in registry
        scanner_class = registry.get(name)
        if scanner_class is None:
            return self._skip_scanner(name, f"Scanner '{name}' not in registry")

        # Check safe mode
        if self.safe_mode:
            allowed, reason = self.safe_mode.can_request(
                url=self.config.target,
                method="GET",
                scanner=name,
            )
            if not allowed:
                return self._skip_scanner(name, f"Blocked by safe mode: {reason}")

        # Mark running
        sp.status = "running"
        sp.start_time = time.time()
        self.events.emit(ScanEvent(
            event_type=EventType.SCANNER_STARTED,
            scanner=name,
            message=f"Scanner '{name}' started",
        ))

        try:
            # Instantiate and run the scanner
            scanner = scanner_class(self.config, self.context)
            scan_result = scanner.run()

            sp.end_time = time.time()
            sp.status = "completed"
            sp.findings_count = len(scan_result.findings) if scan_result else 0

            # Collect findings
            if scan_result:
                self._scan_results.append(scan_result)
                for finding in scan_result.findings:
                    self._all_findings.append(finding)
                    self.progress.record_finding(finding)
                    self.events.emit(ScanEvent(
                        event_type=EventType.FINDING_DISCOVERED,
                        scanner=name,
                        finding=finding,
                        message=f"[{finding.severity}] {finding.title}",
                    ))

            self.progress.completed_scanners += 1
            self.events.emit(ScanEvent(
                event_type=EventType.SCANNER_COMPLETED,
                scanner=name,
                message=f"Scanner '{name}' completed: {sp.findings_count} findings",
                data={"duration": sp.duration, "findings": sp.findings_count},
            ))

            return ScannerRunResult(
                scanner_name=name,
                scan_result=scan_result,
                duration=sp.duration,
            )

        except WAFBlockedError as e:
            sp.end_time = time.time()
            sp.status = "failed"
            sp.error = str(e)
            self.progress.failed_scanners += 1
            self._errors.append({"scanner": name, "type": "waf_blocked", "message": str(e)})

            self.events.emit(ScanEvent(
                event_type=EventType.WAF_DETECTED,
                scanner=name,
                message=str(e),
            ))
            self.events.emit(ScanEvent(
                event_type=EventType.SCANNER_FAILED,
                scanner=name,
                message=str(e),
            ))

            return ScannerRunResult(scanner_name=name, error=str(e), duration=sp.duration)

        except ScanTimeoutError as e:
            sp.end_time = time.time()
            sp.status = "failed"
            sp.error = str(e)
            self.progress.failed_scanners += 1
            self._errors.append({"scanner": name, "type": "timeout", "message": str(e)})

            self.events.emit(ScanEvent(
                event_type=EventType.SCANNER_FAILED,
                scanner=name,
                message=str(e),
            ))

            return ScannerRunResult(scanner_name=name, error=str(e), duration=sp.duration)

        except (ScannerError, SecProbeError) as e:
            sp.end_time = time.time()
            sp.status = "failed"
            sp.error = str(e)
            self.progress.failed_scanners += 1
            self._errors.append({"scanner": name, "type": "scanner_error", "message": str(e)})

            self.events.emit(ScanEvent(
                event_type=EventType.SCANNER_FAILED,
                scanner=name,
                message=str(e),
            ))

            return ScannerRunResult(scanner_name=name, error=str(e), duration=sp.duration)

        except Exception as e:
            sp.end_time = time.time()
            sp.status = "failed"
            sp.error = str(e)
            self.progress.failed_scanners += 1
            self._errors.append({
                "scanner": name,
                "type": "unexpected",
                "message": str(e),
                "traceback": traceback.format_exc(),
            })

            self.events.emit(ScanEvent(
                event_type=EventType.SCANNER_FAILED,
                scanner=name,
                message=f"Unexpected error: {e}",
            ))

            return ScannerRunResult(scanner_name=name, error=str(e), duration=sp.duration)

    def _skip_scanner(self, name: str, reason: str) -> ScannerRunResult:
        """Skip a scanner and record the reason."""
        sp = self.progress.scanner_progress.get(name)
        if sp:
            sp.status = "skipped"
        self.progress.skipped_scanners += 1

        self.events.emit(ScanEvent(
            event_type=EventType.SCANNER_SKIPPED,
            scanner=name,
            message=reason,
        ))

        return ScannerRunResult(scanner_name=name, was_skipped=True, skip_reason=reason)

    # ── Analysis Phase ────────────────────────────────────────────

    def _run_analysis(self):
        """Run post-scan analysis: deduplication, grouping."""
        if not self._all_findings:
            return

        # Deduplicate findings
        if self.config.dedup:
            self._deduped_groups = self.deduplicator.deduplicate(self._all_findings)
            stats = self.deduplicator.get_stats(self._deduped_groups)
            log.info(
                f"Dedup: {stats['total_findings']} → {stats['unique_findings']} "
                f"({stats['duplicates_removed']} dupes removed, "
                f"{stats['cross_scanner_groups']} cross-scanner groups)"
            )

    # ── Report Phase ──────────────────────────────────────────────

    def _generate_report(self):
        """Generate the scan report if an output format is configured."""
        if self.config.output_format == "none":
            return

        try:
            from secprobe.report import ReportGenerator
            generator = ReportGenerator(self._scan_results, self.config.target)
            generator.generate(
                self.config.output_format,
                self.config.output_file,
            )
        except ImportError:
            log.warning("ReportGenerator not available")
        except Exception as e:
            log.error(f"Report generation failed: {e}")

    # ── Finalization ──────────────────────────────────────────────

    def _finalize(self) -> list[ScanResult]:
        """Finalize the session and return results."""
        return self._scan_results

    # ── Public API ────────────────────────────────────────────────

    @property
    def results(self) -> list[ScanResult]:
        """All ScanResult objects from completed scanners."""
        return list(self._scan_results)

    @property
    def findings(self) -> list[Finding]:
        """All findings (before dedup)."""
        return list(self._all_findings)

    @property
    def deduped_findings(self) -> list[FindingGroup]:
        """Deduplicated finding groups."""
        return list(self._deduped_groups)

    @property
    def errors(self) -> list[dict]:
        """All errors encountered during the scan."""
        return list(self._errors)

    @property
    def duration(self) -> float:
        """Total scan duration in seconds."""
        if self._start_time is None:
            return 0.0
        end = self._end_time or time.time()
        return end - self._start_time

    def get_scanner_result(self, name: str) -> Optional[ScanResult]:
        """Get ScanResult for a specific scanner."""
        for sr in self._scan_results:
            if sr.scanner_name == name:
                return sr
        return None

    def summary(self) -> dict[str, Any]:
        """Complete session summary."""
        findings_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self._all_findings:
            if f.severity in findings_by_sev:
                findings_by_sev[f.severity] += 1

        scanner_summaries = {}
        for name, sp in self.progress.scanner_progress.items():
            scanner_summaries[name] = {
                "status": sp.status,
                "duration": round(sp.duration, 2),
                "findings": sp.findings_count,
                "error": sp.error,
            }

        dedup_stats = {}
        if self._deduped_groups:
            dedup_stats = self.deduplicator.get_stats(self._deduped_groups)

        return {
            "target": self.config.target,
            "phase": self._phase.name,
            "duration": round(self.duration, 2),
            "scanners": {
                "total": self.progress.total_scanners,
                "completed": self.progress.completed_scanners,
                "failed": self.progress.failed_scanners,
                "skipped": self.progress.skipped_scanners,
                "details": scanner_summaries,
            },
            "findings": {
                "total": len(self._all_findings),
                "by_severity": findings_by_sev,
                "unique_groups": len(self._deduped_groups),
                "dedup": dedup_stats,
            },
            "errors": self._errors,
        }

    # ── Risk Score ────────────────────────────────────────────────

    def risk_score(self) -> tuple[float, str]:
        """
        Calculate overall risk score (0-100) and letter grade.

        Scoring:
          CRITICAL = 25pts each
          HIGH     = 15pts each
          MEDIUM   = 5pts each
          LOW      = 1pt each
          INFO     = 0pts
        Capped at 100.
        """
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}
        score = 0
        for f in self._all_findings:
            score += weights.get(f.severity, 0)
        score = min(100, score)

        if score >= 80:
            grade = "F"
        elif score >= 60:
            grade = "D"
        elif score >= 40:
            grade = "C"
        elif score >= 20:
            grade = "B"
        elif score > 0:
            grade = "A-"
        else:
            grade = "A+"

        return score, grade
