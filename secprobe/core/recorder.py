"""
Scan Replay / Time Travel — Record, replay, and diff HTTP interactions.

Records every HTTP request/response during a scan, enabling:
  - Full scan replay for debugging and verification
  - Diffing two scans to see what changed between runs
  - HAR-like JSON export for sharing and archival
  - Step-by-step callback replay for analysis tooling
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Optional


# ─────────────────────────────────────────────────────────────────
# Data Model
# ─────────────────────────────────────────────────────────────────

@dataclass
class ScanRecord:
    """A single recorded HTTP request/response pair."""

    timestamp: str
    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ScanRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ─────────────────────────────────────────────────────────────────
# Diff Result
# ─────────────────────────────────────────────────────────────────

@dataclass
class DiffEntry:
    """A single difference between two recordings."""

    index: int
    field: str
    kind: str  # "changed", "added", "removed"
    old_value: Any = None
    new_value: Any = None


@dataclass
class RecordingDiff:
    """Result of comparing two recordings."""

    added: list[ScanRecord] = field(default_factory=list)
    removed: list[ScanRecord] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


# ─────────────────────────────────────────────────────────────────
# Recorder
# ─────────────────────────────────────────────────────────────────

class ScanRecorder:
    """Records HTTP interactions during a scan for replay and analysis.

    Usage:
        recorder = ScanRecorder()
        recorder.start()

        # Wrap your HTTP calls
        record = recorder.record_request("GET", "https://example.com/api")
        # ... perform the request ...
        recorder.record_response(record, status_code=200, response_body="OK")

        recorder.stop()
        recorder.save("scan_recording.json")

    Replay later:
        recorder = ScanRecorder.load("scan_recording.json")
        recorder.replay(callback=my_handler)
    """

    def __init__(self, target: str = "", scan_id: str = ""):
        self.target = target
        self.scan_id = scan_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.records: list[ScanRecord] = []
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._recording = False

    # ── Recording lifecycle ─────────────────────────────────────

    def start(self) -> None:
        """Begin recording."""
        self._start_time = time.monotonic()
        self._recording = True

    def stop(self) -> None:
        """Stop recording."""
        self._end_time = time.monotonic()
        self._recording = False

    @property
    def is_recording(self) -> bool:
        return self._recording

    @property
    def duration_seconds(self) -> float:
        if self._start_time is None:
            return 0.0
        end = self._end_time or time.monotonic()
        return end - self._start_time

    @property
    def record_count(self) -> int:
        return len(self.records)

    # ── Recording requests ──────────────────────────────────────

    def record_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: str = "",
        metadata: Optional[dict[str, Any]] = None,
    ) -> ScanRecord:
        """Record an outgoing HTTP request. Returns the record to be updated with the response."""
        record = ScanRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=method.upper(),
            url=url,
            request_headers=headers or {},
            request_body=body,
            metadata=metadata or {},
        )
        record._start_time = time.monotonic()  # type: ignore[attr-defined]
        return record

    def record_response(
        self,
        record: ScanRecord,
        status_code: int,
        response_headers: Optional[dict[str, str]] = None,
        response_body: str = "",
    ) -> ScanRecord:
        """Record the response for a previously started request."""
        start = getattr(record, "_start_time", None)
        if start is not None:
            record.duration_ms = (time.monotonic() - start) * 1000
        record.status_code = status_code
        record.response_headers = response_headers or {}
        record.response_body = response_body
        self.records.append(record)
        return record

    def add_record(self, record: ScanRecord) -> None:
        """Add a fully-formed record directly."""
        self.records.append(record)

    # ── Persistence ─────────────────────────────────────────────

    def save(self, filepath: str) -> str:
        """Save the recording to a HAR-like JSON file.

        Returns the filepath written.
        """
        data = {
            "secprobe_recording": {
                "version": "1.0",
                "scan_id": self.scan_id,
                "target": self.target,
                "created": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": self.duration_seconds,
                "record_count": len(self.records),
            },
            "entries": [r.to_dict() for r in self.records],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    @classmethod
    def load(cls, filepath: str) -> ScanRecorder:
        """Load a recording from a JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        meta = data.get("secprobe_recording", {})
        recorder = cls(
            target=meta.get("target", ""),
            scan_id=meta.get("scan_id", ""),
        )
        for entry in data.get("entries", []):
            recorder.records.append(ScanRecord.from_dict(entry))
        return recorder

    # ── Replay ──────────────────────────────────────────────────

    def replay(
        self,
        callback: Callable[[int, ScanRecord], None],
        delay_ms: float = 0,
    ) -> int:
        """Replay the recording step by step, calling callback(index, record) for each.

        Args:
            callback: Function called with (step_index, record) for each entry.
            delay_ms: Optional delay between steps in milliseconds (0 = no delay).

        Returns:
            Number of records replayed.
        """
        for i, record in enumerate(self.records):
            callback(i, record)
            if delay_ms > 0 and i < len(self.records) - 1:
                time.sleep(delay_ms / 1000.0)
        return len(self.records)

    # ── Diff ────────────────────────────────────────────────────

    def diff(self, other: ScanRecorder) -> RecordingDiff:
        """Compare this recording with another and return differences.

        Matching is done by (method, url) pairs. Records present in self
        but not other are 'removed'; records in other but not self are 'added'.
        Records in both are compared field-by-field for changes.
        """
        self_by_key = self._index_by_method_url(self.records)
        other_by_key = self._index_by_method_url(other.records)

        self_keys = set(self_by_key.keys())
        other_keys = set(other_by_key.keys())

        result = RecordingDiff()

        # Removed: in self but not in other
        for key in sorted(self_keys - other_keys):
            result.removed.extend(self_by_key[key])

        # Added: in other but not in self
        for key in sorted(other_keys - self_keys):
            result.added.extend(other_by_key[key])

        # Changed: in both — compare fields
        compare_fields = [
            "status_code", "response_headers", "response_body",
        ]
        for key in sorted(self_keys & other_keys):
            old_records = self_by_key[key]
            new_records = other_by_key[key]
            # Compare pairwise up to the shorter list
            for i in range(min(len(old_records), len(new_records))):
                old_r = old_records[i]
                new_r = new_records[i]
                changes: list[DiffEntry] = []
                for fld in compare_fields:
                    old_val = getattr(old_r, fld)
                    new_val = getattr(new_r, fld)
                    if old_val != new_val:
                        changes.append(DiffEntry(
                            index=i,
                            field=fld,
                            kind="changed",
                            old_value=old_val,
                            new_value=new_val,
                        ))
                if changes:
                    result.changed.append({
                        "method": old_r.method,
                        "url": old_r.url,
                        "differences": [asdict(d) for d in changes],
                    })

        # Build summary
        parts = []
        if result.added:
            parts.append(f"{len(result.added)} added")
        if result.removed:
            parts.append(f"{len(result.removed)} removed")
        if result.changed:
            parts.append(f"{len(result.changed)} changed")
        result.summary = ", ".join(parts) if parts else "no differences"

        return result

    @staticmethod
    def _index_by_method_url(
        records: list[ScanRecord],
    ) -> dict[tuple[str, str], list[ScanRecord]]:
        """Group records by (method, url)."""
        index: dict[tuple[str, str], list[ScanRecord]] = {}
        for r in records:
            key = (r.method, r.url)
            index.setdefault(key, []).append(r)
        return index

    # ── Filtering & Analysis ────────────────────────────────────

    def filter(
        self,
        method: Optional[str] = None,
        url_contains: Optional[str] = None,
        status_code: Optional[int] = None,
        min_duration_ms: Optional[float] = None,
    ) -> list[ScanRecord]:
        """Filter records by criteria."""
        results = self.records
        if method:
            results = [r for r in results if r.method == method.upper()]
        if url_contains:
            results = [r for r in results if url_contains in r.url]
        if status_code is not None:
            results = [r for r in results if r.status_code == status_code]
        if min_duration_ms is not None:
            results = [r for r in results if r.duration_ms >= min_duration_ms]
        return results

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics about the recording."""
        if not self.records:
            return {
                "total_requests": 0,
                "methods": {},
                "status_codes": {},
                "avg_duration_ms": 0.0,
                "total_duration_ms": 0.0,
                "unique_urls": 0,
            }
        methods: dict[str, int] = {}
        status_codes: dict[int, int] = {}
        durations: list[float] = []
        urls: set[str] = set()

        for r in self.records:
            methods[r.method] = methods.get(r.method, 0) + 1
            status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1
            durations.append(r.duration_ms)
            urls.add(r.url)

        return {
            "total_requests": len(self.records),
            "methods": methods,
            "status_codes": status_codes,
            "avg_duration_ms": sum(durations) / len(durations) if durations else 0.0,
            "total_duration_ms": sum(durations),
            "unique_urls": len(urls),
        }
