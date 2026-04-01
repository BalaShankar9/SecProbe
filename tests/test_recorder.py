"""Tests for the Scan Replay / Time Travel feature."""

import json
import os
import tempfile

import pytest

from secprobe.core.recorder import ScanRecord, ScanRecorder, RecordingDiff


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

def _make_record(method="GET", url="https://example.com", status=200, body="OK", duration=10.0):
    return ScanRecord(
        timestamp="2025-01-01T00:00:00+00:00",
        method=method,
        url=url,
        request_headers={"User-Agent": "SecProbe"},
        request_body="",
        status_code=status,
        response_headers={"Content-Type": "text/html"},
        response_body=body,
        duration_ms=duration,
    )


# ─────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────

class TestScanRecord:
    def test_to_dict_round_trip(self):
        record = _make_record()
        d = record.to_dict()
        restored = ScanRecord.from_dict(d)
        assert restored.method == "GET"
        assert restored.url == "https://example.com"
        assert restored.status_code == 200
        assert restored.response_body == "OK"

    def test_from_dict_ignores_extra_keys(self):
        d = _make_record().to_dict()
        d["unknown_field"] = "should be ignored"
        record = ScanRecord.from_dict(d)
        assert record.method == "GET"


class TestScanRecorder:
    def test_start_stop_lifecycle(self):
        rec = ScanRecorder(target="https://example.com")
        assert not rec.is_recording
        rec.start()
        assert rec.is_recording
        rec.stop()
        assert not rec.is_recording
        assert rec.duration_seconds > 0

    def test_record_request_and_response(self):
        rec = ScanRecorder()
        rec.start()
        record = rec.record_request("GET", "https://example.com/api", headers={"Accept": "application/json"})
        rec.record_response(record, status_code=200, response_body='{"ok": true}')
        rec.stop()

        assert rec.record_count == 1
        assert rec.records[0].method == "GET"
        assert rec.records[0].status_code == 200
        assert rec.records[0].duration_ms >= 0

    def test_add_record_directly(self):
        rec = ScanRecorder()
        rec.add_record(_make_record())
        rec.add_record(_make_record(method="POST", url="https://example.com/login"))
        assert rec.record_count == 2

    def test_save_and_load(self):
        rec = ScanRecorder(target="https://example.com", scan_id="test-001")
        rec.add_record(_make_record())
        rec.add_record(_make_record(method="POST", url="https://example.com/api", status=201))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            rec.save(filepath)

            # Verify JSON structure
            with open(filepath) as f:
                data = json.load(f)
            assert "secprobe_recording" in data
            assert data["secprobe_recording"]["scan_id"] == "test-001"
            assert data["secprobe_recording"]["target"] == "https://example.com"
            assert len(data["entries"]) == 2

            # Load back
            loaded = ScanRecorder.load(filepath)
            assert loaded.target == "https://example.com"
            assert loaded.scan_id == "test-001"
            assert loaded.record_count == 2
            assert loaded.records[0].method == "GET"
            assert loaded.records[1].method == "POST"
            assert loaded.records[1].status_code == 201
        finally:
            os.unlink(filepath)

    def test_replay_calls_callback(self):
        rec = ScanRecorder()
        rec.add_record(_make_record(url="https://example.com/1"))
        rec.add_record(_make_record(url="https://example.com/2"))
        rec.add_record(_make_record(url="https://example.com/3"))

        visited = []
        rec.replay(callback=lambda idx, record: visited.append((idx, record.url)))

        assert len(visited) == 3
        assert visited[0] == (0, "https://example.com/1")
        assert visited[1] == (1, "https://example.com/2")
        assert visited[2] == (2, "https://example.com/3")

    def test_replay_returns_count(self):
        rec = ScanRecorder()
        rec.add_record(_make_record())
        count = rec.replay(callback=lambda i, r: None)
        assert count == 1

    def test_diff_identical_recordings(self):
        rec1 = ScanRecorder()
        rec1.add_record(_make_record())
        rec2 = ScanRecorder()
        rec2.add_record(_make_record())

        diff = rec1.diff(rec2)
        assert diff.summary == "no differences"
        assert len(diff.added) == 0
        assert len(diff.removed) == 0
        assert len(diff.changed) == 0

    def test_diff_added_and_removed(self):
        rec1 = ScanRecorder()
        rec1.add_record(_make_record(url="https://example.com/old"))
        rec1.add_record(_make_record(url="https://example.com/shared"))

        rec2 = ScanRecorder()
        rec2.add_record(_make_record(url="https://example.com/shared"))
        rec2.add_record(_make_record(url="https://example.com/new"))

        diff = rec1.diff(rec2)
        assert len(diff.removed) == 1
        assert diff.removed[0].url == "https://example.com/old"
        assert len(diff.added) == 1
        assert diff.added[0].url == "https://example.com/new"
        assert "1 added" in diff.summary
        assert "1 removed" in diff.summary

    def test_diff_changed_status_code(self):
        rec1 = ScanRecorder()
        rec1.add_record(_make_record(url="https://example.com/api", status=200))

        rec2 = ScanRecorder()
        rec2.add_record(_make_record(url="https://example.com/api", status=500))

        diff = rec1.diff(rec2)
        assert len(diff.changed) == 1
        assert diff.changed[0]["url"] == "https://example.com/api"
        assert any(
            d["field"] == "status_code" and d["old_value"] == 200 and d["new_value"] == 500
            for d in diff.changed[0]["differences"]
        )

    def test_filter_by_method(self):
        rec = ScanRecorder()
        rec.add_record(_make_record(method="GET"))
        rec.add_record(_make_record(method="POST"))
        rec.add_record(_make_record(method="GET"))

        results = rec.filter(method="GET")
        assert len(results) == 2

    def test_filter_by_status_code(self):
        rec = ScanRecorder()
        rec.add_record(_make_record(status=200))
        rec.add_record(_make_record(status=404))
        rec.add_record(_make_record(status=200))

        results = rec.filter(status_code=404)
        assert len(results) == 1

    def test_get_stats(self):
        rec = ScanRecorder()
        rec.add_record(_make_record(method="GET", url="https://a.com", duration=10))
        rec.add_record(_make_record(method="POST", url="https://b.com", duration=20))
        rec.add_record(_make_record(method="GET", url="https://a.com", duration=30))

        stats = rec.get_stats()
        assert stats["total_requests"] == 3
        assert stats["methods"]["GET"] == 2
        assert stats["methods"]["POST"] == 1
        assert stats["unique_urls"] == 2
        assert stats["avg_duration_ms"] == 20.0

    def test_get_stats_empty(self):
        rec = ScanRecorder()
        stats = rec.get_stats()
        assert stats["total_requests"] == 0
        assert stats["avg_duration_ms"] == 0.0
