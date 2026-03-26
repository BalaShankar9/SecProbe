import pytest
import tempfile
from pathlib import Path
from secprobe.intelligence.procedure_recorder import ProcedureRecorder


class FakeFinding:
    def __init__(self, title, category, url, evidence=""):
        self.title = title
        self.severity = "CRITICAL"
        self.category = category
        self.url = url
        self.cwe = "CWE-89"
        self.evidence = evidence


class TestProcedureRecorder:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.recorder = ProcedureRecorder(storage_path=self.tmpdir)

    def teardown_method(self):
        self.recorder.close()

    def test_record_from_findings(self):
        findings = [
            FakeFinding(
                "SQL Injection in parameter 'q'",
                "sqli",
                "http://example.com/search",
                "Payload: ' OR 1=1--\nResponse: 200 OK"
            ),
        ]
        count = self.recorder.record_from_findings(findings, ["wordpress", "mysql"])
        assert count == 1

    def test_find_recorded_procedure(self):
        findings = [
            FakeFinding("SQLi", "sqli", "http://test.com/api", "Payload: test"),
        ]
        self.recorder.record_from_findings(findings, ["express"])
        procs = self.recorder.find_known_procedures("sqli", "express")
        assert len(procs) >= 1

    def test_empty_findings(self):
        count = self.recorder.record_from_findings([], ["wordpress"])
        assert count == 0

    def test_get_quick_wins_empty(self):
        wins = self.recorder.get_quick_wins(["wordpress"])
        assert wins == []

    def test_get_quick_wins_after_learning(self):
        for i in range(3):
            self.recorder.record_from_findings(
                [FakeFinding(f"SQLi #{i}", "sqli", f"http://test.com/ep{i}", "Payload: test")],
                ["wordpress"]
            )
        wins = self.recorder.get_quick_wins(["wordpress"])
        assert len(wins) >= 1
