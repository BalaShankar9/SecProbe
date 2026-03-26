import pytest
import tempfile
from pathlib import Path
from secprobe.intelligence.learning import ScanLearner
from secprobe.intelligence.planner import ScanPlanner


class TestScanLearner:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.learner = ScanLearner(storage_path=self.tmpdir)

    def teardown_method(self):
        self.learner.close()

    def test_learn_from_scan(self):
        class FakeFinding:
            title = "SQL Injection"
            severity = "CRITICAL"
            category = "sqli"
            url = "/api/test"
            cwe = "CWE-89"
            evidence = "Payload: ' OR 1=1--"

        stats = self.learner.learn_from_scan(
            target="example.com",
            tech_stack=["wordpress", "mysql"],
            findings=[FakeFinding()],
            scan_duration=30.0,
        )
        assert stats["correlations_updated"] > 0
        assert stats["episode_recorded"] is True

    def test_get_priorities_after_learning(self):
        class FakeFinding:
            title = "SQL Injection"
            severity = "CRITICAL"
            category = "sqli"
            url = "/test"
            cwe = "CWE-89"
            evidence = ""

        # Learn multiple scans
        for _ in range(5):
            self.learner.learn_from_scan("test.com", ["wordpress"], [FakeFinding()])

        priorities = self.learner.get_scan_priorities(["wordpress"])
        assert len(priorities) > 0
        # sqli should be high priority after 5 scans finding it
        sqli_entries = [p for p in priorities if p[0] == "sqli"]
        assert len(sqli_entries) > 0

    def test_normalize_vuln_type(self):
        assert ScanLearner._normalize_vuln_type("SQL Injection") == "sqli"
        assert ScanLearner._normalize_vuln_type("xss") == "xss"
        assert ScanLearner._normalize_vuln_type("CORS") == "cors"
        assert ScanLearner._normalize_vuln_type("") == ""

    def test_empty_scan(self):
        stats = self.learner.learn_from_scan("test.com", [], [], 0.0)
        assert stats["episode_recorded"] is True


class TestScanPlanner:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.planner = ScanPlanner(storage_path=self.tmpdir)

    def teardown_method(self):
        self.planner.close()

    def test_plan_with_no_data(self):
        scanners = ["sqli_scanner", "xss_scanner", "header_scanner"]
        result = self.planner.plan_scan("test.com", ["wordpress"], scanners)
        assert len(result) == 3  # Returns all scanners

    def test_recommended_divisions_default(self):
        divs = self.planner.get_recommended_divisions([])
        assert 1 in divs   # Recon always included
        assert 18 in divs  # Compliance always included
        assert 19 in divs  # Intel always included
