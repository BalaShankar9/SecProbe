import pytest
from secprobe.benchmark.juice_shop import JuiceShopBenchmark
from secprobe.benchmark.report import BenchmarkReport


class TestJuiceShopBenchmark:
    def test_challenge_list(self):
        bench = JuiceShopBenchmark()
        challenges = bench.get_challenges()
        assert len(challenges) >= 40
        names = {c["name"] for c in challenges}
        assert any("SQL" in n or "sqli" in n.lower() or "Login" in n for n in names)
        assert any("XSS" in n or "xss" in n.lower() or "DOM" in n for n in names)

    def test_match_sqli_finding(self):
        bench = JuiceShopBenchmark()
        finding = {"category": "sqli", "title": "SQL Injection (UNION-based)", "url": "/rest/products/search"}
        matches = bench.match_finding(finding)
        assert len(matches) >= 1
        assert any("Christmas" in m.name or "Database" in m.name or "Credential" in m.name for m in matches)

    def test_match_header_finding(self):
        bench = JuiceShopBenchmark()
        finding = {"category": "headers", "title": "Missing header: Content-Security-Policy", "url": "http://example.com"}
        matches = bench.match_finding(finding)
        assert len(matches) >= 1

    def test_run_benchmark(self):
        bench = JuiceShopBenchmark()
        findings = [
            {"category": "sqli", "title": "SQL Injection", "url": "/rest/products/search"},
            {"category": "headers", "title": "Missing HSTS header", "url": ""},
            {"category": "cors", "title": "CORS misconfiguration", "url": ""},
        ]
        result = bench.run_benchmark(findings)
        assert result["total_challenges"] >= 40
        assert result["detected"] >= 1
        assert 0 <= result["detection_rate"] <= 1.0

    def test_detection_rate_calculation(self):
        report = BenchmarkReport()
        report.total_challenges = 100
        report.detected = 80
        report.false_positives = 2
        assert report.detection_rate == 0.80
        assert report.fp_rate == pytest.approx(2 / 82, rel=0.01)

    def test_empty_report(self):
        report = BenchmarkReport()
        report.total_challenges = 100
        report.detected = 0
        assert report.detection_rate == 0.0
        assert report.grade == "F"

    def test_grade_assignment(self):
        report = BenchmarkReport()
        report.total_challenges = 100
        report.detected = 95
        assert report.grade == "A+"
        report.detected = 80
        assert report.grade == "B"
        report.detected = 50
        assert report.grade == "F"

    def test_markdown_output(self):
        report = BenchmarkReport(total_challenges=100, detected=75, target="Juice Shop")
        md = report.to_markdown()
        assert "75.0%" in md
        assert "Juice Shop" in md
