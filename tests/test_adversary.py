import pytest
from secprobe.adversary.attack_mapper import ATTACKMapper, VULN_TO_ATTACK
from secprobe.adversary.kill_chain import KillChainBuilder
from secprobe.adversary.scoring import SecurityScorer


class FakeFinding:
    def __init__(self, title, category, severity="HIGH", url=""):
        self.title = title
        self.category = category
        self.severity = severity
        self.url = url


class TestATTACKMapper:
    def test_map_sqli(self):
        mapper = ATTACKMapper()
        f = FakeFinding("SQL Injection", "sqli")
        mappings = mapper.map_finding(f)
        assert len(mappings) >= 1
        assert any(m.tactic_id == "TA0001" for m in mappings)

    def test_map_xss(self):
        mapper = ATTACKMapper()
        f = FakeFinding("XSS", "xss")
        mappings = mapper.map_finding(f)
        assert len(mappings) >= 1

    def test_map_unknown(self):
        mapper = ATTACKMapper()
        f = FakeFinding("Unknown", "unknown_category")
        assert mapper.map_finding(f) == []

    def test_kill_chain_coverage(self):
        mapper = ATTACKMapper()
        findings = [FakeFinding("SQLi", "sqli"), FakeFinding("XSS", "xss")]
        coverage = mapper.get_kill_chain_coverage(findings)
        assert coverage["Initial Access"]["covered"] is True
        assert coverage["Impact"]["covered"] is False

    def test_all_categories_mapped(self):
        assert len(VULN_TO_ATTACK) >= 15


class TestKillChainBuilder:
    def test_build_sqli_chain(self):
        builder = KillChainBuilder()
        findings = [FakeFinding("SQL Injection", "sqli", "CRITICAL", "/api/search")]
        chains = builder.build_chains(findings)
        assert len(chains) >= 1
        assert any("SQLi" in c.name or "Data" in c.name for c in chains)

    def test_build_no_chain(self):
        builder = KillChainBuilder()
        findings = [FakeFinding("Missing Header", "headers", "LOW")]
        chains = builder.build_chains(findings)
        assert len(chains) == 0

    def test_chain_has_steps(self):
        builder = KillChainBuilder()
        findings = [FakeFinding("SSRF", "ssrf", "HIGH")]
        chains = builder.build_chains(findings)
        if chains:
            assert chains[0].length >= 1


class TestSecurityScorer:
    def test_perfect_score(self):
        scorer = SecurityScorer()
        score = scorer.score(
            findings=[],
            headers_present=["Strict-Transport-Security", "Content-Security-Policy",
                           "X-Content-Type-Options", "X-Frame-Options",
                           "Referrer-Policy", "Permissions-Policy"],
            has_rate_limiting=True,
            has_waf=True,
        )
        assert score.total >= 80
        assert score.grade in ("A+", "A", "A-", "B+")

    def test_terrible_score(self):
        scorer = SecurityScorer()
        findings = [FakeFinding("Critical", "sqli", "CRITICAL")] * 3
        score = scorer.score(findings=findings)
        assert score.total < 30
        assert score.grade == "F"

    def test_score_components(self):
        scorer = SecurityScorer()
        score = scorer.score(findings=[], headers_present=[])
        assert score.vulnerability_score == 40.0  # No vulns = perfect
        assert score.configuration_score == 0.0   # No headers = zero
        assert score.architecture_score == 20.0   # No arch issues = perfect
