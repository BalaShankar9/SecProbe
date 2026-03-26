import pytest
from secprobe.analysis.vuln_dna import VulnDNA, VulnDNAEngine
from secprobe.deception.honeypot_detector import HoneypotDetector, HoneypotIndicator


class FakeFinding:
    def __init__(self, title="", category="", severity="HIGH", url="", evidence=""):
        self.title = title
        self.category = category
        self.severity = severity
        self.url = url
        self.evidence = evidence


class TestVulnDNA:
    def test_fingerprint(self):
        engine = VulnDNAEngine()
        f = FakeFinding("SQLi", "sqli", "CRITICAL", "/api?id=1", "MySQL error syntax")
        dna = engine.fingerprint(f)
        assert dna.category == "sqli"
        assert dna.dna_hash

    def test_similarity(self):
        d1 = VulnDNA("a", "sqli", "parameter", "mysql", "CRITICAL", "error_based")
        d2 = VulnDNA("b", "sqli", "parameter", "mysql", "HIGH", "error_based")
        assert d1.similarity(d2) >= 0.8  # Very similar

    def test_dissimilarity(self):
        d1 = VulnDNA("a", "sqli", "parameter", "mysql", "CRITICAL", "error_based")
        d2 = VulnDNA("b", "xss", "header", "nodejs", "LOW", "reflection")
        assert d1.similarity(d2) < 0.3  # Very different

    def test_find_siblings(self):
        engine = VulnDNAEngine()
        target = VulnDNA("a", "sqli", "parameter", "mysql", "CRITICAL", "error_based")
        others = [
            VulnDNA("b", "sqli", "parameter", "mysql", "HIGH", "union_based"),  # Sibling
            VulnDNA("c", "xss", "header", "nodejs", "LOW", "reflection"),  # Not sibling
        ]
        siblings = engine.find_siblings(target, others, threshold=0.5)
        assert len(siblings) >= 1
        assert siblings[0][0].category == "sqli"

    def test_cluster_findings(self):
        engine = VulnDNAEngine()
        findings = [
            FakeFinding("SQLi 1", "sqli", "CRITICAL", "/api", "MySQL error"),
            FakeFinding("SQLi 2", "sqli", "HIGH", "/search", "MySQL syntax"),
            FakeFinding("XSS", "xss", "MEDIUM", "/page", "Reflected script"),
        ]
        clusters = engine.cluster_findings(findings)
        assert len(clusters) >= 1


class TestHoneypotDetector:
    def test_no_indicators(self):
        detector = HoneypotDetector()
        indicators = detector.analyze({"open_ports": [80, 443]})
        assert len(indicators) == 0

    def test_excessive_ports(self):
        detector = HoneypotDetector()
        indicators = detector.analyze({"open_ports": list(range(100))})
        assert any(i.indicator == "excessive_ports" for i in indicators)

    def test_known_signature(self):
        detector = HoneypotDetector()
        indicators = detector.analyze({
            "open_ports": [22],
            "service_banners": {"22": "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"},
        })
        assert any("cowrie" in i.indicator for i in indicators)

    def test_is_likely_honeypot(self):
        detector = HoneypotDetector()
        indicators = [
            HoneypotIndicator("sig", 0.9, "Known signature"),
            HoneypotIndicator("ports", 0.8, "Too many ports"),
        ]
        is_hp, conf = detector.is_likely_honeypot(indicators)
        assert is_hp is True
        assert conf > 0.6

    def test_not_honeypot(self):
        detector = HoneypotDetector()
        is_hp, conf = detector.is_likely_honeypot([])
        assert is_hp is False
