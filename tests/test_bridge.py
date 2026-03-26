"""Tests for the Agent-to-Scanner Bridge."""

import pytest
from unittest.mock import MagicMock, patch
from secprobe.swarm.bridge import AgentScannerBridge, ATTACK_TYPE_TO_SCANNER, AgentRunResult
from secprobe.core.http_client import HTTPClient
from secprobe.core.crawler import AttackSurface, Endpoint


class TestAttackTypeMapping:
    def test_sqli_maps_to_scanner(self):
        assert ATTACK_TYPE_TO_SCANNER["sqli"] == "sqli_scanner"
        assert ATTACK_TYPE_TO_SCANNER["sqli-union"] == "sqli_scanner"

    def test_xss_maps_to_scanner(self):
        assert ATTACK_TYPE_TO_SCANNER["xss"] == "xss_scanner"
        assert ATTACK_TYPE_TO_SCANNER["xss-reflected"] == "xss_scanner"

    def test_dom_xss_maps_to_domxss(self):
        assert ATTACK_TYPE_TO_SCANNER["xss-dom"] == "domxss_scanner"

    def test_all_major_types_mapped(self):
        required = ["sqli", "xss", "ssti", "cmdi", "lfi", "ssrf", "cors", "jwt", "csrf", "idor"]
        for t in required:
            assert t in ATTACK_TYPE_TO_SCANNER, f"Missing mapping for {t}"

    def test_mapping_count(self):
        assert len(ATTACK_TYPE_TO_SCANNER) >= 50

    def test_infrastructure_types_mapped(self):
        infra = ["port-scan", "ssl", "headers", "cookies", "dns", "tech", "directory"]
        for t in infra:
            assert t in ATTACK_TYPE_TO_SCANNER, f"Missing mapping for {t}"

    def test_advanced_types_mapped(self):
        advanced = ["prototype", "cloud", "cve", "takeover", "waf", "fuzzing", "passive"]
        for t in advanced:
            assert t in ATTACK_TYPE_TO_SCANNER, f"Missing mapping for {t}"


class TestBridgeResolution:
    def setup_method(self):
        self.bridge = AgentScannerBridge(http_client=HTTPClient())

    def test_resolve_sqli_agent(self):
        spec = MagicMock()
        spec.attack_types = ("sqli-union", "sqli-error")
        assert self.bridge._resolve_scanner(spec) == "sqli_scanner"

    def test_resolve_xss_agent(self):
        spec = MagicMock()
        spec.attack_types = ("xss-reflected",)
        assert self.bridge._resolve_scanner(spec) == "xss_scanner"

    def test_resolve_unknown_returns_none(self):
        spec = MagicMock()
        spec.attack_types = ("unknown-type",)
        assert self.bridge._resolve_scanner(spec) is None

    def test_resolve_empty_attack_types(self):
        spec = MagicMock()
        spec.attack_types = ()
        assert self.bridge._resolve_scanner(spec) is None

    def test_resolve_with_underscore_normalization(self):
        spec = MagicMock()
        spec.attack_types = ("sqli_union",)
        assert self.bridge._resolve_scanner(spec) == "sqli_scanner"

    def test_resolve_with_space_normalization(self):
        spec = MagicMock()
        spec.attack_types = ("cache poison",)
        assert self.bridge._resolve_scanner(spec) == "cache_poisoning_scanner"

    def test_resolve_first_matching_type_wins(self):
        spec = MagicMock()
        spec.attack_types = ("xss", "sqli")
        assert self.bridge._resolve_scanner(spec) == "xss_scanner"

    def test_load_sqli_scanner(self):
        cls = self.bridge._load_scanner("sqli_scanner")
        assert cls is not None
        assert "Scanner" in cls.__name__

    def test_load_header_scanner(self):
        cls = self.bridge._load_scanner("header_scanner")
        assert cls is not None

    def test_load_nonexistent_scanner(self):
        cls = self.bridge._load_scanner("nonexistent_scanner")
        assert cls is None

    def test_scanner_cache(self):
        """Loading same scanner twice returns cached class."""
        cls1 = self.bridge._load_scanner("cors_scanner")
        cls2 = self.bridge._load_scanner("cors_scanner")
        assert cls1 is cls2

    def test_get_scanner_for_agent(self):
        spec = MagicMock()
        spec.attack_types = ("jwt",)
        assert self.bridge.get_scanner_for_agent(spec) == "jwt_scanner"


class TestBridgeCoverage:
    def test_coverage_report(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())
        # Load real agents
        from secprobe.swarm.registry import SwarmRegistry
        registry = SwarmRegistry()
        registry.load_all()

        all_agents = list(registry._agents.values())
        report = bridge.get_coverage_report(all_agents)

        assert report["total_agents"] == 600
        assert report["mapped_scanners"] >= 20  # At least 20 different scanners used
        assert report["unmapped_agents"] < 500  # Some agents have niche attack types

    def test_coverage_report_empty_agents(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())
        report = bridge.get_coverage_report([])
        assert report["total_agents"] == 0
        assert report["mapped_scanners"] == 0
        assert report["unmapped_agents"] == 0

    def test_coverage_report_with_unmapped(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())
        spec = MagicMock()
        spec.id = "unmapped-agent"
        spec.attack_types = ("totally-unknown-type",)
        report = bridge.get_coverage_report([spec])
        assert report["unmapped_agents"] == 1
        assert "unmapped-agent" in report["unmapped"]


class TestBridgeExecution:
    def test_run_agent_returns_result(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())
        spec = MagicMock()
        spec.id = "test-agent"
        spec.name = "Test Agent"
        spec.division = 1
        spec.attack_types = ("headers",)

        result = bridge.run_agent(spec, "http://127.0.0.1:99999", timeout=3)
        assert isinstance(result, AgentRunResult)
        assert result.agent_id == "test-agent"
        assert result.scanner_used == "header_scanner"

    def test_run_agent_unmapped_type(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())
        spec = MagicMock()
        spec.id = "unmapped-agent"
        spec.name = "Unmapped Agent"
        spec.division = 1
        spec.attack_types = ("totally-unknown-type",)

        result = bridge.run_agent(spec, "http://127.0.0.1:99999", timeout=3)
        assert isinstance(result, AgentRunResult)
        assert result.error is not None
        assert "No scanner mapped" in result.error
        assert result.scanner_used == ""

    def test_run_agent_has_duration(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())
        spec = MagicMock()
        spec.id = "timed-agent"
        spec.name = "Timed Agent"
        spec.division = 1
        spec.attack_types = ("headers",)

        result = bridge.run_agent(spec, "http://127.0.0.1:99999", timeout=3)
        assert result.duration_seconds >= 0

    def test_run_agents_for_division_deduplicates(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())

        specs = []
        for i in range(5):
            spec = MagicMock()
            spec.id = f"sqli-agent-{i}"
            spec.name = f"SQLi Agent {i}"
            spec.division = 2
            spec.attack_types = ("sqli",)
            specs.append(spec)

        results = bridge.run_agents_for_division(specs, "http://127.0.0.1:99999")
        # Should only run sqli_scanner once despite 5 agents
        assert len(results) == 1
        assert results[0].scanner_used == "sqli_scanner"

    def test_run_agents_for_division_multiple_scanners(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())

        spec1 = MagicMock()
        spec1.id = "sqli-agent"
        spec1.name = "SQLi Agent"
        spec1.division = 2
        spec1.attack_types = ("sqli",)

        spec2 = MagicMock()
        spec2.id = "xss-agent"
        spec2.name = "XSS Agent"
        spec2.division = 2
        spec2.attack_types = ("xss",)

        results = bridge.run_agents_for_division([spec1, spec2], "http://127.0.0.1:99999")
        assert len(results) == 2
        scanner_names = {r.scanner_used for r in results}
        assert "sqli_scanner" in scanner_names
        assert "xss_scanner" in scanner_names

    def test_run_agents_respects_max_agents(self):
        bridge = AgentScannerBridge(http_client=HTTPClient())

        specs = []
        attack_types = ["sqli", "xss", "cors", "jwt", "csrf"]
        for i, atype in enumerate(attack_types):
            spec = MagicMock()
            spec.id = f"agent-{i}"
            spec.name = f"Agent {i}"
            spec.division = 1
            spec.attack_types = (atype,)
            specs.append(spec)

        results = bridge.run_agents_for_division(specs, "http://127.0.0.1:99999", max_agents=2)
        assert len(results) <= 2


class TestAgentRunResult:
    def test_default_values(self):
        result = AgentRunResult(
            agent_id="test",
            agent_name="Test",
            division=1,
            scanner_used="sqli_scanner",
        )
        assert result.findings == []
        assert result.endpoints_tested == 0
        assert result.requests_made == 0
        assert result.duration_seconds == 0.0
        assert result.error is None

    def test_with_error(self):
        result = AgentRunResult(
            agent_id="test",
            agent_name="Test",
            division=1,
            scanner_used="",
            error="Something went wrong",
        )
        assert result.error == "Something went wrong"
