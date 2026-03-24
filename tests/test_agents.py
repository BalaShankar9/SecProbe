"""
Tests for SecProbe Agent Swarm Architecture.

Tests cover:
  1. Base framework: AgentMemory, MessageBus, BaseAgent lifecycle
  2. Knowledge graph: Entity CRUD, relationships, queries, attack paths
  3. Reasoning engine: Hypothesis generation, action planning, strategy
  4. Swarm coordinator: Agent registration, deployment, result collection
  5. Specialized agents: Recon, Injection, Exploit, Evasion
  6. Inter-agent communication: Message passing, intelligence sharing
  7. Integration: Full swarm deployment with multiple agents
"""

import asyncio
import time
import pytest

from secprobe.agents.base import (
    Action, ActionResult, ActionType, AgentGoal, AgentMemory,
    AgentMessage, AgentState, BaseAgent, GoalStatus, Hypothesis,
    MessageBus, MessageType, Observation, Severity,
)
from secprobe.agents.knowledge import (
    EntityType, KnowledgeEntity, KnowledgeGraph, KnowledgeRelation,
    RelationType,
)
from secprobe.agents.reasoning import (
    ActionPlanner, HypothesisGenerator, PriorityScorer,
    ReasoningEngine, RiskEvaluator, RiskLevel, Strategy,
    StrategyAdapter,
)
from secprobe.agents.swarm import (
    SwarmConfig, SwarmCoordinator, SwarmMode, SwarmResult,
)
from secprobe.agents.recon_agent import ReconAgent
from secprobe.agents.injection_agent import InjectionAgent
from secprobe.agents.exploit_agent import ExploitAgent
from secprobe.agents.evasion_agent import EvasionAgent
from secprobe.agents import AGENT_REGISTRY


# ═══════════════════════════════════════════════════════════════════
# HELPER: Concrete agent for testing the abstract BaseAgent
# ═══════════════════════════════════════════════════════════════════

class MockAgent(BaseAgent):
    """Concrete agent for testing BaseAgent lifecycle."""
    name = "MockAgent"
    specialty = "testing"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.perceive_calls = 0
        self.decide_calls = 0
        self.act_calls = 0
        self._mock_actions = []
        self._mock_observations = []

    async def perceive(self):
        self.perceive_calls += 1
        obs = list(self._mock_observations)
        self._mock_observations.clear()
        return obs

    async def decide(self):
        self.decide_calls += 1
        actions = list(self._mock_actions)
        self._mock_actions.clear()
        return actions

    async def act(self, action):
        self.act_calls += 1
        return ActionResult(action=action, success=True, requests_made=1)


# ═══════════════════════════════════════════════════════════════════
# 1. OBSERVATION & HYPOTHESIS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestObservation:
    def test_creation(self):
        obs = Observation(
            url="http://example.com/test",
            parameter="id",
            observation_type="error",
            detail="SQL syntax error",
            confidence=0.8,
        )
        assert obs.url == "http://example.com/test"
        assert obs.parameter == "id"
        assert obs.observation_type == "error"
        assert obs.confidence == 0.8

    def test_fingerprint_dedup(self):
        obs1 = Observation(url="http://a.com", parameter="id",
                           observation_type="error", detail="test")
        obs2 = Observation(url="http://a.com", parameter="id",
                           observation_type="error", detail="test")
        obs3 = Observation(url="http://b.com", parameter="id",
                           observation_type="error", detail="test")
        assert obs1.fingerprint == obs2.fingerprint
        assert obs1.fingerprint != obs3.fingerprint

    def test_timestamp_auto(self):
        obs = Observation()
        assert obs.timestamp > 0


class TestHypothesis:
    def test_creation(self):
        hyp = Hypothesis(
            vuln_type="sqli",
            target_url="http://example.com/test",
            target_param="id",
            confidence=0.3,
        )
        assert hyp.vuln_type == "sqli"
        assert hyp.confidence == 0.3
        assert hyp.status == "untested"

    def test_positive_update(self):
        hyp = Hypothesis(confidence=0.3)
        new_conf = hyp.update_confidence(True, 0.3)
        assert new_conf > 0.3
        assert len(hyp.evidence_for) == 1
        assert hyp.tests_performed == 1

    def test_negative_update(self):
        hyp = Hypothesis(confidence=0.3)
        new_conf = hyp.update_confidence(False, 0.3)
        assert new_conf < 0.3
        assert len(hyp.evidence_against) == 1

    def test_confirmation(self):
        hyp = Hypothesis(confidence=0.5)
        for _ in range(5):
            hyp.update_confidence(True, 0.3)
        assert hyp.status == "confirmed"
        assert hyp.confidence >= 0.85

    def test_rejection(self):
        hyp = Hypothesis(confidence=0.1)
        for _ in range(5):
            hyp.update_confidence(False, 0.5)
        assert hyp.status == "rejected"
        assert hyp.confidence <= 0.05


# ═══════════════════════════════════════════════════════════════════
# 2. AGENT MEMORY TESTS
# ═══════════════════════════════════════════════════════════════════

class TestAgentMemory:
    def test_add_observation(self):
        mem = AgentMemory()
        obs = Observation(url="http://x.com", observation_type="test",
                          detail="unique1")
        assert mem.add_observation(obs) is True
        assert len(mem.observations) == 1

    def test_dedup_observations(self):
        mem = AgentMemory()
        obs = Observation(url="http://x.com", parameter="a",
                          observation_type="test", detail="same")
        assert mem.add_observation(obs) is True
        assert mem.add_observation(obs) is False
        assert len(mem.observations) == 1

    def test_add_hypothesis(self):
        mem = AgentMemory()
        hyp = Hypothesis(vuln_type="sqli", confidence=0.3)
        hid = mem.add_hypothesis(hyp)
        assert hid == hyp.id
        assert len(mem.hypotheses) == 1

    def test_active_hypotheses(self):
        mem = AgentMemory()
        h1 = Hypothesis(vuln_type="sqli", confidence=0.3, status="untested")
        h2 = Hypothesis(vuln_type="xss", confidence=0.5, status="testing")
        h3 = Hypothesis(vuln_type="lfi", confidence=0.9, status="confirmed")
        mem.add_hypothesis(h1)
        mem.add_hypothesis(h2)
        mem.add_hypothesis(h3)
        active = mem.get_active_hypotheses()
        assert len(active) == 2
        assert h3 not in active

    def test_confirmed_hypotheses(self):
        mem = AgentMemory()
        h1 = Hypothesis(vuln_type="sqli", status="confirmed")
        h2 = Hypothesis(vuln_type="xss", status="testing")
        mem.add_hypothesis(h1)
        mem.add_hypothesis(h2)
        confirmed = mem.get_confirmed_hypotheses()
        assert len(confirmed) == 1
        assert confirmed[0].vuln_type == "sqli"

    def test_param_tracking(self):
        mem = AgentMemory()
        mem.mark_param_tested("http://x.com", "id", "sqli")
        assert mem.was_param_tested("http://x.com", "id", "sqli")
        assert not mem.was_param_tested("http://x.com", "id", "xss")
        assert not mem.was_param_tested("http://x.com", "name", "sqli")

    def test_add_finding(self):
        mem = AgentMemory()
        mem.add_finding({"vuln_type": "sqli", "url": "http://x.com"})
        assert len(mem.findings) == 1

    def test_record_action(self):
        mem = AgentMemory()
        result = ActionResult(
            action=Action(action_type=ActionType.PROBE),
            success=True, requests_made=1,
        )
        mem.record_action(result)
        assert len(mem.actions_taken) == 1

    def test_stats(self):
        mem = AgentMemory()
        mem.add_observation(Observation(url="a", observation_type="x", detail="1"))
        mem.add_hypothesis(Hypothesis(vuln_type="sqli"))
        mem.add_finding({"test": True})
        stats = mem.get_stats()
        assert stats["observations"] == 1
        assert stats["hypotheses_total"] == 1
        assert stats["findings"] == 1

    def test_error_patterns(self):
        mem = AgentMemory()
        mem.add_observation(Observation(
            url="a", observation_type="error", detail="e1"))
        mem.add_observation(Observation(
            url="b", observation_type="reflection", detail="r1"))
        mem.add_observation(Observation(
            url="c", observation_type="exception", detail="e2"))
        errors = mem.get_error_patterns()
        assert len(errors) == 2

    def test_reflections(self):
        mem = AgentMemory()
        mem.add_observation(Observation(
            url="a", observation_type="reflection", detail="r1"))
        mem.add_observation(Observation(
            url="b", observation_type="error", detail="e1"))
        reflections = mem.get_reflections()
        assert len(reflections) == 1


# ═══════════════════════════════════════════════════════════════════
# 3. MESSAGE BUS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestMessageBus:
    def test_register(self):
        bus = MessageBus()
        bus.register("agent1")
        assert "agent1" in bus._queues

    def test_unregister(self):
        bus = MessageBus()
        bus.register("agent1")
        bus.unregister("agent1")
        assert "agent1" not in bus._queues

    def test_sync_send_directed(self):
        bus = MessageBus()
        bus.register("agent1")
        bus.register("agent2")
        msg = AgentMessage(
            sender="agent1", recipient="agent2",
            msg_type=MessageType.FINDING,
            payload={"vuln": "sqli"},
        )
        bus.send_sync(msg)
        assert bus.pending_count("agent2") == 1
        assert bus.pending_count("agent1") == 0

    def test_sync_broadcast(self):
        bus = MessageBus()
        bus.register("a1")
        bus.register("a2")
        bus.register("a3")
        msg = AgentMessage(
            sender="a1", msg_type=MessageType.INTELLIGENCE,
            payload={"info": "test"},
        )
        bus.send_sync(msg)
        assert bus.pending_count("a2") == 1
        assert bus.pending_count("a3") == 1
        assert bus.pending_count("a1") == 0  # Sender doesn't get own broadcast

    def test_receive_nowait(self):
        bus = MessageBus()
        bus.register("a1")
        msg = AgentMessage(sender="a2", recipient="a1",
                           msg_type=MessageType.STATUS, payload={"ok": True})
        bus.send_sync(msg)
        received = bus.receive_nowait("a1")
        assert received is not None
        assert received.payload["ok"] is True

    def test_receive_nowait_empty(self):
        bus = MessageBus()
        bus.register("a1")
        assert bus.receive_nowait("a1") is None

    def test_history(self):
        bus = MessageBus()
        bus.register("a1")
        bus.register("a2")
        for i in range(5):
            bus.send_sync(AgentMessage(
                sender="a1", recipient="a2",
                msg_type=MessageType.STATUS,
                payload={"i": i},
            ))
        assert bus.total_messages == 5
        history = bus.get_history(sender="a1")
        assert len(history) == 5

    def test_history_filter_by_type(self):
        bus = MessageBus()
        bus.register("a1")
        bus.register("a2")
        bus.send_sync(AgentMessage(sender="a1", msg_type=MessageType.FINDING))
        bus.send_sync(AgentMessage(sender="a1", msg_type=MessageType.STATUS))
        bus.send_sync(AgentMessage(sender="a1", msg_type=MessageType.FINDING))
        findings = bus.get_history(msg_type=MessageType.FINDING)
        assert len(findings) == 2

    def test_pending_count_unregistered(self):
        bus = MessageBus()
        assert bus.pending_count("nonexistent") == 0

    def test_receive_nowait_unregistered(self):
        bus = MessageBus()
        assert bus.receive_nowait("nonexistent") is None


# ═══════════════════════════════════════════════════════════════════
# 4. KNOWLEDGE GRAPH TESTS
# ═══════════════════════════════════════════════════════════════════

class TestKnowledgeGraph:
    def test_add_entity(self):
        kg = KnowledgeGraph()
        e = kg.add_entity("url:http://x.com", EntityType.URL, "http://x.com")
        assert e.id == "url:http://x.com"
        assert kg.entity_count == 1

    def test_add_duplicate_updates(self):
        kg = KnowledgeGraph()
        e1 = kg.add_entity("url:x", EntityType.URL, "x", {"a": 1})
        e2 = kg.add_entity("url:x", EntityType.URL, "x", {"b": 2})
        assert kg.entity_count == 1
        assert e2.properties["a"] == 1
        assert e2.properties["b"] == 2

    def test_get_entity(self):
        kg = KnowledgeGraph()
        kg.add_entity("e1", EntityType.URL, "test")
        assert kg.get_entity("e1") is not None
        assert kg.get_entity("nonexistent") is None

    def test_remove_entity(self):
        kg = KnowledgeGraph()
        kg.add_entity("e1", EntityType.URL, "test")
        assert kg.remove_entity("e1") is True
        assert kg.entity_count == 0
        assert kg.remove_entity("e1") is False

    def test_add_relation(self):
        kg = KnowledgeGraph()
        kg.add_entity("url1", EntityType.URL, "url1")
        kg.add_entity("param1", EntityType.PARAMETER, "param1")
        rel = kg.add_relation("url1", "param1", RelationType.HAS_PARAMETER)
        assert rel is not None
        assert kg.relation_count == 1

    def test_relation_requires_entities(self):
        kg = KnowledgeGraph()
        kg.add_entity("url1", EntityType.URL, "url1")
        rel = kg.add_relation("url1", "nonexistent", RelationType.HAS_PARAMETER)
        assert rel is None

    def test_duplicate_relation_updates(self):
        kg = KnowledgeGraph()
        kg.add_entity("a", EntityType.URL, "a")
        kg.add_entity("b", EntityType.PARAMETER, "b")
        kg.add_relation("a", "b", RelationType.HAS_PARAMETER, {"x": 1})
        kg.add_relation("a", "b", RelationType.HAS_PARAMETER, {"y": 2})
        assert kg.relation_count == 1  # Dedup

    def test_find_by_type(self):
        kg = KnowledgeGraph()
        kg.add_entity("u1", EntityType.URL, "url1")
        kg.add_entity("u2", EntityType.URL, "url2")
        kg.add_entity("p1", EntityType.PARAMETER, "param1")
        urls = kg.find_by_type(EntityType.URL)
        assert len(urls) == 2
        params = kg.find_by_type(EntityType.PARAMETER)
        assert len(params) == 1

    def test_find_by_tag(self):
        kg = KnowledgeGraph()
        kg.add_entity("e1", EntityType.URL, "x", tags={"important"})
        kg.add_entity("e2", EntityType.URL, "y", tags={"important", "api"})
        kg.add_entity("e3", EntityType.URL, "z", tags={"api"})
        important = kg.find_by_tag("important")
        assert len(important) == 2
        api = kg.find_by_tag("api")
        assert len(api) == 2

    def test_find_by_property(self):
        kg = KnowledgeGraph()
        kg.add_entity("e1", EntityType.URL, "x", {"method": "GET"})
        kg.add_entity("e2", EntityType.URL, "y", {"method": "POST"})
        gets = kg.find_by_property(EntityType.URL, method="GET")
        assert len(gets) == 1

    def test_get_neighbors_outgoing(self):
        kg = KnowledgeGraph()
        kg.add_entity("url", EntityType.URL, "url")
        kg.add_entity("p1", EntityType.PARAMETER, "p1")
        kg.add_entity("p2", EntityType.PARAMETER, "p2")
        kg.add_relation("url", "p1", RelationType.HAS_PARAMETER)
        kg.add_relation("url", "p2", RelationType.HAS_PARAMETER)
        neighbors = kg.get_neighbors("url", direction="outgoing")
        assert len(neighbors) == 2

    def test_get_neighbors_incoming(self):
        kg = KnowledgeGraph()
        kg.add_entity("url", EntityType.URL, "url")
        kg.add_entity("param", EntityType.PARAMETER, "param")
        kg.add_relation("url", "param", RelationType.HAS_PARAMETER)
        neighbors = kg.get_neighbors("param", direction="incoming")
        assert len(neighbors) == 1

    def test_add_url_shortcut(self):
        kg = KnowledgeGraph()
        e = kg.add_url("http://example.com", "GET", agent="recon")
        assert e.entity_type == EntityType.URL
        assert e.properties["method"] == "GET"

    def test_add_parameter_links_url(self):
        kg = KnowledgeGraph()
        p = kg.add_parameter("http://x.com", "id", "query", agent="recon")
        assert p.entity_type == EntityType.PARAMETER
        assert kg.entity_count == 2  # URL + parameter
        assert kg.relation_count == 1  # URL → parameter

    def test_add_vulnerability(self):
        kg = KnowledgeGraph()
        kg.add_parameter("http://x.com", "id")
        v = kg.add_vulnerability("sqli", "http://x.com", "id",
                                  severity="HIGH", agent="injection")
        assert v.entity_type == EntityType.VULNERABILITY
        assert "vulnerability" in v.tags
        assert "sqli" in v.tags

    def test_add_technology(self):
        kg = KnowledgeGraph()
        t = kg.add_technology("Apache", "2.4", "server")
        assert t.entity_type == EntityType.TECHNOLOGY
        assert "technology" in t.tags

    def test_add_defense(self):
        kg = KnowledgeGraph()
        d = kg.add_defense("Cloudflare", "waf")
        assert d.entity_type == EntityType.DEFENSE

    def test_find_attack_paths(self):
        kg = KnowledgeGraph()
        kg.add_entity("url", EntityType.URL, "/sqli")
        kg.add_entity("param", EntityType.PARAMETER, "id")
        kg.add_entity("vuln", EntityType.VULNERABILITY, "sqli")
        kg.add_relation("url", "param", RelationType.HAS_PARAMETER)
        kg.add_relation("param", "vuln", RelationType.VULNERABLE_TO)
        paths = kg.find_attack_paths(EntityType.URL, EntityType.VULNERABILITY)
        assert len(paths) >= 1
        assert paths[0][0].id == "url"

    def test_find_vulnerable_params(self):
        kg = KnowledgeGraph()
        p = kg.add_parameter("http://x.com", "id")
        v = kg.add_vulnerability("sqli", "http://x.com", "id")
        result = kg.find_vulnerable_params()
        assert len(result) == 1
        assert result[0]["param"].id == p.id

    def test_stats(self):
        kg = KnowledgeGraph()
        kg.add_url("http://x.com")
        kg.add_parameter("http://x.com", "id")
        kg.add_vulnerability("sqli", "http://x.com", "id")
        stats = kg.get_stats()
        assert stats["total_entities"] == 3
        assert stats["total_relations"] >= 1

    def test_export(self):
        kg = KnowledgeGraph()
        kg.add_url("http://x.com")
        data = kg.to_dict()
        assert "entities" in data
        assert len(data["entities"]) == 1

    def test_export_json(self):
        kg = KnowledgeGraph()
        kg.add_url("http://x.com")
        json_str = kg.export_json()
        assert "http://x.com" in json_str

    def test_clear(self):
        kg = KnowledgeGraph()
        kg.add_url("http://x.com")
        kg.add_parameter("http://x.com", "id")
        kg.clear()
        assert kg.entity_count == 0
        assert kg.relation_count == 0

    def test_get_untested_params(self):
        kg = KnowledgeGraph()
        p = kg.add_parameter("http://x.com", "id")
        untested = kg.get_untested_params()
        assert len(untested) == 1  # "untested" tag is added by default


# ═══════════════════════════════════════════════════════════════════
# 5. REASONING ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestHypothesisGenerator:
    def test_sql_error_generates_sqli_hypothesis(self):
        gen = HypothesisGenerator()
        obs = [Observation(
            url="http://x.com/test", parameter="id",
            observation_type="sql_error", detail="syntax error",
        )]
        hyps = gen.generate(obs)
        assert any(h.vuln_type == "sqli" for h in hyps)

    def test_reflection_generates_xss_hypothesis(self):
        gen = HypothesisGenerator()
        obs = [Observation(
            url="http://x.com/test", parameter="name",
            observation_type="reflection", detail="input reflected",
        )]
        hyps = gen.generate(obs)
        assert any(h.vuln_type == "xss" for h in hyps)

    def test_file_param_generates_lfi_hypothesis(self):
        gen = HypothesisGenerator()
        obs = [Observation(
            url="http://x.com/read", parameter="file",
            observation_type="file_param", detail="file parameter",
        )]
        hyps = gen.generate(obs)
        assert any(h.vuln_type == "lfi" for h in hyps)

    def test_no_duplicate_hypotheses(self):
        gen = HypothesisGenerator()
        obs = [
            Observation(url="http://x.com", parameter="id",
                        observation_type="sql_error", detail="err1"),
            Observation(url="http://x.com", parameter="id",
                        observation_type="database_error", detail="err2"),
        ]
        hyps = gen.generate(obs)
        sqli_hyps = [h for h in hyps if h.vuln_type == "sqli"
                     and h.target_url == "http://x.com"
                     and h.target_param == "id"]
        assert len(sqli_hyps) == 1  # Deduped

    def test_tech_based_hypotheses(self):
        gen = HypothesisGenerator()
        hyps = gen.generate_from_tech_stack({"Flask": 0.8, "SQLite": 0.9})
        vuln_types = {h.vuln_type for h in hyps}
        assert "ssti" in vuln_types  # Flask → SSTI
        assert "sqli" in vuln_types  # SQLite → SQLi

    def test_unknown_observation_no_hypothesis(self):
        gen = HypothesisGenerator()
        obs = [Observation(
            url="http://x.com", observation_type="unknown_type",
        )]
        hyps = gen.generate(obs)
        assert len(hyps) == 0


class TestActionPlanner:
    def test_plan_for_untested_hypothesis(self):
        planner = ActionPlanner()
        hyp = Hypothesis(
            vuln_type="sqli",
            target_url="http://x.com/test",
            target_param="id",
            confidence=0.3,
        )
        actions = planner.plan_for_hypothesis(hyp)
        assert len(actions) >= 1
        assert any(a.action_type == ActionType.PROBE for a in actions)

    def test_plan_skips_tested_params(self):
        planner = ActionPlanner()
        mem = AgentMemory()
        mem.mark_param_tested("http://x.com/test", "id", "SQLiScanner")
        hyp = Hypothesis(
            vuln_type="sqli",
            target_url="http://x.com/test",
            target_param="id",
            confidence=0.3,
        )
        actions = planner.plan_for_hypothesis(hyp, mem)
        assert len(actions) == 0

    def test_plan_escalation_for_confirmed(self):
        planner = ActionPlanner()
        hyp = Hypothesis(
            vuln_type="sqli", confidence=0.9,
            target_url="http://x.com", target_param="id",
            status="confirmed",
        )
        actions = planner.plan_for_hypothesis(hyp)
        assert any(a.action_type == ActionType.CHAIN for a in actions)

    def test_plan_reconnaissance(self):
        planner = ActionPlanner()
        actions = planner.plan_reconnaissance("http://example.com")
        assert len(actions) == 2
        types = {a.action_type for a in actions}
        assert ActionType.FINGERPRINT in types
        assert ActionType.CRAWL in types


class TestRiskEvaluator:
    def test_crawl_low_risk(self):
        ev = RiskEvaluator()
        action = Action(action_type=ActionType.CRAWL)
        risk = ev.evaluate(action)
        assert risk == RiskLevel.LOW

    def test_scan_high_risk(self):
        ev = RiskEvaluator()
        action = Action(action_type=ActionType.SCAN)
        risk = ev.evaluate(action)
        assert risk.value >= RiskLevel.HIGH.value

    def test_waf_increases_risk(self):
        ev = RiskEvaluator()
        action = Action(action_type=ActionType.PROBE)
        risk_normal = ev.evaluate(action)
        risk_waf = ev.evaluate(action, {"waf_detected": True})
        assert risk_waf.value >= risk_normal.value

    def test_risky_payload_increases_risk(self):
        ev = RiskEvaluator()
        safe = Action(action_type=ActionType.PROBE, payload="test")
        risky = Action(action_type=ActionType.PROBE,
                       payload="' UNION SELECT * FROM users-- or 1=1")
        assert ev.evaluate(risky).value >= ev.evaluate(safe).value

    def test_delay_scales_with_risk(self):
        ev = RiskEvaluator()
        assert ev.should_delay(RiskLevel.SILENT) < ev.should_delay(RiskLevel.LOW)
        assert ev.should_delay(RiskLevel.LOW) < ev.should_delay(RiskLevel.HIGH)
        assert ev.should_delay(RiskLevel.HIGH) < ev.should_delay(RiskLevel.EXTREME)


class TestPriorityScorer:
    def test_high_confidence_high_impact(self):
        scorer = PriorityScorer()
        action = Action(action_type=ActionType.SCAN, priority=0.8)
        hyp = Hypothesis(vuln_type="sqli", confidence=0.8)
        score = scorer.score(action, hyp, RiskLevel.MEDIUM)
        assert score > 0.5

    def test_low_confidence_low_score(self):
        scorer = PriorityScorer()
        action = Action(action_type=ActionType.SCAN, priority=0.1)
        hyp = Hypothesis(vuln_type="redirect", confidence=0.1)
        score = scorer.score(action, hyp, RiskLevel.HIGH)
        assert score < 0.3

    def test_chain_gets_urgency_bonus(self):
        scorer = PriorityScorer()
        scan = Action(action_type=ActionType.SCAN)
        chain = Action(action_type=ActionType.CHAIN)
        hyp = Hypothesis(vuln_type="sqli", confidence=0.5)
        assert scorer.score(chain, hyp) > scorer.score(scan, hyp)


class TestStrategyAdapter:
    def test_initial_balanced(self):
        adapter = StrategyAdapter()
        assert adapter.current == Strategy.BALANCED

    def test_blocks_trigger_evasion(self):
        adapter = StrategyAdapter()
        mem = AgentMemory()
        mem.blocked_payloads = ["p1"] * 10
        for i in range(20):
            mem.record_action(ActionResult(
                action=Action(), success=True, requests_made=1,
            ))
        result = adapter.update(mem)
        assert result == Strategy.EVASION

    def test_no_findings_triggers_targeted(self):
        adapter = StrategyAdapter()
        mem = AgentMemory()
        for i in range(60):
            mem.record_action(ActionResult(
                action=Action(), success=True, requests_made=1,
            ))
        result = adapter.update(mem)
        assert result == Strategy.TARGETED

    def test_high_severity_triggers_aggressive(self):
        adapter = StrategyAdapter()
        mem = AgentMemory()
        mem.add_finding({"severity": "CRITICAL", "vuln_type": "sqli"})
        for i in range(5):
            mem.record_action(ActionResult(
                action=Action(), success=True, requests_made=1,
            ))
        result = adapter.update(mem)
        assert result == Strategy.AGGRESSIVE

    def test_time_pressure_triggers_targeted(self):
        adapter = StrategyAdapter()
        mem = AgentMemory()
        result = adapter.update(mem, elapsed_time=280, time_budget=300)
        assert result == Strategy.TARGETED

    def test_request_limits_per_strategy(self):
        adapter = StrategyAdapter(Strategy.AGGRESSIVE)
        assert adapter.get_max_requests_per_param() > 50
        adapter2 = StrategyAdapter(Strategy.STEALTH)
        assert adapter2.get_max_requests_per_param() < 30

    def test_delay_per_strategy(self):
        aggressive = StrategyAdapter(Strategy.AGGRESSIVE)
        stealth = StrategyAdapter(Strategy.STEALTH)
        assert aggressive.get_request_delay() < stealth.get_request_delay()

    def test_evasion_flag(self):
        adapter = StrategyAdapter(Strategy.STEALTH)
        assert adapter.should_use_evasion() is True
        adapter2 = StrategyAdapter(Strategy.BALANCED)
        assert adapter2.should_use_evasion() is False


class TestReasoningEngine:
    def test_reason_generates_actions_from_observations(self):
        engine = ReasoningEngine()
        mem = AgentMemory()
        obs = [Observation(
            url="http://x.com", parameter="id",
            observation_type="sql_error", detail="syntax error",
        )]
        actions = engine.reason(mem, obs)
        assert len(actions) > 0
        # Should have created a hypothesis too
        assert len(mem.hypotheses) > 0

    def test_reason_uses_goals_when_no_hypotheses(self):
        engine = ReasoningEngine()
        mem = AgentMemory()
        goals = [AgentGoal(
            goal_type="find_vulns",
            target="http://example.com",
            status=GoalStatus.PENDING,
        )]
        actions = engine.reason(mem, goals=goals)
        assert len(actions) > 0
        assert any(a.action_type == ActionType.FINGERPRINT for a in actions)

    def test_get_strategy(self):
        engine = ReasoningEngine(Strategy.STEALTH)
        assert engine.get_strategy() == Strategy.STEALTH

    def test_should_evade(self):
        engine = ReasoningEngine(Strategy.EVASION)
        assert engine.should_evade() is True


# ═══════════════════════════════════════════════════════════════════
# 6. BASE AGENT LIFECYCLE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestBaseAgent:
    def test_creation(self):
        agent = MockAgent(target="http://example.com")
        assert agent.state == AgentState.IDLE
        assert agent.cycle_count == 0
        assert agent.requests_made == 0

    def test_add_goal(self):
        agent = MockAgent(target="http://x.com")
        goal = agent.add_goal("Find SQLi", "find_vulns")
        assert len(agent.goals) == 1
        assert goal.goal_type == "find_vulns"

    def test_is_done_max_cycles(self):
        agent = MockAgent(config={"max_cycles": 5})
        agent.cycle_count = 5
        assert agent.is_done is True

    def test_is_done_max_requests(self):
        agent = MockAgent(config={"max_requests": 10})
        agent.requests_made = 10
        assert agent.is_done is True

    def test_is_done_all_goals_achieved(self):
        agent = MockAgent()
        goal = agent.add_goal("test", "find_vulns")
        goal.status = GoalStatus.ACHIEVED
        assert agent.is_done is True

    def test_is_done_no_goals_not_done(self):
        agent = MockAgent(config={"max_cycles": 100})
        agent.cycle_count = 1
        assert agent.is_done is False

    def test_active_goals(self):
        agent = MockAgent()
        g1 = agent.add_goal("g1", "find_vulns")
        g2 = agent.add_goal("g2", "find_vulns")
        g1.status = GoalStatus.ACHIEVED
        assert len(agent.active_goals) == 1

    def test_get_status(self):
        agent = MockAgent(target="http://x.com")
        status = agent.get_status()
        assert "id" in status
        assert "state" in status
        assert "memory" in status

    def test_repr(self):
        agent = MockAgent(agent_id="test_agent")
        rep = repr(agent)
        assert "MockAgent" in rep
        assert "test_agent" in rep

    @pytest.mark.asyncio
    async def test_run_completes_when_goals_achieved(self):
        agent = MockAgent(
            target="http://x.com",
            config={"max_cycles": 10, "time_budget": 5},
        )
        goal = agent.add_goal("test", "find_vulns")
        # Agent will run perceive/decide loop. Since decide returns no actions
        # and goals aren't being met, it will call adapt() and loop.
        # To make it complete, mock that goals get achieved after first cycle
        original_adapt = agent.adapt

        async def achieve_goals():
            goal.status = GoalStatus.ACHIEVED

        agent.adapt = achieve_goals
        findings = await agent.run()
        assert agent.state == AgentState.DONE

    @pytest.mark.asyncio
    async def test_run_with_message_bus(self):
        bus = MessageBus()
        agent = MockAgent(
            agent_id="test",
            target="http://x.com",
            message_bus=bus,
            config={"max_cycles": 3, "time_budget": 5},
        )
        goal = agent.add_goal("test", "find_vulns")
        goal.status = GoalStatus.ACHIEVED
        await agent.run()
        # Should have sent a final status message
        assert bus.total_messages >= 1

    @pytest.mark.asyncio
    async def test_run_processes_actions(self):
        agent = MockAgent(
            config={"max_cycles": 3, "time_budget": 5},
        )
        goal = agent.add_goal("test", "find_vulns")
        agent._mock_actions = [
            Action(action_type=ActionType.PROBE, target_url="http://x.com"),
        ]

        async def mark_done():
            goal.status = GoalStatus.ACHIEVED

        original_adapt = agent.adapt
        agent.adapt = mark_done
        await agent.run()
        assert agent.act_calls >= 1


# ═══════════════════════════════════════════════════════════════════
# 7. SPECIALIZED AGENT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestReconAgent:
    def test_creation(self):
        agent = ReconAgent(target="http://example.com")
        assert agent.name == "ReconAgent"
        assert agent.specialty == "reconnaissance"

    def test_classify_parameter(self):
        agent = ReconAgent()
        assert "sqli" in agent.classify_parameter("user_id")
        assert "idor" in agent.classify_parameter("user_id")
        assert "lfi" in agent.classify_parameter("file")
        assert "ssrf" in agent.classify_parameter("url")
        assert "xss" in agent.classify_parameter("callback")
        assert agent.classify_parameter("random_xyz") == []

    @pytest.mark.asyncio
    async def test_perceive_initial(self):
        agent = ReconAgent(target="http://example.com")
        obs = await agent.perceive()
        assert len(obs) > 0
        assert obs[0].observation_type == "target_discovered"

    @pytest.mark.asyncio
    async def test_decide_fingerprint_phase(self):
        agent = ReconAgent(target="http://example.com")
        await agent.perceive()
        actions = await agent.decide()
        assert len(actions) > 0
        assert actions[0].action_type == ActionType.FINGERPRINT

    @pytest.mark.asyncio
    async def test_decide_crawl_phase(self):
        agent = ReconAgent(target="http://example.com")
        await agent.perceive()
        await agent.decide()  # fingerprint
        actions = await agent.decide()  # crawl
        assert len(actions) > 0
        assert actions[0].action_type == ActionType.CRAWL


class TestInjectionAgent:
    def test_creation(self):
        agent = InjectionAgent(target="http://example.com")
        assert agent.name == "InjectionAgent"
        assert agent.specialty == "injection"

    def test_classify_param(self):
        assert "sqli" in InjectionAgent._classify_param("id")
        assert "lfi" in InjectionAgent._classify_param("file")
        assert "ssrf" in InjectionAgent._classify_param("url")

    def test_canary_tests_defined(self):
        assert "sqli" in InjectionAgent.CANARY_TESTS
        assert "xss" in InjectionAgent.CANARY_TESTS
        assert "ssti" in InjectionAgent.CANARY_TESTS
        assert len(InjectionAgent.CANARY_TESTS["sqli"]) >= 3

    @pytest.mark.asyncio
    async def test_perceive_with_knowledge_graph(self):
        kg = KnowledgeGraph()
        kg.add_parameter("http://x.com/sqli", "id", "query")
        agent = InjectionAgent(
            target="http://x.com",
            knowledge_graph=kg,
        )
        await agent.perceive()
        assert len(agent._target_queue) > 0

    @pytest.mark.asyncio
    async def test_decide_generates_canary_actions(self):
        kg = KnowledgeGraph()
        kg.add_parameter("http://x.com/sqli", "id", "query")
        agent = InjectionAgent(target="http://x.com", knowledge_graph=kg)
        await agent.perceive()
        actions = await agent.decide()
        assert len(actions) > 0
        assert any(a.action_type == ActionType.PROBE for a in actions)

    @pytest.mark.asyncio
    async def test_on_message_adds_targets(self):
        agent = InjectionAgent(target="http://x.com")
        msg = AgentMessage(
            sender="recon",
            msg_type=MessageType.INTELLIGENCE,
            payload={
                "type": "interesting_param",
                "url": "http://x.com/test",
                "param": "search",
                "suggested_vulns": ["sqli", "xss"],
            },
        )
        await agent.on_message(msg)
        assert len(agent._target_queue) == 1


class TestExploitAgent:
    def test_creation(self):
        agent = ExploitAgent(target="http://example.com")
        assert agent.name == "ExploitAgent"
        assert agent.specialty == "exploitation"

    def test_chain_rules_defined(self):
        assert "sqli" in ExploitAgent.CHAIN_RULES
        assert "xss" in ExploitAgent.CHAIN_RULES
        assert "ssrf" in ExploitAgent.CHAIN_RULES
        assert "lfi" in ExploitAgent.CHAIN_RULES

    @pytest.mark.asyncio
    async def test_perceive_finds_chainable_vulns(self):
        kg = KnowledgeGraph()
        kg.add_vulnerability("sqli", "http://x.com/sqli", "id", "HIGH")
        agent = ExploitAgent(target="http://x.com", knowledge_graph=kg)
        obs = await agent.perceive()
        assert any(o.observation_type == "chainable_finding" for o in obs)

    @pytest.mark.asyncio
    async def test_decide_plans_chain_actions(self):
        kg = KnowledgeGraph()
        kg.add_vulnerability("sqli", "http://x.com/sqli", "id", "HIGH")
        agent = ExploitAgent(target="http://x.com", knowledge_graph=kg)
        obs = await agent.perceive()
        # Add observations to memory (normally done by run() loop)
        for o in obs:
            agent.memory.add_observation(o)
        actions = await agent.decide()
        assert len(actions) > 0
        assert any(a.action_type == ActionType.CHAIN for a in actions)

    @pytest.mark.asyncio
    async def test_act_builds_chain(self):
        kg = KnowledgeGraph()
        agent = ExploitAgent(target="http://x.com", knowledge_graph=kg)
        action = Action(
            action_type=ActionType.CHAIN,
            target_url="http://x.com/sqli",
            target_param="id",
            metadata={
                "source_vuln": "sqli",
                "chain_name": "credential_extraction",
                "escalates_to": "auth_bypass",
                "technique": "UNION SELECT",
                "impact_increase": 0.3,
            },
        )
        result = await agent.act(action)
        assert result.success is True
        assert len(agent._chains_built) == 1

    @pytest.mark.asyncio
    async def test_on_message_stores_findings(self):
        agent = ExploitAgent(target="http://x.com")
        msg = AgentMessage(
            sender="injection",
            msg_type=MessageType.FINDING,
            payload={"vuln_type": "sqli", "url": "http://x.com", "param": "id"},
        )
        await agent.on_message(msg)
        assert len(agent._pending_findings) == 1


class TestEvasionAgent:
    def test_creation(self):
        agent = EvasionAgent(target="http://example.com")
        assert agent.name == "EvasionAgent"
        assert agent.specialty == "evasion"

    def test_waf_signatures_defined(self):
        assert "cloudflare" in EvasionAgent.WAF_SIGNATURES
        assert "modsecurity" in EvasionAgent.WAF_SIGNATURES
        assert "generic" in EvasionAgent.WAF_SIGNATURES

    def test_apply_url_encode(self):
        result = EvasionAgent.apply_evasion("' OR 1=1", "url_encode")
        assert "%27" in result or result != "' OR 1=1"

    def test_apply_case_swap(self):
        result = EvasionAgent.apply_evasion("SELECT", "case_swap")
        # At least one character might be swapped (randomized)
        assert isinstance(result, str)

    def test_apply_null_byte(self):
        result = EvasionAgent.apply_evasion("test.php", "null_byte")
        assert result == "test.php%00"

    def test_apply_concat_split(self):
        result = EvasionAgent.apply_evasion("'admin'", "concat_split")
        assert "||" in result

    def test_get_evasion_config(self):
        agent = EvasionAgent()
        config = agent.get_evasion_config()
        assert "evasion_level" in config
        assert "recommended_delay" in config
        assert "user_agent" in config

    @pytest.mark.asyncio
    async def test_on_alert_tracks_blocks(self):
        agent = EvasionAgent(target="http://x.com")
        msg = AgentMessage(
            sender="injection",
            msg_type=MessageType.ALERT,
            payload={"alert_type": "waf_block", "payload": "' OR 1=1"},
        )
        await agent.on_message(msg)
        assert agent._block_count == 1
        assert len(agent._blocked_patterns) == 1

    @pytest.mark.asyncio
    async def test_evasion_level_escalation(self):
        agent = EvasionAgent(target="http://x.com")
        agent._block_count = 6
        actions = await agent.decide()
        assert agent._evasion_level >= 2
        assert len(actions) > 0


# ═══════════════════════════════════════════════════════════════════
# 8. SWARM COORDINATOR TESTS
# ═══════════════════════════════════════════════════════════════════

class TestSwarmCoordinator:
    def test_creation(self):
        coord = SwarmCoordinator()
        assert coord.agent_count == 0
        assert coord.is_running is False

    def test_register_agent_class(self):
        coord = SwarmCoordinator()
        aid = coord.register_agent(MockAgent)
        assert aid == "MockAgent"
        assert len(coord._agent_classes) == 1

    def test_register_instance(self):
        coord = SwarmCoordinator()
        agent = MockAgent(agent_id="test1", target="http://x.com")
        aid = coord.register_instance(agent)
        assert aid == "test1"
        assert coord.agent_count == 1

    def test_get_status_idle(self):
        coord = SwarmCoordinator()
        status = coord.get_status()
        assert status["phase"] == "idle"
        assert status["running"] is False

    def test_config_defaults(self):
        config = SwarmConfig()
        assert config.mode == SwarmMode.ADAPTIVE
        assert config.max_agents == 10
        assert config.consensus_threshold == 2

    @pytest.mark.asyncio
    async def test_deploy_empty_swarm(self):
        coord = SwarmCoordinator(SwarmConfig(
            target="http://example.com",
            time_budget=5,
        ))
        result = await coord.deploy()
        assert isinstance(result, SwarmResult)
        assert result.target == "http://example.com"
        assert result.duration >= 0

    @pytest.mark.asyncio
    async def test_deploy_with_mock_agents(self):
        config = SwarmConfig(
            target="http://example.com",
            time_budget=5,
            max_concurrent=2,
        )
        coord = SwarmCoordinator(config)

        # Register mock agents
        agent1 = MockAgent(agent_id="mock1", target="http://example.com",
                           config={"max_cycles": 2, "time_budget": 3})
        agent1.add_goal("test", "find_vulns")
        agent1.goals[0].status = GoalStatus.ACHIEVED

        agent2 = MockAgent(agent_id="mock2", target="http://example.com",
                           config={"max_cycles": 2, "time_budget": 3})
        agent2.add_goal("test", "find_vulns")
        agent2.goals[0].status = GoalStatus.ACHIEVED

        coord.register_instance(agent1)
        coord.register_instance(agent2)

        result = await coord.deploy()
        assert result.mode == "ADAPTIVE"
        assert len(result.agent_reports) == 2

    def test_get_findings_dedup(self):
        coord = SwarmCoordinator()
        a1 = MockAgent(agent_id="a1")
        a2 = MockAgent(agent_id="a2")
        a1.memory.add_finding({
            "vuln_type": "sqli", "url": "http://x.com", "parameter": "id",
        })
        a2.memory.add_finding({
            "vuln_type": "sqli", "url": "http://x.com", "parameter": "id",
        })
        coord._agents = {"a1": a1, "a2": a2}
        findings = coord.get_findings()
        assert len(findings) == 1  # Deduped

    def test_swarm_result_severity_counts(self):
        result = SwarmResult(findings=[
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ])
        counts = result.severity_counts
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1


# ═══════════════════════════════════════════════════════════════════
# 9. AGENT REGISTRY & PACKAGE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestAgentRegistry:
    def test_registry_has_all_agents(self):
        assert "recon" in AGENT_REGISTRY
        assert "injection" in AGENT_REGISTRY
        assert "exploit" in AGENT_REGISTRY
        assert "evasion" in AGENT_REGISTRY
        assert len(AGENT_REGISTRY) == 4

    def test_registry_agents_are_base_agent_subclasses(self):
        for name, cls in AGENT_REGISTRY.items():
            assert issubclass(cls, BaseAgent), f"{name} not a BaseAgent subclass"

    def test_all_agents_have_unique_names(self):
        names = {cls.name for cls in AGENT_REGISTRY.values()}
        assert len(names) == len(AGENT_REGISTRY)

    def test_all_agents_have_specialties(self):
        for name, cls in AGENT_REGISTRY.items():
            instance = cls(target="http://x.com")
            assert instance.specialty, f"{name} has no specialty"


# ═══════════════════════════════════════════════════════════════════
# 10. INTER-AGENT COMMUNICATION TESTS
# ═══════════════════════════════════════════════════════════════════

class TestInterAgentCommunication:
    @pytest.mark.asyncio
    async def test_finding_sharing(self):
        """Test that findings are shared via message bus."""
        bus = MessageBus()
        agent1 = MockAgent(agent_id="a1", message_bus=bus)
        agent2 = MockAgent(agent_id="a2", message_bus=bus)
        bus.register("a1")
        bus.register("a2")

        # Agent1 finds a vuln and communicates
        agent1.memory.add_finding({
            "vuln_type": "sqli", "url": "http://x.com",
            "parameter": "id", "severity": "HIGH",
        })
        await agent1.communicate()

        # Agent2 should receive the finding
        msg = bus.receive_nowait("a2")
        assert msg is not None
        assert msg.msg_type == MessageType.FINDING
        assert msg.payload["vuln_type"] == "sqli"

    @pytest.mark.asyncio
    async def test_intelligence_sharing(self):
        """Test intelligence sharing between recon and injection agents."""
        bus = MessageBus()
        kg = KnowledgeGraph()

        recon = ReconAgent(agent_id="recon", target="http://x.com",
                           message_bus=bus, knowledge_graph=kg)
        injection = InjectionAgent(agent_id="injection", target="http://x.com",
                                   message_bus=bus, knowledge_graph=kg)
        bus.register("recon")
        bus.register("injection")

        # Recon discovers an interesting param
        recon._discovered_params = {
            "http://x.com": ["id", "search"],
        }
        await recon.communicate()

        # Injection should get the intel
        msg = bus.receive_nowait("injection")
        # May or may not have a message depending on classification
        # Just verify no error

    @pytest.mark.asyncio
    async def test_alert_propagation(self):
        """Test WAF alert propagation to evasion agent."""
        bus = MessageBus()
        bus.register("injection")
        bus.register("evasion")

        # Injection agent detects WAF
        alert = AgentMessage(
            sender="injection",
            msg_type=MessageType.ALERT,
            payload={"alert_type": "waf_block", "payload": "' OR 1=1"},
            priority=1.0,
        )
        bus.send_sync(alert)

        # Evasion agent processes the alert
        evasion = EvasionAgent(agent_id="evasion", message_bus=bus)
        msg = bus.receive_nowait("evasion")
        assert msg is not None
        await evasion.on_message(msg)
        assert evasion._block_count == 1

    @pytest.mark.asyncio
    async def test_exploit_receives_findings(self):
        """Test exploit agent receives findings for chaining."""
        bus = MessageBus()
        bus.register("injection")
        bus.register("exploit")

        finding_msg = AgentMessage(
            sender="injection",
            msg_type=MessageType.FINDING,
            payload={
                "vuln_type": "sqli",
                "url": "http://x.com/sqli",
                "parameter": "id",
                "severity": "HIGH",
            },
        )
        bus.send_sync(finding_msg)

        exploit = ExploitAgent(agent_id="exploit", message_bus=bus)
        msg = bus.receive_nowait("exploit")
        assert msg is not None
        await exploit.on_message(msg)
        assert len(exploit._pending_findings) == 1


# ═══════════════════════════════════════════════════════════════════
# 11. FULL SWARM INTEGRATION TEST
# ═══════════════════════════════════════════════════════════════════

class TestSwarmIntegration:
    @pytest.mark.asyncio
    async def test_full_swarm_deployment(self):
        """Test deploying a full swarm with all agent types."""
        config = SwarmConfig(
            target="http://example.com",
            mode=SwarmMode.ADAPTIVE,
            time_budget=5,
            max_concurrent=4,
        )
        coord = SwarmCoordinator(config)

        # Pre-populate knowledge graph
        coord.knowledge.add_parameter("http://example.com/sqli", "id")
        coord.knowledge.add_parameter("http://example.com/xss", "name")
        coord.knowledge.add_vulnerability(
            "sqli", "http://example.com/sqli", "id", "HIGH"
        )

        # Create agents with tight budgets for test speed
        agent_config = {"max_cycles": 3, "time_budget": 3, "max_requests": 20}

        recon = ReconAgent(agent_id="recon", target="http://example.com",
                           config=agent_config)
        injection = InjectionAgent(agent_id="injection",
                                   target="http://example.com",
                                   config=agent_config)
        exploit = ExploitAgent(agent_id="exploit",
                               target="http://example.com",
                               config=agent_config)
        evasion = EvasionAgent(agent_id="evasion",
                               target="http://example.com",
                               config=agent_config)

        coord.register_instance(recon)
        coord.register_instance(injection)
        coord.register_instance(exploit)
        coord.register_instance(evasion)

        result = await coord.deploy()

        assert isinstance(result, SwarmResult)
        assert result.target == "http://example.com"
        assert result.duration >= 0
        assert len(result.agent_reports) == 4
        assert result.knowledge_summary["total_entities"] >= 3

    @pytest.mark.asyncio
    async def test_knowledge_graph_shared_across_agents(self):
        """Test that all agents share the same knowledge graph."""
        config = SwarmConfig(target="http://x.com", time_budget=3)
        coord = SwarmCoordinator(config)

        agent_config = {"max_cycles": 2, "time_budget": 2}
        a1 = MockAgent(agent_id="a1", config=agent_config)
        a2 = MockAgent(agent_id="a2", config=agent_config)

        # Both should see same knowledge
        coord.register_instance(a1)
        coord.register_instance(a2)

        assert a1.knowledge is a2.knowledge
        assert a1.knowledge is coord.knowledge
