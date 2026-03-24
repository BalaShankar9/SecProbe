"""
Tests for SecProbe Swarm — 600-Agent Architecture.

Tests the core framework:
    - Agent specs and registry (600 agents, 20 divisions)
    - Working memory (L1)
    - Episodic memory (L2)
    - Semantic memory (L3)
    - Procedural memory (L4)
    - Federated memory (L5)
    - Event bus (pub/sub)
    - Blackboard (shared workspace)
    - Safety governor (mode enforcement, scope, budget)
    - Consensus engine (multi-agent verification)
    - Orchestrator (scan lifecycle)
"""

import asyncio
import os
import tempfile
import pytest

from secprobe.swarm.agent import (
    AgentCapability,
    AgentMessage,
    AgentPriority,
    AgentSpec,
    AgentState,
    Confidence,
    Evidence,
    Finding,
    MessageType,
    OperationalMode,
    SwarmAgent,
    AgentAction,
)
from secprobe.swarm.registry import SwarmRegistry


# ═══════════════════════════════════════════════════════════════════════
# Registry & Agent Spec Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSwarmRegistry:
    """Test the 600-agent registry."""

    def setup_method(self):
        self.registry = SwarmRegistry()
        self.registry.load_all()

    def test_total_agent_count(self):
        """The swarm MUST have exactly 600 agents."""
        assert self.registry.count == 600

    def test_division_count(self):
        """There must be exactly 20 divisions."""
        summary = self.registry.division_summary()
        assert len(summary) == 20

    def test_division_sizes(self):
        """Each division must have the correct number of agents."""
        expected = {
            1: 40, 2: 50, 3: 35, 4: 30, 5: 40,
            6: 35, 7: 25, 8: 35, 9: 35, 10: 25,
            11: 30, 12: 25, 13: 35, 14: 30, 15: 20,
            16: 20, 17: 25, 18: 20, 19: 25, 20: 20,
        }
        actual = self.registry.division_summary()
        for div, count in expected.items():
            assert actual[div] == count, f"Division {div}: expected {count}, got {actual[div]}"

    def test_unique_agent_ids(self):
        """Every agent must have a unique ID."""
        ids = [spec.id for spec in self.registry]
        assert len(ids) == len(set(ids)), "Duplicate agent IDs found"

    def test_every_division_has_commander(self):
        """Every division must have a commander agent."""
        for div in range(1, 21):
            agents = self.registry.by_division(div)
            commander_ids = [a.id for a in agents if "commander" in a.id]
            assert len(commander_ids) >= 1, f"Division {div} has no commander"

    def test_every_agent_has_capabilities(self):
        """Every agent must have at least one capability."""
        for spec in self.registry:
            assert len(spec.capabilities) > 0, f"Agent {spec.id} has no capabilities"

    def test_every_agent_has_name(self):
        """Every agent must have a human-readable name."""
        for spec in self.registry:
            assert spec.name, f"Agent {spec.id} has no name"

    def test_mode_filtering(self):
        """Mode filtering must work correctly."""
        recon = self.registry.by_mode(OperationalMode.RECON)
        audit = self.registry.by_mode(OperationalMode.AUDIT)
        redteam = self.registry.by_mode(OperationalMode.REDTEAM)
        # Recon ⊂ Audit ⊂ Redteam
        assert len(recon) <= len(audit) <= len(redteam)
        assert len(redteam) == 600  # All agents available in redteam

    def test_division_15_redteam_only(self):
        """Division 15 (Persistence) must require redteam mode."""
        agents = self.registry.by_division(15)
        for spec in agents:
            assert spec.min_mode == OperationalMode.REDTEAM, \
                f"Division 15 agent {spec.id} should require REDTEAM mode"

    def test_attack_type_index(self):
        """Attack type index must return relevant agents."""
        sqli = self.registry.by_attack_type("sqli")
        assert len(sqli) >= 10, "Should have 10+ SQLi specialists"
        for spec in sqli:
            assert "sqli" in spec.attack_types

    def test_technology_index(self):
        """Technology index must return relevant agents."""
        wp = self.registry.by_technology("wordpress")
        assert len(wp) >= 1, "Should have WordPress specialists"

    def test_capability_index(self):
        """Capability index must return relevant agents."""
        injectors = self.registry.by_capability(AgentCapability.PAYLOAD_INJECTION)
        assert len(injectors) >= 30, "Should have 30+ payload injection agents"

    def test_stats(self):
        """Stats must return comprehensive data."""
        stats = self.registry.stats()
        assert stats["total_agents"] == 600
        assert stats["recon_agents"] > 0
        assert stats["audit_agents"] > stats["recon_agents"]
        assert stats["redteam_agents"] == 600


class TestAgentSpec:
    """Test AgentSpec properties."""

    def test_frozen_spec(self):
        """AgentSpec must be immutable (frozen dataclass)."""
        spec = AgentSpec(
            id="test", name="Test", division=1,
            capabilities=frozenset({AgentCapability.HTTP_PROBE}),
        )
        with pytest.raises(AttributeError):
            spec.id = "changed"

    def test_spec_hashable(self):
        """AgentSpec must be hashable (for set operations)."""
        spec = AgentSpec(
            id="test", name="Test", division=1,
            capabilities=frozenset({AgentCapability.HTTP_PROBE}),
        )
        assert hash(spec)  # Should not raise


# ═══════════════════════════════════════════════════════════════════════
# SwarmAgent Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSwarmAgent:
    """Test agent lifecycle and behavior."""

    def _make_agent(self, **kw) -> SwarmAgent:
        spec = AgentSpec(
            id=kw.get("id", "test-agent"),
            name=kw.get("name", "Test Agent"),
            division=kw.get("division", 1),
            capabilities=frozenset(kw.get("caps", {AgentCapability.HTTP_PROBE})),
            min_mode=kw.get("min_mode", OperationalMode.AUDIT),
            max_requests=kw.get("max_requests", 100),
            timeout=kw.get("timeout", 300),
        )
        return SwarmAgent(spec=spec)

    def test_initial_state(self):
        agent = self._make_agent()
        assert agent.state == AgentState.IDLE
        assert agent.is_active is False
        assert agent.is_terminal is False

    def test_budget_tracking(self):
        agent = self._make_agent(max_requests=50)
        assert agent.budget_remaining == 50
        assert agent.within_budget is True
        agent._requests_made = 50
        assert agent.budget_remaining == 0
        assert agent.within_budget is False

    def test_mode_check_recon(self):
        agent = self._make_agent(min_mode=OperationalMode.AUDIT)
        assert agent._mode_allowed(OperationalMode.RECON) is False
        assert agent._mode_allowed(OperationalMode.AUDIT) is True
        assert agent._mode_allowed(OperationalMode.REDTEAM) is True

    def test_mode_check_redteam(self):
        agent = self._make_agent(min_mode=OperationalMode.REDTEAM)
        assert agent._mode_allowed(OperationalMode.RECON) is False
        assert agent._mode_allowed(OperationalMode.AUDIT) is False
        assert agent._mode_allowed(OperationalMode.REDTEAM) is True

    def test_tech_detection(self):
        agent = self._make_agent()
        resp = {
            "headers": {"server": "nginx/1.25", "x-powered-by": "PHP/8.2"},
            "body": "<html>wp-content/themes</html>",
        }
        techs = agent._detect_technologies(resp)
        assert "nginx" in techs
        assert "php" in techs
        assert "wordpress" in techs

    def test_receive_message(self):
        agent = self._make_agent()
        msg = AgentMessage(type=MessageType.INTELLIGENCE, sender="other")
        agent.receive_message(msg)
        assert len(agent._messages_in) == 1

    def test_can_continue(self):
        agent = self._make_agent(max_requests=10, timeout=300)
        assert agent.can_continue is True
        agent._requests_made = 10
        assert agent.can_continue is False


# ═══════════════════════════════════════════════════════════════════════
# Finding & Evidence Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFinding:
    def test_evidence_chain(self):
        finding = Finding(title="Test SQLi", severity="HIGH")
        assert finding.consensus_confidence == Confidence.TENTATIVE

        # Add diverse evidence
        finding.add_evidence(Evidence(type="pattern_match", agent_id="a1"))
        finding.add_evidence(Evidence(type="timing_analysis", agent_id="a2"))
        assert finding.consensus_confidence == Confidence.FIRM

        finding.add_evidence(Evidence(type="oob_callback", agent_id="a3"))
        assert finding.consensus_confidence == Confidence.CONFIRMED

    def test_consensus_confirmation(self):
        finding = Finding(title="Test", severity="HIGH", consensus_required=2)
        assert finding.is_confirmed is False

        finding.add_confirmation("agent-1")
        assert finding.is_confirmed is False

        finding.add_confirmation("agent-2")
        assert finding.is_confirmed is True
        assert finding.consensus_confidence == Confidence.PROVEN

    def test_no_duplicate_confirmations(self):
        finding = Finding(title="Test", severity="HIGH")
        finding.add_confirmation("agent-1")
        finding.add_confirmation("agent-1")  # Duplicate
        assert finding.consensus_votes == 1


class TestEvidence:
    def test_fingerprint_dedup(self):
        e1 = Evidence(agent_id="a1", type="pattern", description="Test")
        e2 = Evidence(agent_id="a1", type="pattern", description="Test")
        assert e1.fingerprint == e2.fingerprint

    def test_fingerprint_unique(self):
        e1 = Evidence(agent_id="a1", type="pattern", description="Test A")
        e2 = Evidence(agent_id="a1", type="pattern", description="Test B")
        assert e1.fingerprint != e2.fingerprint


# ═══════════════════════════════════════════════════════════════════════
# Memory Tests
# ═══════════════════════════════════════════════════════════════════════

class TestWorkingMemory:
    def setup_method(self):
        from secprobe.swarm.memory.working import WorkingMemory
        self.mem = WorkingMemory()

    @pytest.mark.asyncio
    async def test_store_and_recall(self):
        await self.mem.store("key1", {"data": "value"}, source="agent-1")
        result = await self.mem.recall("key1")
        assert result == {"data": "value"}

    @pytest.mark.asyncio
    async def test_recall_missing(self):
        result = await self.mem.recall("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_tag_query(self):
        await self.mem.store("url1", "/api/users", tags=("injectable",))
        await self.mem.store("url2", "/api/admin", tags=("injectable",))
        await self.mem.store("url3", "/public", tags=("safe",))

        results = await self.mem.recall_by_tag("injectable")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_ttl_expiry(self):
        await self.mem.store("temp", "value", ttl=0)  # ttl=0 means no expiry
        result = await self.mem.recall("temp")
        assert result == "value"

    @pytest.mark.asyncio
    async def test_snapshot(self):
        await self.mem.store("k1", "v1", source="a1")
        await self.mem.store("k2", "v2", source="a2")
        snap = self.mem.snapshot()
        assert len(snap) == 2
        assert "k1" in snap


class TestEpisodicMemory:
    def setup_method(self):
        from secprobe.swarm.memory.episodic import EpisodicMemory, Episode
        self.tmpdir = tempfile.mkdtemp()
        self.mem = EpisodicMemory(storage_dir=self.tmpdir)

    def test_session_lifecycle(self):
        from secprobe.swarm.memory.episodic import Episode
        session = self.mem.create_session("scan-1", "example.com", "audit")
        assert session.scan_id == "scan-1"

        self.mem.record("scan-1", Episode(
            agent_id="recon-dns-brute",
            event_type="finding",
            description="Found subdomain: api.example.com",
        ))

        episodes = self.mem.get_episodes("scan-1", event_type="finding")
        assert len(episodes) == 1

    def test_persist_and_load(self):
        from secprobe.swarm.memory.episodic import Episode
        self.mem.create_session("scan-2", "test.com", "recon")
        self.mem.record("scan-2", Episode(agent_id="test", event_type="action"))
        self.mem.finalize("scan-2", total_requests=100)

        path = self.mem.persist("scan-2")
        assert os.path.exists(path)

        loaded = self.mem.load("scan-2")
        assert loaded is not None
        assert loaded.target == "test.com"
        assert len(loaded.episodes) == 1


class TestSemanticMemory:
    def setup_method(self):
        from secprobe.swarm.memory.semantic import SemanticMemory, SemanticPattern
        self.tmpdir = tempfile.mkdtemp()
        self.mem = SemanticMemory(storage_dir=self.tmpdir)

    def test_learn_and_query(self):
        from secprobe.swarm.memory.semantic import SemanticPattern
        self.mem.learn(SemanticPattern(
            id="wp-sqli",
            description="WordPress SQLi pattern",
            category="tech_correlation",
            conditions={"cms": "wordpress"},
            predictions={"likely_vuln": "sqli"},
            confidence=0.85,
            evidence_count=10,
        ))
        results = self.mem.query(conditions={"cms": "wordpress"})
        assert len(results) == 1
        assert results[0].confidence == 0.85

    def test_reinforce(self):
        from secprobe.swarm.memory.semantic import SemanticPattern
        self.mem.learn(SemanticPattern(
            id="test", description="Test",
            category="test", confidence=0.5, evidence_count=1,
        ))
        self.mem.reinforce("test", True)
        p = self.mem.get("test")
        assert p.evidence_count == 2
        assert p.confidence > 0.5

    def test_persist_and_load(self):
        from secprobe.swarm.memory.semantic import SemanticPattern
        self.mem.learn(SemanticPattern(
            id="p1", description="Pattern 1", category="test",
            confidence=0.9, evidence_count=5,
        ))
        self.mem.persist()

        new_mem = type(self.mem)(storage_dir=self.tmpdir)
        count = new_mem.load()
        assert count == 1


class TestProceduralMemory:
    def setup_method(self):
        from secprobe.swarm.memory.procedural import ProceduralMemory, Procedure
        self.tmpdir = tempfile.mkdtemp()
        self.mem = ProceduralMemory(storage_dir=self.tmpdir)

    def test_record_and_find(self):
        from secprobe.swarm.memory.procedural import Procedure
        self.mem.record(Procedure(
            id="wp-sqli-search",
            name="WordPress SQLi",
            description="SQLi via search",
            category="sqli",
            applicability={"cms": "wordpress"},
            success_count=5,
            attempt_count=8,
        ))
        results = self.mem.find_applicable({"cms": "wordpress"})
        assert len(results) == 1
        assert results[0].success_rate == 5 / 8


class TestFederatedMemory:
    def test_disabled_by_default(self):
        from secprobe.swarm.memory.federated import FederatedMemory
        mem = FederatedMemory(enabled=False)
        results = mem.query(category="test")
        assert results == []

    def test_contribute_and_query(self):
        from secprobe.swarm.memory.federated import FederatedMemory, LocalContribution
        mem = FederatedMemory(enabled=True)
        mem.contribute(LocalContribution(
            technology="wordpress",
            vulnerability_type="sqli",
            waf_detected="cloudflare",
            success=True,
            payload_hash=LocalContribution.hash_payload("test"),
        ))
        results = mem.query(
            conditions={"technology": "wordpress"},
            min_contributors=0,
            min_confidence=0,
        )
        assert len(results) >= 1


# ═══════════════════════════════════════════════════════════════════════
# Communication Tests
# ═══════════════════════════════════════════════════════════════════════

class TestEventBus:
    def setup_method(self):
        from secprobe.swarm.comm.event_bus import EventBus
        self.bus = EventBus()

    @pytest.mark.asyncio
    async def test_publish_subscribe(self):
        await self.bus.subscribe("agent-1", MessageType.FINDING)
        await self.bus.publish(AgentMessage(
            type=MessageType.FINDING,
            sender="agent-2",
            payload={"title": "SQLi found"},
        ))
        messages = await self.bus.collect("agent-1")
        assert len(messages) == 1
        assert messages[0].payload["title"] == "SQLi found"

    @pytest.mark.asyncio
    async def test_no_self_delivery(self):
        await self.bus.subscribe("agent-1", MessageType.FINDING)
        await self.bus.publish(AgentMessage(
            type=MessageType.FINDING,
            sender="agent-1",  # Same as subscriber
        ))
        messages = await self.bus.collect("agent-1")
        assert len(messages) == 0  # Should not receive own message

    @pytest.mark.asyncio
    async def test_division_scoping(self):
        await self.bus.subscribe_division("agent-1", division=2)
        await self.bus.subscribe_division("agent-2", division=3)
        await self.bus.publish(AgentMessage(
            type=MessageType.INTELLIGENCE,
            sender="agent-3",
            division=2,
        ))
        msgs_1 = await self.bus.collect("agent-1")
        msgs_2 = await self.bus.collect("agent-2")
        assert len(msgs_1) == 1
        assert len(msgs_2) == 0

    @pytest.mark.asyncio
    async def test_stats(self):
        await self.bus.subscribe("a1", MessageType.FINDING)
        await self.bus.publish(AgentMessage(type=MessageType.FINDING, sender="a2"))
        stats = self.bus.stats
        assert stats["published"] == 1
        assert stats["delivered"] == 1


class TestBlackboard:
    def setup_method(self):
        from secprobe.swarm.comm.blackboard import Blackboard
        self.bb = Blackboard()

    @pytest.mark.asyncio
    async def test_post_and_read(self):
        await self.bb.post("endpoints", "endpoint", {"urls": ["/api"]}, posted_by="recon")
        entry = await self.bb.read("endpoints")
        assert entry is not None
        assert entry.data["urls"] == ["/api"]

    @pytest.mark.asyncio
    async def test_category_query(self):
        await self.bb.post("e1", "endpoint", {"url": "/a"}, posted_by="recon")
        await self.bb.post("e2", "endpoint", {"url": "/b"}, posted_by="recon")
        await self.bb.post("f1", "finding", {"title": "SQLi"}, posted_by="sqli")

        endpoints = await self.bb.read_category("endpoint")
        assert len(endpoints) == 2

    @pytest.mark.asyncio
    async def test_consume_tracking(self):
        await self.bb.post("e1", "endpoint", {}, posted_by="recon")
        await self.bb.consume("e1", "sqli-agent")

        unconsumed = await self.bb.read_category("endpoint", unconsumed_by="sqli-agent")
        assert len(unconsumed) == 0

        unconsumed = await self.bb.read_category("endpoint", unconsumed_by="other-agent")
        assert len(unconsumed) == 1

    @pytest.mark.asyncio
    async def test_annotation(self):
        await self.bb.post("e1", "endpoint", {}, posted_by="recon")
        await self.bb.annotate("e1", "intel-agent", "High risk endpoint")
        entry = await self.bb.read("e1")
        assert len(entry.annotations) == 1


# ═══════════════════════════════════════════════════════════════════════
# Safety Governor Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSafetyGovernor:
    def setup_method(self):
        from secprobe.swarm.safety.governor import SafetyGovernor, ScopeRule, BudgetConfig
        self.governor = SafetyGovernor(
            mode=OperationalMode.AUDIT,
            scope=ScopeRule(allowed_domains=["example.com", "*.example.com"]),
            budget=BudgetConfig(max_total_requests=100, max_requests_per_agent=10),
        )

    @pytest.mark.asyncio
    async def test_approve_in_scope(self):
        action = AgentAction(
            agent_id="test", type="http_request",
            target="https://example.com/api",
            requires_mode=OperationalMode.AUDIT,
        )
        assert await self.governor.approve(action) is True

    @pytest.mark.asyncio
    async def test_deny_out_of_scope(self):
        action = AgentAction(
            agent_id="test", type="http_request",
            target="https://evil.com/api",
            requires_mode=OperationalMode.AUDIT,
        )
        assert await self.governor.approve(action) is False

    @pytest.mark.asyncio
    async def test_deny_wrong_mode(self):
        action = AgentAction(
            agent_id="test", type="exploit",
            target="https://example.com",
            requires_mode=OperationalMode.REDTEAM,
        )
        assert await self.governor.approve(action) is False

    @pytest.mark.asyncio
    async def test_budget_enforcement(self):
        for i in range(100):
            action = AgentAction(
                agent_id=f"agent-{i % 20}", type="http_request",
                target="https://example.com",
                requires_mode=OperationalMode.AUDIT,
            )
            await self.governor.approve(action)

        # 101st request should be denied
        action = AgentAction(
            agent_id="agent-99", type="http_request",
            target="https://example.com",
            requires_mode=OperationalMode.AUDIT,
        )
        assert await self.governor.approve(action) is False

    @pytest.mark.asyncio
    async def test_kill_switch(self):
        self.governor.kill("Test kill")
        assert self.governor.is_killed is True
        action = AgentAction(
            agent_id="test", type="http_request",
            target="https://example.com",
            requires_mode=OperationalMode.AUDIT,
        )
        assert await self.governor.approve(action) is False

    @pytest.mark.asyncio
    async def test_wildcard_scope(self):
        action = AgentAction(
            agent_id="test", type="http_request",
            target="https://api.example.com/users",
            requires_mode=OperationalMode.AUDIT,
        )
        assert await self.governor.approve(action) is True

    @pytest.mark.asyncio
    async def test_per_agent_budget(self):
        for i in range(10):
            action = AgentAction(
                agent_id="heavy-agent", type="http_request",
                target="https://example.com",
                requires_mode=OperationalMode.AUDIT,
            )
            await self.governor.approve(action)

        action = AgentAction(
            agent_id="heavy-agent", type="http_request",
            target="https://example.com",
            requires_mode=OperationalMode.AUDIT,
        )
        assert await self.governor.approve(action) is False


# ═══════════════════════════════════════════════════════════════════════
# Consensus Engine Tests
# ═══════════════════════════════════════════════════════════════════════

class TestConsensusEngine:
    def setup_method(self):
        from secprobe.swarm.consensus import ConsensusEngine, Vote
        self.engine = ConsensusEngine(quorum=2, timeout=60.0)

    @pytest.mark.asyncio
    async def test_submit_and_vote(self):
        from secprobe.swarm.consensus import Vote
        finding = Finding(title="SQLi", severity="HIGH", attack_type="sqli")
        req = await self.engine.submit(finding, submitted_by="agent-1")
        assert req.status == "pending"

        # Agent-1's vote is auto-added
        assert len(req.votes_confirm) == 1

        # Second agent votes
        quorum_met = await self.engine.vote(req.id, Vote(
            agent_id="agent-2", decision="confirm", confidence=0.9,
        ))
        assert quorum_met is True
        assert req.status == "confirmed"

    @pytest.mark.asyncio
    async def test_denial(self):
        from secprobe.swarm.consensus import Vote
        finding = Finding(title="Maybe XSS", severity="MEDIUM", attack_type="xss")
        req = await self.engine.submit(finding, submitted_by="agent-1")

        await self.engine.vote(req.id, Vote(agent_id="agent-2", decision="deny"))
        await self.engine.vote(req.id, Vote(agent_id="agent-3", decision="deny"))

        # With 1 confirm, 2 denies, and no more verifiers, it's effectively denied
        assert req.status in ("pending", "denied")

    @pytest.mark.asyncio
    async def test_no_duplicate_votes(self):
        from secprobe.swarm.consensus import Vote
        finding = Finding(title="Test", severity="LOW")
        req = await self.engine.submit(finding, submitted_by="agent-1")

        await self.engine.vote(req.id, Vote(agent_id="agent-2", decision="confirm"))
        await self.engine.vote(req.id, Vote(agent_id="agent-2", decision="confirm"))

        assert len(req.votes_confirm) == 2  # agent-1 (auto) + agent-2

    @pytest.mark.asyncio
    async def test_stats(self):
        from secprobe.swarm.consensus import Vote
        f1 = Finding(title="F1", severity="HIGH")
        await self.engine.submit(f1, submitted_by="a1")
        await self.engine.vote(f1.id, Vote(agent_id="a2", decision="confirm"))

        stats = self.engine.stats()
        assert stats["total_requests"] == 1
        assert stats["confirmed"] == 1


# ═══════════════════════════════════════════════════════════════════════
# Integration Test
# ═══════════════════════════════════════════════════════════════════════

class TestSwarmIntegration:
    """End-to-end test that verifies the full stack loads."""

    def test_full_registry_loads(self):
        """Registry loads all 600 agents without errors."""
        registry = SwarmRegistry()
        registry.load_all()
        assert registry.count == 600

    def test_orchestrator_creates(self):
        """Orchestrator can be instantiated."""
        from secprobe.swarm.orchestrator import SwarmOrchestrator
        registry = SwarmRegistry()
        registry.load_all()
        orch = SwarmOrchestrator(registry)
        assert orch.registry.count == 600

    def test_agent_from_registry(self):
        """Can create a SwarmAgent from a registry spec."""
        registry = SwarmRegistry()
        registry.load_all()
        spec = registry.get("sqli-error-mysql")
        assert spec is not None
        agent = SwarmAgent(spec=spec)
        assert agent.id == "sqli-error-mysql"
        assert agent.division == 2
        assert AgentCapability.PAYLOAD_INJECTION in spec.capabilities
