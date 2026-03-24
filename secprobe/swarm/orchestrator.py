"""
Swarm Orchestrator — Strategic command that runs 600 agents.

The orchestrator manages the complete scan lifecycle:
    Phase 1: Reconnaissance   — Deploy D01, build target profile
    Phase 2: Intelligence     — D19 analyzes recon, builds threat model
    Phase 3: Targeted Strike  — Deploy relevant divisions based on threat model
    Phase 4: Deep Exploitation— D14 chains findings (audit/redteam only)
    Phase 5: Verification     — Consensus engine confirms all findings
    Phase 6: Reporting        — D18+D19 generate compliance reports

The orchestrator is adaptive — it doesn't deploy all 600 agents at once.
It starts with recon, analyzes results, then deploys only the divisions
relevant to the target. A WordPress blog might activate 80 agents;
a complex government API might activate 400+.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from secprobe.swarm.agent import (
    AgentPriority,
    Confidence,
    Finding,
    OperationalMode,
    SwarmAgent,
)
from secprobe.swarm.registry import SwarmRegistry
from secprobe.swarm.consensus import ConsensusEngine
from secprobe.swarm.comm.event_bus import EventBus
from secprobe.swarm.comm.blackboard import Blackboard
from secprobe.swarm.memory.working import WorkingMemory
from secprobe.swarm.memory.episodic import EpisodicMemory, Episode
from secprobe.swarm.memory.semantic import SemanticMemory
from secprobe.swarm.memory.procedural import ProceduralMemory
from secprobe.swarm.memory.federated import FederatedMemory
from secprobe.swarm.safety.governor import SafetyGovernor, ScopeRule, BudgetConfig


class ScanPhase(Enum):
    """Phases of a swarm scan."""
    INIT = auto()
    RECON = auto()
    INTELLIGENCE = auto()
    TARGETED_STRIKE = auto()
    DEEP_EXPLOITATION = auto()
    VERIFICATION = auto()
    REPORTING = auto()
    DONE = auto()
    FAILED = auto()


@dataclass
class SwarmConfig:
    """Configuration for a swarm scan."""
    target: str
    mode: OperationalMode = OperationalMode.AUDIT
    scope: ScopeRule | None = None
    budget: BudgetConfig | None = None
    max_concurrent_agents: int = 50
    consensus_quorum: int = 2
    consensus_timeout: float = 120.0
    federated_learning: bool = False
    output_formats: list[str] = field(default_factory=lambda: ["console", "json"])
    output_file: str = ""
    verbose: bool = False
    divisions_override: list[int] | None = None  # Force specific divisions


@dataclass
class SwarmResult:
    """Complete results from a swarm scan."""
    scan_id: str = ""
    target: str = ""
    mode: str = ""
    phase: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    total_agents_deployed: int = 0
    total_requests: int = 0
    divisions_activated: list[int] = field(default_factory=list)
    tech_profile: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    grade: str = ""
    consensus_stats: dict = field(default_factory=dict)
    governor_stats: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.end_time > 0:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    @property
    def finding_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class SwarmOrchestrator:
    """
    The top-level orchestrator for SecProbe's 600-agent swarm.

    Usage:
        registry = SwarmRegistry()
        registry.load_all()

        orchestrator = SwarmOrchestrator(registry)
        result = await orchestrator.run(SwarmConfig(
            target="https://example.com",
            mode=OperationalMode.AUDIT,
            scope=ScopeRule(allowed_domains=["example.com", "*.example.com"]),
        ))

        print(f"Risk score: {result.risk_score}/100 ({result.grade})")
        for f in result.findings:
            print(f"  [{f.severity}] {f.title} (confidence: {f.consensus_confidence.name})")
    """

    def __init__(self, registry: SwarmRegistry):
        self.registry = registry
        self._scan_id = ""
        self._phase = ScanPhase.INIT
        self._agents: dict[str, SwarmAgent] = {}
        self._result = SwarmResult()

        # Swarm infrastructure
        self._event_bus = EventBus()
        self._blackboard = Blackboard()
        self._working_memory = WorkingMemory()
        self._consensus: ConsensusEngine | None = None
        self._governor: SafetyGovernor | None = None

        # Long-term memory (loaded from disk)
        self._episodic = EpisodicMemory()
        self._semantic = SemanticMemory()
        self._procedural = ProceduralMemory()
        self._federated = FederatedMemory()

    async def run(self, config: SwarmConfig) -> SwarmResult:
        """
        Execute a complete swarm scan.

        This is the main entry point — it orchestrates all 600 agents
        through the 6 scan phases.
        """
        self._scan_id = uuid.uuid4().hex[:12]
        self._result = SwarmResult(
            scan_id=self._scan_id,
            target=config.target,
            mode=config.mode.value,
            start_time=time.time(),
        )

        try:
            # ── Phase 0: Initialize ───────────────────────────────
            self._phase = ScanPhase.INIT
            await self._initialize(config)

            # ── Phase 1: Reconnaissance ───────────────────────────
            self._phase = ScanPhase.RECON
            tech_profile = await self._run_recon(config)
            self._result.tech_profile = tech_profile

            # ── Phase 2: Intelligence Analysis ────────────────────
            self._phase = ScanPhase.INTELLIGENCE
            target_divisions = await self._analyze_and_plan(config, tech_profile)
            self._result.divisions_activated = target_divisions

            # ── Phase 3: Targeted Strike ──────────────────────────
            self._phase = ScanPhase.TARGETED_STRIKE
            findings = await self._run_targeted_strike(config, target_divisions)

            # ── Phase 4: Deep Exploitation (audit/redteam) ────────
            if config.mode in (OperationalMode.AUDIT, OperationalMode.REDTEAM):
                self._phase = ScanPhase.DEEP_EXPLOITATION
                exploit_findings = await self._run_exploitation(config, findings)
                findings.extend(exploit_findings)

            # ── Phase 5: Consensus Verification ───────────────────
            self._phase = ScanPhase.VERIFICATION
            verified = await self._verify_findings(findings)
            self._result.findings = verified

            # ── Phase 6: Reporting ────────────────────────────────
            self._phase = ScanPhase.REPORTING
            await self._generate_reports(config, verified)

            self._phase = ScanPhase.DONE
            self._result.end_time = time.time()
            self._result.total_agents_deployed = len(self._agents)
            self._result.risk_score = self._calculate_risk_score(verified)
            self._result.grade = self._calculate_grade(self._result.risk_score)
            if self._consensus:
                self._result.consensus_stats = self._consensus.stats()
            if self._governor:
                self._result.governor_stats = self._governor.status()

            # Persist learnings
            await self._persist_learnings(config)

        except Exception as exc:
            self._phase = ScanPhase.FAILED
            self._result.errors.append(str(exc))
            self._result.end_time = time.time()

        finally:
            await self._shutdown()

        return self._result

    # ── Phase Implementations ──────────────────────────────────────

    async def _initialize(self, config: SwarmConfig):
        """Initialize all swarm infrastructure."""
        # Set up safety governor
        scope = config.scope or ScopeRule(
            allowed_domains=[self._extract_domain(config.target)]
        )
        budget = config.budget or BudgetConfig()
        self._governor = SafetyGovernor(
            mode=config.mode, scope=scope, budget=budget,
        )

        # Set up consensus engine
        self._consensus = ConsensusEngine(
            quorum=config.consensus_quorum,
            timeout=config.consensus_timeout,
        )

        # Load long-term memory
        self._semantic.load()
        self._procedural.load()
        if config.federated_learning:
            self._federated.enabled = True
            self._federated.load()

        # Create episodic session
        self._episodic.create_session(
            self._scan_id, config.target, config.mode.value,
        )

    async def _run_recon(self, config: SwarmConfig) -> dict:
        """Phase 1: Deploy recon agents, build target profile."""
        recon_specs = self.registry.by_division(1)
        recon_specs.sort(key=lambda s: s.priority, reverse=True)

        # Deploy recon agents with concurrency control
        tech_profile = {}
        agents = await self._deploy_agents(recon_specs, config)

        # Run all recon agents concurrently
        semaphore = asyncio.Semaphore(config.max_concurrent_agents)
        tasks = []
        for agent in agents:
            tasks.append(self._run_agent_with_semaphore(
                agent, config.target, config.mode, semaphore,
            ))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect tech profile from working memory
        tech = await self._working_memory.recall("target_tech")
        if tech:
            tech_profile = tech

        # Record in episodic memory
        self._episodic.record(self._scan_id, Episode(
            agent_id="orchestrator",
            event_type="phase_complete",
            description="Reconnaissance complete",
            data={"tech_profile": tech_profile, "agents_deployed": len(agents)},
            outcome="success",
        ))

        return tech_profile

    async def _analyze_and_plan(self, config: SwarmConfig,
                                 tech_profile: dict) -> list[int]:
        """Phase 2: Analyze recon results, decide which divisions to deploy."""
        if config.divisions_override:
            return config.divisions_override

        # Always include these divisions
        target_divisions = [2, 13, 18, 19, 20]  # Injection, Evasion, Compliance, Intel, Meta

        # Technology-based division selection
        techs = tech_profile.get("technologies", [])
        if isinstance(techs, dict):
            techs = list(techs.keys())

        # Check for API indicators
        api_indicators = {"swagger", "graphql", "api", "rest", "openapi", "grpc"}
        if any(t.lower() in api_indicators for t in techs):
            target_divisions.append(5)  # API Security

        # Check for auth pages
        has_auth = await self._working_memory.recall("has_login_form")
        if has_auth:
            target_divisions.extend([3, 4])  # Auth, AuthZ

        # Check for file upload
        has_upload = await self._working_memory.recall("has_file_upload")
        if has_upload:
            target_divisions.append(12)  # File handling

        # Always include client-side for web targets
        target_divisions.append(6)  # Client-side

        # Crypto always relevant
        target_divisions.append(7)  # Crypto

        # Infrastructure for any target
        target_divisions.append(8)  # Infrastructure

        # Cloud if indicators found
        cloud_indicators = {"aws", "gcp", "azure", "firebase", "cloudflare",
                           "s3", "lambda", "heroku"}
        if any(t.lower() in cloud_indicators for t in techs):
            target_divisions.append(9)  # Cloud

        # Supply chain if CMS/framework detected
        cms_indicators = {"wordpress", "drupal", "joomla", "magento", "shopify"}
        if any(t.lower() in cms_indicators for t in techs):
            target_divisions.append(10)  # Supply chain

        # Business logic for e-commerce/SaaS
        biz_indicators = {"cart", "checkout", "payment", "subscription", "pricing"}
        if any(t.lower() in biz_indicators for t in techs):
            target_divisions.append(11)  # Business logic

        # Social engineering (email security) always useful
        target_divisions.append(16)

        # Redteam-only divisions
        if config.mode == OperationalMode.REDTEAM:
            target_divisions.extend([14, 15, 17])  # Exploit, Persist, Mobile

        # Audit mode gets exploitation for proof
        if config.mode == OperationalMode.AUDIT:
            target_divisions.append(14)  # Exploit

        # Check semantic memory for patterns
        patterns = self._semantic.query(
            conditions={"technologies": techs},
            min_confidence=0.7,
        )
        for pattern in patterns:
            predicted_divs = pattern.predictions.get("recommended_divisions", [])
            target_divisions.extend(predicted_divs)

        # Deduplicate and sort
        target_divisions = sorted(set(target_divisions))

        self._episodic.record(self._scan_id, Episode(
            agent_id="orchestrator",
            event_type="decision",
            description=f"Selected divisions: {target_divisions}",
            data={"divisions": target_divisions, "tech_profile": tech_profile},
        ))

        return target_divisions

    async def _run_targeted_strike(self, config: SwarmConfig,
                                    divisions: list[int]) -> list[Finding]:
        """Phase 3: Deploy division agents for targeted testing."""
        all_findings: list[Finding] = []

        for div_num in divisions:
            if div_num == 1:  # Recon already ran
                continue
            if self._governor and self._governor.is_killed:
                break

            specs = self.registry.by_division(div_num)
            # Filter by mode
            specs = [
                s for s in specs
                if self._mode_allows(config.mode, s.min_mode)
            ]
            specs.sort(key=lambda s: s.priority, reverse=True)

            agents = await self._deploy_agents(specs, config)

            semaphore = asyncio.Semaphore(config.max_concurrent_agents)
            tasks = []
            for agent in agents:
                tasks.append(self._run_agent_with_semaphore(
                    agent, config.target, config.mode, semaphore,
                ))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect findings from agents
            for agent in agents:
                all_findings.extend(agent._findings)

        return all_findings

    async def _run_exploitation(self, config: SwarmConfig,
                                 findings: list[Finding]) -> list[Finding]:
        """Phase 4: Chain vulnerabilities and prove exploitability."""
        if not findings:
            return []

        # Post findings to blackboard for exploit agents
        for f in findings:
            await self._blackboard.post(
                f"finding-{f.id}", "confirmed_finding",
                {"finding": f.title, "url": f.url, "type": f.attack_type,
                 "severity": f.severity},
                posted_by="orchestrator",
            )

        # Deploy exploitation division
        specs = self.registry.by_division(14)
        specs = [s for s in specs if self._mode_allows(config.mode, s.min_mode)]
        agents = await self._deploy_agents(specs, config)

        semaphore = asyncio.Semaphore(config.max_concurrent_agents)
        tasks = [
            self._run_agent_with_semaphore(a, config.target, config.mode, semaphore)
            for a in agents
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        exploit_findings = []
        for agent in agents:
            exploit_findings.extend(agent._findings)

        return exploit_findings

    async def _verify_findings(self, findings: list[Finding]) -> list[Finding]:
        """Phase 5: Multi-agent consensus verification."""
        if not self._consensus:
            return findings

        # Submit all findings for consensus
        for finding in findings:
            await self._consensus.submit(finding, finding.discovered_by)

        # For findings already at FIRM or higher, auto-confirm
        for finding in findings:
            if finding.consensus_confidence >= Confidence.FIRM:
                await self._consensus.vote(finding.id, type("Vote", (), {
                    "agent_id": "auto-verifier",
                    "decision": "confirm",
                    "evidence": None,
                    "reason": "Pre-existing high confidence",
                    "confidence": 0.9,
                    "timestamp": time.time(),
                })())

        # Check all pending
        await self._consensus.check_all_pending()

        # Return confirmed findings + high-confidence unverified
        confirmed = self._consensus.confirmed_findings
        confirmed_ids = {f.id for f in confirmed}

        # Also include findings that timed out but had at least tentative confidence
        all_verified = list(confirmed)
        for finding in findings:
            if (finding.id not in confirmed_ids
                    and finding.consensus_confidence >= Confidence.TENTATIVE):
                all_verified.append(finding)

        return all_verified

    async def _generate_reports(self, config: SwarmConfig,
                                 findings: list[Finding]):
        """Phase 6: Generate reports via intelligence division."""
        # Deploy compliance and intelligence agents
        for div_num in [18, 19]:
            specs = self.registry.by_division(div_num)
            specs = [s for s in specs if "commander" in s.id or "report" in s.id
                     or "compliance" in s.id or "scorer" in s.id]
            await self._deploy_agents(specs, config)

    # ── Agent Lifecycle ────────────────────────────────────────────

    async def _deploy_agents(self, specs: list, config: SwarmConfig) -> list[SwarmAgent]:
        """Create and initialize SwarmAgent instances from specs."""
        agents = []
        for spec in specs:
            agent = SwarmAgent(
                spec=spec,
                event_bus=self._event_bus,
                working_memory=self._working_memory,
                safety_governor=self._governor,
            )
            await agent.initialize()
            self._agents[agent.id] = agent
            if self._governor:
                self._governor.register_agent(agent.id)
            agents.append(agent)
        return agents

    async def _run_agent_with_semaphore(self, agent: SwarmAgent,
                                         target: str, mode: OperationalMode,
                                         semaphore: asyncio.Semaphore):
        """Run an agent with concurrency control."""
        async with semaphore:
            try:
                return await agent.run(target, mode)
            except Exception as exc:
                self._result.errors.append(f"{agent.id}: {exc}")
                return []

    async def _shutdown(self):
        """Clean up all agents and persist state."""
        for agent in self._agents.values():
            try:
                await agent.shutdown()
            except Exception:
                pass
        await self._event_bus.drain()
        if self._governor:
            self._governor.persist_audit(self._scan_id)

    async def _persist_learnings(self, config: SwarmConfig):
        """Persist learnings to long-term memory."""
        # Episodic
        self._episodic.finalize(
            self._scan_id,
            findings_summary=self._result.finding_counts,
            agents_deployed=list(self._agents.keys()),
            divisions_activated=self._result.divisions_activated,
            total_requests=self._result.governor_stats.get("total_requests", 0),
            tech_profile=self._result.tech_profile,
        )
        self._episodic.persist(self._scan_id)

        # Semantic + procedural
        self._semantic.persist()
        self._procedural.persist()

        # Federated
        if config.federated_learning and self._federated.enabled:
            self._federated.persist()

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(target: str) -> str:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target)
            return parsed.hostname or target
        except Exception:
            return target

    @staticmethod
    def _mode_allows(current: OperationalMode, required: OperationalMode) -> bool:
        order = {OperationalMode.RECON: 0, OperationalMode.AUDIT: 1, OperationalMode.REDTEAM: 2}
        return order.get(current, 0) >= order.get(required, 0)

    @staticmethod
    def _calculate_risk_score(findings: list[Finding]) -> float:
        """Calculate risk score 0-100 from findings."""
        if not findings:
            return 0.0
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        total = sum(weights.get(f.severity, 0) for f in findings)
        return min(100.0, total)

    @staticmethod
    def _calculate_grade(risk_score: float) -> str:
        """Convert risk score to letter grade."""
        if risk_score <= 5:
            return "A+"
        elif risk_score <= 10:
            return "A"
        elif risk_score <= 20:
            return "B"
        elif risk_score <= 35:
            return "C"
        elif risk_score <= 55:
            return "D"
        else:
            return "F"

    @property
    def phase(self) -> ScanPhase:
        return self._phase

    @property
    def progress(self) -> dict:
        """Real-time progress info."""
        return {
            "scan_id": self._scan_id,
            "phase": self._phase.name,
            "agents_deployed": len(self._agents),
            "findings_so_far": len(self._result.findings),
            "elapsed": self._result.duration,
            "governor": self._governor.status() if self._governor else {},
        }
