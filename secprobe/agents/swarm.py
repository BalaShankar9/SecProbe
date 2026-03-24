"""
Swarm Coordinator — Multi-agent orchestration engine.

Manages the lifecycle and collaboration of multiple autonomous
scanning agents. This is the "general" commanding the "soldiers."

Responsibilities:
  1. Agent Lifecycle: Spawn, monitor, terminate agents
  2. Message Routing: Route messages between agents
  3. Knowledge Sharing: Maintain shared knowledge graph
  4. Strategy: Adapt swarm strategy based on progress
  5. Consensus: Confirm vulns via multi-agent agreement
  6. Assembly: Combine findings into attack chains

Swarm deployment modes:
  - RECONNAISSANCE: Deploy recon agents first, then specialists
  - FULL_ASSAULT: Deploy all agents simultaneously
  - SURGICAL: Deploy only targeted agents based on fingerprint
  - STEALTH: Sequential agents with long delays
  - ADAPTIVE: Start balanced, adapt based on conditions

Architecture:
  SwarmCoordinator
    ├── MessageBus (routes inter-agent messages)
    ├── KnowledgeGraph (shared intelligence)
    ├── Agent pool (registered agents)
    └── Strategy engine (adapts swarm behavior)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Type

from secprobe.agents.base import (
    AgentGoal, AgentMessage, AgentState, BaseAgent,
    GoalStatus, MessageBus, MessageType,
)
from secprobe.agents.knowledge import KnowledgeGraph, EntityType


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

class SwarmMode(Enum):
    """Swarm deployment modes."""
    RECONNAISSANCE = auto()  # Recon first, then attack
    FULL_ASSAULT = auto()    # All agents at once
    SURGICAL = auto()        # Targeted based on fingerprint
    STEALTH = auto()         # Sequential, slow
    ADAPTIVE = auto()        # Starts balanced, adapts


@dataclass
class SwarmConfig:
    """Configuration for a swarm deployment."""
    target: str = ""
    mode: SwarmMode = SwarmMode.ADAPTIVE
    max_agents: int = 10
    max_total_requests: int = 5000
    time_budget: int = 600        # seconds
    max_concurrent: int = 4       # max concurrent agents
    consensus_threshold: int = 2  # min agents to confirm a finding
    request_delay: float = 0.3    # base delay between requests
    stealth_mode: bool = False
    verbose: bool = False


@dataclass
class SwarmResult:
    """Complete results from a swarm scan."""
    target: str = ""
    mode: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    findings: list[dict] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)
    agent_reports: list[dict] = field(default_factory=list)
    knowledge_summary: dict = field(default_factory=dict)
    total_requests: int = 0
    vulns_confirmed: int = 0
    vulns_unconfirmed: int = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0.0

    @property
    def severity_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts


# ═══════════════════════════════════════════════════════════════════
# SWARM COORDINATOR
# ═══════════════════════════════════════════════════════════════════

class SwarmCoordinator:
    """
    Orchestrates a swarm of autonomous scanning agents.

    This is the core innovation — instead of running scanners
    sequentially, we deploy intelligent agents that collaborate,
    share knowledge, and adapt in real-time.

    Usage:
        coordinator = SwarmCoordinator(config)
        coordinator.register_agent(ReconAgent)
        coordinator.register_agent(InjectionAgent)
        coordinator.register_agent(ExploitAgent)
        result = await coordinator.deploy(target_url)
    """

    def __init__(self, config: SwarmConfig = None):
        self.config = config or SwarmConfig()
        self.bus = MessageBus()
        self.knowledge = KnowledgeGraph()
        self._agent_classes: dict[str, Type[BaseAgent]] = {}
        self._agents: dict[str, BaseAgent] = {}
        self._agent_tasks: dict[str, asyncio.Task] = {}
        self._running = False
        self._start_time = 0.0
        self._total_requests = 0
        self._phase = "idle"
        self._findings_cache: dict[str, dict] = {}  # dedup key → finding

    # ── Registration ─────────────────────────────────────────────

    def register_agent(self, agent_class: Type[BaseAgent],
                       agent_id: str = "") -> str:
        """Register an agent class for deployment."""
        aid = agent_id or agent_class.name
        self._agent_classes[aid] = agent_class
        return aid

    def register_instance(self, agent: BaseAgent) -> str:
        """Register a pre-configured agent instance."""
        self._agents[agent.id] = agent
        agent.bus = self.bus
        agent.knowledge = self.knowledge
        self.bus.register(agent.id)
        return agent.id

    # ── Deployment ───────────────────────────────────────────────

    async def deploy(self, target: str = "") -> SwarmResult:
        """
        Deploy the agent swarm against a target.

        Lifecycle:
        1. Initialize shared infrastructure
        2. Spawn agents based on mode
        3. Monitor progress and adapt
        4. Collect and merge results
        5. Build attack chains from findings
        """
        target = target or self.config.target
        self._running = True
        self._start_time = time.time()
        self._phase = "initializing"

        result = SwarmResult(
            target=target,
            mode=self.config.mode.name,
            start_time=self._start_time,
        )

        # Register target in knowledge graph
        self.knowledge.add_url(target, agent="coordinator")

        try:
            # Phase 1: Spawn agents based on mode
            self._phase = "spawning"
            await self._spawn_agents(target)

            # Phase 2: Run agents concurrently
            self._phase = "scanning"
            await self._run_agents()

            # Phase 3: Collect results
            self._phase = "collecting"
            result = self._collect_results(result)

            # Phase 4: Build attack chains
            self._phase = "chaining"
            result.attack_chains = self._build_attack_chains()

        except asyncio.CancelledError:
            self._phase = "cancelled"
        except Exception as exc:
            self._phase = "error"
            result.agent_reports.append({
                "agent": "coordinator",
                "error": str(exc),
            })
        finally:
            self._running = False
            self._phase = "done"
            result.end_time = time.time()
            result.knowledge_summary = self.knowledge.get_stats()

        return result

    def deploy_sync(self, target: str = "") -> SwarmResult:
        """Synchronous wrapper for deploy()."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.deploy(target))
        finally:
            loop.close()

    # ── Agent Management ─────────────────────────────────────────

    async def _spawn_agents(self, target: str):
        """Spawn agents based on deployment mode."""
        mode = self.config.mode
        agent_config = {
            "max_cycles": 50,
            "max_requests": self.config.max_total_requests // max(
                1, len(self._agent_classes) + len(self._agents)
            ),
            "time_budget": self.config.time_budget,
            "request_delay": self.config.request_delay,
            "stealth": self.config.stealth_mode,
        }

        # Instantiate agent classes
        for aid, cls in self._agent_classes.items():
            agent = cls(
                agent_id=aid,
                target=target,
                message_bus=self.bus,
                knowledge_graph=self.knowledge,
                config=agent_config,
            )
            # Add default goal
            agent.add_goal(
                f"Find vulnerabilities in {target}",
                goal_type="find_vulns",
                target=target,
            )
            self._agents[aid] = agent
            self.bus.register(aid)

        # Mode-specific deployment ordering
        if mode == SwarmMode.RECONNAISSANCE:
            # Find recon agents and run them first
            recon = {k: v for k, v in self._agents.items()
                     if v.specialty == "reconnaissance"}
            others = {k: v for k, v in self._agents.items()
                      if v.specialty != "reconnaissance"}
            self._agents = {**recon, **others}

        elif mode == SwarmMode.STEALTH:
            for agent in self._agents.values():
                agent.config["request_delay"] = max(
                    agent.config.get("request_delay", 0), 2.0
                )
                agent.config["max_requests"] = min(
                    agent.config.get("max_requests", 100), 50
                )

    async def _run_agents(self):
        """Run all agents with concurrency control."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        tasks = []

        async def run_with_semaphore(agent: BaseAgent):
            async with semaphore:
                return await agent.run()

        for agent in self._agents.values():
            task = asyncio.create_task(run_with_semaphore(agent))
            self._agent_tasks[agent.id] = task
            tasks.append(task)

        # Wait for all agents with timeout
        if tasks:
            done, pending = await asyncio.wait(
                tasks,
                timeout=self.config.time_budget,
                return_when=asyncio.ALL_COMPLETED,
            )
            # Cancel any timed-out agents
            for task in pending:
                task.cancel()

    # ── Result Collection ────────────────────────────────────────

    def _collect_results(self, result: SwarmResult) -> SwarmResult:
        """Collect and merge findings from all agents."""
        all_findings = []
        seen_keys = set()

        for agent in self._agents.values():
            result.agent_reports.append(agent.get_status())
            result.total_requests += agent.requests_made

            for finding in agent.memory.findings:
                # Dedup key
                key = (
                    finding.get("vuln_type", ""),
                    finding.get("url", ""),
                    finding.get("parameter", ""),
                )
                if key in seen_keys:
                    # Multi-agent confirmation
                    existing = self._findings_cache.get(str(key))
                    if existing:
                        existing["confirmed_by"] = existing.get(
                            "confirmed_by", 1
                        ) + 1
                    continue

                seen_keys.add(key)
                finding["confirmed_by"] = 1
                self._findings_cache[str(key)] = finding
                all_findings.append(finding)

        # Mark confirmed vs unconfirmed
        for finding in all_findings:
            if finding.get("confirmed_by", 1) >= self.config.consensus_threshold:
                finding["consensus"] = True
                result.vulns_confirmed += 1
            else:
                finding["consensus"] = False
                result.vulns_unconfirmed += 1

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(
            key=lambda f: severity_order.get(f.get("severity", "INFO"), 5)
        )

        result.findings = all_findings
        return result

    def _build_attack_chains(self) -> list[dict]:
        """Build attack chains from the knowledge graph."""
        chains = []
        vuln_entities = self.knowledge.find_by_type(EntityType.VULNERABILITY)

        for vuln in vuln_entities:
            # Look for chain paths
            downstream = self.knowledge.get_neighbors(
                vuln.id, direction="outgoing"
            )
            if downstream:
                chain = {
                    "start": vuln.to_dict(),
                    "chain": [d.to_dict() for d in downstream],
                    "impact": self._assess_chain_impact(vuln, downstream),
                }
                chains.append(chain)

        chains.sort(key=lambda c: c["impact"], reverse=True)
        return chains

    @staticmethod
    def _assess_chain_impact(root, chain_nodes) -> float:
        """Assess the impact of an attack chain (0.0-1.0)."""
        severity_values = {
            "critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3,
        }
        base = severity_values.get(
            root.properties.get("severity", "medium").lower(), 0.5
        )
        chain_bonus = min(0.3, len(chain_nodes) * 0.1)
        return min(1.0, base + chain_bonus)

    # ── Monitoring ───────────────────────────────────────────────

    def get_status(self) -> dict:
        """Get current swarm status."""
        return {
            "phase": self._phase,
            "running": self._running,
            "elapsed": time.time() - self._start_time if self._start_time else 0,
            "agents": {
                aid: agent.get_status()
                for aid, agent in self._agents.items()
            },
            "total_requests": sum(
                a.requests_made for a in self._agents.values()
            ),
            "total_findings": sum(
                len(a.memory.findings) for a in self._agents.values()
            ),
            "knowledge_graph": self.knowledge.get_stats(),
            "message_bus": {
                "total_messages": self.bus.total_messages,
            },
        }

    def get_findings(self) -> list[dict]:
        """Get all unique findings across all agents."""
        all_findings = []
        seen = set()
        for agent in self._agents.values():
            for finding in agent.memory.findings:
                key = (
                    finding.get("vuln_type", ""),
                    finding.get("url", ""),
                    finding.get("parameter", ""),
                )
                if key not in seen:
                    seen.add(key)
                    all_findings.append(finding)
        return all_findings

    @property
    def agent_count(self) -> int:
        return len(self._agents)

    @property
    def is_running(self) -> bool:
        return self._running
