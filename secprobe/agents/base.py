"""
Agent Base Framework — Autonomous security testing agents.

This is the foundation for SecProbe's agent swarm architecture.
Each agent is an autonomous entity that can:

  - PERCEIVE: Analyze HTTP responses, errors, behaviors
  - DECIDE:   Choose next actions based on goals + observations
  - ACT:      Execute scanning operations using SecProbe scanners
  - COMMUNICATE: Share findings with other agents via messages
  - LEARN:    Update beliefs based on outcomes

Design principles:
  1. Goal-oriented: Agents pursue goals, not instructions
  2. Evidence-based: Every decision is backed by observations
  3. Adaptive: Agents change strategy when blocked
  4. Collaborative: Agents share knowledge via message bus
  5. Autonomous: Each agent runs independently

This is what separates SecProbe from every other scanner:
  Traditional scanner: for payload in list: send(payload); check(response)
  SecProbe agent:      form hypothesis → test → update belief → adapt → escalate

Architecture:
  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
  │ ReconAgent   │────▶│ KnowledgeGraph│◀────│ EvasionAgent│
  └──────┬──────┘     └──────┬───────┘     └──────┬──────┘
         │                   │                     │
         ▼                   ▼                     ▼
  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
  │InjectionAgent│────▶│   SwarmCoord  │◀────│ ExploitAgent│
  └─────────────┘     └──────────────┘     └─────────────┘
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from secprobe.agents.knowledge import KnowledgeGraph


# ═══════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════

class AgentState(Enum):
    """Lifecycle state of an agent."""
    IDLE = auto()         # Created but not started
    OBSERVING = auto()    # Gathering information
    DECIDING = auto()     # Choosing next action
    ACTING = auto()       # Executing an action
    COMMUNICATING = auto()  # Sharing with other agents
    WAITING = auto()      # Waiting for dependency / response
    ADAPTING = auto()     # Changing strategy
    DONE = auto()         # Finished execution
    FAILED = auto()       # Unrecoverable error


class MessageType(Enum):
    """Types of inter-agent messages."""
    FINDING = auto()        # Confirmed vulnerability
    INTELLIGENCE = auto()   # Observation that may help others
    REQUEST = auto()        # Ask another agent for help
    RESPONSE = auto()       # Reply to a request
    COMMAND = auto()        # Directive from coordinator
    STATUS = auto()         # Progress update
    ALERT = auto()          # Urgent: WAF detected, rate limit, etc.
    HYPOTHESIS = auto()     # Proposed theory for others to test


class ActionType(Enum):
    """Types of actions an agent can take."""
    SCAN = auto()           # Run a specific scanner
    PROBE = auto()          # Send a single test request
    FINGERPRINT = auto()    # Technology detection
    CRAWL = auto()          # Discover new endpoints
    FUZZ = auto()           # Fuzz a parameter
    EVOLVE_PAYLOAD = auto() # Mutate payloads for evasion
    CHAIN = auto()          # Chain multiple findings
    EXTRACT = auto()        # Extract data via confirmed vuln
    WAIT = auto()           # Deliberate delay (stealth)
    ESCALATE = auto()       # Attempt privilege escalation
    REPORT = auto()         # Document a finding


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class GoalStatus(Enum):
    """Status of an agent's goal."""
    PENDING = auto()
    IN_PROGRESS = auto()
    ACHIEVED = auto()
    FAILED = auto()
    ABANDONED = auto()


# ═══════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AgentMessage:
    """A message passed between agents via the message bus."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    sender: str = ""
    recipient: str = ""       # Empty = broadcast to all
    msg_type: MessageType = MessageType.STATUS
    payload: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    priority: float = 0.5    # 0.0 (lowest) to 1.0 (highest)
    in_reply_to: str = ""    # ID of message this replies to

    def __repr__(self) -> str:
        return (f"Msg({self.msg_type.name}: {self.sender}→"
                f"{self.recipient or 'ALL'} | {list(self.payload.keys())})")


@dataclass
class Observation:
    """Something an agent has observed about the target."""
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    observation_type: str = ""   # "reflection", "error", "timing", "block", etc.
    detail: str = ""
    raw_response_code: int = 0
    raw_response_length: int = 0
    response_time: float = 0.0
    confidence: float = 0.0      # 0.0-1.0 how sure we are
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Unique identifier for deduplication."""
        raw = f"{self.url}|{self.parameter}|{self.observation_type}|{self.detail}"
        return hashlib.md5(raw.encode()).hexdigest()[:10]


@dataclass
class Hypothesis:
    """A theory about a potential vulnerability."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    vuln_type: str = ""          # "sqli", "xss", "lfi", etc.
    target_url: str = ""
    target_param: str = ""
    description: str = ""
    confidence: float = 0.0      # Prior probability
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    status: str = "untested"     # untested, testing, confirmed, rejected
    tests_performed: int = 0

    def update_confidence(self, positive: bool, strength: float = 0.3) -> float:
        """Bayesian-style confidence update."""
        if positive:
            self.confidence = self.confidence + strength * (1 - self.confidence)
            self.evidence_for.append(f"test_{self.tests_performed}")
        else:
            self.confidence = self.confidence * (1 - strength)
            self.evidence_against.append(f"test_{self.tests_performed}")
        self.tests_performed += 1

        if self.confidence >= 0.85:
            self.status = "confirmed"
        elif self.confidence <= 0.05 and self.tests_performed >= 3:
            self.status = "rejected"
        else:
            self.status = "testing"
        return self.confidence


@dataclass
class AgentGoal:
    """A goal an agent is pursuing."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    description: str = ""
    goal_type: str = ""     # "find_vulns", "extract_data", "chain_exploit", etc.
    target: str = ""        # URL or parameter
    status: GoalStatus = GoalStatus.PENDING
    priority: float = 0.5
    parent_goal: str = ""   # ID of parent goal (for sub-goals)
    sub_goals: list[str] = field(default_factory=list)
    constraints: dict = field(default_factory=dict)  # max_requests, time_limit, etc.
    progress: float = 0.0   # 0.0-1.0


@dataclass
class Action:
    """An action to be executed by an agent."""
    action_type: ActionType = ActionType.PROBE
    target_url: str = ""
    target_param: str = ""
    scanner_name: str = ""
    payload: str = ""
    metadata: dict = field(default_factory=dict)
    reason: str = ""           # Why this action was chosen
    expected_outcome: str = "" # What we expect to observe
    priority: float = 0.5


@dataclass
class ActionResult:
    """The result of executing an action."""
    action: Action = field(default_factory=Action)
    success: bool = False
    observations: list[Observation] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    error: str = ""
    duration: float = 0.0
    requests_made: int = 0


# ═══════════════════════════════════════════════════════════════════
# AGENT MEMORY
# ═══════════════════════════════════════════════════════════════════

class AgentMemory:
    """
    Agent's working memory — what it knows and what it's tried.

    This is crucial: agents remember FAILURES as well as successes.
    A failed payload is valuable data — it tells us what's filtered.
    """

    def __init__(self, max_observations: int = 10000):
        self.observations: deque[Observation] = deque(maxlen=max_observations)
        self.hypotheses: dict[str, Hypothesis] = {}  # id → Hypothesis
        self.findings: list[dict] = []
        self.actions_taken: deque[ActionResult] = deque(maxlen=5000)
        self.blocked_payloads: list[str] = []
        self.working_payloads: list[str] = []
        self.tested_params: dict[str, set[str]] = {}  # url → {params tested}
        self.tech_stack: dict[str, float] = {}  # tech → confidence
        self._observation_index: set[str] = set()  # Dedup fingerprints

    def add_observation(self, obs: Observation) -> bool:
        """Add observation, returns False if duplicate."""
        fp = obs.fingerprint
        if fp in self._observation_index:
            return False
        self._observation_index.add(fp)
        self.observations.append(obs)
        return True

    def add_hypothesis(self, hyp: Hypothesis) -> str:
        """Add a hypothesis to test. Returns hypothesis ID."""
        self.hypotheses[hyp.id] = hyp
        return hyp.id

    def get_active_hypotheses(self) -> list[Hypothesis]:
        """Get hypotheses still being tested."""
        return [h for h in self.hypotheses.values()
                if h.status in ("untested", "testing")]

    def get_confirmed_hypotheses(self) -> list[Hypothesis]:
        """Get confirmed (high confidence) hypotheses."""
        return [h for h in self.hypotheses.values()
                if h.status == "confirmed"]

    def add_finding(self, finding: dict):
        """Record a confirmed vulnerability."""
        self.findings.append(finding)

    def record_action(self, result: ActionResult):
        """Record the result of an action taken."""
        self.actions_taken.append(result)

    def mark_param_tested(self, url: str, param: str, scanner: str):
        """Track which params have been tested by which scanners."""
        key = f"{url}|{scanner}"
        if key not in self.tested_params:
            self.tested_params[key] = set()
        self.tested_params[key].add(param)

    def was_param_tested(self, url: str, param: str, scanner: str) -> bool:
        """Check if a param was already tested by a scanner."""
        key = f"{url}|{scanner}"
        return param in self.tested_params.get(key, set())

    def get_error_patterns(self) -> list[Observation]:
        """Get observations where errors were triggered."""
        return [o for o in self.observations
                if o.observation_type in ("error", "exception", "stack_trace")]

    def get_reflections(self) -> list[Observation]:
        """Get observations where input was reflected."""
        return [o for o in self.observations
                if o.observation_type == "reflection"]

    def get_timing_anomalies(self) -> list[Observation]:
        """Get observations with unusual response times."""
        return [o for o in self.observations
                if o.observation_type == "timing_anomaly"]

    def get_stats(self) -> dict:
        """Get memory statistics."""
        return {
            "observations": len(self.observations),
            "hypotheses_total": len(self.hypotheses),
            "hypotheses_active": len(self.get_active_hypotheses()),
            "hypotheses_confirmed": len(self.get_confirmed_hypotheses()),
            "findings": len(self.findings),
            "actions_taken": len(self.actions_taken),
            "blocked_payloads": len(self.blocked_payloads),
            "working_payloads": len(self.working_payloads),
        }


# ═══════════════════════════════════════════════════════════════════
# MESSAGE BUS
# ═══════════════════════════════════════════════════════════════════

class MessageBus:
    """
    Async message bus for inter-agent communication.

    Supports:
    - Directed messages (agent-to-agent)
    - Broadcast messages (agent-to-all)
    - Priority queuing
    - Message history for audit trail
    """

    def __init__(self, max_history: int = 10000):
        self._queues: dict[str, asyncio.Queue] = {}
        self._broadcast_queue: asyncio.Queue = asyncio.Queue()
        self._history: deque[AgentMessage] = deque(maxlen=max_history)
        self._subscribers: dict[str, list[str]] = {}  # topic → [agent_ids]

    def register(self, agent_id: str):
        """Register an agent on the bus."""
        if agent_id not in self._queues:
            self._queues[agent_id] = asyncio.Queue()

    def unregister(self, agent_id: str):
        """Remove an agent from the bus."""
        self._queues.pop(agent_id, None)

    async def send(self, message: AgentMessage):
        """Send a message to a specific agent or broadcast."""
        self._history.append(message)
        if message.recipient and message.recipient in self._queues:
            await self._queues[message.recipient].put(message)
        elif not message.recipient:
            # Broadcast to all except sender
            for agent_id, queue in self._queues.items():
                if agent_id != message.sender:
                    await queue.put(message)

    def send_sync(self, message: AgentMessage):
        """Synchronous send — for non-async contexts."""
        self._history.append(message)
        if message.recipient and message.recipient in self._queues:
            self._queues[message.recipient].put_nowait(message)
        elif not message.recipient:
            for agent_id, queue in self._queues.items():
                if agent_id != message.sender:
                    queue.put_nowait(message)

    async def receive(self, agent_id: str,
                      timeout: float = 1.0) -> Optional[AgentMessage]:
        """Receive next message for an agent (with timeout)."""
        if agent_id not in self._queues:
            return None
        try:
            return await asyncio.wait_for(
                self._queues[agent_id].get(), timeout=timeout
            )
        except asyncio.TimeoutError:
            return None

    def receive_nowait(self, agent_id: str) -> Optional[AgentMessage]:
        """Non-blocking receive."""
        if agent_id not in self._queues:
            return None
        try:
            return self._queues[agent_id].get_nowait()
        except asyncio.QueueEmpty:
            return None

    def pending_count(self, agent_id: str) -> int:
        """Number of pending messages for an agent."""
        if agent_id in self._queues:
            return self._queues[agent_id].qsize()
        return 0

    def get_history(self, sender: str = "", msg_type: MessageType = None,
                    limit: int = 100) -> list[AgentMessage]:
        """Query message history."""
        results = []
        for msg in reversed(self._history):
            if sender and msg.sender != sender:
                continue
            if msg_type and msg.msg_type != msg_type:
                continue
            results.append(msg)
            if len(results) >= limit:
                break
        return results

    @property
    def total_messages(self) -> int:
        return len(self._history)


# ═══════════════════════════════════════════════════════════════════
# BASE AGENT
# ═══════════════════════════════════════════════════════════════════

class BaseAgent(ABC):
    """
    Abstract base class for all autonomous scanning agents.

    Lifecycle:
      1. Initialize with target, goals, and optional config
      2. run() enters the perceive → decide → act → communicate loop
      3. Each cycle: check inbox, update memory, choose action, execute
      4. Agent terminates when goals are met or budget exhausted

    Subclasses implement:
      - perceive(): Analyze new information
      - decide(): Choose next action
      - act(): Execute the chosen action
      - on_message(): Handle incoming messages
    """

    name: str = "BaseAgent"
    specialty: str = "general"

    def __init__(
        self,
        agent_id: str = "",
        target: str = "",
        goals: Optional[list[AgentGoal]] = None,
        message_bus: Optional[MessageBus] = None,
        knowledge_graph: Optional[KnowledgeGraph] = None,
        config: Optional[dict] = None,
    ):
        self.id = agent_id or f"{self.name}_{uuid.uuid4().hex[:6]}"
        self.target = target
        self.goals = goals or []
        self.bus = message_bus
        self.knowledge = knowledge_graph
        self.config = config or {}

        self.state = AgentState.IDLE
        self.memory = AgentMemory()
        self.cycle_count = 0
        self.max_cycles = self.config.get("max_cycles", 100)
        self.max_requests = self.config.get("max_requests", 500)
        self.requests_made = 0
        self.start_time = 0.0
        self.time_budget = self.config.get("time_budget", 300)  # seconds
        self._action_queue: deque[Action] = deque()
        self._http_client = None
        self._running = False

    # ── Properties ───────────────────────────────────────────────

    @property
    def is_done(self) -> bool:
        """Check if agent should stop."""
        if self.state in (AgentState.DONE, AgentState.FAILED):
            return True
        if self.cycle_count >= self.max_cycles:
            return True
        if self.requests_made >= self.max_requests:
            return True
        if self.start_time and (time.time() - self.start_time) > self.time_budget:
            return True
        if self.goals and all(
            g.status in (GoalStatus.ACHIEVED, GoalStatus.FAILED, GoalStatus.ABANDONED)
            for g in self.goals
        ):
            return True
        return False

    @property
    def elapsed_time(self) -> float:
        if self.start_time:
            return time.time() - self.start_time
        return 0.0

    @property
    def active_goals(self) -> list[AgentGoal]:
        return [g for g in self.goals
                if g.status in (GoalStatus.PENDING, GoalStatus.IN_PROGRESS)]

    # ── Core Loop ────────────────────────────────────────────────

    async def run(self) -> list[dict]:
        """
        Main agent loop: perceive → decide → act → communicate.

        Returns list of confirmed findings.
        """
        self._running = True
        self.start_time = time.time()
        self.state = AgentState.OBSERVING

        if self.bus:
            self.bus.register(self.id)

        try:
            while not self.is_done:
                self.cycle_count += 1

                # 1. Check inbox for messages from other agents
                await self._process_inbox()

                # 2. PERCEIVE: Gather and analyze information
                self.state = AgentState.OBSERVING
                observations = await self.perceive()
                for obs in observations:
                    self.memory.add_observation(obs)

                # 3. DECIDE: Choose next action(s)
                self.state = AgentState.DECIDING
                actions = await self.decide()

                if not actions and not self._action_queue:
                    # Nothing to do — check if goals are met
                    if not self.active_goals:
                        self.state = AgentState.DONE
                        break
                    # Still have goals but no actions — might need to adapt
                    self.state = AgentState.ADAPTING
                    await self.adapt()
                    continue

                # Queue all decided actions
                for action in actions:
                    self._action_queue.append(action)

                # 4. ACT: Execute next action from queue
                if self._action_queue:
                    action = self._action_queue.popleft()
                    self.state = AgentState.ACTING
                    result = await self.act(action)
                    self.memory.record_action(result)
                    self.requests_made += result.requests_made

                    # Process action results
                    await self._process_result(result)

                # 5. COMMUNICATE: Share relevant findings
                self.state = AgentState.COMMUNICATING
                await self.communicate()

            # Loop exited normally (is_done returned True)
            if self.state != AgentState.FAILED:
                self.state = AgentState.DONE

        except Exception as exc:
            self.state = AgentState.FAILED
            self.memory.add_observation(Observation(
                observation_type="agent_error",
                detail=str(exc),
            ))

        finally:
            self._running = False
            if self.bus:
                # Send final status
                self.bus.send_sync(AgentMessage(
                    sender=self.id,
                    msg_type=MessageType.STATUS,
                    payload={
                        "status": self.state.name,
                        "findings": len(self.memory.findings),
                        "cycles": self.cycle_count,
                        "requests": self.requests_made,
                    },
                ))

        return self.memory.findings

    def run_sync(self) -> list[dict]:
        """Synchronous wrapper for run()."""
        return asyncio.get_event_loop().run_until_complete(self.run())

    # ── Abstract Methods (subclasses implement) ──────────────────

    @abstractmethod
    async def perceive(self) -> list[Observation]:
        """
        Gather observations about the target.

        Returns new observations from analyzing responses,
        knowledge graph, or message inbox.
        """
        ...

    @abstractmethod
    async def decide(self) -> list[Action]:
        """
        Choose next action(s) based on current state.

        Considers: goals, observations, hypotheses, budget.
        Returns prioritized list of actions.
        """
        ...

    @abstractmethod
    async def act(self, action: Action) -> ActionResult:
        """
        Execute a specific action.

        Could be: send HTTP request, run scanner, evolve payload, etc.
        Returns the result of the action.
        """
        ...

    # ── Overridable Hooks ────────────────────────────────────────

    async def on_message(self, message: AgentMessage):
        """Handle an incoming message from another agent."""
        if message.msg_type == MessageType.FINDING:
            # Store findings from other agents
            self.memory.add_observation(Observation(
                url=message.payload.get("url", ""),
                parameter=message.payload.get("parameter", ""),
                observation_type="external_finding",
                detail=str(message.payload),
                confidence=message.payload.get("confidence", 0.8),
            ))
        elif message.msg_type == MessageType.ALERT:
            # Urgent: adapt behavior
            await self.on_alert(message)
        elif message.msg_type == MessageType.INTELLIGENCE:
            self.memory.add_observation(Observation(
                url=message.payload.get("url", ""),
                observation_type="external_intel",
                detail=str(message.payload),
                confidence=0.5,
            ))

    async def on_alert(self, message: AgentMessage):
        """Handle urgent alerts (WAF, rate limit, etc.)."""
        alert_type = message.payload.get("alert_type", "")
        if alert_type == "waf_block":
            self.memory.blocked_payloads.append(
                message.payload.get("payload", "")
            )
        elif alert_type == "rate_limit":
            # Slow down
            self.config["request_delay"] = self.config.get("request_delay", 0) + 1.0

    async def adapt(self):
        """Change strategy when current approach isn't working."""
        pass  # Subclasses override

    async def communicate(self):
        """Share relevant information with other agents."""
        if not self.bus:
            return

        # Share new confirmed findings
        for finding in self.memory.findings:
            if not finding.get("_shared"):
                self.bus.send_sync(AgentMessage(
                    sender=self.id,
                    msg_type=MessageType.FINDING,
                    payload=finding,
                    priority=0.9,
                ))
                finding["_shared"] = True

        # Share new confirmed hypotheses
        for hyp in self.memory.get_confirmed_hypotheses():
            if not hasattr(hyp, "_shared"):
                self.bus.send_sync(AgentMessage(
                    sender=self.id,
                    msg_type=MessageType.INTELLIGENCE,
                    payload={
                        "type": "confirmed_hypothesis",
                        "vuln_type": hyp.vuln_type,
                        "url": hyp.target_url,
                        "param": hyp.target_param,
                        "confidence": hyp.confidence,
                    },
                    priority=0.8,
                ))
                hyp._shared = True

    # ── Internal Methods ─────────────────────────────────────────

    async def _process_inbox(self):
        """Process all pending messages."""
        if not self.bus:
            return
        while True:
            msg = self.bus.receive_nowait(self.id)
            if msg is None:
                break
            await self.on_message(msg)

    async def _process_result(self, result: ActionResult):
        """Process the result of an action — update hypotheses, add findings."""
        for obs in result.observations:
            self.memory.add_observation(obs)

        for finding in result.findings:
            self.memory.add_finding(finding)

        # Update relevant hypotheses
        for hyp in self.memory.get_active_hypotheses():
            if (hyp.target_url == result.action.target_url and
                    hyp.target_param == result.action.target_param):
                has_evidence = len(result.findings) > 0 or any(
                    o.confidence > 0.7 for o in result.observations
                )
                hyp.update_confidence(has_evidence)

    # ── Utility ──────────────────────────────────────────────────

    def add_goal(self, description: str, goal_type: str = "find_vulns",
                 target: str = "", priority: float = 0.5) -> AgentGoal:
        """Add a new goal for this agent."""
        goal = AgentGoal(
            description=description,
            goal_type=goal_type,
            target=target or self.target,
            priority=priority,
        )
        self.goals.append(goal)
        return goal

    def get_status(self) -> dict:
        """Get current agent status."""
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state.name,
            "cycle": self.cycle_count,
            "requests": self.requests_made,
            "elapsed": self.elapsed_time,
            "findings": len(self.memory.findings),
            "active_goals": len(self.active_goals),
            "memory": self.memory.get_stats(),
        }

    def __repr__(self) -> str:
        return (f"<{self.name}({self.id}) state={self.state.name} "
                f"cycle={self.cycle_count} findings={len(self.memory.findings)}>")
