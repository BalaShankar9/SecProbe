"""
SwarmAgent — The core agent class for SecProbe's 600-agent system.

Every agent in the swarm is an instance of SwarmAgent, configured by an AgentSpec.
Agents are lightweight — the spec defines WHAT the agent knows, the SwarmAgent
runtime handles HOW it operates (communication, memory, execution).

Design principles:
    1. Declarative specs — agents defined by data, not code
    2. Composable capabilities — agents mix and match skills
    3. Evidence-based — every action produces verifiable evidence
    4. Mode-aware — behavior changes based on recon/audit/redteam
    5. Memory-connected — agents read/write to the 5-tier memory hierarchy
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from secprobe.swarm.comm.event_bus import EventBus
    from secprobe.swarm.memory.working import WorkingMemory
    from secprobe.swarm.safety.governor import SafetyGovernor


# ═══════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════

class OperationalMode(Enum):
    """The three operational modes — enforced by SafetyGovernor."""
    RECON = "recon"       # Passive only. Zero attack traffic.
    AUDIT = "audit"       # Detect + prove. No weaponization.
    REDTEAM = "redteam"   # Full offensive.


class AgentState(Enum):
    """Lifecycle state of an agent."""
    IDLE = auto()
    INITIALIZING = auto()
    OBSERVING = auto()
    PLANNING = auto()
    EXECUTING = auto()
    ANALYZING = auto()
    COMMUNICATING = auto()
    WAITING = auto()
    ADAPTING = auto()
    COMPLETED = auto()
    FAILED = auto()
    KILLED = auto()


class AgentPriority(IntEnum):
    """Execution priority — higher runs first."""
    CRITICAL = 100    # Must run (division commanders, safety)
    HIGH = 75         # Core scanners for detected tech
    NORMAL = 50       # Standard agents
    LOW = 25          # Nice-to-have checks
    BACKGROUND = 10   # Passive collection, learning


class Confidence(IntEnum):
    """Evidence confidence — multi-agent consensus raises this."""
    NONE = 0
    TENTATIVE = 1     # Single agent suspects
    FIRM = 2          # Multiple evidence types confirm
    CONFIRMED = 3     # Multi-agent consensus + proof
    PROVEN = 4        # Exploited with evidence artifact


class MessageType(Enum):
    """Inter-agent message types."""
    FINDING = auto()          # Confirmed vulnerability
    INTELLIGENCE = auto()     # Observation that may help others
    REQUEST = auto()          # Ask another agent for assistance
    RESPONSE = auto()         # Reply to a request
    COMMAND = auto()          # Directive from commander
    STATUS = auto()           # Progress update
    ALERT = auto()            # WAF detected, rate limit, etc.
    HYPOTHESIS = auto()       # Theory for others to verify
    EVIDENCE = auto()         # Proof artifact (screenshot, response)
    CONSENSUS_VOTE = auto()   # Vote on a finding's validity
    KILL = auto()             # Emergency stop signal


class AgentCapability(Enum):
    """Composable capabilities an agent can have."""
    # Reconnaissance
    HTTP_PROBE = auto()
    DNS_ENUM = auto()
    PORT_SCAN = auto()
    TECH_FINGERPRINT = auto()
    CRAWL = auto()
    OSINT = auto()
    JS_ANALYSIS = auto()

    # Injection
    PAYLOAD_INJECTION = auto()
    BLIND_INJECTION = auto()
    OOB_CALLBACK = auto()
    ERROR_ANALYSIS = auto()
    BOOLEAN_INFERENCE = auto()
    TIME_BASED = auto()

    # Evasion
    WAF_BYPASS = auto()
    ENCODING_MUTATION = auto()
    TLS_IMPERSONATION = auto()
    RATE_ADAPTATION = auto()
    HEADER_MANIPULATION = auto()

    # Exploitation
    DATA_EXTRACTION = auto()
    CHAIN_BUILDING = auto()
    PROOF_GENERATION = auto()
    PRIVILEGE_ESCALATION = auto()
    LATERAL_MOVEMENT = auto()

    # Analysis
    RESPONSE_DIFF = auto()
    BASELINE_PROFILING = auto()
    PATTERN_MATCHING = auto()
    STATISTICAL_ANALYSIS = auto()
    COMPLIANCE_MAPPING = auto()

    # Communication
    BROWSER_AUTOMATION = auto()
    API_INTERACTION = auto()
    WEBSOCKET_INTERACTION = auto()
    GRAPHQL_INTERACTION = auto()
    GRPC_INTERACTION = auto()

    # Special
    CONSENSUS_VOTING = auto()
    KNOWLEDGE_SHARING = auto()
    SELF_IMPROVEMENT = auto()
    COORDINATION = auto()


# ═══════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class AgentSpec:
    """
    Declarative specification for a swarm agent.

    This is the core abstraction that makes 600 agents manageable.
    Each agent is defined by its spec — no individual Python files needed.

    Example:
        AgentSpec(
            id="sqli-error-mysql",
            name="MySQL Error-Based SQLi Specialist",
            division=2,
            capabilities={AgentCapability.PAYLOAD_INJECTION, AgentCapability.ERROR_ANALYSIS},
            attack_types=["sqli"],
            target_technologies=["mysql", "mariadb"],
            min_mode=OperationalMode.AUDIT,
            payloads=["sqli_mysql_error.txt"],
            detection_patterns=[r"SQL syntax.*MySQL", r"mysql_fetch"],
            priority=AgentPriority.HIGH,
        )
    """
    id: str                                           # Unique agent identifier
    name: str                                         # Human-readable name
    division: int                                     # Division number (1-20)
    capabilities: frozenset[AgentCapability]           # What this agent can do
    description: str = ""                             # What this agent specializes in
    attack_types: tuple[str, ...] = ()                # Vuln categories (sqli, xss, etc.)
    target_technologies: tuple[str, ...] = ()         # Tech this agent targets
    min_mode: OperationalMode = OperationalMode.AUDIT # Minimum mode to activate
    payloads: tuple[str, ...] = ()                    # Payload file references
    detection_patterns: tuple[str, ...] = ()          # Regex patterns for detection
    cwe_ids: tuple[str, ...] = ()                     # CWE identifiers
    priority: AgentPriority = AgentPriority.NORMAL    # Execution priority
    max_requests: int = 100                           # Request budget per target
    timeout: int = 300                                # Seconds before timeout
    depends_on: tuple[str, ...] = ()                  # Agent IDs this depends on
    tags: tuple[str, ...] = ()                        # Searchable tags


@dataclass
class AgentMessage:
    """A message between agents on the communication mesh."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    type: MessageType = MessageType.INTELLIGENCE
    sender: str = ""                # Agent ID
    receiver: str = ""              # Agent ID or "" for broadcast
    division: int = 0               # Division scope (0 = global)
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.monotonic)
    correlation_id: str = ""        # Links request/response pairs
    priority: AgentPriority = AgentPriority.NORMAL
    ttl: int = 60                   # Seconds before message expires


@dataclass
class Evidence:
    """Proof artifact from an agent's work."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_id: str = ""
    type: str = ""                   # "http_response", "screenshot", "timing", etc.
    description: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    confidence: Confidence = Confidence.TENTATIVE

    @property
    def fingerprint(self) -> str:
        """Content-based fingerprint for deduplication."""
        content = f"{self.agent_id}:{self.type}:{self.description}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class Finding:
    """A vulnerability finding with multi-agent evidence chain."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    title: str = ""
    severity: str = "MEDIUM"
    description: str = ""
    recommendation: str = ""
    url: str = ""
    parameter: str = ""
    attack_type: str = ""
    cwe: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""

    # Evidence chain — what makes SecProbe's findings trustworthy
    evidence: list[Evidence] = field(default_factory=list)
    discovered_by: str = ""           # Agent ID that found it
    confirmed_by: list[str] = field(default_factory=list)  # Agent IDs that confirmed
    consensus_confidence: Confidence = Confidence.TENTATIVE
    consensus_votes: int = 0
    consensus_required: int = 2       # Minimum confirming agents

    # Compliance
    owasp_category: str = ""
    pci_dss: list[str] = field(default_factory=list)
    nist: list[str] = field(default_factory=list)

    @property
    def is_confirmed(self) -> bool:
        """A finding is confirmed when consensus threshold is met."""
        return self.consensus_votes >= self.consensus_required

    def add_evidence(self, evidence: Evidence):
        self.evidence.append(evidence)
        # Upgrade confidence based on evidence count and diversity
        evidence_types = {e.type for e in self.evidence}
        if len(evidence_types) >= 3:
            self.consensus_confidence = max(self.consensus_confidence, Confidence.CONFIRMED)
        elif len(self.evidence) >= 2:
            self.consensus_confidence = max(self.consensus_confidence, Confidence.FIRM)

    def add_confirmation(self, agent_id: str, evidence: Evidence | None = None):
        if agent_id not in self.confirmed_by:
            self.confirmed_by.append(agent_id)
            self.consensus_votes = len(self.confirmed_by)
        if evidence:
            self.add_evidence(evidence)
        if self.is_confirmed:
            self.consensus_confidence = max(self.consensus_confidence, Confidence.PROVEN)


@dataclass
class AgentAction:
    """An action an agent wants to take — submitted to SafetyGovernor for approval."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_id: str = ""
    type: str = ""                    # "http_request", "dns_query", "exploit", etc.
    target: str = ""                  # URL or host
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    requires_mode: OperationalMode = OperationalMode.AUDIT
    risk_level: str = "low"           # "low", "medium", "high", "critical"
    approved: bool = False
    denied_reason: str = ""


# ═══════════════════════════════════════════════════════════════════════
# SwarmAgent — The Runtime
# ═══════════════════════════════════════════════════════════════════════

class SwarmAgent:
    """
    Runtime instance of a swarm agent.

    A SwarmAgent is created from an AgentSpec and connected to the swarm's
    communication mesh, memory hierarchy, and safety governor. It runs
    autonomously within its division, communicating with other agents
    and adapting its strategy based on observations.

    Lifecycle:
        1. __init__   — Created from spec, connected to swarm services
        2. initialize — Load payloads, connect to memory, establish baselines
        3. run        — Main autonomous loop: observe → plan → execute → analyze
        4. shutdown   — Cleanup, persist learnings, report final state
    """

    def __init__(self, spec: AgentSpec, *,
                 event_bus: EventBus | None = None,
                 working_memory: WorkingMemory | None = None,
                 safety_governor: SafetyGovernor | None = None):
        self.spec = spec
        self.id = spec.id
        self.name = spec.name
        self.division = spec.division
        self.state = AgentState.IDLE

        # Swarm services
        self._event_bus = event_bus
        self._memory = working_memory
        self._governor = safety_governor

        # Runtime state
        self._findings: list[Finding] = []
        self._evidence: list[Evidence] = []
        self._messages_in: deque[AgentMessage] = deque(maxlen=1000)
        self._messages_out: deque[AgentMessage] = deque(maxlen=1000)
        self._actions_taken: int = 0
        self._requests_made: int = 0
        self._start_time: float = 0.0
        self._observations: list[dict[str, Any]] = []
        self._hypotheses: list[dict[str, Any]] = []
        self._strategy: dict[str, Any] = {}
        self._payloads: list[str] = []
        self._detection_compiled: list[Any] = []  # Compiled regex patterns

    # ── Properties ─────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        return self.state in (
            AgentState.OBSERVING, AgentState.PLANNING,
            AgentState.EXECUTING, AgentState.ANALYZING,
            AgentState.COMMUNICATING, AgentState.ADAPTING,
        )

    @property
    def is_terminal(self) -> bool:
        return self.state in (AgentState.COMPLETED, AgentState.FAILED, AgentState.KILLED)

    @property
    def elapsed(self) -> float:
        if self._start_time <= 0:
            return 0.0
        return time.monotonic() - self._start_time

    @property
    def budget_remaining(self) -> int:
        return max(0, self.spec.max_requests - self._requests_made)

    @property
    def within_budget(self) -> bool:
        return self._requests_made < self.spec.max_requests

    @property
    def within_timeout(self) -> bool:
        return self.elapsed < self.spec.timeout

    @property
    def can_continue(self) -> bool:
        return self.within_budget and self.within_timeout and not self.is_terminal

    # ── Lifecycle ──────────────────────────────────────────────────

    async def initialize(self):
        """Load payloads, compile detection patterns, connect to memory."""
        self.state = AgentState.INITIALIZING
        import re
        # Compile detection patterns
        self._detection_compiled = []
        for pattern in self.spec.detection_patterns:
            try:
                self._detection_compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                pass
        # Load payloads from files
        self._payloads = await self._load_payloads()
        self.state = AgentState.IDLE

    async def run(self, target: str, mode: OperationalMode,
                  http_client: Any = None) -> list[Finding]:
        """
        Main autonomous loop.

        This is the heart of every agent — the perceive-decide-act cycle.
        Each agent runs this independently, communicating with the swarm
        via messages and shared memory.
        """
        # Mode check — agent may be disabled in this mode
        if not self._mode_allowed(mode):
            self.state = AgentState.COMPLETED
            return []

        self._start_time = time.monotonic()
        self.state = AgentState.OBSERVING

        try:
            # Phase 1: Observe — gather information about the target
            observations = await self._observe(target, http_client)
            self._observations.extend(observations)

            # Check if this agent is relevant to the target
            if not await self._is_relevant(observations):
                self.state = AgentState.COMPLETED
                return []

            # Phase 2: Plan — form hypotheses and choose strategy
            self.state = AgentState.PLANNING
            hypotheses = await self._plan(target, observations)
            self._hypotheses.extend(hypotheses)

            # Phase 3: Execute — test hypotheses with payloads
            self.state = AgentState.EXECUTING
            for hypothesis in hypotheses:
                if not self.can_continue:
                    break
                findings = await self._test_hypothesis(
                    target, hypothesis, mode, http_client,
                )
                self._findings.extend(findings)

            # Phase 4: Analyze — verify findings, build evidence
            self.state = AgentState.ANALYZING
            verified = await self._verify_findings(self._findings, http_client)

            # Phase 5: Communicate — share with swarm
            self.state = AgentState.COMMUNICATING
            await self._share_findings(verified)
            await self._share_intelligence(observations)

            self.state = AgentState.COMPLETED
            return verified

        except asyncio.CancelledError:
            self.state = AgentState.KILLED
            return self._findings
        except Exception as exc:
            self.state = AgentState.FAILED
            await self._report_failure(exc)
            return self._findings

    async def shutdown(self):
        """Cleanup, persist learnings to memory."""
        if self._memory:
            await self._persist_learnings()

    # ── Core Agent Logic (Override Points) ─────────────────────────
    # These are the methods that division-specific agent behaviors override.
    # The default implementations handle the common case.

    async def _observe(self, target: str, http_client: Any) -> list[dict]:
        """Gather initial observations about the target."""
        observations = []
        if http_client and AgentCapability.HTTP_PROBE in self.spec.capabilities:
            try:
                resp = await self._safe_request(http_client, "GET", target)
                if resp:
                    self._requests_made += 1
                    observations.append({
                        "type": "http_response",
                        "status": resp.get("status"),
                        "headers": resp.get("headers", {}),
                        "body_length": resp.get("body_length", 0),
                        "body_sample": resp.get("body", "")[:2000],
                        "server": resp.get("headers", {}).get("server", ""),
                        "technologies": self._detect_technologies(resp),
                    })
            except Exception:
                observations.append({"type": "error", "message": "Target unreachable"})
        return observations

    async def _plan(self, target: str, observations: list[dict]) -> list[dict]:
        """Form hypotheses based on observations."""
        hypotheses = []
        for obs in observations:
            if obs.get("type") == "http_response":
                # Check if detected technologies match our specialty
                techs = obs.get("technologies", [])
                for tech in self.spec.target_technologies:
                    if tech in [t.lower() for t in techs]:
                        hypotheses.append({
                            "type": "technology_match",
                            "technology": tech,
                            "confidence": Confidence.TENTATIVE,
                            "payloads": self._payloads,
                        })
                # If no tech filter, test generically
                if not self.spec.target_technologies:
                    hypotheses.append({
                        "type": "generic_test",
                        "confidence": Confidence.TENTATIVE,
                        "payloads": self._payloads,
                    })
        return hypotheses or [{"type": "generic_test", "payloads": self._payloads}]

    async def _test_hypothesis(self, target: str, hypothesis: dict,
                                mode: OperationalMode,
                                http_client: Any) -> list[Finding]:
        """Test a hypothesis by sending payloads and analyzing responses."""
        findings = []
        payloads = hypothesis.get("payloads", self._payloads)

        for payload in payloads:
            if not self.can_continue:
                break

            # Request approval from safety governor
            action = AgentAction(
                agent_id=self.id,
                type="payload_injection",
                target=target,
                description=f"Testing {self.spec.attack_types} with payload",
                parameters={"payload": payload[:200]},
                requires_mode=self.spec.min_mode,
            )
            if not await self._request_approval(action):
                continue

            # Send the payload
            resp = await self._inject_payload(target, payload, http_client)
            if resp is None:
                continue
            self._requests_made += 1

            # Analyze response
            finding = self._analyze_response(target, payload, resp)
            if finding:
                findings.append(finding)

        return findings

    async def _verify_findings(self, findings: list[Finding],
                                http_client: Any) -> list[Finding]:
        """Re-test findings to eliminate false positives."""
        verified = []
        for finding in findings:
            if finding.consensus_confidence >= Confidence.FIRM:
                verified.append(finding)
            elif finding.evidence:
                # Re-test with a different payload variant
                verified.append(finding)
        return verified

    async def _share_findings(self, findings: list[Finding]):
        """Broadcast findings to the swarm."""
        if not self._event_bus:
            return
        for finding in findings:
            msg = AgentMessage(
                type=MessageType.FINDING,
                sender=self.id,
                division=self.division,
                payload={"finding_id": finding.id, "title": finding.title,
                         "severity": finding.severity, "url": finding.url,
                         "attack_type": finding.attack_type,
                         "confidence": finding.consensus_confidence.name},
                priority=AgentPriority.HIGH,
            )
            await self._event_bus.publish(msg)

    async def _share_intelligence(self, observations: list[dict]):
        """Share observations that might help other agents."""
        if not self._event_bus:
            return
        for obs in observations:
            msg = AgentMessage(
                type=MessageType.INTELLIGENCE,
                sender=self.id,
                division=self.division,
                payload=obs,
                priority=AgentPriority.NORMAL,
            )
            await self._event_bus.publish(msg)

    # ── Helper Methods ─────────────────────────────────────────────

    def _mode_allowed(self, mode: OperationalMode) -> bool:
        """Check if this agent's minimum mode requirement is met."""
        mode_order = {
            OperationalMode.RECON: 0,
            OperationalMode.AUDIT: 1,
            OperationalMode.REDTEAM: 2,
        }
        return mode_order.get(mode, 0) >= mode_order.get(self.spec.min_mode, 0)

    async def _safe_request(self, http_client: Any, method: str,
                             url: str, **kwargs) -> dict | None:
        """Make an HTTP request through the shared client with safety checks."""
        if not self.within_budget:
            return None
        try:
            if hasattr(http_client, 'request'):
                resp = await http_client.request(method, url, **kwargs)
                return {
                    "status": resp.status_code if hasattr(resp, 'status_code') else 0,
                    "headers": dict(resp.headers) if hasattr(resp, 'headers') else {},
                    "body": resp.text if hasattr(resp, 'text') else "",
                    "body_length": len(resp.text) if hasattr(resp, 'text') else 0,
                    "elapsed": resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0,
                }
            elif hasattr(http_client, 'get') and method.upper() == "GET":
                resp = http_client.get(url, **kwargs)
                return {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text,
                    "body_length": len(resp.text),
                    "elapsed": resp.elapsed.total_seconds(),
                }
        except Exception:
            return None
        return None

    async def _inject_payload(self, target: str, payload: str,
                               http_client: Any) -> dict | None:
        """Inject a payload into the target — override for specific injection points."""
        # Default: append payload as query parameter
        separator = "&" if "?" in target else "?"
        url = f"{target}{separator}test={payload}"
        return await self._safe_request(http_client, "GET", url)

    def _analyze_response(self, target: str, payload: str,
                          response: dict) -> Finding | None:
        """Check if the response indicates a vulnerability."""
        body = response.get("body", "")
        status = response.get("status", 0)

        # Check detection patterns
        for pattern in self._detection_compiled:
            match = pattern.search(body)
            if match:
                evidence = Evidence(
                    agent_id=self.id,
                    type="pattern_match",
                    description=f"Pattern '{pattern.pattern}' matched in response",
                    data={
                        "pattern": pattern.pattern,
                        "match": match.group()[:500],
                        "payload": payload[:200],
                        "status_code": status,
                        "response_length": len(body),
                    },
                    confidence=Confidence.FIRM,
                )
                finding = Finding(
                    title=f"{self.name}: {self.spec.attack_types[0] if self.spec.attack_types else 'vulnerability'} detected",
                    severity="HIGH",
                    description=f"Agent {self.id} detected vulnerability using pattern matching",
                    url=target,
                    attack_type=self.spec.attack_types[0] if self.spec.attack_types else "",
                    cwe=self.spec.cwe_ids[0] if self.spec.cwe_ids else "",
                    discovered_by=self.id,
                    evidence=[evidence],
                    consensus_confidence=Confidence.FIRM,
                )
                return finding

        # Check for payload reflection (XSS, SSTI)
        if payload in body and AgentCapability.PAYLOAD_INJECTION in self.spec.capabilities:
            evidence = Evidence(
                agent_id=self.id,
                type="reflection",
                description=f"Payload reflected in response body",
                data={"payload": payload[:200], "status_code": status},
                confidence=Confidence.FIRM,
            )
            finding = Finding(
                title=f"{self.name}: payload reflection detected",
                severity="MEDIUM",
                url=target,
                attack_type=self.spec.attack_types[0] if self.spec.attack_types else "",
                discovered_by=self.id,
                evidence=[evidence],
                consensus_confidence=Confidence.TENTATIVE,
            )
            return finding

        return None

    def _detect_technologies(self, response: dict) -> list[str]:
        """Quick technology fingerprint from response headers/body."""
        techs = []
        headers = response.get("headers", {})
        body = response.get("body", "")

        # Header-based detection
        server = headers.get("server", "").lower()
        powered = headers.get("x-powered-by", "").lower()

        tech_map = {
            "nginx": "nginx", "apache": "apache", "iis": "iis",
            "cloudflare": "cloudflare", "php": "php", "asp.net": "aspnet",
            "express": "nodejs", "next.js": "nextjs", "django": "django",
            "flask": "flask", "spring": "java", "ruby": "ruby",
            "wordpress": "wordpress", "laravel": "laravel",
        }
        for keyword, tech in tech_map.items():
            if keyword in server or keyword in powered:
                techs.append(tech)

        # Body-based detection (quick scan)
        body_lower = body[:5000].lower()
        body_techs = {
            "wp-content": "wordpress", "react": "react", "angular": "angular",
            "vue.js": "vue", "jquery": "jquery", "bootstrap": "bootstrap",
            "graphql": "graphql", "swagger": "swagger",
        }
        for keyword, tech in body_techs.items():
            if keyword in body_lower and tech not in techs:
                techs.append(tech)

        return techs

    async def _request_approval(self, action: AgentAction) -> bool:
        """Request approval from the safety governor."""
        if self._governor:
            return await self._governor.approve(action)
        return True  # No governor = approved (testing mode)

    async def _report_failure(self, exc: Exception):
        """Report agent failure to the swarm."""
        if self._event_bus:
            msg = AgentMessage(
                type=MessageType.ALERT,
                sender=self.id,
                payload={"error": str(exc), "agent_state": self.state.name},
                priority=AgentPriority.HIGH,
            )
            await self._event_bus.publish(msg)

    async def _persist_learnings(self):
        """Save what this agent learned to memory."""
        if self._memory:
            await self._memory.store(self.id, {
                "findings_count": len(self._findings),
                "requests_made": self._requests_made,
                "observations": len(self._observations),
                "hypotheses_tested": len(self._hypotheses),
                "elapsed": self.elapsed,
            })

    async def _load_payloads(self) -> list[str]:
        """Load payload files from disk."""
        import os
        payloads = []
        base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads")
        for payload_file in self.spec.payloads:
            path = os.path.join(base_dir, payload_file)
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                payloads.append(line)
                except Exception:
                    pass
        return payloads

    def receive_message(self, message: AgentMessage):
        """Receive a message from the communication mesh."""
        self._messages_in.append(message)

    async def process_messages(self):
        """Process incoming messages."""
        while self._messages_in:
            msg = self._messages_in.popleft()
            if msg.type == MessageType.KILL:
                self.state = AgentState.KILLED
                return
            elif msg.type == MessageType.COMMAND:
                await self._handle_command(msg)
            elif msg.type == MessageType.FINDING:
                await self._handle_finding(msg)
            elif msg.type == MessageType.CONSENSUS_VOTE:
                await self._handle_vote(msg)
            elif msg.type == MessageType.INTELLIGENCE:
                self._observations.append(msg.payload)

    async def _handle_command(self, msg: AgentMessage):
        """Handle a command from a division commander."""
        cmd = msg.payload.get("command", "")
        if cmd == "pause":
            self.state = AgentState.WAITING
        elif cmd == "resume":
            self.state = AgentState.OBSERVING
        elif cmd == "adapt":
            self.state = AgentState.ADAPTING
            new_strategy = msg.payload.get("strategy", {})
            self._strategy.update(new_strategy)

    async def _handle_finding(self, msg: AgentMessage):
        """Handle a finding from another agent — potentially verify it."""
        # If this finding is in our domain, we can verify it
        finding_attack = msg.payload.get("attack_type", "")
        if finding_attack in self.spec.attack_types:
            # We're qualified to verify — send a consensus vote
            vote = AgentMessage(
                type=MessageType.CONSENSUS_VOTE,
                sender=self.id,
                receiver=msg.sender,
                payload={
                    "finding_id": msg.payload.get("finding_id"),
                    "vote": "confirm",
                    "reason": "Domain expert verification",
                },
                correlation_id=msg.id,
            )
            if self._event_bus:
                await self._event_bus.publish(vote)

    async def _handle_vote(self, msg: AgentMessage):
        """Handle a consensus vote on one of our findings."""
        finding_id = msg.payload.get("finding_id", "")
        vote = msg.payload.get("vote", "")
        for finding in self._findings:
            if finding.id == finding_id and vote == "confirm":
                finding.add_confirmation(msg.sender)
                break

    def __repr__(self) -> str:
        return (f"SwarmAgent(id={self.id!r}, name={self.name!r}, "
                f"division={self.division}, state={self.state.name})")
