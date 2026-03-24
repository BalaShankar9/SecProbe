"""
Division 20 — Meta-Coordination.

20 agents providing swarm-level orchestration: strategic planning, resource
allocation, scheduling, adaptive control, health monitoring, rate control,
budget tracking, consensus, kill switch, scope, mode enforcement, audit
logging, progress reporting, error recovery, memory, learning coordination,
session management, config optimization, telemetry, and supreme command.
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


def agents() -> list[AgentSpec]:
    return [
        # ── Strategic Planner (1) ────────────────────────────────────
        _s(
            "meta-strategic-planner", "Strategic Scan Planner", 20,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING},
            description="Analyzes the target's attack surface profile from initial "
                        "reconnaissance and constructs a phased scan strategy that "
                        "prioritizes divisions by relevance, orders dependent scans, "
                        "and allocates time budgets per phase.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "strategy", "planning"),
        ),

        # ── Resource Allocator (1) ───────────────────────────────────
        _s(
            "meta-resource-allocator", "Resource Allocation Manager", 20,
            {Cap.COORDINATION, Cap.STATISTICAL_ANALYSIS},
            description="Dynamically allocates concurrency slots, request budgets, and "
                        "memory quotas across 20 divisions based on target relevance "
                        "scores, finding density, and remaining time budget.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "resource", "allocation"),
        ),

        # ── Division Scheduler (1) ───────────────────────────────────
        _s(
            "meta-division-scheduler", "Division Execution Scheduler", 20,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING},
            description="Schedules division activation order respecting dependencies "
                        "(recon before audit, audit before redteam), parallelizes "
                        "independent divisions, and manages the global execution DAG.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            depends_on=("meta-strategic-planner",),
            tags=("meta", "scheduler", "dag"),
        ),

        # ── Adaptive Controller (1) ──────────────────────────────────
        _s(
            "meta-adaptive-controller", "Adaptive Scan Controller", 20,
            {Cap.COORDINATION, Cap.SELF_IMPROVEMENT, Cap.STATISTICAL_ANALYSIS},
            description="Monitors scan progress and dynamically adjusts strategy: "
                        "reallocates budget from low-yield divisions to high-finding "
                        "areas, activates dormant specialists when new technologies "
                        "are discovered, and adapts to defensive responses.",
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "adaptive", "control"),
        ),

        # ── Health Monitor (1) ───────────────────────────────────────
        _s(
            "meta-health-monitor", "Agent Health Monitor", 20,
            {Cap.COORDINATION, Cap.STATISTICAL_ANALYSIS},
            description="Monitors all 600 agents for health indicators: stuck states, "
                        "excessive error rates, timeout breaches, memory leaks, and "
                        "unresponsive agents, triggering restart or replacement actions.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "health", "monitoring"),
        ),

        # ── Rate Controller (1) ──────────────────────────────────────
        _s(
            "meta-rate-controller", "Global Rate Controller", 20,
            {Cap.RATE_ADAPTATION, Cap.COORDINATION, Cap.STATISTICAL_ANALYSIS},
            description="Enforces global request rate limits across all agents to prevent "
                        "target overload, adapts to WAF detection signals (429 responses, "
                        "CAPTCHA), and implements exponential backoff with jitter.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "rate-limit", "throttle"),
        ),

        # ── Budget Tracker (1) ───────────────────────────────────────
        _s(
            "meta-budget-tracker", "Request Budget Tracker", 20,
            {Cap.COORDINATION, Cap.STATISTICAL_ANALYSIS},
            description="Tracks global and per-agent request budgets, enforces hard "
                        "limits, provides burn-rate analytics, and projects budget "
                        "exhaustion times to ensure scan completion within allocated "
                        "request quotas.",
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "budget", "tracking"),
        ),

        # ── Consensus Manager (1) ────────────────────────────────────
        _s(
            "meta-consensus-manager", "Multi-Agent Consensus Manager", 20,
            {Cap.CONSENSUS_VOTING, Cap.COORDINATION, Cap.KNOWLEDGE_SHARING},
            description="Manages the multi-agent consensus protocol for finding "
                        "validation: distributes findings to qualified verifier agents, "
                        "collects votes, resolves disagreements, and promotes findings "
                        "through confidence tiers (Tentative to Proven).",
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "consensus", "validation"),
        ),

        # ── Kill Switch (1) ──────────────────────────────────────────
        _s(
            "meta-kill-switch", "Emergency Kill Switch", 20,
            {Cap.COORDINATION},
            description="Monitors for emergency stop conditions: target unresponsive, "
                        "out-of-scope detection, legal boundary breach, operator abort "
                        "signal. Issues immediate KILL messages to all 600 agents and "
                        "persists partial results on activation.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=5,
            tags=("meta", "kill-switch", "emergency"),
        ),

        # ── Scope Guardian (1) ───────────────────────────────────────
        _s(
            "meta-scope-guardian", "Scope Boundary Guardian", 20,
            {Cap.COORDINATION, Cap.PATTERN_MATCHING},
            description="Enforces target scope boundaries by validating every outbound "
                        "request URL against the allowed domain/IP/path whitelist, "
                        "blocking out-of-scope requests, and alerting on scope creep "
                        "from crawler or redirect following.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "scope", "boundary"),
        ),

        # ── Mode Enforcer (1) ────────────────────────────────────────
        _s(
            "meta-mode-enforcer", "Operational Mode Enforcer", 20,
            {Cap.COORDINATION, Cap.PATTERN_MATCHING},
            description="Enforces the current operational mode (recon/audit/redteam) "
                        "across all agents, blocking actions that exceed mode permissions, "
                        "auditing mode transition requests, and preventing unauthorized "
                        "escalation from audit to redteam.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "mode", "enforcement"),
        ),

        # ── Audit Logger (1) ─────────────────────────────────────────
        _s(
            "meta-audit-logger", "Immutable Audit Logger", 20,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING},
            description="Records an immutable audit trail of all agent actions, findings, "
                        "scope decisions, mode changes, and operator commands with "
                        "timestamps, agent IDs, and cryptographic chain integrity for "
                        "forensic review and compliance evidence.",
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "audit", "logging", "compliance"),
        ),

        # ── Progress Reporter (1) ────────────────────────────────────
        _s(
            "meta-progress-reporter", "Scan Progress Reporter", 20,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING},
            description="Provides real-time scan progress to operators: percentage "
                        "complete per division, active agent count, findings discovered, "
                        "estimated time remaining, and current scan phase with throughput "
                        "metrics.",
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "progress", "dashboard"),
        ),

        # ── Error Recovery (1) ───────────────────────────────────────
        _s(
            "meta-error-recovery", "Error Recovery Coordinator", 20,
            {Cap.COORDINATION, Cap.SELF_IMPROVEMENT},
            description="Handles agent failures gracefully: restarts crashed agents with "
                        "preserved state, redistributes workload from failed agents, "
                        "implements circuit breaker patterns for persistent failures, "
                        "and maintains scan continuity.",
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "error", "recovery", "resilience"),
        ),

        # ── Memory Manager (1) ───────────────────────────────────────
        _s(
            "meta-memory-manager", "5-Tier Memory Manager", 20,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING},
            description="Manages the 5-tier memory hierarchy (working, short-term, "
                        "episodic, semantic, long-term), handles promotion/demotion "
                        "between tiers, enforces memory quotas, and coordinates shared "
                        "memory access across all 600 agents.",
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "memory", "hierarchy"),
        ),

        # ── Learning Coordinator (1) ─────────────────────────────────
        _s(
            "meta-learning-coordinator", "Cross-Scan Learning Coordinator", 20,
            {Cap.SELF_IMPROVEMENT, Cap.KNOWLEDGE_SHARING, Cap.STATISTICAL_ANALYSIS},
            description="Coordinates learning across scan sessions: persists effective "
                        "payload patterns, successful evasion techniques, per-technology "
                        "finding distributions, and false positive signatures to improve "
                        "future scan accuracy.",
            priority=Pri.BACKGROUND,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "learning", "cross-session"),
        ),

        # ── Session Manager (1) ──────────────────────────────────────
        _s(
            "meta-session-manager", "Scan Session Manager", 20,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING},
            description="Manages scan session lifecycle: initialization with target "
                        "validation, state checkpointing for resume capability, session "
                        "serialization/deserialization, and clean shutdown with result "
                        "persistence.",
            priority=Pri.HIGH,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "session", "persistence"),
        ),

        # ── Config Optimizer (1) ─────────────────────────────────────
        _s(
            "meta-config-optimizer", "Runtime Configuration Optimizer", 20,
            {Cap.SELF_IMPROVEMENT, Cap.STATISTICAL_ANALYSIS},
            description="Tunes runtime parameters (concurrency, timeouts, batch sizes, "
                        "retry policies) based on target response characteristics, "
                        "network latency measurements, and historical performance data "
                        "for optimal throughput.",
            priority=Pri.NORMAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "config", "optimization"),
        ),

        # ── Telemetry (1) ────────────────────────────────────────────
        _s(
            "meta-telemetry", "Swarm Telemetry Collector", 20,
            {Cap.STATISTICAL_ANALYSIS, Cap.KNOWLEDGE_SHARING},
            description="Collects and aggregates operational telemetry from all agents: "
                        "request counts, response times, error rates, finding rates, "
                        "memory usage, and agent state transitions for operational "
                        "visibility and post-scan analysis.",
            priority=Pri.BACKGROUND,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("meta", "telemetry", "metrics", "observability"),
        ),

        # ── Supreme Commander (1) ────────────────────────────────────
        _s(
            "meta-supreme-commander", "Supreme Swarm Commander", 20,
            {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING,
             Cap.SELF_IMPROVEMENT},
            description="Top-level coordinator for the entire 600-agent swarm. Receives "
                        "status from all 20 division commanders, makes global strategic "
                        "decisions, resolves inter-division conflicts, authorizes mode "
                        "transitions, and serves as the operator's primary control interface.",
            priority=Pri.CRITICAL,
            min_mode=Mode.RECON,
            max_requests=10,
            tags=("commander", "supreme", "swarm-leader"),
        ),
    ]
