"""
Reasoning Engine — Decision-making core for autonomous agents.

This is the "brain" that separates SecProbe's agents from simple
script-based scanners. Every decision is:
  - Evidence-based (grounded in observations)
  - Goal-directed (pursuing specific objectives)
  - Risk-aware (balancing reward vs detection risk)
  - Adaptive (learns from outcomes)

Components:
  1. HypothesisGenerator: Creates testable theories from observations
  2. ActionPlanner: Converts hypotheses into concrete test actions
  3. RiskEvaluator: Scores detection risk of each action
  4. PriorityScorer: Ranks actions by expected value
  5. StrategyAdapter: Changes approach based on results

Decision flow:
  Observations → Hypotheses → Actions → Priority → Execute → Update

This replaces the naive "run all scanners on everything" with
intelligent, targeted, evidence-based testing.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from secprobe.agents.base import (
    Action, ActionType, AgentGoal, AgentMemory, GoalStatus,
    Hypothesis, Observation, Severity,
)


# ═══════════════════════════════════════════════════════════════════
# HYPOTHESIS GENERATOR
# ═══════════════════════════════════════════════════════════════════

class HypothesisGenerator:
    """
    Creates testable hypotheses from raw observations.

    Pattern matching:
      Observation(error + param) → Hypothesis(injection possible)
      Observation(reflection)    → Hypothesis(XSS possible)
      Observation(timing change) → Hypothesis(blind injection)
      Observation(path traversal)→ Hypothesis(LFI possible)
    """

    # Observation patterns that suggest vulnerability types
    VULN_INDICATORS = {
        "sqli": {
            "triggers": ["sql_error", "database_error", "syntax_error",
                         "mysql", "postgresql", "sqlite", "oracle",
                         "unescaped_quote"],
            "prior": 0.35,
            "description": "SQL injection likely — database error triggered",
        },
        "xss": {
            "triggers": ["reflection", "unescaped_output", "html_injection",
                         "script_context", "attribute_context"],
            "prior": 0.40,
            "description": "Cross-site scripting likely — input reflected",
        },
        "lfi": {
            "triggers": ["path_in_param", "file_param", "include_error",
                         "open_error", "permission_denied"],
            "prior": 0.25,
            "description": "Local file inclusion likely — file parameter found",
        },
        "ssti": {
            "triggers": ["template_error", "jinja_error", "expression_evaluated",
                         "math_result", "template_syntax"],
            "prior": 0.30,
            "description": "Template injection likely — expression evaluated",
        },
        "cmdi": {
            "triggers": ["command_output", "shell_error", "timeout_on_sleep",
                         "os_error", "ping_output"],
            "prior": 0.30,
            "description": "Command injection likely — OS behavior observed",
        },
        "ssrf": {
            "triggers": ["url_param", "fetch_param", "redirect_to_internal",
                         "dns_lookup", "connection_refused"],
            "prior": 0.20,
            "description": "SSRF likely — URL parameter processes requests",
        },
        "nosql": {
            "triggers": ["json_error", "mongodb_error", "query_operator",
                         "boolean_diff", "nosql_syntax"],
            "prior": 0.20,
            "description": "NoSQL injection likely — query structure affected",
        },
        "xxe": {
            "triggers": ["xml_parse", "xml_error", "dtd_processing",
                         "entity_expansion", "xml_content_type"],
            "prior": 0.15,
            "description": "XXE likely — XML processing detected",
        },
        "idor": {
            "triggers": ["sequential_id", "predictable_id", "user_id_param",
                         "different_data_returned", "auth_boundary_weak"],
            "prior": 0.25,
            "description": "IDOR likely — sequential IDs in parameters",
        },
        "redirect": {
            "triggers": ["redirect_param", "url_redirect", "open_redirect",
                         "redirect_to_external"],
            "prior": 0.30,
            "description": "Open redirect likely — redirect parameter found",
        },
    }

    def generate(self, observations: list[Observation],
                 existing: dict[str, Hypothesis] = None) -> list[Hypothesis]:
        """Generate hypotheses from observations."""
        hypotheses = []
        existing = existing or {}
        existing_keys = {
            f"{h.vuln_type}:{h.target_url}:{h.target_param}"
            for h in existing.values()
        }

        for obs in observations:
            for vuln_type, config in self.VULN_INDICATORS.items():
                if obs.observation_type in config["triggers"]:
                    key = f"{vuln_type}:{obs.url}:{obs.parameter}"
                    if key in existing_keys:
                        # Update existing hypothesis confidence
                        for h in existing.values():
                            if (h.vuln_type == vuln_type and
                                    h.target_url == obs.url and
                                    h.target_param == obs.parameter):
                                h.update_confidence(True, 0.15)
                        continue

                    hyp = Hypothesis(
                        vuln_type=vuln_type,
                        target_url=obs.url,
                        target_param=obs.parameter,
                        description=config["description"],
                        confidence=config["prior"],
                    )
                    hypotheses.append(hyp)
                    existing_keys.add(key)

        return hypotheses

    def generate_from_tech_stack(self, tech_stack: dict[str, float]
                                 ) -> list[Hypothesis]:
        """Generate hypotheses based on detected technologies."""
        hypotheses = []
        tech_vuln_map = {
            "php": [("lfi", 0.3), ("ssti", 0.2), ("cmdi", 0.15)],
            "python": [("ssti", 0.25), ("cmdi", 0.15)],
            "java": [("xxe", 0.35), ("ssti", 0.15)],
            "nodejs": [("nosql", 0.25), ("ssti", 0.2), ("ssrf", 0.15)],
            "mysql": [("sqli", 0.3)],
            "postgresql": [("sqli", 0.3)],
            "sqlite": [("sqli", 0.35)],
            "mongodb": [("nosql", 0.35)],
            "wordpress": [("sqli", 0.25), ("xss", 0.3), ("lfi", 0.2)],
            "flask": [("ssti", 0.35), ("sqli", 0.2)],
            "django": [("ssti", 0.15), ("idor", 0.2)],
            "express": [("nosql", 0.25), ("ssrf", 0.15)],
        }

        for tech, confidence in tech_stack.items():
            tech_lower = tech.lower()
            for tech_key, vuln_list in tech_vuln_map.items():
                if tech_key in tech_lower:
                    for vuln_type, prior in vuln_list:
                        adjusted_prior = prior * confidence
                        hypotheses.append(Hypothesis(
                            vuln_type=vuln_type,
                            description=f"{vuln_type} likely due to {tech} detected",
                            confidence=adjusted_prior,
                        ))

        return hypotheses


# ═══════════════════════════════════════════════════════════════════
# ACTION PLANNER
# ═══════════════════════════════════════════════════════════════════

class ActionPlanner:
    """
    Converts hypotheses into concrete test actions.

    For each hypothesis, generates a sequence of tests
    from least to most aggressive:
      1. Canary test (harmless probe to verify basic behavior)
      2. Detection test (test for the specific vuln type)
      3. Confirmation test (prove exploitability)
      4. Escalation test (chain with other findings)
    """

    # Scanner to use for each vuln type
    VULN_SCANNER_MAP = {
        "sqli": "SQLiScanner",
        "xss": "XSSScanner",
        "lfi": "LFIScanner",
        "ssti": "SSTIScanner",
        "cmdi": "CMDiScanner",
        "ssrf": "SSRFScanner",
        "nosql": "NoSQLScanner",
        "xxe": "XXEScanner",
        "redirect": "RedirectScanner",
        "idor": "IDORScanner",
        "crlf": "CRLFScanner",
        "hpp": "HPPScanner",
        "ldap": "LDAPScanner",
        "xpath": "XPathScanner",
    }

    # Canary payloads — harmless probes to test behavior
    CANARY_PAYLOADS = {
        "sqli": ["'", "1 OR 1=1", "1' OR '1'='1"],
        "xss": ["<b>test</b>", "test\"test", "<script>1</script>"],
        "lfi": ["../etc/passwd", "....//....//etc/passwd"],
        "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        "cmdi": ["; echo test", "| echo test", "$(echo test)"],
        "ssrf": ["http://127.0.0.1", "http://localhost"],
        "nosql": ["{'$gt':''}", "[$ne]="],
        "xxe": ['<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe "test">]><x>&xxe;</x>'],
    }

    def plan_for_hypothesis(self, hyp: Hypothesis,
                            memory: AgentMemory = None) -> list[Action]:
        """Generate test actions for a hypothesis."""
        actions = []

        # Skip if already tested
        if memory and hyp.target_url and hyp.target_param:
            scanner = self.VULN_SCANNER_MAP.get(hyp.vuln_type, "")
            if memory.was_param_tested(hyp.target_url, hyp.target_param, scanner):
                return []

        # Phase 1: Canary test (if untested)
        if hyp.tests_performed == 0:
            canaries = self.CANARY_PAYLOADS.get(hyp.vuln_type, [])
            if canaries:
                actions.append(Action(
                    action_type=ActionType.PROBE,
                    target_url=hyp.target_url,
                    target_param=hyp.target_param,
                    payload=canaries[0],
                    reason=f"Canary test for {hyp.vuln_type}",
                    expected_outcome=f"Error or behavior change suggesting {hyp.vuln_type}",
                    priority=hyp.confidence,
                ))

        # Phase 2: Full scanner (if canary was promising)
        if hyp.confidence >= 0.2:
            scanner = self.VULN_SCANNER_MAP.get(hyp.vuln_type, "")
            if scanner:
                actions.append(Action(
                    action_type=ActionType.SCAN,
                    target_url=hyp.target_url,
                    target_param=hyp.target_param,
                    scanner_name=scanner,
                    reason=f"Full {hyp.vuln_type} scan — confidence {hyp.confidence:.0%}",
                    expected_outcome=f"Confirm {hyp.vuln_type} vulnerability",
                    priority=hyp.confidence * 0.9,
                ))

        # Phase 3: Escalation (if confirmed)
        if hyp.status == "confirmed":
            actions.append(Action(
                action_type=ActionType.CHAIN,
                target_url=hyp.target_url,
                target_param=hyp.target_param,
                reason=f"Chain {hyp.vuln_type} with other findings",
                expected_outcome="Higher-impact attack chain",
                priority=0.95,
                metadata={"vuln_type": hyp.vuln_type},
            ))

        return actions

    def plan_reconnaissance(self, target_url: str) -> list[Action]:
        """Generate initial reconnaissance actions."""
        return [
            Action(
                action_type=ActionType.FINGERPRINT,
                target_url=target_url,
                reason="Technology fingerprinting",
                expected_outcome="Identify tech stack for targeted testing",
                priority=0.95,
            ),
            Action(
                action_type=ActionType.CRAWL,
                target_url=target_url,
                reason="Attack surface discovery",
                expected_outcome="Discover endpoints, params, forms",
                priority=0.90,
            ),
        ]


# ═══════════════════════════════════════════════════════════════════
# RISK EVALUATOR
# ═══════════════════════════════════════════════════════════════════

class RiskLevel(Enum):
    """Detection risk level for an action."""
    SILENT = 0     # Passive observation only
    LOW = 1        # Normal-looking requests
    MEDIUM = 2     # Slightly suspicious requests
    HIGH = 3       # Likely to trigger WAF/IDS
    EXTREME = 4    # Will definitely be detected


class RiskEvaluator:
    """
    Evaluates the detection risk of each action.

    Factors:
    - Action type (crawl is low risk, fuzz is high)
    - Payload aggressiveness
    - Request rate
    - WAF presence
    - Previous blocks
    """

    ACTION_RISK = {
        ActionType.CRAWL: RiskLevel.LOW,
        ActionType.FINGERPRINT: RiskLevel.LOW,
        ActionType.PROBE: RiskLevel.MEDIUM,
        ActionType.SCAN: RiskLevel.HIGH,
        ActionType.FUZZ: RiskLevel.HIGH,
        ActionType.EVOLVE_PAYLOAD: RiskLevel.MEDIUM,
        ActionType.CHAIN: RiskLevel.EXTREME,
        ActionType.EXTRACT: RiskLevel.EXTREME,
        ActionType.ESCALATE: RiskLevel.EXTREME,
        ActionType.WAIT: RiskLevel.SILENT,
        ActionType.REPORT: RiskLevel.SILENT,
    }

    RISKY_PATTERNS = [
        "union select", "or 1=1", "<script>", "../../",
        "; ls", "| cat", "${", "{{", "<!ENTITY",
        "sleep(", "benchmark(", "waitfor delay",
    ]

    def evaluate(self, action: Action, context: dict = None) -> RiskLevel:
        """Evaluate risk level of an action."""
        context = context or {}
        base_risk = self.ACTION_RISK.get(action.action_type, RiskLevel.MEDIUM)

        # Check payload for risky patterns
        if action.payload:
            payload_lower = action.payload.lower()
            pattern_hits = sum(
                1 for p in self.RISKY_PATTERNS if p in payload_lower
            )
            if pattern_hits >= 2:
                base_risk = RiskLevel(min(base_risk.value + 1, 4))

        # WAF presence increases all risks
        if context.get("waf_detected"):
            base_risk = RiskLevel(min(base_risk.value + 1, 4))

        # Recent blocks increase risk
        if context.get("recent_blocks", 0) > 3:
            base_risk = RiskLevel(min(base_risk.value + 1, 4))

        return base_risk

    def should_delay(self, risk: RiskLevel) -> float:
        """Suggested delay (seconds) based on risk level."""
        delays = {
            RiskLevel.SILENT: 0.0,
            RiskLevel.LOW: 0.1,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 1.5,
            RiskLevel.EXTREME: 3.0,
        }
        return delays.get(risk, 0.5)


# ═══════════════════════════════════════════════════════════════════
# PRIORITY SCORER
# ═══════════════════════════════════════════════════════════════════

class PriorityScorer:
    """
    Ranks actions by expected value: reward × probability - risk.

    This is what makes our scanning efficient — we test the
    highest-value targets first instead of blindly testing everything.
    """

    # Expected impact if vulnerability is confirmed
    VULN_IMPACT = {
        "sqli": 0.95,      # Database compromise
        "cmdi": 0.98,      # System compromise
        "ssti": 0.90,      # Code execution
        "ssrf": 0.80,      # Internal network access
        "lfi": 0.75,       # File system access
        "xxe": 0.70,       # File read / SSRF
        "xss": 0.60,       # Session hijack
        "nosql": 0.65,     # Data access
        "idor": 0.55,      # Data access
        "redirect": 0.30,  # Phishing aid
        "crlf": 0.35,      # Header injection
        "hpp": 0.25,       # Logic bypass
    }

    def score(self, action: Action, hypothesis: Hypothesis = None,
              risk: RiskLevel = RiskLevel.MEDIUM) -> float:
        """
        Calculate priority score for an action.

        Score = (impact × probability) - risk_penalty + urgency_bonus
        """
        # Base probability from hypothesis or action priority
        probability = hypothesis.confidence if hypothesis else action.priority

        # Expected impact
        vuln_type = (hypothesis.vuln_type if hypothesis
                     else action.metadata.get("vuln_type", ""))
        impact = self.VULN_IMPACT.get(vuln_type, 0.5)

        # Risk penalty (higher risk = lower priority)
        risk_penalty = risk.value * 0.1

        # Urgency bonus for escalation actions
        urgency = 0.0
        if action.action_type == ActionType.CHAIN:
            urgency = 0.2
        elif action.action_type == ActionType.FINGERPRINT:
            urgency = 0.15

        score = (impact * probability) - risk_penalty + urgency
        return max(0.0, min(1.0, score))


# ═══════════════════════════════════════════════════════════════════
# STRATEGY ADAPTER
# ═══════════════════════════════════════════════════════════════════

class Strategy(Enum):
    """Scanning strategy types."""
    AGGRESSIVE = auto()    # Maximum speed, all scanners
    BALANCED = auto()      # Normal scanning
    STEALTH = auto()       # Slow, evasive
    TARGETED = auto()      # Focus on high-probability targets only
    EVASION = auto()       # WAF bypass mode


class StrategyAdapter:
    """
    Adapts scanning strategy based on observed conditions.

    Triggers:
    - Too many blocks → switch to STEALTH or EVASION
    - No findings + many tests → switch to TARGETED
    - High-value finding → switch to AGGRESSIVE on that area
    - Time running out → switch to TARGETED (highest-value only)
    """

    def __init__(self, initial_strategy: Strategy = Strategy.BALANCED):
        self.current = initial_strategy
        self.history: list[tuple[float, Strategy, str]] = []
        self._block_count = 0
        self._test_count = 0
        self._finding_count = 0
        self._last_finding_time = 0.0

    def update(self, memory: AgentMemory, elapsed_time: float = 0.0,
               time_budget: float = 300.0) -> Strategy:
        """Re-evaluate strategy based on current state."""
        old = self.current
        self._block_count = len(memory.blocked_payloads)
        self._test_count = len(memory.actions_taken)
        self._finding_count = len(memory.findings)

        # Rule 1: Too many blocks → evasion
        if self._test_count > 10 and self._block_count / max(1, self._test_count) > 0.3:
            self.current = Strategy.EVASION
            reason = f"Block rate {self._block_count}/{self._test_count} too high"

        # Rule 2: Time running low → targeted
        elif elapsed_time > time_budget * 0.75:
            self.current = Strategy.TARGETED
            reason = f"Time running low: {elapsed_time:.0f}s / {time_budget:.0f}s"

        # Rule 3: Lots of tests, no findings → targeted
        elif self._test_count > 50 and self._finding_count == 0:
            self.current = Strategy.TARGETED
            reason = f"No findings after {self._test_count} tests"

        # Rule 4: Found high-severity → aggressive in that area
        elif any(f.get("severity") in ("CRITICAL", "HIGH") for f in memory.findings):
            self.current = Strategy.AGGRESSIVE
            reason = "High-severity finding — escalating"

        else:
            self.current = Strategy.BALANCED
            reason = "Normal conditions"

        if self.current != old:
            self.history.append((elapsed_time, self.current, reason))

        return self.current

    def get_max_requests_per_param(self) -> int:
        """How many requests per parameter based on strategy."""
        limits = {
            Strategy.AGGRESSIVE: 100,
            Strategy.BALANCED: 50,
            Strategy.STEALTH: 20,
            Strategy.TARGETED: 30,
            Strategy.EVASION: 15,
        }
        return limits.get(self.current, 50)

    def get_request_delay(self) -> float:
        """Delay between requests based on strategy."""
        delays = {
            Strategy.AGGRESSIVE: 0.05,
            Strategy.BALANCED: 0.3,
            Strategy.STEALTH: 2.0,
            Strategy.TARGETED: 0.5,
            Strategy.EVASION: 1.0,
        }
        return delays.get(self.current, 0.3)

    def should_use_evasion(self) -> bool:
        """Whether to apply evasion techniques to payloads."""
        return self.current in (Strategy.STEALTH, Strategy.EVASION)


# ═══════════════════════════════════════════════════════════════════
# MASTER REASONING ENGINE
# ═══════════════════════════════════════════════════════════════════

class ReasoningEngine:
    """
    Complete reasoning pipeline for agent decision-making.

    Combines all components:
      Observations → HypothesisGenerator → ActionPlanner
      → RiskEvaluator → PriorityScorer → StrategyAdapter

    This is the AI-equivalent of a pentester's brain:
    "I see this behavior → I think this vulnerability exists →
     Here's how I'll test it → Here's the risk → Go"
    """

    def __init__(self, strategy: Strategy = Strategy.BALANCED):
        self.hypothesis_gen = HypothesisGenerator()
        self.action_planner = ActionPlanner()
        self.risk_evaluator = RiskEvaluator()
        self.priority_scorer = PriorityScorer()
        self.strategy_adapter = StrategyAdapter(strategy)

    def reason(
        self,
        memory: AgentMemory,
        new_observations: list[Observation] = None,
        goals: list[AgentGoal] = None,
        context: dict = None,
    ) -> list[Action]:
        """
        Full reasoning cycle: observations → prioritized actions.

        1. Generate hypotheses from new observations
        2. Plan actions for each hypothesis
        3. Evaluate risk of each action
        4. Score and prioritize
        5. Adapt strategy if needed
        6. Return sorted action list
        """
        context = context or {}
        new_observations = new_observations or []

        # 1. Generate new hypotheses
        new_hyps = self.hypothesis_gen.generate(
            new_observations, memory.hypotheses
        )
        for hyp in new_hyps:
            memory.add_hypothesis(hyp)

        # 2. Plan actions for all active hypotheses
        all_actions = []
        active = memory.get_active_hypotheses()

        for hyp in active:
            actions = self.action_planner.plan_for_hypothesis(hyp, memory)
            for action in actions:
                risk = self.risk_evaluator.evaluate(action, context)
                score = self.priority_scorer.score(action, hyp, risk)
                action.priority = score
                action.metadata["hypothesis_id"] = hyp.id
                action.metadata["risk_level"] = risk.name
                all_actions.append(action)

        # 3. Goal-based actions (if no hypothesis-driven actions)
        if not all_actions and goals:
            for goal in goals:
                if goal.status in (GoalStatus.PENDING, GoalStatus.IN_PROGRESS):
                    if goal.goal_type == "find_vulns":
                        recon_actions = self.action_planner.plan_reconnaissance(
                            goal.target
                        )
                        all_actions.extend(recon_actions)
                        goal.status = GoalStatus.IN_PROGRESS

        # 4. Adapt strategy
        elapsed = context.get("elapsed_time", 0.0)
        budget = context.get("time_budget", 300.0)
        self.strategy_adapter.update(memory, elapsed, budget)

        # 5. Filter by strategy
        max_requests = self.strategy_adapter.get_max_requests_per_param()
        if self.strategy_adapter.current == Strategy.TARGETED:
            # Only keep high-priority actions
            all_actions = [a for a in all_actions if a.priority >= 0.5]

        # 6. Sort by priority (highest first)
        all_actions.sort(key=lambda a: a.priority, reverse=True)

        return all_actions

    def get_strategy(self) -> Strategy:
        """Get current scanning strategy."""
        return self.strategy_adapter.current

    def get_delay(self) -> float:
        """Get recommended delay between requests."""
        return self.strategy_adapter.get_request_delay()

    def should_evade(self) -> bool:
        """Whether to apply evasion techniques."""
        return self.strategy_adapter.should_use_evasion()
