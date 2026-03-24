"""
Reinforcement Learning Engine — Agents that learn from outcomes.

This is what makes our agents truly autonomous: they don't just
follow rules — they learn which actions produce the best results
and adjust their behavior accordingly.

Components:

  1. Q-Learning Agent
     - State: (target_tech, vuln_hypotheses, defense_level, phase)
     - Actions: (scan_type, param, payload_strategy, evasion_level)
     - Reward: +10 confirmed vuln, +2 promising observation,
               -5 WAF block, -1 no result, -10 false positive

  2. Policy Gradient for Payload Selection
     - Learns which payload mutations are effective per WAF type
     - Softmax policy over mutation operators
     - REINFORCE algorithm with baseline

  3. Experience Replay Buffer
     - Stores (state, action, reward, next_state) transitions
     - Priority replay: high-reward transitions replayed more
     - Cross-agent sharing: all agents feed the same buffer

  4. Reward Shaping
     - Dense rewards (not just final vuln/no-vuln)
     - Intermediate signals: error triggered, reflection found, etc.
     - Curiosity bonus: reward for novel observations

  5. Multi-Armed Bandit for Scanner Selection
     - UCB1 algorithm: balance exploit vs explore
     - Tracks success rate per scanner per tech stack
     - Thompson Sampling for Bayesian exploration

What no other scanner has:
  - Agents that literally get better at finding vulns over time
  - Cross-target transfer: learnings from site A help on site B
  - WAF-adaptive: learns bypass strategies specific to each WAF
  - Self-correcting: reduces false positives through experience
"""

from __future__ import annotations

import json
import math
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

from secprobe.agents.base import (
    Action, ActionResult, ActionType, Observation,
)


# ═══════════════════════════════════════════════════════════════════
# STATE / ACTION ENCODING
# ═══════════════════════════════════════════════════════════════════

class ScanPhase(Enum):
    """Phases of a scan."""
    RECON = auto()
    CANARY = auto()
    ACTIVE = auto()
    CONFIRM = auto()
    ESCALATE = auto()
    EVADE = auto()


@dataclass
class ScanState:
    """
    Encoded state for RL decision making.

    Captures everything relevant to choosing the next action.
    """
    target_tech: str = ""          # "php", "python", "java", etc.
    waf_type: str = ""             # "cloudflare", "modsecurity", etc.
    defense_level: int = 0         # 0=none, 1=basic, 2=moderate, 3=aggressive
    phase: ScanPhase = ScanPhase.RECON
    vuln_hypotheses: int = 0       # Number of active hypotheses
    confirmed_vulns: int = 0
    block_rate: float = 0.0        # Fraction of requests blocked
    observations_count: int = 0
    params_tested: int = 0
    params_total: int = 0
    time_remaining_frac: float = 1.0  # Fraction of time budget remaining
    requests_remaining_frac: float = 1.0

    def to_key(self) -> str:
        """Convert state to a hashable key for Q-table."""
        return (
            f"{self.target_tech}|{self.waf_type}|{self.defense_level}|"
            f"{self.phase.name}|{min(5, self.vuln_hypotheses)}|"
            f"{min(5, self.confirmed_vulns)}|"
            f"{int(self.block_rate * 10)}|"
            f"{int(self.time_remaining_frac * 4)}|"
            f"{int(self.requests_remaining_frac * 4)}"
        )

    def to_vector(self) -> list[float]:
        """Convert state to numeric vector for neural approaches."""
        tech_map = {"php": 0, "python": 1, "java": 2, "nodejs": 3,
                    "ruby": 4, "go": 5, "dotnet": 6, "": 7}
        waf_map = {"cloudflare": 0, "akamai": 1, "aws_waf": 2,
                   "modsecurity": 3, "imperva": 4, "": 5}

        return [
            tech_map.get(self.target_tech, 7) / 7.0,
            waf_map.get(self.waf_type, 5) / 5.0,
            self.defense_level / 3.0,
            list(ScanPhase).index(self.phase) / 5.0,
            min(1.0, self.vuln_hypotheses / 10.0),
            min(1.0, self.confirmed_vulns / 5.0),
            self.block_rate,
            min(1.0, self.observations_count / 100.0),
            self.params_tested / max(1, self.params_total),
            self.time_remaining_frac,
            self.requests_remaining_frac,
        ]


@dataclass
class ScanAction:
    """
    Encoded action for RL.
    """
    scan_type: str = ""            # "sqli", "xss", "lfi", etc.
    strategy: str = "balanced"     # "aggressive", "balanced", "stealth"
    evasion_level: int = 0         # 0-3
    payload_strategy: str = "default"  # "default", "evolved", "minimal"

    def to_key(self) -> str:
        return f"{self.scan_type}|{self.strategy}|{self.evasion_level}|{self.payload_strategy}"

    @staticmethod
    def all_actions() -> list[ScanAction]:
        """Generate all possible actions."""
        actions = []
        for scan_type in ["sqli", "xss", "lfi", "ssti", "cmdi", "ssrf",
                          "nosql", "xxe", "recon", "fingerprint"]:
            for strategy in ["aggressive", "balanced", "stealth"]:
                for evasion in [0, 1, 2]:
                    for payload in ["default", "evolved", "minimal"]:
                        actions.append(ScanAction(
                            scan_type=scan_type,
                            strategy=strategy,
                            evasion_level=evasion,
                            payload_strategy=payload,
                        ))
        return actions


# ═══════════════════════════════════════════════════════════════════
# REWARD SYSTEM
# ═══════════════════════════════════════════════════════════════════

class RewardSignal(Enum):
    """Types of reward signals."""
    VULN_CONFIRMED = auto()       # Found a real vulnerability
    VULN_CRITICAL = auto()        # Found a critical vulnerability
    VULN_CHAIN = auto()           # Successfully chained vulnerabilities
    PROMISING_OBSERVATION = auto() # Saw something worth investigating
    ERROR_TRIGGERED = auto()      # Triggered a server error (good signal)
    REFLECTION_FOUND = auto()     # Input reflected in output
    NOVEL_OBSERVATION = auto()    # Something never seen before
    WAF_BYPASS = auto()           # Successfully bypassed WAF
    NO_RESULT = auto()            # Nothing interesting happened
    WAF_BLOCKED = auto()          # Got blocked by WAF
    RATE_LIMITED = auto()         # Hit rate limit
    FALSE_POSITIVE = auto()       # Reported something that wasn't real
    TIME_WASTED = auto()          # Spent too long on unproductive path
    DUPLICATE_FINDING = auto()    # Found something already known


class RewardShaper:
    """
    Dense reward shaping — gives agents learning signals at every step.

    Raw reward is sparse: +1 for vuln, 0 for nothing.
    Shaped reward is dense: intermediate signals guide learning.
    """

    # Base rewards for each signal type
    REWARD_TABLE = {
        RewardSignal.VULN_CONFIRMED: 10.0,
        RewardSignal.VULN_CRITICAL: 20.0,
        RewardSignal.VULN_CHAIN: 15.0,
        RewardSignal.PROMISING_OBSERVATION: 2.0,
        RewardSignal.ERROR_TRIGGERED: 1.0,
        RewardSignal.REFLECTION_FOUND: 1.5,
        RewardSignal.NOVEL_OBSERVATION: 3.0,
        RewardSignal.WAF_BYPASS: 5.0,
        RewardSignal.NO_RESULT: -0.5,
        RewardSignal.WAF_BLOCKED: -3.0,
        RewardSignal.RATE_LIMITED: -2.0,
        RewardSignal.FALSE_POSITIVE: -8.0,
        RewardSignal.TIME_WASTED: -1.0,
        RewardSignal.DUPLICATE_FINDING: -0.5,
    }

    def __init__(self):
        self._seen_observations: set[str] = set()  # For novelty bonus
        self._cumulative_reward = 0.0
        self._reward_history: list[tuple[float, float, str]] = []  # (time, reward, signal)

    def compute_reward(self, result: ActionResult,
                       signals: list[RewardSignal] = None) -> float:
        """
        Compute total reward from an action result.

        Combines explicit signals with automatic detection.
        """
        signals = signals or []
        total = 0.0

        # Explicit signals
        for signal in signals:
            total += self.REWARD_TABLE.get(signal, 0.0)

        # Auto-detect signals from result
        if result.findings:
            for finding in result.findings:
                sev = finding.get("severity", "MEDIUM")
                if sev == "CRITICAL":
                    total += self.REWARD_TABLE[RewardSignal.VULN_CRITICAL]
                else:
                    total += self.REWARD_TABLE[RewardSignal.VULN_CONFIRMED]

        elif not result.observations and not result.findings:
            total += self.REWARD_TABLE[RewardSignal.NO_RESULT]

        # Novelty bonus
        for obs in result.observations:
            if obs.fingerprint not in self._seen_observations:
                self._seen_observations.add(obs.fingerprint)
                total += self.REWARD_TABLE[RewardSignal.NOVEL_OBSERVATION] * 0.3

        # Efficiency penalty: reward per request
        if result.requests_made > 0:
            efficiency = total / result.requests_made
            total += efficiency * 0.1  # Small bonus for efficiency

        self._cumulative_reward += total
        self._reward_history.append((time.time(), total, str(signals)))

        return total

    @property
    def cumulative(self) -> float:
        return self._cumulative_reward

    @property
    def average_reward(self) -> float:
        if not self._reward_history:
            return 0.0
        return sum(r for _, r, _ in self._reward_history) / len(self._reward_history)

    def get_history(self, last_n: int = 50) -> list[tuple[float, float, str]]:
        return self._reward_history[-last_n:]


# ═══════════════════════════════════════════════════════════════════
# EXPERIENCE REPLAY BUFFER
# ═══════════════════════════════════════════════════════════════════

@dataclass
class Experience:
    """A single (state, action, reward, next_state) transition."""
    state: ScanState = field(default_factory=ScanState)
    action: ScanAction = field(default_factory=ScanAction)
    reward: float = 0.0
    next_state: ScanState = field(default_factory=ScanState)
    done: bool = False
    timestamp: float = field(default_factory=time.time)
    priority: float = 1.0  # For prioritized replay
    agent_id: str = ""


class ExperienceReplayBuffer:
    """
    Experience replay with prioritized sampling.

    Stores transitions from all agents and replays them for learning.
    High-reward transitions are replayed more frequently (priority replay).

    This is crucial: without replay, agents forget what worked.
    With replay, they consolidate successful strategies.
    """

    def __init__(self, capacity: int = 50000, alpha: float = 0.6):
        self.buffer: deque[Experience] = deque(maxlen=capacity)
        self.priorities: deque[float] = deque(maxlen=capacity)
        self.alpha = alpha  # Priority exponent (0 = uniform, 1 = full priority)
        self._max_priority = 1.0

    def add(self, experience: Experience):
        """Add a transition to the buffer."""
        experience.priority = self._max_priority
        self.buffer.append(experience)
        self.priorities.append(self._max_priority)

    def sample(self, batch_size: int = 32) -> list[Experience]:
        """Sample a batch using prioritized replay."""
        if len(self.buffer) == 0:
            return []

        batch_size = min(batch_size, len(self.buffer))

        # Compute sampling probabilities
        priorities = list(self.priorities)
        total = sum(p ** self.alpha for p in priorities)
        if total == 0:
            # Uniform sampling
            indices = random.sample(range(len(self.buffer)), batch_size)
        else:
            probs = [(p ** self.alpha) / total for p in priorities]
            indices = random.choices(range(len(self.buffer)),
                                     weights=probs, k=batch_size)

        return [self.buffer[i] for i in indices]

    def update_priorities(self, indices: list[int], td_errors: list[float]):
        """Update priorities based on TD errors."""
        for idx, td_error in zip(indices, td_errors):
            if 0 <= idx < len(self.priorities):
                priority = abs(td_error) + 1e-6
                self.priorities[idx] = priority
                self._max_priority = max(self._max_priority, priority)

    @property
    def size(self) -> int:
        return len(self.buffer)

    def get_stats(self) -> dict:
        if not self.buffer:
            return {"size": 0, "avg_reward": 0.0}
        rewards = [e.reward for e in self.buffer]
        return {
            "size": len(self.buffer),
            "avg_reward": sum(rewards) / len(rewards),
            "max_reward": max(rewards),
            "min_reward": min(rewards),
            "positive_ratio": sum(1 for r in rewards if r > 0) / len(rewards),
        }


# ═══════════════════════════════════════════════════════════════════
# Q-LEARNING ENGINE
# ═══════════════════════════════════════════════════════════════════

class QLearningEngine:
    """
    Tabular Q-learning for scan action selection.

    Q(s, a) = Q(s, a) + α[r + γ·max_a'Q(s', a') - Q(s, a)]

    The Q-table maps (state, action) → expected future reward.
    This tells agents: "In this situation, this action will yield
    the best long-term results."

    Features:
    - Epsilon-greedy exploration (starts exploratory, becomes focused)
    - Eligibility traces (credit assignment across multiple steps)
    - Adaptive learning rate (decreases with experience)
    - State aggregation (reduces state space for faster learning)
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount: float = 0.95,
        epsilon: float = 0.3,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.05,
    ):
        self.lr = learning_rate
        self.gamma = discount
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min

        self.q_table: dict[str, dict[str, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self.visit_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.eligibility: dict[str, dict[str, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._trace_decay = 0.9  # Lambda for eligibility traces
        self._total_updates = 0

    def select_action(self, state: ScanState,
                      available_actions: list[ScanAction] = None
                      ) -> ScanAction:
        """
        Select action using epsilon-greedy policy.

        With probability epsilon: random exploration
        With probability 1-epsilon: best known action (exploitation)
        """
        if not available_actions:
            available_actions = self._get_relevant_actions(state)

        state_key = state.to_key()

        # Epsilon-greedy
        if random.random() < self.epsilon:
            return random.choice(available_actions)

        # Exploit: choose best Q-value action
        best_action = available_actions[0]
        best_q = float('-inf')

        for action in available_actions:
            action_key = action.to_key()
            q = self.q_table[state_key][action_key]
            # UCB bonus for under-explored actions
            visits = self.visit_counts[state_key][action_key]
            total_visits = sum(self.visit_counts[state_key].values()) or 1
            ucb_bonus = math.sqrt(2 * math.log(total_visits + 1) / (visits + 1))
            effective_q = q + 0.5 * ucb_bonus

            if effective_q > best_q:
                best_q = effective_q
                best_action = action

        return best_action

    def update(self, state: ScanState, action: ScanAction,
               reward: float, next_state: ScanState,
               done: bool = False):
        """
        Q-learning update with eligibility traces.

        Q(s,a) += α[r + γ·max Q(s',a') - Q(s,a)] × e(s,a)
        """
        state_key = state.to_key()
        action_key = action.to_key()
        next_state_key = next_state.to_key()

        # Current Q-value
        current_q = self.q_table[state_key][action_key]

        # Max Q-value for next state
        if done:
            max_next_q = 0.0
        else:
            next_qs = self.q_table[next_state_key]
            max_next_q = max(next_qs.values()) if next_qs else 0.0

        # TD error
        td_error = reward + self.gamma * max_next_q - current_q

        # Adaptive learning rate (decreases with visits)
        visits = self.visit_counts[state_key][action_key]
        adaptive_lr = self.lr / (1 + visits * 0.01)

        # Update with eligibility trace
        self.eligibility[state_key][action_key] = 1.0

        for s_key in list(self.eligibility.keys()):
            for a_key in list(self.eligibility[s_key].keys()):
                trace = self.eligibility[s_key][a_key]
                if trace > 0.01:
                    self.q_table[s_key][a_key] += adaptive_lr * td_error * trace
                    self.eligibility[s_key][a_key] *= self.gamma * self._trace_decay
                else:
                    del self.eligibility[s_key][a_key]
            if not self.eligibility[s_key]:
                del self.eligibility[s_key]

        # Update visit count
        self.visit_counts[state_key][action_key] += 1
        self._total_updates += 1

        # Decay epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

        return td_error

    def batch_update(self, experiences: list[Experience]):
        """Update Q-values from a batch of experiences."""
        td_errors = []
        for exp in experiences:
            td = self.update(exp.state, exp.action, exp.reward,
                             exp.next_state, exp.done)
            td_errors.append(td)
        return td_errors

    def get_q_values(self, state: ScanState) -> dict[str, float]:
        """Get all Q-values for a state."""
        return dict(self.q_table[state.to_key()])

    def get_best_action(self, state: ScanState) -> tuple[ScanAction, float]:
        """Get the best action and its Q-value for a state."""
        state_key = state.to_key()
        q_values = self.q_table[state_key]

        if not q_values:
            return ScanAction(), 0.0

        best_key = max(q_values, key=q_values.get)
        parts = best_key.split("|")
        action = ScanAction(
            scan_type=parts[0] if len(parts) > 0 else "",
            strategy=parts[1] if len(parts) > 1 else "balanced",
            evasion_level=int(parts[2]) if len(parts) > 2 else 0,
            payload_strategy=parts[3] if len(parts) > 3 else "default",
        )
        return action, q_values[best_key]

    def reset_traces(self):
        """Reset eligibility traces (start of new episode)."""
        self.eligibility.clear()

    def _get_relevant_actions(self, state: ScanState) -> list[ScanAction]:
        """Generate actions relevant to the current state."""
        actions = []
        scan_types = ["sqli", "xss", "lfi", "ssti", "cmdi", "ssrf"]

        if state.phase == ScanPhase.RECON:
            scan_types = ["recon", "fingerprint"]
        elif state.phase == ScanPhase.EVADE:
            scan_types = [st for st in scan_types]  # All types but with evasion

        for st in scan_types:
            strategies = ["balanced"]
            if state.defense_level == 0:
                strategies.append("aggressive")
            if state.defense_level > 1:
                strategies = ["stealth"]

            for strategy in strategies:
                evasion = min(state.defense_level, 2)
                actions.append(ScanAction(
                    scan_type=st, strategy=strategy,
                    evasion_level=evasion, payload_strategy="default"
                ))

        return actions if actions else [ScanAction()]

    def get_stats(self) -> dict:
        """Get Q-learning statistics."""
        all_q = [q for state in self.q_table.values() for q in state.values()]
        return {
            "states_visited": len(self.q_table),
            "total_updates": self._total_updates,
            "epsilon": round(self.epsilon, 4),
            "avg_q_value": sum(all_q) / len(all_q) if all_q else 0.0,
            "max_q_value": max(all_q) if all_q else 0.0,
            "min_q_value": min(all_q) if all_q else 0.0,
        }

    def export(self) -> dict:
        """Export Q-table for persistence."""
        return {
            "q_table": {s: dict(a) for s, a in self.q_table.items()},
            "visit_counts": {s: dict(a) for s, a in self.visit_counts.items()},
            "epsilon": self.epsilon,
            "total_updates": self._total_updates,
        }

    def load(self, data: dict):
        """Load Q-table from exported data."""
        for s, actions in data.get("q_table", {}).items():
            for a, q in actions.items():
                self.q_table[s][a] = q
        for s, actions in data.get("visit_counts", {}).items():
            for a, c in actions.items():
                self.visit_counts[s][a] = c
        self.epsilon = data.get("epsilon", self.epsilon)
        self._total_updates = data.get("total_updates", 0)


# ═══════════════════════════════════════════════════════════════════
# MULTI-ARMED BANDIT (Scanner Selection)
# ═══════════════════════════════════════════════════════════════════

class BanditArm:
    """A single arm (scanner) in the multi-armed bandit."""

    def __init__(self, name: str):
        self.name = name
        self.pulls = 0
        self.total_reward = 0.0
        self.successes = 0
        # For Thompson Sampling (Beta distribution parameters)
        self.alpha = 1.0  # Prior successes
        self.beta_param = 1.0   # Prior failures

    @property
    def mean_reward(self) -> float:
        return self.total_reward / self.pulls if self.pulls > 0 else 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / self.pulls if self.pulls > 0 else 0.0

    def update(self, reward: float, success: bool = False):
        """Update arm statistics after a pull."""
        self.pulls += 1
        self.total_reward += reward
        if success:
            self.successes += 1
            self.alpha += 1
        else:
            self.beta_param += 1

    def thompson_sample(self) -> float:
        """Sample from Beta distribution for Thompson Sampling."""
        return random.betavariate(self.alpha, self.beta_param)


class MultiArmedBandit:
    """
    Multi-armed bandit for scanner/strategy selection.

    Supports multiple algorithms:
    - UCB1 (Upper Confidence Bound): balance explore vs exploit
    - Thompson Sampling: Bayesian approach
    - Epsilon-Greedy: simple but effective

    Contextual bandit: conditions on (tech_stack, waf_type).
    """

    def __init__(self, algorithm: str = "ucb1"):
        self.algorithm = algorithm
        self.arms: dict[str, dict[str, BanditArm]] = defaultdict(dict)
        # Context → {arm_name → BanditArm}

    def add_arm(self, name: str, context: str = "default"):
        """Register a new arm (scanner/strategy)."""
        if name not in self.arms[context]:
            self.arms[context][name] = BanditArm(name)

    def select(self, context: str = "default",
               available: list[str] = None) -> str:
        """Select an arm using the configured algorithm."""
        arms = self.arms.get(context, {})
        if not arms:
            # No arms for this context — use default
            arms = self.arms.get("default", {})
        if not arms:
            return available[0] if available else ""

        if available:
            arms = {k: v for k, v in arms.items() if k in available}
        if not arms:
            return available[0] if available else ""

        if self.algorithm == "ucb1":
            return self._ucb1_select(arms)
        elif self.algorithm == "thompson":
            return self._thompson_select(arms)
        else:
            return self._epsilon_greedy_select(arms)

    def update(self, arm_name: str, reward: float, success: bool = False,
               context: str = "default"):
        """Update arm after pulling it."""
        if arm_name not in self.arms[context]:
            self.arms[context][arm_name] = BanditArm(arm_name)
        self.arms[context][arm_name].update(reward, success)

    def _ucb1_select(self, arms: dict[str, BanditArm]) -> str:
        """UCB1: select arm with highest upper confidence bound."""
        total_pulls = sum(a.pulls for a in arms.values()) or 1
        best_arm = ""
        best_ucb = float('-inf')

        for name, arm in arms.items():
            if arm.pulls == 0:
                return name  # Always try untested arms first

            ucb = arm.mean_reward + math.sqrt(
                2 * math.log(total_pulls) / arm.pulls
            )
            if ucb > best_ucb:
                best_ucb = ucb
                best_arm = name

        return best_arm

    def _thompson_select(self, arms: dict[str, BanditArm]) -> str:
        """Thompson Sampling: select arm with highest beta sample."""
        best_arm = ""
        best_sample = float('-inf')

        for name, arm in arms.items():
            sample = arm.thompson_sample()
            if sample > best_sample:
                best_sample = sample
                best_arm = name

        return best_arm

    def _epsilon_greedy_select(self, arms: dict[str, BanditArm],
                                epsilon: float = 0.1) -> str:
        """Epsilon-greedy selection."""
        if random.random() < epsilon:
            return random.choice(list(arms.keys()))

        best_arm = max(arms.items(), key=lambda x: x[1].mean_reward)
        return best_arm[0]

    def get_stats(self, context: str = "default") -> dict:
        """Get bandit statistics for a context."""
        arms = self.arms.get(context, {})
        return {
            name: {
                "pulls": arm.pulls,
                "mean_reward": round(arm.mean_reward, 4),
                "success_rate": round(arm.success_rate, 4),
            }
            for name, arm in arms.items()
        }

    def get_best_arm(self, context: str = "default") -> tuple[str, float]:
        """Get the best-performing arm for a context."""
        arms = self.arms.get(context, {})
        if not arms:
            return "", 0.0
        best = max(arms.items(), key=lambda x: x[1].mean_reward)
        return best[0], best[1].mean_reward


# ═══════════════════════════════════════════════════════════════════
# POLICY GRADIENT (Payload Mutation Strategy)
# ═══════════════════════════════════════════════════════════════════

class PolicyGradient:
    """
    Policy gradient for learning payload mutation strategies.

    Instead of fixed mutation rules, we learn a probability distribution
    over mutation operators that maximizes bypass rate.

    Uses REINFORCE with baseline:
      ∇J(θ) = E[∇log π(a|s)(R - b)]

    Where:
      π(a|s) = softmax(θ) = probability of choosing mutation a in state s
      R = reward (1 for bypass, 0 for block)
      b = baseline (running average reward)
    """

    def __init__(self, actions: list[str] = None,
                 learning_rate: float = 0.01):
        self.actions = actions or [
            "url_encode", "double_encode", "case_swap",
            "comment_inject", "null_byte", "unicode_escape",
            "hex_encode", "concat_split", "whitespace",
            "newline_inject", "no_mutation",
        ]
        self.lr = learning_rate
        # Theta parameters (log-preferences for each action per context)
        self.theta: dict[str, list[float]] = defaultdict(
            lambda: [0.0] * len(self.actions)
        )
        self.baseline: dict[str, float] = defaultdict(float)
        self._baseline_count: dict[str, int] = defaultdict(int)
        self._history: list[dict] = []

    def _softmax(self, logits: list[float]) -> list[float]:
        """Compute softmax probabilities."""
        max_logit = max(logits)
        exp_logits = [math.exp(l - max_logit) for l in logits]
        total = sum(exp_logits)
        return [e / total for e in exp_logits]

    def select_mutation(self, context: str = "default") -> str:
        """Select a mutation operator using the learned policy."""
        probs = self._softmax(self.theta[context])
        idx = random.choices(range(len(self.actions)), weights=probs, k=1)[0]
        return self.actions[idx]

    def update(self, context: str, action: str, reward: float):
        """
        Update policy using REINFORCE with baseline.

        θ += α(R - b) ∇log π(a|s)
        """
        if action not in self.actions:
            return

        action_idx = self.actions.index(action)
        probs = self._softmax(self.theta[context])

        # Update baseline (running average)
        self._baseline_count[context] += 1
        n = self._baseline_count[context]
        self.baseline[context] += (reward - self.baseline[context]) / n

        # Policy gradient update
        advantage = reward - self.baseline[context]

        for i in range(len(self.actions)):
            if i == action_idx:
                # ∇log π = (1 - π(a))  for chosen action
                grad = 1.0 - probs[i]
            else:
                # ∇log π = -π(a)  for other actions
                grad = -probs[i]

            self.theta[context][i] += self.lr * advantage * grad

        self._history.append({
            "context": context, "action": action,
            "reward": reward, "advantage": advantage,
        })

    def get_policy(self, context: str = "default") -> dict[str, float]:
        """Get current mutation probabilities for a context."""
        probs = self._softmax(self.theta[context])
        return {self.actions[i]: round(p, 4) for i, p in enumerate(probs)}

    def get_best_mutation(self, context: str = "default") -> str:
        """Get the most likely mutation for a context."""
        probs = self._softmax(self.theta[context])
        return self.actions[probs.index(max(probs))]

    def get_stats(self) -> dict:
        return {
            "contexts": len(self.theta),
            "total_updates": len(self._history),
            "baselines": {k: round(v, 4) for k, v in self.baseline.items()},
        }


# ═══════════════════════════════════════════════════════════════════
# COMPLETE RL SYSTEM
# ═══════════════════════════════════════════════════════════════════

class RLSystem:
    """
    Complete Reinforcement Learning system for agent training.

    Integrates:
    - Q-Learning for scan action selection
    - Multi-Armed Bandit for scanner selection
    - Policy Gradient for payload mutation
    - Experience Replay for memory consolidation
    - Reward Shaping for dense learning signals
    """

    def __init__(self, config: dict = None):
        config = config or {}
        self.q_engine = QLearningEngine(
            learning_rate=config.get("learning_rate", 0.1),
            discount=config.get("discount", 0.95),
            epsilon=config.get("epsilon", 0.3),
        )
        self.bandit = MultiArmedBandit(
            algorithm=config.get("bandit_algorithm", "ucb1")
        )
        self.policy = PolicyGradient(
            learning_rate=config.get("policy_lr", 0.01)
        )
        self.replay_buffer = ExperienceReplayBuffer(
            capacity=config.get("buffer_capacity", 50000)
        )
        self.reward_shaper = RewardShaper()

        # Initialize scanner arms
        for scanner in ["sqli", "xss", "lfi", "ssti", "cmdi",
                        "ssrf", "nosql", "xxe", "recon"]:
            self.bandit.add_arm(scanner)

        self._train_step = 0

    def observe_result(self, state: ScanState, action: ScanAction,
                       result: ActionResult, next_state: ScanState,
                       done: bool = False,
                       signals: list[RewardSignal] = None) -> float:
        """
        Process an action result through the full RL pipeline.

        Returns the computed reward.
        """
        # Compute reward
        reward = self.reward_shaper.compute_reward(result, signals)

        # Store experience
        experience = Experience(
            state=state, action=action, reward=reward,
            next_state=next_state, done=done,
        )
        self.replay_buffer.add(experience)

        # Online Q-learning update
        td_error = self.q_engine.update(state, action, reward, next_state, done)

        # Update bandit
        success = len(result.findings) > 0
        self.bandit.update(action.scan_type, reward, success,
                           context=state.target_tech or "default")

        self._train_step += 1

        return reward

    def train_from_replay(self, batch_size: int = 32) -> list[float]:
        """Train on a batch of replayed experiences."""
        batch = self.replay_buffer.sample(batch_size)
        if not batch:
            return []
        return self.q_engine.batch_update(batch)

    def select_scanner(self, tech: str = "default",
                       available: list[str] = None) -> str:
        """Select best scanner using multi-armed bandit."""
        return self.bandit.select(context=tech, available=available)

    def select_mutation(self, waf_type: str = "default") -> str:
        """Select best payload mutation using policy gradient."""
        return self.policy.select_mutation(context=waf_type)

    def select_action(self, state: ScanState,
                      available: list[ScanAction] = None) -> ScanAction:
        """Select best action using Q-learning."""
        return self.q_engine.select_action(state, available)

    def get_stats(self) -> dict:
        """Get comprehensive RL statistics."""
        return {
            "train_steps": self._train_step,
            "q_learning": self.q_engine.get_stats(),
            "bandit": self.bandit.get_stats(),
            "policy": self.policy.get_stats(),
            "replay_buffer": self.replay_buffer.get_stats(),
            "cumulative_reward": self.reward_shaper.cumulative,
            "avg_reward": self.reward_shaper.average_reward,
        }

    def export(self) -> dict:
        """Export learned parameters for persistence."""
        return {
            "q_table": self.q_engine.export(),
            "policy_theta": dict(self.policy.theta),
            "policy_baseline": dict(self.policy.baseline),
            "train_step": self._train_step,
        }

    def load(self, data: dict):
        """Load learned parameters."""
        if "q_table" in data:
            self.q_engine.load(data["q_table"])
        if "policy_theta" in data:
            for ctx, theta in data["policy_theta"].items():
                self.policy.theta[ctx] = theta
        if "policy_baseline" in data:
            for ctx, bl in data["policy_baseline"].items():
                self.policy.baseline[ctx] = bl
        self._train_step = data.get("train_step", 0)
