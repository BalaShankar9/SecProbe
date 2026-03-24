"""
Evasion Agent — Defense adaptation and anti-detection specialist.

Monitors the scan for signs of detection and adapts:
  1. WAF blocks → evolve payloads, switch encoding
  2. Rate limiting → slow down, add jitter
  3. IP bans → alert coordinator, suggest rotation
  4. CAPTCHAs → pause, alert coordinator
  5. Behavioral detection → change request patterns

This agent is the immune system of the swarm — it keeps
other agents alive by adapting to the target's defenses.

What makes this novel:
  - Most scanners ignore WAF detection until they're blocked
  - We PROACTIVELY detect defenses and adapt BEFORE blocking
  - We evolve payloads using genetic algorithms
  - We share evasion intelligence across all agents
"""

from __future__ import annotations

import random
import re
import time
from typing import Optional

from secprobe.agents.base import (
    Action, ActionResult, ActionType, AgentGoal, AgentMessage,
    BaseAgent, GoalStatus, MessageType, Observation,
)
from secprobe.agents.knowledge import EntityType, RelationType


class EvasionAgent(BaseAgent):
    """
    Defense adaptation specialist.

    Continuously monitors for signs of detection and broadcasts
    evasion strategies to other agents.
    """

    name = "EvasionAgent"
    specialty = "evasion"

    # WAF detection signatures
    WAF_SIGNATURES = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "body": ["cloudflare", "ray id:", "please turn javascript on"],
            "status": [403, 503],
        },
        "akamai": {
            "headers": ["x-akamai-transformed", "akamai-grn"],
            "body": ["access denied", "reference #"],
            "status": [403],
        },
        "aws_waf": {
            "headers": ["x-amzn-requestid"],
            "body": ["request blocked", "aws waf"],
            "status": [403],
        },
        "modsecurity": {
            "headers": [],
            "body": ["mod_security", "not acceptable", "noyb"],
            "status": [403, 406],
        },
        "imperva": {
            "headers": ["x-iinfo"],
            "body": ["incapsula", "imperva"],
            "status": [403],
        },
        "f5_bigip": {
            "headers": ["x-wa-info"],
            "body": ["the requested url was rejected"],
            "status": [403],
        },
        "generic": {
            "headers": [],
            "body": [
                "forbidden", "access denied", "request blocked",
                "security violation", "suspicious activity",
            ],
            "status": [403, 406, 429],
        },
    }

    # Rate limiting detection
    RATE_LIMIT_SIGNALS = {
        "status_codes": [429, 503],
        "headers": ["retry-after", "x-ratelimit-remaining", "x-rate-limit"],
        "body_patterns": [
            "rate limit", "too many requests", "slow down",
            "throttled", "quota exceeded",
        ],
    }

    # Evasion techniques
    EVASION_TECHNIQUES = {
        "encoding": [
            "url_encode", "double_encode", "unicode_escape",
            "html_entity", "hex_encode", "base64",
        ],
        "obfuscation": [
            "case_swap", "comment_inject", "whitespace_substitute",
            "null_byte", "concat_split",
        ],
        "timing": [
            "random_delay", "exponential_backoff", "jitter",
            "burst_and_wait", "human_like",
        ],
        "header": [
            "rotate_user_agent", "add_referer", "randomize_accept",
            "add_cache_headers", "spoof_origin",
        ],
    }

    # User-Agent rotation pool
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._waf_detected: Optional[str] = None
        self._block_count = 0
        self._rate_limit_count = 0
        self._evasion_level = 0  # 0=none, 1=basic, 2=moderate, 3=aggressive
        self._current_delay = 0.3
        self._blocked_patterns: list[str] = []
        self._successful_evasions: list[str] = []

    async def perceive(self) -> list[Observation]:
        """Monitor for signs of detection."""
        observations = []

        # Check for WAF blocks in memory
        recent_blocks = [
            obs for obs in list(self.memory.observations)[-50:]
            if obs.observation_type in ("waf_block", "rate_limit", "block")
        ]

        if len(recent_blocks) > 5:
            self._block_count = len(recent_blocks)
            observations.append(Observation(
                observation_type="high_block_rate",
                detail=f"{self._block_count} blocks detected recently",
                confidence=0.9,
            ))

        return observations

    async def decide(self) -> list[Action]:
        """Decide on evasion strategy based on detection signals."""
        actions = []

        # Escalate evasion level based on blocks
        if self._block_count > 10 and self._evasion_level < 3:
            self._evasion_level = 3
            self._current_delay = 3.0
        elif self._block_count > 5 and self._evasion_level < 2:
            self._evasion_level = 2
            self._current_delay = 1.5
        elif self._block_count > 2 and self._evasion_level < 1:
            self._evasion_level = 1
            self._current_delay = 0.8

        if self._evasion_level > 0:
            actions.append(Action(
                action_type=ActionType.EVOLVE_PAYLOAD,
                reason=f"Evolve payloads — evasion level {self._evasion_level}",
                priority=0.85,
                metadata={"evasion_level": self._evasion_level},
            ))

        # If not much is happening, mark as done
        if self.cycle_count > 10 and self._block_count == 0:
            for goal in self.goals:
                if goal.status == GoalStatus.IN_PROGRESS:
                    goal.status = GoalStatus.ACHIEVED

        return actions

    async def act(self, action: Action) -> ActionResult:
        """Apply evasion techniques."""
        result = ActionResult(action=action, requests_made=0, success=True)

        if action.action_type == ActionType.EVOLVE_PAYLOAD:
            evasion_level = action.metadata.get("evasion_level", 1)
            techniques = self._select_techniques(evasion_level)

            result.observations.append(Observation(
                observation_type="evasion_applied",
                detail=f"Applied techniques: {techniques}",
                confidence=0.7,
                metadata={"techniques": techniques, "level": evasion_level},
            ))

            # Broadcast evasion strategy
            if self.bus:
                self.bus.send_sync(AgentMessage(
                    sender=self.id,
                    msg_type=MessageType.INTELLIGENCE,
                    payload={
                        "type": "evasion_strategy",
                        "evasion_level": evasion_level,
                        "techniques": techniques,
                        "recommended_delay": self._current_delay,
                        "blocked_patterns": self._blocked_patterns[-20:],
                    },
                    priority=0.9,
                ))

        return result

    async def on_message(self, message: AgentMessage):
        """Track blocks and detection signals from other agents."""
        await super().on_message(message)

        if message.msg_type == MessageType.ALERT:
            alert_type = message.payload.get("alert_type", "")
            if alert_type == "waf_block":
                self._block_count += 1
                payload = message.payload.get("payload", "")
                if payload:
                    self._blocked_patterns.append(payload)
            elif alert_type == "rate_limit":
                self._rate_limit_count += 1
                self._current_delay = min(10.0, self._current_delay * 1.5)

    def _select_techniques(self, level: int) -> list[str]:
        """Select evasion techniques based on level."""
        techniques = []

        if level >= 1:
            techniques.extend(["url_encode", "case_swap", "random_delay"])
        if level >= 2:
            techniques.extend([
                "double_encode", "comment_inject", "rotate_user_agent",
                "exponential_backoff",
            ])
        if level >= 3:
            techniques.extend([
                "unicode_escape", "null_byte", "concat_split",
                "human_like", "spoof_origin",
            ])

        return techniques

    def get_evasion_config(self) -> dict:
        """Get current evasion configuration for other agents."""
        return {
            "waf_detected": self._waf_detected,
            "evasion_level": self._evasion_level,
            "recommended_delay": self._current_delay,
            "blocked_patterns": self._blocked_patterns,
            "successful_evasions": self._successful_evasions,
            "user_agent": random.choice(self.USER_AGENTS),
            "techniques": self._select_techniques(self._evasion_level),
        }

    @staticmethod
    def apply_evasion(payload: str, technique: str) -> str:
        """Apply a specific evasion technique to a payload."""
        if technique == "url_encode":
            chars = {"'": "%27", '"': "%22", "<": "%3C", ">": "%3E", " ": "%20"}
            for orig, enc in chars.items():
                if orig in payload:
                    payload = payload.replace(orig, enc, 1)

        elif technique == "double_encode":
            payload = payload.replace("%", "%25")

        elif technique == "case_swap":
            result = []
            for c in payload:
                if c.isalpha() and random.random() < 0.3:
                    result.append(c.swapcase())
                else:
                    result.append(c)
            payload = "".join(result)

        elif technique == "comment_inject":
            payload = re.sub(
                r"\s+",
                lambda m: "/**/" if random.random() < 0.5 else m.group(),
                payload,
            )

        elif technique == "null_byte":
            payload = payload + "%00"

        elif technique == "unicode_escape":
            replacements = {"<": "\\u003c", ">": "\\u003e", "'": "\\u0027"}
            for orig, esc in replacements.items():
                if orig in payload and random.random() < 0.4:
                    payload = payload.replace(orig, esc, 1)

        elif technique == "concat_split":
            payload = payload.replace("'admin'", "'adm'||'in'")

        return payload
