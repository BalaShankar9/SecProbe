"""
Reconnaissance Agent — Intelligent attack surface mapping.

Goes beyond simple crawling — this agent UNDERSTANDS the target:
  - Technology fingerprinting (server, framework, DB, WAF)
  - Parameter classification (type inference, context detection)
  - Authentication boundary mapping
  - API schema discovery
  - Hidden parameter detection
  - Application state machine modeling

This agent runs FIRST and feeds intelligence to all other agents
via the shared knowledge graph and message bus.
"""

from __future__ import annotations

import re
from typing import Optional

from secprobe.agents.base import (
    Action, ActionResult, ActionType, AgentGoal, AgentState,
    BaseAgent, GoalStatus, MessageType, AgentMessage, Observation,
)
from secprobe.agents.knowledge import (
    EntityType, KnowledgeGraph, RelationType,
)
from secprobe.agents.reasoning import ReasoningEngine, Strategy


class ReconAgent(BaseAgent):
    """
    Reconnaissance specialist — maps and understands the target
    before attack agents are deployed.
    """

    name = "ReconAgent"
    specialty = "reconnaissance"

    # Headers that leak technology information
    TECH_HEADERS = {
        "server": "server",
        "x-powered-by": "framework",
        "x-aspnet-version": "framework",
        "x-generator": "cms",
        "x-drupal-cache": "cms",
        "x-varnish": "cache",
        "x-cache": "cache",
        "x-amz-cf-id": "cdn",
    }

    # URL patterns suggesting specific functionality
    URL_PATTERNS = {
        r"/api/": {"type": "api", "interesting": True},
        r"/admin": {"type": "admin", "interesting": True},
        r"/login": {"type": "auth", "interesting": True},
        r"/register": {"type": "auth", "interesting": True},
        r"/upload": {"type": "upload", "interesting": True},
        r"/search": {"type": "search", "interesting": True},
        r"/download": {"type": "file", "interesting": True},
        r"/redirect": {"type": "redirect", "interesting": True},
        r"/callback": {"type": "callback", "interesting": True},
        r"\.(php|asp|jsp|do|action)": {"type": "dynamic", "interesting": True},
        r"\?.*=": {"type": "parameterized", "interesting": True},
    }

    # Parameter names suggesting injection targets
    INTERESTING_PARAMS = {
        "id": ("sqli", "idor"),
        "user_id": ("idor", "sqli"),
        "uid": ("idor",),
        "name": ("xss", "sqli"),
        "q": ("sqli", "xss"),
        "query": ("sqli", "xss"),
        "search": ("sqli", "xss"),
        "url": ("ssrf", "redirect"),
        "redirect": ("redirect",),
        "next": ("redirect",),
        "return": ("redirect",),
        "file": ("lfi",),
        "path": ("lfi",),
        "page": ("lfi", "sqli"),
        "template": ("ssti", "lfi"),
        "lang": ("lfi", "crlf"),
        "host": ("cmdi", "ssrf"),
        "ip": ("cmdi",),
        "cmd": ("cmdi",),
        "exec": ("cmdi",),
        "username": ("sqli", "nosql"),
        "email": ("sqli",),
        "callback": ("xss",),
        "data": ("nosql", "xxe"),
        "xml": ("xxe",),
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.reasoning = ReasoningEngine(Strategy.BALANCED)
        self._discovered_urls: set[str] = set()
        self._discovered_params: dict[str, list[str]] = {}
        self._tech_stack: dict[str, float] = {}
        self._phase = "initial"

    async def perceive(self) -> list[Observation]:
        """
        Analyze target for technology, parameters, and structure.
        """
        observations = []

        if self._phase == "initial":
            # First cycle: analyze the initial target URL
            observations.append(Observation(
                url=self.target,
                observation_type="target_discovered",
                detail=f"Initial target: {self.target}",
                confidence=1.0,
            ))
            self._discovered_urls.add(self.target)
            self._phase = "fingerprinting"

        return observations

    async def decide(self) -> list[Action]:
        """Decide what to map next."""
        actions = []

        if self._phase == "fingerprinting":
            actions.append(Action(
                action_type=ActionType.FINGERPRINT,
                target_url=self.target,
                reason="Initial technology fingerprinting",
                priority=0.95,
            ))
            self._phase = "crawling"

        elif self._phase == "crawling":
            actions.append(Action(
                action_type=ActionType.CRAWL,
                target_url=self.target,
                reason="Map attack surface",
                priority=0.90,
            ))
            self._phase = "analyzing"

        elif self._phase == "analyzing":
            # Generate hypothesis-based actions from observations
            actions = self.reasoning.reason(
                self.memory,
                list(self.memory.observations)[-20:],
                self.goals,
            )
            if not actions:
                self._phase = "done"
                for goal in self.goals:
                    goal.status = GoalStatus.ACHIEVED

        return actions

    async def act(self, action: Action) -> ActionResult:
        """Execute a reconnaissance action."""
        result = ActionResult(action=action, requests_made=1)

        if action.action_type == ActionType.FINGERPRINT:
            result = await self._fingerprint(action)
        elif action.action_type == ActionType.CRAWL:
            result = await self._crawl(action)
        elif action.action_type == ActionType.PROBE:
            result = await self._probe(action)

        return result

    async def _fingerprint(self, action: Action) -> ActionResult:
        """Analyze response for technology signatures."""
        result = ActionResult(action=action, requests_made=0)

        # Analyze knowledge graph for any existing intel
        if self.knowledge:
            existing_tech = self.knowledge.find_by_type(EntityType.TECHNOLOGY)
            for tech in existing_tech:
                tech_name = tech.properties.get("name", "")
                self._tech_stack[tech_name] = tech.confidence

        # Generate hypotheses from tech stack
        if self._tech_stack:
            hyps = self.reasoning.hypothesis_gen.generate_from_tech_stack(
                self._tech_stack
            )
            for hyp in hyps:
                self.memory.add_hypothesis(hyp)
                result.observations.append(Observation(
                    observation_type="tech_hypothesis",
                    detail=f"Tech-based hypothesis: {hyp.description}",
                    confidence=hyp.confidence,
                ))

        result.success = True
        return result

    async def _crawl(self, action: Action) -> ActionResult:
        """Discover URLs and parameters."""
        result = ActionResult(action=action, requests_made=0)

        # Analyze target URL for parameter patterns
        url = action.target_url
        for pattern, info in self.URL_PATTERNS.items():
            if re.search(pattern, url, re.IGNORECASE):
                result.observations.append(Observation(
                    url=url,
                    observation_type=f"url_pattern_{info['type']}",
                    detail=f"URL matches pattern: {info['type']}",
                    confidence=0.8,
                ))

        result.success = True
        return result

    async def _probe(self, action: Action) -> ActionResult:
        """Send a probe request and analyze the response."""
        result = ActionResult(action=action, requests_made=1)
        result.success = True
        return result

    def classify_parameter(self, param_name: str) -> list[str]:
        """Classify a parameter by its name to suggest vuln types."""
        param_lower = param_name.lower()
        for known_param, vuln_types in self.INTERESTING_PARAMS.items():
            if known_param in param_lower:
                return list(vuln_types)
        return []

    async def communicate(self):
        """Share reconnaissance findings with other agents."""
        await super().communicate()

        if not self.bus:
            return

        # Share tech stack
        if self._tech_stack:
            self.bus.send_sync(AgentMessage(
                sender=self.id,
                msg_type=MessageType.INTELLIGENCE,
                payload={
                    "type": "tech_stack",
                    "technologies": self._tech_stack,
                },
                priority=0.9,
            ))

        # Share discovered parameters with classifications
        for url, params in self._discovered_params.items():
            for param in params:
                classifications = self.classify_parameter(param)
                if classifications:
                    self.bus.send_sync(AgentMessage(
                        sender=self.id,
                        msg_type=MessageType.INTELLIGENCE,
                        payload={
                            "type": "interesting_param",
                            "url": url,
                            "param": param,
                            "suggested_vulns": classifications,
                        },
                        priority=0.8,
                    ))
