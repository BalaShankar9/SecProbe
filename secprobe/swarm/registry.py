"""
SwarmRegistry — Central registry for all 600 specialized agents.

Agents are defined declaratively in division files (divisions/d01_recon.py, etc.).
The registry indexes them by division, attack type, technology, and capability
for fast lookup during scan planning.
"""

from __future__ import annotations

from typing import Iterator

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


class SwarmRegistry:
    """
    Central registry of all 600 agent specifications.

    Usage:
        registry = SwarmRegistry()
        registry.load_all()
        sqli_agents = registry.by_attack_type("sqli")
        wp_agents = registry.by_technology("wordpress")
    """

    def __init__(self):
        self._agents: dict[str, AgentSpec] = {}
        self._by_division: dict[int, list[str]] = {}
        self._by_attack_type: dict[str, list[str]] = {}
        self._by_technology: dict[str, list[str]] = {}
        self._by_capability: dict[Cap, list[str]] = {}

    @property
    def count(self) -> int:
        return len(self._agents)

    def register(self, spec: AgentSpec):
        """Register an agent specification."""
        self._agents[spec.id] = spec
        self._by_division.setdefault(spec.division, []).append(spec.id)
        for attack in spec.attack_types:
            self._by_attack_type.setdefault(attack, []).append(spec.id)
        for tech in spec.target_technologies:
            self._by_technology.setdefault(tech, []).append(spec.id)
        for cap in spec.capabilities:
            self._by_capability.setdefault(cap, []).append(spec.id)

    def get(self, agent_id: str) -> AgentSpec | None:
        return self._agents.get(agent_id)

    def by_division(self, division: int) -> list[AgentSpec]:
        return [self._agents[i] for i in self._by_division.get(division, [])]

    def by_attack_type(self, attack_type: str) -> list[AgentSpec]:
        return [self._agents[i] for i in self._by_attack_type.get(attack_type, [])]

    def by_technology(self, technology: str) -> list[AgentSpec]:
        return [self._agents[i] for i in self._by_technology.get(technology.lower(), [])]

    def by_capability(self, capability: Cap) -> list[AgentSpec]:
        return [self._agents[i] for i in self._by_capability.get(capability, [])]

    def by_mode(self, mode: Mode) -> list[AgentSpec]:
        """Return agents that can run in the given mode."""
        mode_order = {Mode.RECON: 0, Mode.AUDIT: 1, Mode.REDTEAM: 2}
        level = mode_order.get(mode, 0)
        return [
            spec for spec in self._agents.values()
            if mode_order.get(spec.min_mode, 0) <= level
        ]

    def by_tags(self, *tags: str) -> list[AgentSpec]:
        return [
            spec for spec in self._agents.values()
            if any(t in spec.tags for t in tags)
        ]

    def all(self) -> list[AgentSpec]:
        return list(self._agents.values())

    def __iter__(self) -> Iterator[AgentSpec]:
        return iter(self._agents.values())

    def __len__(self) -> int:
        return len(self._agents)

    def load_all(self):
        """Load all 600 agent definitions from division files."""
        from secprobe.swarm.divisions import (
            d01_recon, d02_injection, d03_auth, d04_authz,
            d05_api, d06_clientside, d07_crypto, d08_infra,
            d09_cloud, d10_supply, d11_bizlogic, d12_file,
            d13_evasion, d14_exploit, d15_persist, d16_social,
            d17_mobile, d18_compliance, d19_intel, d20_meta,
        )
        loaders = [
            d01_recon.agents, d02_injection.agents, d03_auth.agents,
            d04_authz.agents, d05_api.agents, d06_clientside.agents,
            d07_crypto.agents, d08_infra.agents, d09_cloud.agents,
            d10_supply.agents, d11_bizlogic.agents, d12_file.agents,
            d13_evasion.agents, d14_exploit.agents, d15_persist.agents,
            d16_social.agents, d17_mobile.agents, d18_compliance.agents,
            d19_intel.agents, d20_meta.agents,
        ]
        for loader in loaders:
            for spec in loader():
                self.register(spec)

    def division_summary(self) -> dict[int, int]:
        """Return agent count per division."""
        return {div: len(ids) for div, ids in sorted(self._by_division.items())}

    def stats(self) -> dict:
        """Return comprehensive registry statistics."""
        return {
            "total_agents": self.count,
            "divisions": self.division_summary(),
            "attack_types": {k: len(v) for k, v in sorted(self._by_attack_type.items())},
            "technologies": {k: len(v) for k, v in sorted(self._by_technology.items())},
            "capabilities": {k.name: len(v) for k, v in sorted(self._by_capability.items(), key=lambda x: x[0].name)},
            "recon_agents": len(self.by_mode(Mode.RECON)),
            "audit_agents": len(self.by_mode(Mode.AUDIT)),
            "redteam_agents": len(self.by_mode(Mode.REDTEAM)),
        }
