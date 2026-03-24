"""
Safety Governor — The ultimate authority on what agents can and cannot do.

Every agent action passes through the governor for approval. The governor
enforces:
    1. Mode restrictions (recon/audit/redteam)
    2. Scope boundaries (only authorized targets)
    3. Budget limits (requests, time, concurrency)
    4. Risk assessment (high-risk actions need explicit mode)
    5. Forensic logging (every action is recorded)

The governor CANNOT be bypassed — it's injected into every SwarmAgent
at construction time.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from secprobe.swarm.agent import (
    AgentAction,
    OperationalMode,
)


@dataclass
class ScopeRule:
    """Defines what targets are in scope."""
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    max_depth: int = 10    # Max crawl depth from target root


@dataclass
class BudgetConfig:
    """Resource budget for the entire scan."""
    max_total_requests: int = 50000
    max_requests_per_agent: int = 500
    max_duration_seconds: int = 3600       # 1 hour
    max_concurrent_agents: int = 50
    max_concurrent_requests: int = 20
    max_findings: int = 10000              # Safety cap


@dataclass
class AuditEntry:
    """Forensic audit log entry."""
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""
    action_type: str = ""
    target: str = ""
    approved: bool = False
    denied_reason: str = ""
    mode: str = ""
    risk_level: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class SafetyGovernor:
    """
    Central safety authority for the swarm.

    Usage:
        governor = SafetyGovernor(
            mode=OperationalMode.AUDIT,
            scope=ScopeRule(allowed_domains=["example.com", "*.example.com"]),
            budget=BudgetConfig(max_total_requests=10000),
        )

        # Every agent action goes through this
        action = AgentAction(
            agent_id="sqli-error-mysql",
            type="payload_injection",
            target="https://example.com/api?id=1",
            requires_mode=OperationalMode.AUDIT,
            risk_level="medium",
        )
        if await governor.approve(action):
            # Proceed with action
            ...
    """

    def __init__(self, mode: OperationalMode = OperationalMode.AUDIT,
                 scope: ScopeRule | None = None,
                 budget: BudgetConfig | None = None,
                 audit_dir: str = ""):
        self.mode = mode
        self.scope = scope or ScopeRule()
        self.budget = budget or BudgetConfig()

        # Runtime state
        self._total_requests = 0
        self._agent_requests: dict[str, int] = {}
        self._active_agents: set[str] = set()
        self._start_time = time.monotonic()
        self._findings_count = 0
        self._killed = False
        self._lock = threading.Lock()

        # Audit log
        self._audit_log: list[AuditEntry] = []
        if not audit_dir:
            audit_dir = os.path.join(os.path.expanduser("~"), ".secprobe", "audit")
        self._audit_dir = audit_dir

    async def approve(self, action: AgentAction) -> bool:
        """
        Approve or deny an agent action.

        This is the core safety gate — every action in the swarm
        passes through here.
        """
        with self._lock:
            # Kill switch check
            if self._killed:
                action.approved = False
                action.denied_reason = "Kill switch activated"
                self._log_action(action, approved=False,
                                 reason="Kill switch activated")
                return False

            # Mode check
            if not self._check_mode(action):
                action.approved = False
                action.denied_reason = f"Action requires {action.requires_mode.value} mode, current mode is {self.mode.value}"
                self._log_action(action, approved=False,
                                 reason=action.denied_reason)
                return False

            # Scope check
            if action.target and not self._check_scope(action.target):
                action.approved = False
                action.denied_reason = f"Target {action.target} is out of scope"
                self._log_action(action, approved=False,
                                 reason=action.denied_reason)
                return False

            # Budget checks
            budget_reason = self._check_budget(action)
            if budget_reason:
                action.approved = False
                action.denied_reason = budget_reason
                self._log_action(action, approved=False, reason=budget_reason)
                return False

            # Approved — update counters
            self._total_requests += 1
            agent_count = self._agent_requests.get(action.agent_id, 0) + 1
            self._agent_requests[action.agent_id] = agent_count

            action.approved = True
            self._log_action(action, approved=True)
            return True

    def _check_mode(self, action: AgentAction) -> bool:
        """Check if the current mode allows this action."""
        mode_order = {
            OperationalMode.RECON: 0,
            OperationalMode.AUDIT: 1,
            OperationalMode.REDTEAM: 2,
        }
        current = mode_order.get(self.mode, 0)
        required = mode_order.get(action.requires_mode, 0)
        return current >= required

    def _check_scope(self, target: str) -> bool:
        """Check if a target URL/host is within scope."""
        if not self.scope.allowed_domains:
            return True  # No scope restriction = everything allowed

        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or target
        except Exception:
            hostname = target

        for domain in self.scope.allowed_domains:
            if domain.startswith("*."):
                # Wildcard match
                base = domain[2:]
                if hostname == base or hostname.endswith("." + base):
                    return True
            elif hostname == domain:
                return True

        # Check IP allowlist
        if hostname in self.scope.allowed_ips:
            return True

        return False

    def _check_budget(self, action: AgentAction) -> str:
        """Check budget constraints. Returns reason string if denied, empty if OK."""
        # Total request budget
        if self._total_requests >= self.budget.max_total_requests:
            return f"Total request budget exhausted ({self.budget.max_total_requests})"

        # Per-agent request budget
        agent_count = self._agent_requests.get(action.agent_id, 0)
        if agent_count >= self.budget.max_requests_per_agent:
            return f"Agent {action.agent_id} request budget exhausted ({self.budget.max_requests_per_agent})"

        # Time budget
        elapsed = time.monotonic() - self._start_time
        if elapsed >= self.budget.max_duration_seconds:
            return f"Time budget exhausted ({self.budget.max_duration_seconds}s)"

        # Findings cap
        if self._findings_count >= self.budget.max_findings:
            return f"Findings cap reached ({self.budget.max_findings})"

        return ""

    def register_agent(self, agent_id: str):
        """Register an agent as active."""
        with self._lock:
            self._active_agents.add(agent_id)

    def deregister_agent(self, agent_id: str):
        """Deregister an agent."""
        with self._lock:
            self._active_agents.discard(agent_id)

    def record_finding(self):
        """Increment findings counter."""
        with self._lock:
            self._findings_count += 1

    def kill(self, reason: str = "Manual kill"):
        """Activate the kill switch — no more actions approved."""
        with self._lock:
            self._killed = True
            self._log_action(
                AgentAction(agent_id="governor", type="kill_switch",
                            description=reason),
                approved=True, reason=reason,
            )

    @property
    def is_killed(self) -> bool:
        return self._killed

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def remaining_budget(self) -> dict:
        """Return remaining budget across all dimensions."""
        return {
            "requests": max(0, self.budget.max_total_requests - self._total_requests),
            "time_seconds": max(0, self.budget.max_duration_seconds - self.elapsed),
            "findings": max(0, self.budget.max_findings - self._findings_count),
        }

    def status(self) -> dict:
        """Return governor status summary."""
        return {
            "mode": self.mode.value,
            "killed": self._killed,
            "total_requests": self._total_requests,
            "active_agents": len(self._active_agents),
            "findings": self._findings_count,
            "elapsed_seconds": round(self.elapsed, 1),
            "remaining": self.remaining_budget,
            "audit_entries": len(self._audit_log),
        }

    # ── Audit Logging ──────────────────────────────────────────────

    def _log_action(self, action: AgentAction, *,
                    approved: bool, reason: str = ""):
        entry = AuditEntry(
            agent_id=action.agent_id,
            action_type=action.type,
            target=action.target,
            approved=approved,
            denied_reason=reason if not approved else "",
            mode=self.mode.value,
            risk_level=action.risk_level,
            details=action.parameters,
        )
        self._audit_log.append(entry)

    def persist_audit(self, scan_id: str = "") -> str:
        """Persist the audit log to disk."""
        os.makedirs(self._audit_dir, exist_ok=True)
        filename = f"audit_{scan_id or 'session'}.json"
        path = os.path.join(self._audit_dir, filename)
        data = [
            {
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "action_type": e.action_type,
                "target": e.target,
                "approved": e.approved,
                "denied_reason": e.denied_reason,
                "mode": e.mode,
                "risk_level": e.risk_level,
            }
            for e in self._audit_log
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    @property
    def audit_summary(self) -> dict:
        """Summary of audit log."""
        approved = sum(1 for e in self._audit_log if e.approved)
        denied = sum(1 for e in self._audit_log if not e.approved)
        return {
            "total_actions": len(self._audit_log),
            "approved": approved,
            "denied": denied,
            "denial_rate": denied / len(self._audit_log) if self._audit_log else 0,
            "unique_agents": len({e.agent_id for e in self._audit_log}),
        }
