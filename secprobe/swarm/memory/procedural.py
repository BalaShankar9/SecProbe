"""
L4: Procedural Memory — Successful attack sequences for replay.

Procedural memory stores "how-to" knowledge — sequences of actions
that successfully found or exploited vulnerabilities. When the swarm
encounters a similar target, it can replay proven sequences.

Example:
    Procedure: "WordPress SQLi via search parameter"
    Steps:
        1. Detect WordPress via wp-content in HTML
        2. Confirm version < 6.0 via readme.html
        3. Send ' OR 1=1-- to /?s= parameter
        4. Confirm via MySQL error pattern in response
        5. Extract data via UNION SELECT
    Applicability: {cms: wordpress, version_lt: 6.0}
    Success rate: 78% across 23 scans
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProcedureStep:
    """A single step in an attack procedure."""
    order: int
    agent_id: str               # Which agent type performs this step
    action: str                 # What action to take
    parameters: dict[str, Any] = field(default_factory=dict)
    expected_outcome: str = ""  # What indicates success
    fallback: str = ""          # What to do if this step fails


@dataclass
class Procedure:
    """A complete attack procedure that can be replayed."""
    id: str
    name: str
    description: str
    category: str                    # "sqli", "xss", "auth_bypass", etc.
    steps: list[ProcedureStep] = field(default_factory=list)
    applicability: dict[str, Any] = field(default_factory=dict)  # Conditions to trigger
    success_count: int = 0
    attempt_count: int = 0
    avg_duration: float = 0.0        # Average seconds to complete
    first_recorded: float = field(default_factory=time.time)
    last_used: float = 0.0
    tags: tuple[str, ...] = ()

    @property
    def success_rate(self) -> float:
        if self.attempt_count == 0:
            return 0.0
        return self.success_count / self.attempt_count

    @property
    def is_proven(self) -> bool:
        """A procedure is proven if it has a good success rate with enough data."""
        return self.success_rate >= 0.6 and self.attempt_count >= 3

    def record_attempt(self, success: bool, duration: float = 0.0):
        """Record the outcome of a procedure replay."""
        self.attempt_count += 1
        if success:
            self.success_count += 1
        self.last_used = time.time()
        if duration > 0:
            # Running average
            self.avg_duration = (
                (self.avg_duration * (self.attempt_count - 1) + duration)
                / self.attempt_count
            )


class ProceduralMemory:
    """
    Stores and retrieves proven attack procedures.

    Usage:
        mem = ProceduralMemory()
        mem.load()

        # Find procedures for this target
        procs = mem.find_applicable({"cms": "wordpress", "waf": "cloudflare"})
        for proc in procs:
            print(f"{proc.name}: {proc.success_rate:.0%} success rate")

        # Record a new procedure from a successful scan
        mem.record(Procedure(
            id="wp-sqli-search",
            name="WordPress SQLi via search",
            description="SQL injection via WordPress search parameter",
            category="sqli",
            steps=[...],
            applicability={"cms": "wordpress"},
        ))

        mem.persist()
    """

    def __init__(self, storage_dir: str = ""):
        if not storage_dir:
            storage_dir = os.path.join(os.path.expanduser("~"), ".secprobe", "memory", "procedural")
        self._storage_dir = storage_dir
        self._procedures: dict[str, Procedure] = {}
        self._by_category: dict[str, list[str]] = {}

    def record(self, procedure: Procedure):
        """Record a new or updated procedure."""
        existing = self._procedures.get(procedure.id)
        if existing:
            existing.record_attempt(True, procedure.avg_duration)
        else:
            self._procedures[procedure.id] = procedure
            self._by_category.setdefault(procedure.category, []).append(procedure.id)

    def find_applicable(self, conditions: dict[str, Any],
                        min_success_rate: float = 0.5) -> list[Procedure]:
        """Find procedures applicable to given target conditions."""
        results = []
        for proc in self._procedures.values():
            if proc.success_rate < min_success_rate:
                continue
            # Check applicability overlap
            overlap = any(
                k in proc.applicability and proc.applicability[k] == v
                for k, v in conditions.items()
            )
            if overlap or not proc.applicability:
                results.append(proc)
        results.sort(key=lambda p: p.success_rate, reverse=True)
        return results

    def by_category(self, category: str) -> list[Procedure]:
        ids = self._by_category.get(category, [])
        return [self._procedures[i] for i in ids if i in self._procedures]

    def get(self, procedure_id: str) -> Procedure | None:
        return self._procedures.get(procedure_id)

    @property
    def count(self) -> int:
        return len(self._procedures)

    def persist(self) -> str:
        """Save all procedures to disk."""
        os.makedirs(self._storage_dir, exist_ok=True)
        path = os.path.join(self._storage_dir, "procedures.json")
        data = [
            {
                "id": p.id, "name": p.name, "description": p.description,
                "category": p.category,
                "steps": [
                    {"order": s.order, "agent_id": s.agent_id, "action": s.action,
                     "parameters": s.parameters, "expected_outcome": s.expected_outcome,
                     "fallback": s.fallback}
                    for s in p.steps
                ],
                "applicability": p.applicability,
                "success_count": p.success_count,
                "attempt_count": p.attempt_count,
                "avg_duration": p.avg_duration,
                "first_recorded": p.first_recorded,
                "last_used": p.last_used,
                "tags": list(p.tags),
            }
            for p in self._procedures.values()
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def load(self) -> int:
        """Load procedures from disk. Returns count loaded."""
        path = os.path.join(self._storage_dir, "procedures.json")
        if not os.path.exists(path):
            return 0
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            proc = Procedure(
                id=item["id"], name=item["name"],
                description=item["description"], category=item["category"],
                steps=[
                    ProcedureStep(
                        order=s["order"], agent_id=s["agent_id"],
                        action=s["action"], parameters=s.get("parameters", {}),
                        expected_outcome=s.get("expected_outcome", ""),
                        fallback=s.get("fallback", ""),
                    )
                    for s in item.get("steps", [])
                ],
                applicability=item.get("applicability", {}),
                success_count=item.get("success_count", 0),
                attempt_count=item.get("attempt_count", 0),
                avg_duration=item.get("avg_duration", 0.0),
                first_recorded=item.get("first_recorded", 0),
                last_used=item.get("last_used", 0),
                tags=tuple(item.get("tags", ())),
            )
            self._procedures[proc.id] = proc
            self._by_category.setdefault(proc.category, []).append(proc.id)
        return len(data)
