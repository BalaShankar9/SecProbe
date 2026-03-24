"""
Blackboard — Shared workspace for collaborative analysis.

The blackboard is where agents post partial results that other agents
can build upon. Unlike the event bus (fire-and-forget), the blackboard
is persistent within a scan — agents can read and annotate each other's work.

Use cases:
    - Recon agent posts discovered endpoints → injection agents consume them
    - Injection agent posts "parameter X is injectable" → exploit agent builds chain
    - WAF agent posts evasion results → all agents adapt their payloads
    - Intelligence agent posts threat model → coordinators adjust strategy
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BlackboardEntry:
    """An entry on the blackboard, potentially annotated by multiple agents."""
    id: str
    category: str                    # "endpoint", "parameter", "finding", "evasion", etc.
    data: dict[str, Any] = field(default_factory=dict)
    posted_by: str = ""              # Agent ID
    posted_at: float = field(default_factory=time.time)
    annotations: list[dict] = field(default_factory=list)
    subscribers: list[str] = field(default_factory=list)  # Agents watching this entry
    priority: int = 50
    consumed_by: list[str] = field(default_factory=list)

    def annotate(self, agent_id: str, note: str, data: dict | None = None):
        """Add an annotation from another agent."""
        self.annotations.append({
            "agent_id": agent_id,
            "note": note,
            "data": data or {},
            "timestamp": time.time(),
        })

    def mark_consumed(self, agent_id: str):
        """Mark that an agent has processed this entry."""
        if agent_id not in self.consumed_by:
            self.consumed_by.append(agent_id)


class Blackboard:
    """
    Thread-safe shared workspace for agent collaboration.

    Usage:
        bb = Blackboard()

        # Recon agent posts endpoints
        await bb.post("endpoints-found", "endpoint", {
            "urls": ["/api/users", "/api/admin"],
            "params": {"id": "integer", "search": "string"},
        }, posted_by="recon-crawler-static")

        # Injection agent reads endpoints
        entries = await bb.read_category("endpoint")
        for entry in entries:
            urls = entry.data.get("urls", [])
            # ... test each URL for injection
            entry.mark_consumed("sqli-error-mysql")

        # Intelligence agent annotates
        await bb.annotate("endpoints-found", "intel-threat-model",
                          "High risk: /api/admin lacks auth",
                          {"risk_level": "high"})
    """

    def __init__(self):
        self._entries: dict[str, BlackboardEntry] = {}
        self._by_category: dict[str, list[str]] = defaultdict(list)
        self._lock = threading.Lock()
        self._watchers: dict[str, list[asyncio.Event]] = defaultdict(list)

    async def post(self, entry_id: str, category: str,
                   data: dict[str, Any], *,
                   posted_by: str = "", priority: int = 50) -> BlackboardEntry:
        """Post a new entry to the blackboard."""
        with self._lock:
            entry = BlackboardEntry(
                id=entry_id, category=category, data=data,
                posted_by=posted_by, priority=priority,
            )
            self._entries[entry_id] = entry
            if entry_id not in self._by_category[category]:
                self._by_category[category].append(entry_id)

            # Notify watchers
            for event in self._watchers.get(category, []):
                event.set()

            return entry

    async def read(self, entry_id: str) -> BlackboardEntry | None:
        """Read a specific entry."""
        with self._lock:
            return self._entries.get(entry_id)

    async def read_category(self, category: str, *,
                            unconsumed_by: str = "") -> list[BlackboardEntry]:
        """Read all entries in a category, optionally filtered by consumption."""
        with self._lock:
            ids = self._by_category.get(category, [])
            entries = [self._entries[i] for i in ids if i in self._entries]
            if unconsumed_by:
                entries = [e for e in entries if unconsumed_by not in e.consumed_by]
            entries.sort(key=lambda e: e.priority, reverse=True)
            return entries

    async def annotate(self, entry_id: str, agent_id: str,
                       note: str, data: dict | None = None):
        """Add an annotation to an existing entry."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.annotate(agent_id, note, data)

    async def update(self, entry_id: str, data: dict[str, Any],
                     updated_by: str = ""):
        """Update an entry's data (merge)."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.data.update(data)
                entry.annotate(updated_by, "data_updated", data)

    async def consume(self, entry_id: str, agent_id: str):
        """Mark an entry as consumed by an agent."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.mark_consumed(agent_id)

    async def watch(self, category: str, timeout: float = 30.0) -> bool:
        """Wait for new entries in a category. Returns True if entry posted."""
        event = asyncio.Event()
        self._watchers[category].append(event)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            self._watchers[category].remove(event)

    async def delete(self, entry_id: str):
        """Remove an entry from the blackboard."""
        with self._lock:
            if entry_id in self._entries:
                del self._entries[entry_id]

    async def clear(self):
        """Clear all entries."""
        with self._lock:
            self._entries.clear()
            self._by_category.clear()

    @property
    def size(self) -> int:
        return len(self._entries)

    def categories(self) -> list[str]:
        return list(self._by_category.keys())

    def snapshot(self) -> dict[str, Any]:
        """Snapshot for persistence."""
        with self._lock:
            return {
                entry_id: {
                    "category": entry.category,
                    "data": entry.data,
                    "posted_by": entry.posted_by,
                    "annotations_count": len(entry.annotations),
                    "consumed_by": entry.consumed_by,
                }
                for entry_id, entry in self._entries.items()
            }
