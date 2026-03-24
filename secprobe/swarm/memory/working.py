"""
L1: Working Memory — Real-time scan state shared across agents.

Working memory is the fastest tier — in-process, shared dict with
thread-safe access. It holds:
    - Current target profile (tech stack, WAF, endpoints)
    - Active findings being investigated
    - Agent states and assignments
    - Shared observations and hypotheses

Working memory is ephemeral — it exists only during a scan session.
After the scan, relevant data promotes to Episodic Memory (L2).
"""

from __future__ import annotations

import asyncio
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class MemoryEntry:
    """A single entry in working memory."""
    key: str
    value: Any
    source: str = ""          # Agent ID that wrote this
    timestamp: float = field(default_factory=time.time)
    ttl: int = 0              # Seconds until expiry (0 = no expiry)
    tags: tuple[str, ...] = ()
    access_count: int = 0

    @property
    def is_expired(self) -> bool:
        if self.ttl <= 0:
            return False
        return (time.time() - self.timestamp) > self.ttl


class WorkingMemory:
    """
    Thread-safe in-process working memory for the current scan.

    Usage:
        mem = WorkingMemory()
        await mem.store("target_tech", {"server": "nginx", "language": "php"}, source="recon-tech-server")
        tech = await mem.recall("target_tech")

        # Store with tags for cross-agent discovery
        await mem.store("sqli_param_found", {"url": "...", "param": "id"},
                        source="injection-point-finder", tags=("injectable", "sqli"))

        # Query by tag
        injectables = await mem.recall_by_tag("injectable")
    """

    def __init__(self):
        self._store: dict[str, MemoryEntry] = {}
        self._by_tag: dict[str, list[str]] = defaultdict(list)
        self._by_source: dict[str, list[str]] = defaultdict(list)
        self._lock = threading.Lock()
        self._event_log: list[dict] = []

    async def store(self, key: str, value: Any, *,
                    source: str = "", ttl: int = 0,
                    tags: tuple[str, ...] = ()):
        """Store a value in working memory."""
        with self._lock:
            entry = MemoryEntry(
                key=key, value=value, source=source,
                ttl=ttl, tags=tags,
            )
            self._store[key] = entry

            # Index by tags
            for tag in tags:
                if key not in self._by_tag[tag]:
                    self._by_tag[tag].append(key)

            # Index by source agent
            if source:
                if key not in self._by_source[source]:
                    self._by_source[source].append(key)

            # Log the write
            self._event_log.append({
                "action": "store", "key": key,
                "source": source, "timestamp": time.time(),
            })

    async def recall(self, key: str) -> Any | None:
        """Recall a value from working memory."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry.is_expired:
                del self._store[key]
                return None
            entry.access_count += 1
            return entry.value

    async def recall_entry(self, key: str) -> MemoryEntry | None:
        """Recall a full MemoryEntry (with metadata)."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None or entry.is_expired:
                return None
            entry.access_count += 1
            return entry

    async def recall_by_tag(self, tag: str) -> list[tuple[str, Any]]:
        """Recall all entries with a given tag."""
        with self._lock:
            results = []
            keys = self._by_tag.get(tag, [])
            for key in keys:
                entry = self._store.get(key)
                if entry and not entry.is_expired:
                    entry.access_count += 1
                    results.append((key, entry.value))
            return results

    async def recall_by_source(self, agent_id: str) -> list[tuple[str, Any]]:
        """Recall all entries from a specific agent."""
        with self._lock:
            results = []
            keys = self._by_source.get(agent_id, [])
            for key in keys:
                entry = self._store.get(key)
                if entry and not entry.is_expired:
                    results.append((key, entry.value))
            return results

    async def exists(self, key: str) -> bool:
        """Check if a key exists and is not expired."""
        with self._lock:
            entry = self._store.get(key)
            return entry is not None and not entry.is_expired

    async def delete(self, key: str) -> bool:
        """Remove an entry from working memory."""
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    async def keys(self, pattern: str = "") -> list[str]:
        """List keys, optionally filtered by prefix pattern."""
        with self._lock:
            if pattern:
                return [k for k in self._store if k.startswith(pattern)]
            return list(self._store.keys())

    async def clear(self):
        """Clear all working memory."""
        with self._lock:
            self._store.clear()
            self._by_tag.clear()
            self._by_source.clear()

    async def gc(self) -> int:
        """Garbage collect expired entries. Returns count removed."""
        with self._lock:
            expired = [k for k, v in self._store.items() if v.is_expired]
            for key in expired:
                del self._store[key]
            return len(expired)

    @property
    def size(self) -> int:
        return len(self._store)

    def snapshot(self) -> dict[str, Any]:
        """Snapshot of all current memory for promotion to L2."""
        with self._lock:
            return {
                key: {
                    "value": entry.value,
                    "source": entry.source,
                    "tags": entry.tags,
                    "access_count": entry.access_count,
                    "timestamp": entry.timestamp,
                }
                for key, entry in self._store.items()
                if not entry.is_expired
            }
