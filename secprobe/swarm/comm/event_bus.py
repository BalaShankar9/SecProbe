"""
Event Bus — Pub/sub event distribution for the swarm.

The event bus routes AgentMessages between agents based on subscriptions.
Agents subscribe to message types or division-scoped channels.

Features:
    - Topic-based subscriptions (by MessageType)
    - Division-scoped channels (only agents in same division)
    - Global broadcast (all agents)
    - Priority-aware delivery (higher priority = delivered first)
    - Message TTL enforcement
    - Async delivery with backpressure
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Callable, Awaitable

from secprobe.swarm.agent import AgentMessage, MessageType, AgentPriority


# Type alias for message handlers
MessageHandler = Callable[[AgentMessage], Awaitable[None]]


class EventBus:
    """
    Async pub/sub event bus for the agent swarm.

    Usage:
        bus = EventBus()

        # Subscribe to specific message types
        await bus.subscribe("sqli-error-mysql", MessageType.INTELLIGENCE)
        await bus.subscribe("sqli-error-mysql", MessageType.COMMAND)

        # Subscribe to all messages in a division
        await bus.subscribe_division("sqli-error-mysql", division=2)

        # Publish a message
        await bus.publish(AgentMessage(
            type=MessageType.FINDING,
            sender="sqli-error-mysql",
            division=2,
            payload={"title": "SQLi confirmed", ...},
        ))

        # Deliver messages to agents
        messages = await bus.collect("sqli-error-mysql")
    """

    def __init__(self, max_queue_size: int = 10000):
        self._max_queue_size = max_queue_size

        # Subscriptions: topic → set of agent IDs
        self._type_subs: dict[MessageType, set[str]] = defaultdict(set)
        self._division_subs: dict[int, set[str]] = defaultdict(set)
        self._global_subs: set[str] = set()

        # Per-agent message queues
        self._queues: dict[str, asyncio.Queue[AgentMessage]] = {}

        # Handlers: agent_id → async callable
        self._handlers: dict[str, MessageHandler] = {}

        # Metrics
        self._published: int = 0
        self._delivered: int = 0
        self._dropped: int = 0

    async def subscribe(self, agent_id: str, message_type: MessageType):
        """Subscribe an agent to a specific message type."""
        self._type_subs[message_type].add(agent_id)
        self._ensure_queue(agent_id)

    async def subscribe_division(self, agent_id: str, division: int):
        """Subscribe an agent to all messages in its division."""
        self._division_subs[division].add(agent_id)
        self._ensure_queue(agent_id)

    async def subscribe_global(self, agent_id: str):
        """Subscribe an agent to all messages."""
        self._global_subs.add(agent_id)
        self._ensure_queue(agent_id)

    async def unsubscribe(self, agent_id: str):
        """Remove all subscriptions for an agent."""
        for subs in self._type_subs.values():
            subs.discard(agent_id)
        for subs in self._division_subs.values():
            subs.discard(agent_id)
        self._global_subs.discard(agent_id)
        self._queues.pop(agent_id, None)

    def register_handler(self, agent_id: str, handler: MessageHandler):
        """Register an async handler for an agent."""
        self._handlers[agent_id] = handler
        self._ensure_queue(agent_id)

    async def publish(self, message: AgentMessage):
        """Publish a message to all relevant subscribers."""
        self._published += 1

        # Check TTL
        if message.ttl > 0:
            age = time.monotonic() - message.timestamp
            if age > message.ttl:
                self._dropped += 1
                return

        # Determine recipients
        recipients: set[str] = set()

        # Type-based subscribers
        type_subs = self._type_subs.get(message.type, set())
        recipients.update(type_subs)

        # Division-scoped subscribers
        if message.division > 0:
            div_subs = self._division_subs.get(message.division, set())
            recipients.update(div_subs)

        # Global subscribers
        recipients.update(self._global_subs)

        # Direct message — only to specific receiver
        if message.receiver:
            recipients = {message.receiver} & (recipients | {message.receiver})

        # Don't deliver to sender
        recipients.discard(message.sender)

        # Deliver to all recipients
        for agent_id in recipients:
            await self._deliver(agent_id, message)

    async def _deliver(self, agent_id: str, message: AgentMessage):
        """Deliver a message to a specific agent."""
        # Try handler first
        handler = self._handlers.get(agent_id)
        if handler:
            try:
                await handler(message)
                self._delivered += 1
                return
            except Exception:
                pass

        # Fall back to queue
        queue = self._queues.get(agent_id)
        if queue:
            if queue.qsize() < self._max_queue_size:
                await queue.put(message)
                self._delivered += 1
            else:
                self._dropped += 1

    async def collect(self, agent_id: str, max_messages: int = 100) -> list[AgentMessage]:
        """Collect pending messages for an agent (non-blocking)."""
        queue = self._queues.get(agent_id)
        if not queue:
            return []
        messages = []
        while not queue.empty() and len(messages) < max_messages:
            try:
                msg = queue.get_nowait()
                messages.append(msg)
            except asyncio.QueueEmpty:
                break
        # Sort by priority (highest first)
        messages.sort(key=lambda m: m.priority, reverse=True)
        return messages

    async def broadcast(self, message: AgentMessage):
        """Broadcast to ALL agents (bypasses subscriptions)."""
        for agent_id in list(self._queues.keys()):
            if agent_id != message.sender:
                await self._deliver(agent_id, message)

    def _ensure_queue(self, agent_id: str):
        if agent_id not in self._queues:
            self._queues[agent_id] = asyncio.Queue(maxsize=self._max_queue_size)

    @property
    def stats(self) -> dict:
        return {
            "published": self._published,
            "delivered": self._delivered,
            "dropped": self._dropped,
            "subscribers": sum(len(s) for s in self._type_subs.values()),
            "queues": len(self._queues),
            "delivery_rate": (
                self._delivered / self._published if self._published > 0 else 0
            ),
        }

    async def drain(self):
        """Clear all queues (used during shutdown)."""
        for queue in self._queues.values():
            while not queue.empty():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
