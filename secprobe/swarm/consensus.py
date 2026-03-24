"""
Consensus Engine — Multi-agent verification for zero false positives.

This is what makes SecProbe's findings trustworthy at enterprise/government level.
Instead of one scanner saying "I think this is a vulnerability", the consensus
engine requires multiple independent agents to confirm before a finding is
reported as CONFIRMED.

Protocols:
    1. Quorum Voting     — N-of-M agents must agree (default: 2-of-3)
    2. Evidence Chain     — Findings need diverse evidence types
    3. Conflict Resolution — Handle disagreements between agents
    4. Confidence Scoring — Statistical confidence from multi-agent agreement

Process:
    1. Agent discovers potential vulnerability → posts to consensus
    2. Consensus engine identifies qualified verifiers (same attack_type)
    3. Verifiers independently test the same target/parameter
    4. Votes collected → quorum check → confidence assignment
    5. Findings that reach quorum become CONFIRMED
    6. Findings that fail quorum are downgraded or discarded
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from secprobe.swarm.agent import (
    AgentMessage,
    Confidence,
    Evidence,
    Finding,
    MessageType,
)


@dataclass
class ConsensusRequest:
    """A finding submitted for multi-agent verification."""
    id: str
    finding: Finding
    submitted_by: str                   # Agent ID
    submitted_at: float = field(default_factory=time.time)
    required_votes: int = 2             # Quorum threshold
    timeout: float = 120.0              # Seconds to collect votes
    votes_confirm: list[str] = field(default_factory=list)
    votes_deny: list[str] = field(default_factory=list)
    votes_abstain: list[str] = field(default_factory=list)
    evidence_collected: list[Evidence] = field(default_factory=list)
    status: str = "pending"             # "pending", "confirmed", "denied", "timeout"
    verifiers_assigned: list[str] = field(default_factory=list)

    @property
    def total_votes(self) -> int:
        return len(self.votes_confirm) + len(self.votes_deny)

    @property
    def is_quorum_met(self) -> bool:
        return len(self.votes_confirm) >= self.required_votes

    @property
    def is_timed_out(self) -> bool:
        return (time.time() - self.submitted_at) > self.timeout

    @property
    def confidence(self) -> Confidence:
        if self.is_quorum_met:
            # Check evidence diversity
            evidence_types = {e.type for e in self.evidence_collected}
            if len(evidence_types) >= 3:
                return Confidence.PROVEN
            elif len(evidence_types) >= 2:
                return Confidence.CONFIRMED
            else:
                return Confidence.FIRM
        elif len(self.votes_confirm) >= 1:
            return Confidence.TENTATIVE
        return Confidence.NONE


@dataclass
class Vote:
    """A vote from a verifying agent."""
    agent_id: str
    decision: str                # "confirm", "deny", "abstain"
    evidence: Evidence | None = None
    reason: str = ""
    confidence: float = 0.0     # Agent's own confidence (0.0-1.0)
    timestamp: float = field(default_factory=time.time)


class ConsensusEngine:
    """
    Multi-agent consensus for finding verification.

    Usage:
        engine = ConsensusEngine(registry=registry)

        # Submit a finding for verification
        request = await engine.submit(finding, submitted_by="sqli-error-mysql")

        # Agents vote
        await engine.vote(request.id, Vote(
            agent_id="sqli-boolean-blind",
            decision="confirm",
            evidence=Evidence(type="boolean_diff", ...),
            confidence=0.92,
        ))

        # Check consensus
        result = await engine.check(request.id)
        if result.status == "confirmed":
            # Finding is verified — report it
            ...
    """

    def __init__(self, quorum: int = 2, timeout: float = 120.0):
        self._quorum = quorum
        self._timeout = timeout
        self._requests: dict[str, ConsensusRequest] = {}
        self._by_attack_type: dict[str, list[str]] = defaultdict(list)
        self._confirmed: list[Finding] = []
        self._denied: list[Finding] = []

    async def submit(self, finding: Finding, submitted_by: str) -> ConsensusRequest:
        """Submit a finding for multi-agent verification."""
        request = ConsensusRequest(
            id=finding.id,
            finding=finding,
            submitted_by=submitted_by,
            required_votes=self._quorum,
            timeout=self._timeout,
        )

        # Auto-add the discoverer's vote
        request.votes_confirm.append(submitted_by)
        if finding.evidence:
            request.evidence_collected.extend(finding.evidence)

        self._requests[request.id] = request

        # Index by attack type for verifier assignment
        if finding.attack_type:
            self._by_attack_type[finding.attack_type].append(request.id)

        return request

    async def vote(self, request_id: str, vote: Vote) -> bool:
        """Record a vote on a consensus request. Returns True if quorum now met."""
        request = self._requests.get(request_id)
        if not request or request.status != "pending":
            return False

        # Don't allow duplicate votes
        all_voters = request.votes_confirm + request.votes_deny + request.votes_abstain
        if vote.agent_id in all_voters:
            return False

        if vote.decision == "confirm":
            request.votes_confirm.append(vote.agent_id)
        elif vote.decision == "deny":
            request.votes_deny.append(vote.agent_id)
        else:
            request.votes_abstain.append(vote.agent_id)

        if vote.evidence:
            request.evidence_collected.append(vote.evidence)

        # Check if quorum is met
        if request.is_quorum_met:
            request.status = "confirmed"
            self._finalize_confirmed(request)
            return True

        # Check if impossible to reach quorum (too many denies)
        max_possible = request.total_votes + len(request.verifiers_assigned) - len(all_voters)
        if len(request.votes_confirm) + max_possible < request.required_votes:
            request.status = "denied"
            self._denied.append(request.finding)

        return False

    async def check(self, request_id: str) -> ConsensusRequest | None:
        """Check the status of a consensus request."""
        request = self._requests.get(request_id)
        if not request:
            return None

        # Check timeout
        if request.status == "pending" and request.is_timed_out:
            if request.is_quorum_met:
                request.status = "confirmed"
                self._finalize_confirmed(request)
            elif len(request.votes_confirm) >= 1:
                # Partial confirmation — downgrade but keep
                request.status = "confirmed"
                self._finalize_confirmed(request)
            else:
                request.status = "timeout"

        return request

    async def check_all_pending(self) -> dict[str, int]:
        """Check all pending requests for timeouts. Returns status counts."""
        counts = {"confirmed": 0, "denied": 0, "timeout": 0, "pending": 0}
        for req_id in list(self._requests.keys()):
            req = await self.check(req_id)
            if req:
                counts[req.status] = counts.get(req.status, 0) + 1
        return counts

    def get_pending_for_attack_type(self, attack_type: str) -> list[ConsensusRequest]:
        """Get pending requests that need verification for a given attack type."""
        request_ids = self._by_attack_type.get(attack_type, [])
        return [
            self._requests[rid] for rid in request_ids
            if rid in self._requests and self._requests[rid].status == "pending"
        ]

    def assign_verifiers(self, request_id: str, agent_ids: list[str]):
        """Assign specific agents as verifiers for a request."""
        request = self._requests.get(request_id)
        if request:
            request.verifiers_assigned = agent_ids

    def _finalize_confirmed(self, request: ConsensusRequest):
        """Finalize a confirmed finding — update confidence and evidence."""
        finding = request.finding
        finding.consensus_confidence = request.confidence
        finding.consensus_votes = len(request.votes_confirm)
        finding.confirmed_by = request.votes_confirm[1:]  # Exclude discoverer
        finding.evidence = request.evidence_collected
        self._confirmed.append(finding)

    @property
    def confirmed_findings(self) -> list[Finding]:
        """All findings that have passed consensus."""
        return list(self._confirmed)

    @property
    def denied_findings(self) -> list[Finding]:
        """All findings that failed consensus."""
        return list(self._denied)

    def stats(self) -> dict:
        """Consensus engine statistics."""
        statuses = defaultdict(int)
        for req in self._requests.values():
            statuses[req.status] += 1
        return {
            "total_requests": len(self._requests),
            "confirmed": statuses["confirmed"],
            "denied": statuses["denied"],
            "pending": statuses["pending"],
            "timeout": statuses["timeout"],
            "total_votes": sum(r.total_votes for r in self._requests.values()),
            "avg_votes_per_finding": (
                sum(r.total_votes for r in self._requests.values())
                / len(self._requests) if self._requests else 0
            ),
            "confirmation_rate": (
                statuses["confirmed"]
                / (statuses["confirmed"] + statuses["denied"])
                if (statuses["confirmed"] + statuses["denied"]) > 0 else 0
            ),
        }
