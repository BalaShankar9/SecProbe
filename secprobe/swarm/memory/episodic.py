"""
L2: Episodic Memory — Complete history of a scan session.

Episodic memory records every significant event during a scan:
    - Agent actions and their outcomes
    - Findings with full evidence chains
    - Strategy decisions and adaptations
    - Target profile evolution

After a scan, episodic memory is persisted to disk (JSON) so it can
be compared with future scans (diff reports) and mined for patterns
(promotion to Semantic Memory L3).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Episode:
    """A single event in the scan timeline."""
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""
    event_type: str = ""       # "action", "finding", "decision", "adaptation", "error"
    description: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    outcome: str = ""          # "success", "failure", "blocked", "timeout"
    confidence: float = 0.0
    tags: tuple[str, ...] = ()


@dataclass
class ScanEpisode:
    """Complete episodic record of a scan session."""
    scan_id: str = ""
    target: str = ""
    mode: str = ""                 # recon/audit/redteam
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    episodes: list[Episode] = field(default_factory=list)
    findings_summary: dict[str, int] = field(default_factory=dict)
    agents_deployed: list[str] = field(default_factory=list)
    divisions_activated: list[int] = field(default_factory=list)
    total_requests: int = 0
    tech_profile: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class EpisodicMemory:
    """
    Persists scan session history to disk.

    Usage:
        mem = EpisodicMemory(storage_dir="~/.secprobe/memory/episodic")
        session = mem.create_session("scan-001", "example.com", "audit")

        # During scan — record events
        mem.record(session.scan_id, Episode(
            agent_id="sqli-error-mysql",
            event_type="finding",
            description="MySQL error-based SQLi confirmed",
            data={"url": "...", "param": "id"},
            outcome="success",
            confidence=0.95,
        ))

        # After scan — persist to disk
        mem.persist(session.scan_id)

        # Later — load for comparison
        old = mem.load("scan-001")
    """

    def __init__(self, storage_dir: str = ""):
        if not storage_dir:
            storage_dir = os.path.join(os.path.expanduser("~"), ".secprobe", "memory", "episodic")
        self._storage_dir = storage_dir
        self._sessions: dict[str, ScanEpisode] = {}

    def create_session(self, scan_id: str, target: str, mode: str) -> ScanEpisode:
        """Create a new episodic session for a scan."""
        session = ScanEpisode(scan_id=scan_id, target=target, mode=mode)
        self._sessions[scan_id] = session
        return session

    def record(self, scan_id: str, episode: Episode):
        """Record an episode to a scan session."""
        session = self._sessions.get(scan_id)
        if session:
            session.episodes.append(episode)

    def get_session(self, scan_id: str) -> ScanEpisode | None:
        return self._sessions.get(scan_id)

    def get_episodes(self, scan_id: str, *,
                     agent_id: str = "", event_type: str = "",
                     tag: str = "") -> list[Episode]:
        """Query episodes with optional filters."""
        session = self._sessions.get(scan_id)
        if not session:
            return []
        results = session.episodes
        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if tag:
            results = [e for e in results if tag in e.tags]
        return results

    def finalize(self, scan_id: str, *,
                 findings_summary: dict[str, int] | None = None,
                 agents_deployed: list[str] | None = None,
                 divisions_activated: list[int] | None = None,
                 total_requests: int = 0,
                 tech_profile: dict | None = None):
        """Finalize a scan session with summary data."""
        session = self._sessions.get(scan_id)
        if not session:
            return
        session.end_time = time.time()
        if findings_summary:
            session.findings_summary = findings_summary
        if agents_deployed:
            session.agents_deployed = agents_deployed
        if divisions_activated:
            session.divisions_activated = divisions_activated
        session.total_requests = total_requests
        if tech_profile:
            session.tech_profile = tech_profile

    def persist(self, scan_id: str) -> str:
        """Persist session to disk as JSON. Returns file path."""
        session = self._sessions.get(scan_id)
        if not session:
            return ""
        os.makedirs(self._storage_dir, exist_ok=True)
        path = os.path.join(self._storage_dir, f"{scan_id}.json")
        data = {
            "scan_id": session.scan_id,
            "target": session.target,
            "mode": session.mode,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "episodes": [
                {
                    "timestamp": e.timestamp,
                    "agent_id": e.agent_id,
                    "event_type": e.event_type,
                    "description": e.description,
                    "data": e.data,
                    "outcome": e.outcome,
                    "confidence": e.confidence,
                    "tags": list(e.tags),
                }
                for e in session.episodes
            ],
            "findings_summary": session.findings_summary,
            "agents_deployed": session.agents_deployed,
            "divisions_activated": session.divisions_activated,
            "total_requests": session.total_requests,
            "tech_profile": session.tech_profile,
            "metadata": session.metadata,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def load(self, scan_id: str) -> ScanEpisode | None:
        """Load a persisted session from disk."""
        path = os.path.join(self._storage_dir, f"{scan_id}.json")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        session = ScanEpisode(
            scan_id=data["scan_id"],
            target=data["target"],
            mode=data["mode"],
            start_time=data["start_time"],
            end_time=data["end_time"],
            episodes=[
                Episode(
                    timestamp=e["timestamp"],
                    agent_id=e["agent_id"],
                    event_type=e["event_type"],
                    description=e["description"],
                    data=e["data"],
                    outcome=e["outcome"],
                    confidence=e["confidence"],
                    tags=tuple(e.get("tags", ())),
                )
                for e in data.get("episodes", [])
            ],
            findings_summary=data.get("findings_summary", {}),
            agents_deployed=data.get("agents_deployed", []),
            divisions_activated=data.get("divisions_activated", []),
            total_requests=data.get("total_requests", 0),
            tech_profile=data.get("tech_profile", {}),
            metadata=data.get("metadata", {}),
        )
        self._sessions[scan_id] = session
        return session

    def list_sessions(self) -> list[str]:
        """List all persisted scan session IDs."""
        if not os.path.exists(self._storage_dir):
            return []
        return [
            f.replace(".json", "")
            for f in os.listdir(self._storage_dir)
            if f.endswith(".json")
        ]

    def diff(self, scan_id_a: str, scan_id_b: str) -> dict:
        """Compare two scan sessions for regression detection."""
        a = self.load(scan_id_a) or self.get_session(scan_id_a)
        b = self.load(scan_id_b) or self.get_session(scan_id_b)
        if not a or not b:
            return {"error": "One or both sessions not found"}

        findings_a = {e.description for e in a.episodes if e.event_type == "finding"}
        findings_b = {e.description for e in b.episodes if e.event_type == "finding"}

        return {
            "scan_a": scan_id_a,
            "scan_b": scan_id_b,
            "new_findings": list(findings_b - findings_a),
            "resolved_findings": list(findings_a - findings_b),
            "persistent_findings": list(findings_a & findings_b),
            "summary_a": a.findings_summary,
            "summary_b": b.findings_summary,
            "request_change": b.total_requests - a.total_requests,
        }
