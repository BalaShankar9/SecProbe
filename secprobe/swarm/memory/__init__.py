"""
5-Tier Memory Hierarchy — The intelligence backbone of the swarm.

    L1: Working Memory   — Current scan state, active findings, real-time data
    L2: Episodic Memory  — Complete scan history (decisions, outcomes, timelines)
    L3: Semantic Memory   — Learned patterns across scans (tech->vuln correlations)
    L4: Procedural Memory — Successful attack sequences (replay for similar targets)
    L5: Federated Memory  — Community intelligence (opt-in, anonymised)

Architecture:
    Each agent reads/writes to L1 during a scan.  After scan completion,
    relevant data promotes to L2->L3->L4.  L5 syncs with the federated
    network periodically.

Quick start::

    from secprobe.swarm.memory import MemoryHierarchy

    mem = MemoryHierarchy()
    # L1: in-process working memory (ephemeral)
    await mem.working.store("target_tech", {"server": "nginx"})

    # L2: persistent scan episodes (SQLite)
    from secprobe.swarm.memory.episodic import ScanEpisode
    mem.episodic.record_episode(ScanEpisode(target="example.com"))

    # L3: learned correlations (SQLite)
    mem.semantic.learn_correlation("wordpress/6.2", "sqli", found=True)

    # L4: proven attack procedures (SQLite)
    from secprobe.swarm.memory.procedural import AttackProcedure, AttackStep
    mem.procedural.record_procedure(AttackProcedure(vuln_type="sqli", ...))

    # L5: community intelligence (opt-in, async, Supabase)
    patterns = await mem.federated.query_patterns("sqli")
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .working import WorkingMemory, MemoryEntry
from .episodic import EpisodicMemory, ScanEpisode
from .semantic import SemanticMemory, TechVulnCorrelation, PayloadEffectiveness
from .procedural import ProceduralMemory, AttackProcedure, AttackStep
from .federated import FederatedMemory, FederatedPattern

logger = logging.getLogger("secprobe.memory")

__all__ = [
    # Facade
    "MemoryHierarchy",
    # L1
    "WorkingMemory",
    "MemoryEntry",
    # L2
    "EpisodicMemory",
    "ScanEpisode",
    # L3
    "SemanticMemory",
    "TechVulnCorrelation",
    "PayloadEffectiveness",
    # L4
    "ProceduralMemory",
    "AttackProcedure",
    "AttackStep",
    # L5
    "FederatedMemory",
    "FederatedPattern",
]


class MemoryHierarchy:
    """
    Unified interface to all 5 memory tiers.

    Provides a single entry point for the swarm orchestrator to interact
    with every level of the memory hierarchy.  Each tier is lazily
    initialised with shared defaults.

    Args:
        storage_path: Base directory for SQLite databases (L2-L4).
            Defaults to ``~/.secprobe/memory/``.
        supabase_url: Supabase project REST URL for L5.
        supabase_key: Supabase anonymous/service key for L5.
        federated: Whether to enable community intelligence (L5).
    """

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        supabase_url: str | None = None,
        supabase_key: str | None = None,
        federated: bool = False,
    ):
        base = Path(storage_path) if storage_path else Path.home() / ".secprobe" / "memory"

        self.working = WorkingMemory()
        self.episodic = EpisodicMemory(storage_path=base / "episodic")
        self.semantic = SemanticMemory(storage_path=base / "semantic")
        self.procedural = ProceduralMemory(storage_path=base / "procedural")
        self.federated = FederatedMemory(
            supabase_url=supabase_url,
            supabase_key=supabase_key,
            enabled=federated,
        )

        logger.info(
            "Memory hierarchy initialised — L1:working L2:episodic L3:semantic "
            "L4:procedural L5:federated(%s)",
            "enabled" if federated else "disabled",
        )

    async def close(self) -> None:
        """Close all persistent connections."""
        self.episodic.close()
        self.semantic.close()
        self.procedural.close()
        await self.federated.close()

    def __repr__(self) -> str:
        return (
            f"<MemoryHierarchy "
            f"L1=WorkingMemory(size={self.working.size}) "
            f"L2=EpisodicMemory(count={self.episodic.count()}) "
            f"L3=SemanticMemory(correlations={self.semantic.correlation_count()}) "
            f"L4=ProceduralMemory(count={self.procedural.count()}) "
            f"L5={self.federated!r}>"
        )
