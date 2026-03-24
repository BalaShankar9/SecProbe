"""
5-Tier Memory Hierarchy — The intelligence backbone of the swarm.

    L1: Working Memory   — Current scan state, active findings, real-time data
    L2: Episodic Memory  — This scan's complete history (decisions, outcomes)
    L3: Semantic Memory   — Learned patterns across scans (tech→vuln correlations)
    L4: Procedural Memory — Successful attack sequences (replay for similar targets)
    L5: Federated Memory  — Community intelligence (opt-in, anonymized)

Architecture:
    Each agent reads/writes to L1 during a scan. After scan completion,
    relevant data promotes to L2→L3→L4. L5 syncs with the federated
    network periodically.
"""
