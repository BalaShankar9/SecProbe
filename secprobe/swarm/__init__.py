"""
SecProbe Swarm — 600-Agent Autonomous Security Testing System.

Architecture:
    Layer 7: Strategic Command    — Mission planning, threat modeling, resource allocation
    Layer 6: Tactical Coordinator — Division commanders, inter-division communication
    Layer 5: Consensus Engine     — Multi-agent verification, evidence chains
    Layer 4: Memory Hierarchy     — 5-tier persistent intelligence
    Layer 3: Communication Mesh   — Event bus, knowledge graph, blackboard, direct messaging
    Layer 2: Execution Engine     — Async I/O, connection pooling, browser pool
    Layer 1: Safety & Governance  — Mode enforcement, scope guard, audit trail, kill switch

Operational Modes:
    recon   — Passive reconnaissance only. Zero attack traffic.
    audit   — Detect + prove exploitability. No weaponization.
    redteam — Full offensive. Data exfil, persistence, lateral movement.

20 Divisions, 600 Specialized Agents:
    D01 Reconnaissance & OSINT          (40 agents)
    D02 Web Injection                   (50 agents)
    D03 Authentication & Session        (35 agents)
    D04 Authorization & Access Control  (30 agents)
    D05 API Security                    (40 agents)
    D06 Client-Side Attacks             (35 agents)
    D07 Cryptographic Attacks           (25 agents)
    D08 Infrastructure & Network        (35 agents)
    D09 Cloud & Serverless              (35 agents)
    D10 Supply Chain & Dependencies     (25 agents)
    D11 Business Logic                  (30 agents)
    D12 File & Data Handling            (25 agents)
    D13 Evasion & Stealth               (35 agents)
    D14 Exploitation & Weaponization    (30 agents)
    D15 Persistence & Lateral Movement  (20 agents)
    D16 Social Engineering Vectors      (20 agents)
    D17 Mobile & IoT                    (25 agents)
    D18 Compliance & Standards          (20 agents)
    D19 Intelligence & Analysis         (25 agents)
    D20 Meta-Coordination               (20 agents)
"""

__all__ = [
    "SwarmAgent",
    "AgentCapability",
    "AgentSpec",
    "Division",
    "DivisionCommander",
    "SwarmRegistry",
    "OperationalMode",
    "SwarmOrchestrator",
]
