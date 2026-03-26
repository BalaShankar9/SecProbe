"""
Attack Graph Engine — BloodHound for Web Applications.

Builds a directed graph of:
- Nodes: endpoints, parameters, auth tokens, user roles, data stores
- Edges: data flows, auth dependencies, vulnerability exploits
- Queries: shortest path from anonymous to admin, all paths to data exfil

No other web security tool builds attack graphs like this.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


class NodeType:
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_TOKEN = "auth_token"
    USER_ROLE = "user_role"
    DATA_STORE = "data_store"
    VULNERABILITY = "vulnerability"
    CAPABILITY = "capability"  # What an attacker gains


class EdgeType:
    DATA_FLOW = "data_flow"           # Data moves from A to B
    AUTH_REQUIRED = "auth_required"     # B requires auth from A
    EXPLOITS = "exploits"              # Vuln at A gives access to B
    ESCALATES_TO = "escalates_to"      # Exploiting A escalates to role B
    CHAINS_TO = "chains_to"           # Finding A enables finding B
    LEAKS = "leaks"                   # A leaks data B


@dataclass(frozen=True)
class GraphNode:
    id: str
    node_type: str
    label: str
    properties: tuple = ()  # Frozen for hashability

    @staticmethod
    def make(node_type: str, label: str, **props) -> GraphNode:
        node_id = hashlib.md5(f"{node_type}:{label}".encode()).hexdigest()[:12]
        return GraphNode(id=node_id, node_type=node_type, label=label,
                        properties=tuple(sorted(props.items())))


@dataclass
class GraphEdge:
    source: str  # Node ID
    target: str  # Node ID
    edge_type: str
    label: str = ""
    weight: float = 1.0  # Lower = easier path
    finding_id: str = ""  # If this edge comes from a finding


@dataclass
class AttackPath:
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_weight: float = 0.0
    impact: str = ""
    risk_level: str = "HIGH"

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def description(self) -> str:
        steps = []
        for i, edge in enumerate(self.edges):
            src = self.nodes[i].label if i < len(self.nodes) else "?"
            tgt = self.nodes[i + 1].label if i + 1 < len(self.nodes) else "?"
            steps.append(f"{src} --[{edge.label}]--> {tgt}")
        return " -> ".join(steps)


class AttackGraph:
    """Directed graph of attack paths through a web application."""

    def __init__(self):
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[GraphEdge]] = defaultdict(list)
        self._reverse_adj: dict[str, list[GraphEdge]] = defaultdict(list)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def add_node(self, node: GraphNode) -> GraphNode:
        self._nodes[node.id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        self._edges.append(edge)
        self._adjacency[edge.source].append(edge)
        self._reverse_adj[edge.target].append(edge)
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> list[tuple[GraphNode, GraphEdge]]:
        result = []
        for edge in self._adjacency.get(node_id, []):
            target = self._nodes.get(edge.target)
            if target:
                result.append((target, edge))
        return result

    # ── Graph building from scan results ─────────────────────

    def build_from_findings(self, findings: list, attack_surface=None):
        """Build the attack graph from scan findings and attack surface."""
        # Add anonymous attacker as root node
        anon = self.add_node(GraphNode.make(NodeType.USER_ROLE, "Anonymous Attacker"))

        # Add capability nodes
        data_access = self.add_node(GraphNode.make(NodeType.CAPABILITY, "Database Access"))
        admin_access = self.add_node(GraphNode.make(NodeType.CAPABILITY, "Admin Access"))
        rce = self.add_node(GraphNode.make(NodeType.CAPABILITY, "Remote Code Execution"))
        data_exfil = self.add_node(GraphNode.make(NodeType.CAPABILITY, "Data Exfiltration"))
        session_hijack = self.add_node(GraphNode.make(NodeType.CAPABILITY, "Session Hijacking"))

        # Add finding nodes and edges
        for finding in findings:
            title = getattr(finding, 'title', '') or ''
            category = (getattr(finding, 'category', '') or '').lower()
            url = getattr(finding, 'url', '') or ''
            severity = str(getattr(finding, 'severity', ''))

            # Create vulnerability node
            vuln_node = self.add_node(GraphNode.make(
                NodeType.VULNERABILITY, title,
                category=category, url=url, severity=severity,
            ))

            # Create endpoint node if URL exists
            ep_node = None
            if url:
                ep_node = self.add_node(GraphNode.make(NodeType.ENDPOINT, url))
                self.add_edge(GraphEdge(
                    source=ep_node.id, target=vuln_node.id,
                    edge_type=EdgeType.EXPLOITS,
                    label=f"Vulnerable to {category}",
                    weight=self._severity_weight(severity),
                ))

            # Anonymous can reach endpoints
            if url:
                self.add_edge(GraphEdge(
                    source=anon.id, target=ep_node.id,
                    edge_type=EdgeType.DATA_FLOW,
                    label="HTTP request",
                    weight=0.1,
                ))

            # Map vulnerability to capabilities gained
            if category in ("sqli", "nosql"):
                self.add_edge(GraphEdge(
                    source=vuln_node.id, target=data_access.id,
                    edge_type=EdgeType.ESCALATES_TO,
                    label="SQL injection → database access",
                    weight=0.5,
                ))
                self.add_edge(GraphEdge(
                    source=data_access.id, target=data_exfil.id,
                    edge_type=EdgeType.CHAINS_TO,
                    label="Read sensitive data",
                    weight=0.3,
                ))
            elif category in ("xss",):
                self.add_edge(GraphEdge(
                    source=vuln_node.id, target=session_hijack.id,
                    edge_type=EdgeType.ESCALATES_TO,
                    label="XSS → steal session cookie",
                    weight=0.7,
                ))
            elif category in ("cmdi", "ssti", "deserialization"):
                self.add_edge(GraphEdge(
                    source=vuln_node.id, target=rce.id,
                    edge_type=EdgeType.ESCALATES_TO,
                    label=f"{category} → command execution",
                    weight=0.3,
                ))
            elif category in ("auth", "idor", "bola"):
                self.add_edge(GraphEdge(
                    source=vuln_node.id, target=admin_access.id,
                    edge_type=EdgeType.ESCALATES_TO,
                    label="Auth bypass → admin access",
                    weight=0.5,
                ))
            elif category in ("lfi",):
                self.add_edge(GraphEdge(
                    source=vuln_node.id, target=data_exfil.id,
                    edge_type=EdgeType.ESCALATES_TO,
                    label="LFI → read server files",
                    weight=0.5,
                ))
            elif category in ("ssrf",):
                self.add_edge(GraphEdge(
                    source=vuln_node.id, target=data_access.id,
                    edge_type=EdgeType.ESCALATES_TO,
                    label="SSRF → internal service access",
                    weight=0.6,
                ))

        # Cross-capability chains
        self.add_edge(GraphEdge(
            source=session_hijack.id, target=admin_access.id,
            edge_type=EdgeType.CHAINS_TO,
            label="Hijacked admin session → admin access",
            weight=0.5,
        ))
        self.add_edge(GraphEdge(
            source=admin_access.id, target=data_exfil.id,
            edge_type=EdgeType.CHAINS_TO,
            label="Admin access → export all data",
            weight=0.3,
        ))

        logger.info("Attack graph built: %d nodes, %d edges", self.node_count, self.edge_count)

    # ── Path finding ─────────────────────────────────────────

    def shortest_path(self, source_id: str, target_id: str) -> Optional[AttackPath]:
        """Find shortest (lowest weight) path between two nodes using Dijkstra."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        import heapq

        distances = {source_id: 0.0}
        previous: dict[str, tuple[str, GraphEdge]] = {}
        visited = set()
        queue = [(0.0, source_id)]

        while queue:
            dist, current = heapq.heappop(queue)
            if current in visited:
                continue
            visited.add(current)

            if current == target_id:
                break

            for edge in self._adjacency.get(current, []):
                if edge.target in visited:
                    continue
                new_dist = dist + edge.weight
                if new_dist < distances.get(edge.target, float('inf')):
                    distances[edge.target] = new_dist
                    previous[edge.target] = (current, edge)
                    heapq.heappush(queue, (new_dist, edge.target))

        if target_id not in previous and source_id != target_id:
            return None

        # Reconstruct path
        path_nodes = []
        path_edges = []
        current = target_id
        while current in previous:
            prev_id, edge = previous[current]
            path_nodes.append(self._nodes[current])
            path_edges.append(edge)
            current = prev_id
        path_nodes.append(self._nodes[source_id])

        path_nodes.reverse()
        path_edges.reverse()

        return AttackPath(
            nodes=path_nodes,
            edges=path_edges,
            total_weight=distances.get(target_id, 0.0),
        )

    def all_paths(self, source_id: str, target_id: str, max_depth: int = 10) -> list[AttackPath]:
        """Find all paths between two nodes (BFS, depth-limited)."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return []

        paths = []
        queue = deque([(source_id, [source_id], [], 0.0)])

        while queue:
            current, node_path, edge_path, weight = queue.popleft()
            if len(node_path) > max_depth:
                continue

            if current == target_id and len(node_path) > 1:
                paths.append(AttackPath(
                    nodes=[self._nodes[n] for n in node_path],
                    edges=list(edge_path),
                    total_weight=weight,
                ))
                continue

            for edge in self._adjacency.get(current, []):
                if edge.target not in node_path:  # Avoid cycles
                    queue.append((
                        edge.target,
                        node_path + [edge.target],
                        edge_path + [edge],
                        weight + edge.weight,
                    ))

        return sorted(paths, key=lambda p: p.total_weight)

    def critical_nodes(self) -> list[tuple[GraphNode, float]]:
        """Find nodes with highest betweenness centrality (best pivot points)."""
        centrality: dict[str, float] = defaultdict(float)

        node_ids = list(self._nodes.keys())
        for source in node_ids:
            # BFS from each node
            distances: dict[str, int] = {source: 0}
            paths: dict[str, int] = {source: 1}
            queue = deque([source])
            order = []

            while queue:
                current = queue.popleft()
                order.append(current)
                for edge in self._adjacency.get(current, []):
                    if edge.target not in distances:
                        distances[edge.target] = distances[current] + 1
                        paths[edge.target] = 0
                        queue.append(edge.target)
                    if distances[edge.target] == distances[current] + 1:
                        paths[edge.target] += paths[current]

            delta: dict[str, float] = defaultdict(float)
            while order:
                w = order.pop()
                for edge in self._adjacency.get(w, []):
                    if distances.get(edge.target, 0) == distances.get(w, 0) + 1:
                        c = (paths[w] / max(paths.get(edge.target, 1), 1)) * (1 + delta[edge.target])
                        delta[w] += c
                if w != source:
                    centrality[w] += delta[w]

        results = [(self._nodes[nid], score) for nid, score in centrality.items() if nid in self._nodes]
        return sorted(results, key=lambda x: x[1], reverse=True)

    # ── Analysis queries ─────────────────────────────────────

    def find_paths_to_capability(self, capability_label: str) -> list[AttackPath]:
        """Find all paths from Anonymous to a specific capability."""
        anon = None
        target = None
        for node in self._nodes.values():
            if node.label == "Anonymous Attacker":
                anon = node
            if node.label == capability_label:
                target = node
        if not anon or not target:
            return []
        return self.all_paths(anon.id, target.id)

    def get_attack_summary(self) -> dict:
        """Summarize the attack graph."""
        capabilities = ["Database Access", "Admin Access", "Remote Code Execution",
                        "Data Exfiltration", "Session Hijacking"]
        summary = {
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
            "reachable_capabilities": [],
            "shortest_attack_paths": {},
            "critical_pivot_points": [],
        }

        for cap in capabilities:
            paths = self.find_paths_to_capability(cap)
            if paths:
                summary["reachable_capabilities"].append(cap)
                summary["shortest_attack_paths"][cap] = {
                    "path_count": len(paths),
                    "shortest_steps": paths[0].length if paths else 0,
                    "description": paths[0].description if paths else "",
                }

        critical = self.critical_nodes()[:5]
        summary["critical_pivot_points"] = [
            {"node": node.label, "type": node.node_type, "centrality": round(score, 3)}
            for node, score in critical
        ]

        return summary

    def to_dot(self) -> str:
        """Export to Graphviz DOT format."""
        lines = ["digraph AttackGraph {", "  rankdir=LR;", '  node [shape=box];']

        type_colors = {
            NodeType.ENDPOINT: "lightblue",
            NodeType.VULNERABILITY: "red",
            NodeType.CAPABILITY: "gold",
            NodeType.USER_ROLE: "lightgreen",
            NodeType.DATA_STORE: "orange",
        }

        for node in self._nodes.values():
            color = type_colors.get(node.node_type, "white")
            label = node.label.replace('"', '\\"')[:50]
            lines.append(f'  "{node.id}" [label="{label}" style=filled fillcolor={color}];')

        for edge in self._edges:
            label = edge.label.replace('"', '\\"')[:30]
            lines.append(f'  "{edge.source}" -> "{edge.target}" [label="{label}"];')

        lines.append("}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export to JSON-serializable dict (for D3.js visualization)."""
        return {
            "nodes": [{"id": n.id, "label": n.label, "type": n.node_type}
                      for n in self._nodes.values()],
            "edges": [{"source": e.source, "target": e.target, "label": e.label,
                       "type": e.edge_type, "weight": e.weight}
                      for e in self._edges],
        }

    @staticmethod
    def _severity_weight(severity: str) -> float:
        s = str(severity).upper()
        if "CRITICAL" in s:
            return 0.1
        if "HIGH" in s:
            return 0.3
        if "MEDIUM" in s:
            return 0.5
        if "LOW" in s:
            return 0.8
        return 1.0
