import pytest
from secprobe.analysis.attack_graph import (
    AttackGraph, GraphNode, GraphEdge, NodeType, EdgeType, AttackPath
)


class FakeFinding:
    def __init__(self, title, category, severity="HIGH", url=""):
        self.title = title
        self.category = category
        self.severity = severity
        self.url = url


class TestAttackGraph:
    def test_add_nodes_and_edges(self):
        g = AttackGraph()
        n1 = g.add_node(GraphNode.make(NodeType.ENDPOINT, "/api/users"))
        n2 = g.add_node(GraphNode.make(NodeType.VULNERABILITY, "SQLi"))
        g.add_edge(GraphEdge(source=n1.id, target=n2.id, edge_type=EdgeType.EXPLOITS, label="test"))
        assert g.node_count == 2
        assert g.edge_count == 1

    def test_shortest_path(self):
        g = AttackGraph()
        a = g.add_node(GraphNode.make(NodeType.USER_ROLE, "A"))
        b = g.add_node(GraphNode.make(NodeType.ENDPOINT, "B"))
        c = g.add_node(GraphNode.make(NodeType.CAPABILITY, "C"))
        g.add_edge(GraphEdge(source=a.id, target=b.id, edge_type=EdgeType.DATA_FLOW, weight=1.0))
        g.add_edge(GraphEdge(source=b.id, target=c.id, edge_type=EdgeType.EXPLOITS, weight=1.0))

        path = g.shortest_path(a.id, c.id)
        assert path is not None
        assert path.length == 2

    def test_no_path(self):
        g = AttackGraph()
        a = g.add_node(GraphNode.make(NodeType.USER_ROLE, "A"))
        b = g.add_node(GraphNode.make(NodeType.ENDPOINT, "B"))
        # No edge between them
        path = g.shortest_path(a.id, b.id)
        assert path is None

    def test_build_from_findings(self):
        g = AttackGraph()
        findings = [
            FakeFinding("SQL Injection", "sqli", "CRITICAL", "/api/search"),
            FakeFinding("XSS", "xss", "HIGH", "/search"),
            FakeFinding("SSRF", "ssrf", "HIGH", "/proxy"),
        ]
        g.build_from_findings(findings)
        assert g.node_count >= 5  # Anon + 3 vulns + capabilities
        assert g.edge_count >= 5

    def test_find_paths_to_capability(self):
        g = AttackGraph()
        findings = [FakeFinding("SQL Injection", "sqli", "CRITICAL", "/api/search")]
        g.build_from_findings(findings)

        paths = g.find_paths_to_capability("Database Access")
        assert len(paths) >= 1

    def test_attack_summary(self):
        g = AttackGraph()
        findings = [
            FakeFinding("SQLi", "sqli", "CRITICAL", "/search"),
            FakeFinding("CMDi", "cmdi", "CRITICAL", "/exec"),
        ]
        g.build_from_findings(findings)
        summary = g.get_attack_summary()
        assert summary["total_nodes"] > 0
        assert len(summary["reachable_capabilities"]) >= 1

    def test_to_dot(self):
        g = AttackGraph()
        g.add_node(GraphNode.make(NodeType.ENDPOINT, "/test"))
        dot = g.to_dot()
        assert "digraph" in dot
        assert "/test" in dot

    def test_to_dict(self):
        g = AttackGraph()
        n = g.add_node(GraphNode.make(NodeType.ENDPOINT, "/test"))
        d = g.to_dict()
        assert len(d["nodes"]) == 1
        assert d["nodes"][0]["label"] == "/test"

    def test_critical_nodes(self):
        g = AttackGraph()
        findings = [
            FakeFinding("SQLi", "sqli", "CRITICAL", "/api"),
            FakeFinding("XSS", "xss", "HIGH", "/web"),
        ]
        g.build_from_findings(findings)
        critical = g.critical_nodes()
        assert len(critical) >= 1  # At least one pivot point

    def test_all_paths(self):
        g = AttackGraph()
        a = g.add_node(GraphNode.make(NodeType.USER_ROLE, "Start"))
        b = g.add_node(GraphNode.make(NodeType.ENDPOINT, "Mid"))
        c = g.add_node(GraphNode.make(NodeType.CAPABILITY, "End"))
        g.add_edge(GraphEdge(source=a.id, target=b.id, edge_type=EdgeType.DATA_FLOW, weight=1.0))
        g.add_edge(GraphEdge(source=b.id, target=c.id, edge_type=EdgeType.EXPLOITS, weight=1.0))
        g.add_edge(GraphEdge(source=a.id, target=c.id, edge_type=EdgeType.DATA_FLOW, weight=5.0))  # Direct but expensive

        paths = g.all_paths(a.id, c.id)
        assert len(paths) == 2  # Via B and direct
        assert paths[0].total_weight < paths[1].total_weight  # Sorted by weight
