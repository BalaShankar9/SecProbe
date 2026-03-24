"""
Knowledge Graph — Shared intelligence between agents.

A graph-based knowledge store where all agents contribute and
query information about the target application. This is the
"shared brain" of the swarm.

Entities:
  - URLs (endpoints discovered)
  - Parameters (input points)
  - Technologies (detected tech stack)
  - Vulnerabilities (confirmed findings)
  - Credentials (extracted creds)
  - Defenses (WAF rules, filters)

Relationships:
  - URL → has_parameter → Parameter
  - URL → uses_technology → Technology
  - Parameter → vulnerable_to → Vulnerability
  - Vulnerability → chains_to → Vulnerability
  - Vulnerability → bypasses → Defense
  - Credential → authenticates → URL

What makes this special:
  1. Every agent reads AND writes to this graph
  2. Queries like "find all params where reflection was observed"
  3. Attack path discovery via graph traversal
  4. Duplicate work prevention (agent checks before testing)
  5. Cross-session persistence (can be serialized)
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

class EntityType(Enum):
    """Types of entities in the knowledge graph."""
    URL = auto()
    PARAMETER = auto()
    TECHNOLOGY = auto()
    VULNERABILITY = auto()
    CREDENTIAL = auto()
    DEFENSE = auto()
    SESSION = auto()
    RESPONSE_PATTERN = auto()
    ATTACK_CHAIN = auto()


class RelationType(Enum):
    """Types of relationships between entities."""
    HAS_PARAMETER = auto()
    USES_TECHNOLOGY = auto()
    VULNERABLE_TO = auto()
    CHAINS_TO = auto()
    BYPASSES = auto()
    AUTHENTICATES = auto()
    BLOCKS = auto()
    REFLECTS_INPUT = auto()
    TRIGGERS_ERROR = auto()
    REDIRECTS_TO = auto()
    INCLUDES_FILE = auto()
    EXECUTES_COMMAND = auto()
    PARENT_OF = auto()
    TESTED_BY = auto()
    DISCOVERED_BY = auto()


@dataclass
class KnowledgeEntity:
    """A node in the knowledge graph."""
    id: str
    entity_type: EntityType
    label: str
    properties: dict = field(default_factory=dict)
    confidence: float = 1.0
    source_agent: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    tags: set[str] = field(default_factory=set)

    def update(self, properties: dict = None, confidence: float = None):
        """Update entity properties."""
        if properties:
            self.properties.update(properties)
        if confidence is not None:
            self.confidence = confidence
        self.updated_at = time.time()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.entity_type.name,
            "label": self.label,
            "properties": self.properties,
            "confidence": self.confidence,
            "source_agent": self.source_agent,
            "tags": list(self.tags),
        }


@dataclass
class KnowledgeRelation:
    """An edge in the knowledge graph."""
    source_id: str
    target_id: str
    relation_type: RelationType
    properties: dict = field(default_factory=dict)
    confidence: float = 1.0
    source_agent: str = ""
    created_at: float = field(default_factory=time.time)

    @property
    def id(self) -> str:
        return f"{self.source_id}-[{self.relation_type.name}]->{self.target_id}"

    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.relation_type.name,
            "properties": self.properties,
            "confidence": self.confidence,
        }


# ═══════════════════════════════════════════════════════════════════
# KNOWLEDGE GRAPH
# ═══════════════════════════════════════════════════════════════════

class KnowledgeGraph:
    """
    Graph-based shared intelligence store for the agent swarm.

    Thread-safe for concurrent agent access.
    Supports complex queries for attack path discovery.
    Can be serialized for cross-session persistence.
    """

    def __init__(self):
        self._entities: dict[str, KnowledgeEntity] = {}
        self._relations: list[KnowledgeRelation] = []
        # Indices for fast lookup
        self._by_type: dict[EntityType, list[str]] = defaultdict(list)
        self._outgoing: dict[str, list[KnowledgeRelation]] = defaultdict(list)
        self._incoming: dict[str, list[KnowledgeRelation]] = defaultdict(list)
        self._by_tag: dict[str, set[str]] = defaultdict(set)

    # ── Entity Operations ────────────────────────────────────────

    def add_entity(
        self,
        entity_id: str,
        entity_type: EntityType,
        label: str,
        properties: dict = None,
        confidence: float = 1.0,
        source_agent: str = "",
        tags: set[str] = None,
    ) -> KnowledgeEntity:
        """Add or update an entity in the graph."""
        if entity_id in self._entities:
            entity = self._entities[entity_id]
            entity.update(properties or {}, confidence)
            if tags:
                entity.tags.update(tags)
            return entity

        entity = KnowledgeEntity(
            id=entity_id,
            entity_type=entity_type,
            label=label,
            properties=properties or {},
            confidence=confidence,
            source_agent=source_agent,
            tags=tags or set(),
        )
        self._entities[entity_id] = entity
        self._by_type[entity_type].append(entity_id)
        if tags:
            for tag in tags:
                self._by_tag[tag].add(entity_id)
        return entity

    def get_entity(self, entity_id: str) -> Optional[KnowledgeEntity]:
        """Get an entity by ID."""
        return self._entities.get(entity_id)

    def remove_entity(self, entity_id: str) -> bool:
        """Remove an entity and all its relations."""
        if entity_id not in self._entities:
            return False
        entity = self._entities.pop(entity_id)
        if entity_id in self._by_type.get(entity.entity_type, []):
            self._by_type[entity.entity_type].remove(entity_id)
        # Remove related edges
        self._relations = [
            r for r in self._relations
            if r.source_id != entity_id and r.target_id != entity_id
        ]
        self._outgoing.pop(entity_id, None)
        self._incoming.pop(entity_id, None)
        return True

    # ── Relation Operations ──────────────────────────────────────

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        properties: dict = None,
        confidence: float = 1.0,
        source_agent: str = "",
    ) -> Optional[KnowledgeRelation]:
        """Add a relationship between two entities."""
        if source_id not in self._entities or target_id not in self._entities:
            return None

        # Check for duplicate
        for existing in self._outgoing.get(source_id, []):
            if (existing.target_id == target_id and
                    existing.relation_type == relation_type):
                existing.properties.update(properties or {})
                existing.confidence = max(existing.confidence, confidence)
                return existing

        relation = KnowledgeRelation(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=properties or {},
            confidence=confidence,
            source_agent=source_agent,
        )
        self._relations.append(relation)
        self._outgoing[source_id].append(relation)
        self._incoming[target_id].append(relation)
        return relation

    def get_relations(
        self,
        source_id: str = "",
        target_id: str = "",
        relation_type: RelationType = None,
    ) -> list[KnowledgeRelation]:
        """Query relations with optional filters."""
        results = self._relations
        if source_id:
            results = [r for r in results if r.source_id == source_id]
        if target_id:
            results = [r for r in results if r.target_id == target_id]
        if relation_type:
            results = [r for r in results if r.relation_type == relation_type]
        return results

    # ── Query Operations ─────────────────────────────────────────

    def find_by_type(self, entity_type: EntityType) -> list[KnowledgeEntity]:
        """Get all entities of a specific type."""
        return [
            self._entities[eid]
            for eid in self._by_type.get(entity_type, [])
            if eid in self._entities
        ]

    def find_by_tag(self, tag: str) -> list[KnowledgeEntity]:
        """Get all entities with a specific tag."""
        return [
            self._entities[eid]
            for eid in self._by_tag.get(tag, set())
            if eid in self._entities
        ]

    def find_by_property(
        self,
        entity_type: EntityType = None,
        **properties,
    ) -> list[KnowledgeEntity]:
        """Find entities matching property criteria."""
        candidates = (
            self.find_by_type(entity_type) if entity_type
            else list(self._entities.values())
        )
        results = []
        for entity in candidates:
            match = all(
                entity.properties.get(k) == v
                for k, v in properties.items()
            )
            if match:
                results.append(entity)
        return results

    def get_neighbors(
        self,
        entity_id: str,
        relation_type: RelationType = None,
        direction: str = "outgoing",
    ) -> list[KnowledgeEntity]:
        """Get neighboring entities."""
        if direction in ("outgoing", "both"):
            relations = self._outgoing.get(entity_id, [])
            if relation_type:
                relations = [r for r in relations if r.relation_type == relation_type]
            neighbors = [
                self._entities[r.target_id]
                for r in relations
                if r.target_id in self._entities
            ]
        else:
            neighbors = []

        if direction in ("incoming", "both"):
            relations = self._incoming.get(entity_id, [])
            if relation_type:
                relations = [r for r in relations if r.relation_type == relation_type]
            neighbors.extend([
                self._entities[r.source_id]
                for r in relations
                if r.source_id in self._entities
            ])

        return neighbors

    # ── Attack Path Discovery ────────────────────────────────────

    def find_attack_paths(
        self,
        start_type: EntityType = EntityType.URL,
        goal_type: EntityType = EntityType.VULNERABILITY,
        max_depth: int = 5,
    ) -> list[list[KnowledgeEntity]]:
        """
        Find all paths from start entities to goal entities.

        This is the key intelligence: discover how vulnerabilities
        chain together to create attack paths.

        Example path:
          URL(/sqli) → PARAM(id) → VULN(sqli) → CHAIN → VULN(data_exfil)
        """
        start_entities = self.find_by_type(start_type)
        goal_ids = {e.id for e in self.find_by_type(goal_type)}
        paths = []

        for start in start_entities:
            self._dfs_paths(start.id, goal_ids, [], set(), paths, max_depth)

        # Sort by path length (shorter = more impactful)
        paths.sort(key=len)
        return paths

    def _dfs_paths(
        self,
        current: str,
        goals: set[str],
        path: list[KnowledgeEntity],
        visited: set[str],
        results: list[list[KnowledgeEntity]],
        max_depth: int,
    ):
        """DFS to find all paths to goal entities."""
        if current in visited or len(path) > max_depth:
            return
        if current not in self._entities:
            return

        entity = self._entities[current]
        path = path + [entity]
        visited = visited | {current}

        if current in goals and len(path) > 1:
            results.append(path)

        for relation in self._outgoing.get(current, []):
            self._dfs_paths(
                relation.target_id, goals, path, visited, results, max_depth
            )

    def find_vulnerable_params(self) -> list[dict]:
        """Find parameters that have been linked to vulnerabilities."""
        params = self.find_by_type(EntityType.PARAMETER)
        results = []
        for param in params:
            vulns = self.get_neighbors(
                param.id,
                relation_type=RelationType.VULNERABLE_TO,
                direction="outgoing",
            )
            if vulns:
                results.append({
                    "param": param,
                    "vulnerabilities": vulns,
                    "url": param.properties.get("url", ""),
                })
        return results

    def find_unchained_vulns(self) -> list[KnowledgeEntity]:
        """Find vulnerabilities that haven't been tested for chaining."""
        vulns = self.find_by_type(EntityType.VULNERABILITY)
        return [
            v for v in vulns
            if not self.get_neighbors(
                v.id, RelationType.CHAINS_TO, "outgoing"
            )
        ]

    def get_untested_params(self, scanner_type: str = "") -> list[KnowledgeEntity]:
        """Get parameters not yet tested by a specific scanner."""
        params = self.find_by_type(EntityType.PARAMETER)
        if not scanner_type:
            return [p for p in params if "untested" in p.tags]

        tested_ids = set()
        for rel in self.get_relations(relation_type=RelationType.TESTED_BY):
            if rel.properties.get("scanner") == scanner_type:
                tested_ids.add(rel.source_id)

        return [p for p in params if p.id not in tested_ids]

    # ── Convenience Adders ───────────────────────────────────────

    def add_url(self, url: str, method: str = "GET",
                properties: dict = None, agent: str = "") -> KnowledgeEntity:
        """Shortcut to add a URL entity."""
        eid = f"url:{method}:{url}"
        props = {"url": url, "method": method}
        if properties:
            props.update(properties)
        return self.add_entity(
            eid, EntityType.URL, url, props,
            source_agent=agent, tags={"url"},
        )

    def add_parameter(self, url: str, param_name: str, param_type: str = "query",
                      properties: dict = None, agent: str = "") -> KnowledgeEntity:
        """Shortcut to add a parameter and link to its URL."""
        url_entity = self.add_url(url, agent=agent)
        param_id = f"param:{url}:{param_name}"
        props = {"name": param_name, "type": param_type, "url": url}
        if properties:
            props.update(properties)
        param_entity = self.add_entity(
            param_id, EntityType.PARAMETER, f"{param_name}@{url}",
            props, source_agent=agent, tags={"parameter", "untested"},
        )
        self.add_relation(
            url_entity.id, param_entity.id,
            RelationType.HAS_PARAMETER, source_agent=agent,
        )
        return param_entity

    def add_vulnerability(
        self, vuln_type: str, url: str, param: str = "",
        severity: str = "MEDIUM", evidence: str = "",
        agent: str = "", confidence: float = 0.9,
    ) -> KnowledgeEntity:
        """Shortcut to add a vulnerability finding."""
        vuln_id = f"vuln:{vuln_type}:{url}:{param}"
        vuln = self.add_entity(
            vuln_id, EntityType.VULNERABILITY, f"{vuln_type}@{url}",
            {
                "vuln_type": vuln_type, "url": url, "parameter": param,
                "severity": severity, "evidence": evidence,
            },
            confidence=confidence, source_agent=agent,
            tags={"vulnerability", vuln_type, severity.lower()},
        )
        # Link to parameter if exists
        param_id = f"param:{url}:{param}"
        if param and param_id in self._entities:
            self.add_relation(
                param_id, vuln_id, RelationType.VULNERABLE_TO,
                source_agent=agent,
            )
        return vuln

    def add_technology(self, name: str, version: str = "",
                       category: str = "", agent: str = "",
                       confidence: float = 0.8) -> KnowledgeEntity:
        """Shortcut to add a detected technology."""
        tech_id = f"tech:{name}"
        return self.add_entity(
            tech_id, EntityType.TECHNOLOGY, name,
            {"name": name, "version": version, "category": category},
            confidence=confidence, source_agent=agent,
            tags={"technology", category.lower()} if category else {"technology"},
        )

    def add_defense(self, name: str, defense_type: str = "waf",
                    properties: dict = None, agent: str = "") -> KnowledgeEntity:
        """Shortcut to add a detected defense mechanism."""
        def_id = f"defense:{defense_type}:{name}"
        props = {"name": name, "defense_type": defense_type}
        if properties:
            props.update(properties)
        return self.add_entity(
            def_id, EntityType.DEFENSE, name, props,
            source_agent=agent, tags={"defense", defense_type},
        )

    # ── Statistics & Export ───────────────────────────────────────

    @property
    def entity_count(self) -> int:
        return len(self._entities)

    @property
    def relation_count(self) -> int:
        return len(self._relations)

    def get_stats(self) -> dict:
        """Get graph statistics."""
        type_counts = {}
        for etype in EntityType:
            count = len(self._by_type.get(etype, []))
            if count > 0:
                type_counts[etype.name] = count
        return {
            "total_entities": self.entity_count,
            "total_relations": self.relation_count,
            "entities_by_type": type_counts,
        }

    def to_dict(self) -> dict:
        """Serialize the graph for persistence."""
        return {
            "entities": [e.to_dict() for e in self._entities.values()],
            "relations": [r.to_dict() for r in self._relations],
        }

    def export_json(self) -> str:
        """Export graph as JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def clear(self):
        """Clear all data."""
        self._entities.clear()
        self._relations.clear()
        self._by_type.clear()
        self._outgoing.clear()
        self._incoming.clear()
        self._by_tag.clear()
