"""
Neural Memory System — Multi-layer cognitive memory for agents.

This gives agents REAL memory that works like a human pentester's brain:

  Layer 1: Episodic Memory (WHAT happened)
    - Raw observations with temporal ordering
    - Associative recall: "I saw something like this before"
    - Automatic decay: old observations fade unless reinforced

  Layer 2: Semantic Memory (WHAT things MEAN)
    - Generalized knowledge: "PHP apps often have LFI"
    - Concept clustering: "these 5 observations all mean WAF block"
    - Cross-target patterns: "Apache+PHP+MySQL = try SQLi first"

  Layer 3: Procedural Memory (HOW to do things)
    - Action sequences that worked before
    - Payload mutation strategies per WAF type
    - Optimal scan orderings per tech stack

  Layer 4: Working Memory (current focus)
    - Active hypotheses (limited capacity, like human 7±2)
    - Current goal stack
    - Recent context window

What makes this world-class:
  - Vector similarity for fuzzy recall (not just exact match)
  - Automatic consolidation: episodic → semantic over time
  - Importance-weighted decay: high-value memories persist
  - Cross-agent memory sharing via knowledge graph
  - Experience replay: agents re-learn from past successes
"""

from __future__ import annotations

import hashlib
import math
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from secprobe.agents.base import (
    Action, ActionResult, ActionType, Hypothesis, Observation,
)


# ═══════════════════════════════════════════════════════════════════
# VECTOR EMBEDDING (lightweight, no external dependencies)
# ═══════════════════════════════════════════════════════════════════

class FeatureExtractor:
    """
    Lightweight feature extraction for observations.

    Maps observations to fixed-length numeric vectors for
    similarity computation. No ML library needed — this uses
    domain-specific feature engineering tailored to security testing.

    Feature vector (64 dimensions):
      [0:16]  — URL path tokens (hashed)
      [16:24] — Parameter name features
      [24:32] — Response characteristics
      [32:40] — Observation type encoding
      [40:48] — Payload characteristics
      [48:56] — Timing features
      [56:64] — Context indicators
    """

    VECTOR_DIM = 64

    # Known observation types → numeric encoding
    OBS_TYPE_MAP = {
        "reflection": 0, "error": 1, "sql_error": 2, "timing_anomaly": 3,
        "block": 4, "waf_block": 5, "rate_limit": 6, "redirect": 7,
        "file_content": 8, "template_eval": 9, "command_output": 10,
        "stack_trace": 11, "header_injection": 12, "xml_parse": 13,
        "canary_sqli": 14, "canary_xss": 15, "canary_ssti": 16,
        "canary_cmdi": 17, "canary_lfi": 18, "canary_nosql": 19,
        "external_finding": 20, "external_intel": 21,
        "chainable_finding": 22, "high_block_rate": 23,
        "evasion_applied": 24, "tech_detected": 25,
        "interesting_param": 26, "agent_error": 27,
        "payload_evolution": 28, "database_error": 29,
    }

    # Parameter name patterns → category
    PARAM_PATTERNS = {
        "id": 0, "user": 1, "name": 2, "pass": 3, "email": 4,
        "file": 5, "path": 6, "url": 7, "query": 8, "search": 9,
        "page": 10, "template": 11, "cmd": 12, "exec": 13,
        "host": 14, "redirect": 15,
    }

    def extract(self, obs: Observation) -> list[float]:
        """Extract feature vector from an observation."""
        vec = [0.0] * self.VECTOR_DIM

        # [0:16] URL path tokens
        if obs.url:
            parts = obs.url.split("/")
            for i, part in enumerate(parts[:16]):
                h = int(hashlib.md5(part.encode()).hexdigest()[:4], 16)
                vec[i] = (h % 1000) / 1000.0

        # [16:24] Parameter features
        if obs.parameter:
            param_lower = obs.parameter.lower()
            for pattern, idx in self.PARAM_PATTERNS.items():
                if pattern in param_lower and idx < 8:
                    vec[16 + idx] = 1.0

        # [24:32] Response characteristics
        vec[24] = min(1.0, obs.raw_response_code / 600.0) if obs.raw_response_code else 0.0
        vec[25] = min(1.0, obs.raw_response_length / 100000.0) if obs.raw_response_length else 0.0
        vec[26] = min(1.0, obs.response_time / 10.0) if obs.response_time else 0.0
        vec[27] = obs.confidence

        # [32:40] Observation type encoding (one-hot-ish)
        obs_idx = self.OBS_TYPE_MAP.get(obs.observation_type, -1)
        if 0 <= obs_idx < 8:
            vec[32 + obs_idx] = 1.0

        # [40:48] Payload characteristics from detail/metadata
        detail_lower = obs.detail.lower() if obs.detail else ""
        vuln_signals = ["sql", "xss", "script", "file", "template",
                        "command", "xml", "redirect"]
        for i, signal in enumerate(vuln_signals):
            if signal in detail_lower:
                vec[40 + i] = 1.0

        # [48:56] Timing features
        if obs.response_time:
            vec[48] = 1.0 if obs.response_time > 5.0 else 0.0  # slow
            vec[49] = 1.0 if obs.response_time > 2.0 else 0.0  # moderate
            vec[50] = 1.0 if obs.response_time < 0.1 else 0.0  # very fast
        # Timestamp normalization (time of day as feature)
        hour_frac = (obs.timestamp % 86400) / 86400.0
        vec[51] = hour_frac

        # [56:64] Context indicators
        meta = obs.metadata or {}
        vec[56] = 1.0 if meta.get("vuln_type") else 0.0
        vec[57] = 1.0 if meta.get("waf_detected") else 0.0
        vec[58] = 1.0 if meta.get("evasion_level", 0) > 0 else 0.0
        vec[59] = float(meta.get("evasion_level", 0)) / 3.0
        vec[60] = 1.0 if meta.get("confirmed") else 0.0
        vec[61] = 1.0 if meta.get("chain_potential") else 0.0
        vec[62] = float(meta.get("tests_performed", 0)) / 20.0
        vec[63] = float(meta.get("impact_score", 0))

        return vec

    def extract_action(self, action: Action) -> list[float]:
        """Extract feature vector from an action."""
        vec = [0.0] * self.VECTOR_DIM

        # Action type encoding
        action_types = list(ActionType)
        for i, at in enumerate(action_types[:16]):
            vec[i] = 1.0 if action.action_type == at else 0.0

        # Target URL features
        if action.target_url:
            parts = action.target_url.split("/")
            for i, part in enumerate(parts[:8]):
                h = int(hashlib.md5(part.encode()).hexdigest()[:4], 16)
                vec[16 + i] = (h % 1000) / 1000.0

        # Parameter features
        if action.target_param:
            param_lower = action.target_param.lower()
            for pattern, idx in self.PARAM_PATTERNS.items():
                if pattern in param_lower and idx < 8:
                    vec[24 + idx] = 1.0

        # Payload features
        if action.payload:
            payload_lower = action.payload.lower()
            vuln_signals = ["'", "select", "<script>", "../",
                            "{{", ";", "$(", "<!entity"]
            for i, sig in enumerate(vuln_signals[:8]):
                if sig in payload_lower:
                    vec[32 + i] = 1.0

        # Priority
        vec[40] = action.priority

        # Metadata
        meta = action.metadata or {}
        vec[41] = 1.0 if meta.get("vuln_type") else 0.0
        vec[42] = float(meta.get("evasion_level", 0)) / 3.0

        return vec

    @staticmethod
    def cosine_similarity(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot_product = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a)) or 1e-10
        norm_b = math.sqrt(sum(x * x for x in b)) or 1e-10
        return dot_product / (norm_a * norm_b)

    @staticmethod
    def euclidean_distance(a: list[float], b: list[float]) -> float:
        """Compute Euclidean distance between two vectors."""
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


# ═══════════════════════════════════════════════════════════════════
# MEMORY ENTRY
# ═══════════════════════════════════════════════════════════════════

@dataclass
class MemoryEntry:
    """A single memory with metadata for retrieval and decay."""
    id: str = ""
    content: Any = None              # The actual observation/action/finding
    vector: list[float] = field(default_factory=list)  # Feature embedding
    memory_type: str = "episodic"    # episodic, semantic, procedural
    category: str = ""               # vuln_type, tech, defense, etc.
    importance: float = 0.5          # 0.0-1.0 how important this memory is
    access_count: int = 0            # How many times recalled
    creation_time: float = field(default_factory=time.time)
    last_access_time: float = field(default_factory=time.time)
    decay_rate: float = 0.01         # How fast this memory fades
    associations: list[str] = field(default_factory=list)  # IDs of related memories
    tags: set[str] = field(default_factory=set)
    source_agent: str = ""
    reinforcement_count: int = 0     # How many times reinforced

    @property
    def strength(self) -> float:
        """
        Current memory strength (decays over time, reinforced by access).

        Uses Ebbinghaus forgetting curve: S = importance × e^(-decay × t)
        Modified with access bonus: +0.1 per access
        """
        age = time.time() - self.creation_time
        base_strength = self.importance * math.exp(-self.decay_rate * age / 3600)
        access_bonus = min(0.5, self.access_count * 0.05)
        reinforcement_bonus = min(0.3, self.reinforcement_count * 0.1)
        return min(1.0, base_strength + access_bonus + reinforcement_bonus)

    @property
    def is_alive(self) -> bool:
        """Memory is still strong enough to be useful."""
        return self.strength > 0.05

    def access(self):
        """Record an access (recall) of this memory."""
        self.access_count += 1
        self.last_access_time = time.time()

    def reinforce(self, strength: float = 0.1):
        """Strengthen this memory (positive outcome confirmed)."""
        self.reinforcement_count += 1
        self.importance = min(1.0, self.importance + strength)
        self.decay_rate = max(0.001, self.decay_rate * 0.8)  # Slower decay


# ═══════════════════════════════════════════════════════════════════
# EPISODIC MEMORY
# ═══════════════════════════════════════════════════════════════════

class EpisodicMemory:
    """
    What happened — time-ordered sequence of experiences.

    Like a pentester's mental log:
      "First I probed /login with a single quote, got MySQL error,
       then tested UNION SELECT, got WAF block, switched to
       time-based blind, confirmed SQLi..."

    Supports:
    - Temporal ordering with efficient lookup
    - Similarity-based recall ("find observations like X")
    - Episode segmentation (group related observations)
    - Importance-weighted decay
    """

    def __init__(self, capacity: int = 5000):
        self.entries: deque[MemoryEntry] = deque(maxlen=capacity)
        self.extractor = FeatureExtractor()
        self._index: dict[str, MemoryEntry] = {}  # id → entry
        self._category_index: dict[str, list[str]] = defaultdict(list)
        self._episodes: list[list[str]] = []  # Groups of related memory IDs
        self._current_episode: list[str] = []

    def store(self, observation: Observation, importance: float = 0.5,
              category: str = "", agent: str = "") -> str:
        """Store an observation as an episodic memory."""
        entry_id = f"ep_{observation.fingerprint}_{len(self.entries)}"
        vector = self.extractor.extract(observation)

        entry = MemoryEntry(
            id=entry_id,
            content=observation,
            vector=vector,
            memory_type="episodic",
            category=category or observation.observation_type,
            importance=importance,
            source_agent=agent,
            tags={observation.observation_type, observation.parameter or "no_param"},
        )

        self.entries.append(entry)
        self._index[entry_id] = entry
        self._category_index[entry.category].append(entry_id)
        self._current_episode.append(entry_id)

        return entry_id

    def recall_similar(self, query: Observation, top_k: int = 5,
                       min_similarity: float = 0.3) -> list[MemoryEntry]:
        """
        Find memories similar to a query observation.

        Uses cosine similarity on feature vectors — this is the
        "I've seen something like this before" ability.
        """
        query_vec = self.extractor.extract(query)
        scored = []

        for entry in self.entries:
            if not entry.is_alive:
                continue
            sim = FeatureExtractor.cosine_similarity(query_vec, entry.vector)
            if sim >= min_similarity:
                # Boost by memory strength
                effective_score = sim * entry.strength
                scored.append((effective_score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = [entry for _, entry in scored[:top_k]]

        # Record access
        for entry in results:
            entry.access()

        return results

    def recall_by_category(self, category: str,
                           limit: int = 20) -> list[MemoryEntry]:
        """Recall all memories of a specific category."""
        ids = self._category_index.get(category, [])
        results = []
        for mid in ids[-limit:]:
            entry = self._index.get(mid)
            if entry and entry.is_alive:
                entry.access()
                results.append(entry)
        return results

    def recall_recent(self, n: int = 10) -> list[MemoryEntry]:
        """Recall the N most recent memories."""
        results = []
        for entry in reversed(self.entries):
            if entry.is_alive:
                entry.access()
                results.append(entry)
            if len(results) >= n:
                break
        return results

    def end_episode(self):
        """End current episode and start a new one."""
        if self._current_episode:
            self._episodes.append(self._current_episode.copy())
            self._current_episode.clear()

    def get_episode(self, index: int = -1) -> list[MemoryEntry]:
        """Get all memories from a specific episode."""
        if not self._episodes:
            return []
        idx = index if index >= 0 else len(self._episodes) + index
        if 0 <= idx < len(self._episodes):
            return [self._index[mid] for mid in self._episodes[idx]
                    if mid in self._index]
        return []

    def reinforce(self, entry_id: str, strength: float = 0.1):
        """Reinforce a memory (it was useful)."""
        entry = self._index.get(entry_id)
        if entry:
            entry.reinforce(strength)

    def garbage_collect(self) -> int:
        """Remove dead memories."""
        dead = [eid for eid, e in self._index.items() if not e.is_alive]
        for eid in dead:
            del self._index[eid]
        return len(dead)

    @property
    def size(self) -> int:
        return len(self._index)

    @property
    def episode_count(self) -> int:
        return len(self._episodes)


# ═══════════════════════════════════════════════════════════════════
# SEMANTIC MEMORY
# ═══════════════════════════════════════════════════════════════════

class SemanticConcept:
    """A generalized concept learned from multiple observations."""

    def __init__(self, concept_id: str, name: str, category: str = ""):
        self.id = concept_id
        self.name = name
        self.category = category
        self.centroid: list[float] = [0.0] * FeatureExtractor.VECTOR_DIM
        self.member_count: int = 0
        self.confidence: float = 0.0
        self.examples: list[str] = []        # Memory IDs of supporting observations
        self.properties: dict[str, Any] = {}  # Learned properties
        self.creation_time: float = time.time()
        self.update_count: int = 0
        self.associations: dict[str, float] = {}  # concept_id → strength

    def add_member(self, vector: list[float], memory_id: str = ""):
        """Add a new observation to this concept (running average)."""
        self.member_count += 1
        self.update_count += 1
        # Running centroid: new_centroid = old + (new - old) / n
        for i in range(len(self.centroid)):
            if i < len(vector):
                self.centroid[i] += (vector[i] - self.centroid[i]) / self.member_count
        if memory_id:
            self.examples.append(memory_id)
            # Keep only last 50 examples
            if len(self.examples) > 50:
                self.examples = self.examples[-50:]
        self.confidence = min(1.0, self.member_count / 10.0)

    def similarity(self, vector: list[float]) -> float:
        """How similar a vector is to this concept's centroid."""
        return FeatureExtractor.cosine_similarity(self.centroid, vector)


class SemanticMemory:
    """
    What things MEAN — generalized knowledge from experience.

    Learns concepts like:
      - "WAF block" = {403 status, short body, specific patterns}
      - "SQL error" = {500 status, error text, database keywords}
      - "PHP app" = {.php URLs, X-Powered-By, PHPSESSID}

    Uses incremental clustering: observations that are similar enough
    get grouped into concepts. Concepts with enough members become
    "knowledge" that guides future decisions.
    """

    def __init__(self, similarity_threshold: float = 0.75,
                 min_members: int = 3):
        self.concepts: dict[str, SemanticConcept] = {}
        self.extractor = FeatureExtractor()
        self.similarity_threshold = similarity_threshold
        self.min_members = min_members
        self._concept_counter = 0

    def learn(self, observation: Observation, memory_id: str = "") -> str:
        """
        Learn from an observation — either add to existing concept
        or create a new one.

        Returns concept ID.
        """
        vector = self.extractor.extract(observation)

        # Find most similar existing concept
        best_concept = None
        best_sim = 0.0

        for concept in self.concepts.values():
            sim = concept.similarity(vector)
            if sim > best_sim:
                best_sim = sim
                best_concept = concept

        if best_concept and best_sim >= self.similarity_threshold:
            # Add to existing concept
            best_concept.add_member(vector, memory_id)
            return best_concept.id
        else:
            # Create new concept
            self._concept_counter += 1
            concept_id = f"concept_{self._concept_counter}"
            concept = SemanticConcept(
                concept_id=concept_id,
                name=f"{observation.observation_type}_{observation.parameter or 'general'}",
                category=observation.observation_type,
            )
            concept.add_member(vector, memory_id)
            self.concepts[concept_id] = concept
            return concept_id

    def classify(self, observation: Observation) -> list[tuple[str, float]]:
        """
        Classify an observation against known concepts.

        Returns list of (concept_id, similarity) sorted by similarity.
        """
        vector = self.extractor.extract(observation)
        results = []
        for concept in self.concepts.values():
            sim = concept.similarity(vector)
            if sim > 0.3 and concept.member_count >= self.min_members:
                results.append((concept.id, sim))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def get_strong_concepts(self, min_confidence: float = 0.5
                            ) -> list[SemanticConcept]:
        """Get well-established concepts."""
        return [c for c in self.concepts.values()
                if c.confidence >= min_confidence]

    def associate(self, concept_a: str, concept_b: str,
                  strength: float = 0.5):
        """Create/strengthen association between two concepts."""
        if concept_a in self.concepts and concept_b in self.concepts:
            ca = self.concepts[concept_a]
            cb = self.concepts[concept_b]
            ca.associations[concept_b] = min(
                1.0, ca.associations.get(concept_b, 0) + strength
            )
            cb.associations[concept_a] = min(
                1.0, cb.associations.get(concept_a, 0) + strength
            )

    def get_associations(self, concept_id: str,
                         min_strength: float = 0.3) -> list[tuple[str, float]]:
        """Get associated concepts above a strength threshold."""
        concept = self.concepts.get(concept_id)
        if not concept:
            return []
        return [(cid, strength) for cid, strength in concept.associations.items()
                if strength >= min_strength]

    @property
    def concept_count(self) -> int:
        return len(self.concepts)


# ═══════════════════════════════════════════════════════════════════
# PROCEDURAL MEMORY
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ActionSequence:
    """A remembered sequence of actions and their outcome."""
    id: str = ""
    actions: list[dict] = field(default_factory=list)  # Ordered action summaries
    outcome: str = ""             # "success", "failure", "partial", "blocked"
    vuln_type: str = ""
    target_tech: str = ""         # Technology context
    defense_context: str = ""     # WAF/defense context
    success_rate: float = 0.0     # Historical success rate
    times_used: int = 0
    times_succeeded: int = 0
    total_requests: int = 0
    avg_time: float = 0.0
    creation_time: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)

    def record_use(self, success: bool, requests: int = 0, time_taken: float = 0.0):
        """Record a use of this action sequence."""
        self.times_used += 1
        if success:
            self.times_succeeded += 1
        self.success_rate = self.times_succeeded / self.times_used
        self.total_requests += requests
        if time_taken > 0:
            self.avg_time = (self.avg_time * (self.times_used - 1) + time_taken) / self.times_used
        self.last_used = time.time()


class ProceduralMemory:
    """
    HOW to do things — learned action sequences.

    Like a pentester's muscle memory:
      "When I see PHP + MySQL, first try UNION-based SQLi,
       if WAF blocks that, try time-based blind with SLEEP encoding..."

    Stores:
    - Successful attack sequences (actions that found vulns)
    - Evasion sequences (bypass patterns that worked)
    - Scan orderings (which scanners to run in what order)
    """

    def __init__(self, max_sequences: int = 1000):
        self.sequences: dict[str, ActionSequence] = {}
        self._max = max_sequences
        self._by_vuln: dict[str, list[str]] = defaultdict(list)
        self._by_tech: dict[str, list[str]] = defaultdict(list)
        self._by_defense: dict[str, list[str]] = defaultdict(list)

    def store_sequence(self, actions: list[Action], outcome: str,
                       vuln_type: str = "", tech: str = "",
                       defense: str = "", requests: int = 0,
                       time_taken: float = 0.0) -> str:
        """Store a new action sequence."""
        seq_id = f"seq_{len(self.sequences)}_{hashlib.md5(str(actions).encode()).hexdigest()[:6]}"

        action_dicts = [{
            "type": a.action_type.name,
            "url": a.target_url,
            "param": a.target_param,
            "payload": a.payload[:100] if a.payload else "",
            "scanner": a.scanner_name,
        } for a in actions]

        seq = ActionSequence(
            id=seq_id,
            actions=action_dicts,
            outcome=outcome,
            vuln_type=vuln_type,
            target_tech=tech,
            defense_context=defense,
            success_rate=1.0 if outcome == "success" else 0.0,
            times_used=1,
            times_succeeded=1 if outcome == "success" else 0,
            total_requests=requests,
            avg_time=time_taken,
        )

        self.sequences[seq_id] = seq

        if vuln_type:
            self._by_vuln[vuln_type].append(seq_id)
        if tech:
            self._by_tech[tech].append(seq_id)
        if defense:
            self._by_defense[defense].append(seq_id)

        # Evict lowest-performing if over capacity
        if len(self.sequences) > self._max:
            self._evict()

        return seq_id

    def recall_for_context(self, vuln_type: str = "", tech: str = "",
                           defense: str = "",
                           min_success_rate: float = 0.3,
                           limit: int = 5) -> list[ActionSequence]:
        """
        Find best action sequences for a given context.

        Priority:
        1. Exact match (same vuln + tech + defense)
        2. Partial match (same vuln + tech)
        3. Vuln type match only
        """
        candidates = []

        # Collect candidates from indices
        candidate_ids = set()
        if vuln_type and vuln_type in self._by_vuln:
            candidate_ids.update(self._by_vuln[vuln_type])
        if tech and tech in self._by_tech:
            candidate_ids.update(self._by_tech[tech])
        if defense and defense in self._by_defense:
            candidate_ids.update(self._by_defense[defense])

        for sid in candidate_ids:
            seq = self.sequences.get(sid)
            if seq and seq.success_rate >= min_success_rate:
                # Score by context match
                score = seq.success_rate
                if seq.vuln_type == vuln_type:
                    score += 0.3
                if seq.target_tech == tech:
                    score += 0.2
                if seq.defense_context == defense:
                    score += 0.2
                candidates.append((score, seq))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [seq for _, seq in candidates[:limit]]

    def get_best_for_vuln(self, vuln_type: str,
                          limit: int = 3) -> list[ActionSequence]:
        """Get highest-success-rate sequences for a vuln type."""
        ids = self._by_vuln.get(vuln_type, [])
        seqs = [self.sequences[sid] for sid in ids if sid in self.sequences]
        seqs.sort(key=lambda s: s.success_rate, reverse=True)
        return seqs[:limit]

    def update_outcome(self, seq_id: str, success: bool,
                       requests: int = 0, time_taken: float = 0.0):
        """Update the outcome of a previously stored sequence."""
        seq = self.sequences.get(seq_id)
        if seq:
            seq.record_use(success, requests, time_taken)

    def _evict(self):
        """Remove lowest-performing sequences."""
        if len(self.sequences) <= self._max:
            return
        # Sort by composite score: success_rate * recency
        scored = []
        now = time.time()
        for sid, seq in self.sequences.items():
            recency = 1.0 / (1.0 + (now - seq.last_used) / 3600)
            score = seq.success_rate * 0.7 + recency * 0.3
            scored.append((score, sid))
        scored.sort(key=lambda x: x[0])

        # Remove bottom 10%
        remove_count = max(1, len(scored) // 10)
        for _, sid in scored[:remove_count]:
            del self.sequences[sid]

    @property
    def size(self) -> int:
        return len(self.sequences)

    def get_stats(self) -> dict:
        """Get procedural memory statistics."""
        if not self.sequences:
            return {"size": 0, "vuln_types": 0, "avg_success_rate": 0.0}
        return {
            "size": len(self.sequences),
            "vuln_types": len(self._by_vuln),
            "tech_contexts": len(self._by_tech),
            "defense_contexts": len(self._by_defense),
            "avg_success_rate": sum(
                s.success_rate for s in self.sequences.values()
            ) / len(self.sequences),
        }


# ═══════════════════════════════════════════════════════════════════
# WORKING MEMORY
# ═══════════════════════════════════════════════════════════════════

class WorkingMemory:
    """
    Current focus — limited capacity active processing.

    Like human working memory (7±2 items), this holds:
    - Active hypotheses being tested
    - Current goal stack
    - Recent context window (last N observations)
    - Attention focus (what to watch for)

    This prevents agents from getting overwhelmed by too many
    simultaneous threads.
    """

    DEFAULT_CAPACITY = 7  # Miller's Law: 7±2

    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        self.capacity = capacity
        self.slots: dict[str, Any] = {}        # Named slots for active items
        self.attention: list[str] = []          # What to watch for
        self.context_window: deque = deque(maxlen=20)  # Recent items
        self.goal_stack: list[dict] = []        # Current goals, LIFO
        self._priority_queue: list[tuple[float, str, Any]] = []  # (priority, key, item)

    def focus(self, key: str, item: Any, priority: float = 0.5) -> bool:
        """
        Add an item to working memory. Returns False if at capacity
        and item is lower priority than all current items.
        """
        if key in self.slots:
            # Update existing
            self.slots[key] = item
            return True

        if len(self.slots) < self.capacity:
            self.slots[key] = item
            self._priority_queue.append((priority, key, item))
            return True

        # At capacity — evict lowest priority if new item is higher
        self._priority_queue.sort(key=lambda x: x[0])
        if self._priority_queue and priority > self._priority_queue[0][0]:
            _, evict_key, _ = self._priority_queue.pop(0)
            del self.slots[evict_key]
            self.slots[key] = item
            self._priority_queue.append((priority, key, item))
            return True

        return False  # Can't fit — too many higher-priority items

    def unfocus(self, key: str):
        """Remove an item from working memory."""
        self.slots.pop(key, None)
        self._priority_queue = [
            (p, k, i) for p, k, i in self._priority_queue if k != key
        ]

    def get(self, key: str, default: Any = None) -> Any:
        """Get a working memory item."""
        return self.slots.get(key, default)

    def add_context(self, item: Any):
        """Add to the sliding context window."""
        self.context_window.append(item)

    def set_attention(self, watch_for: list[str]):
        """Set attention focus — what patterns to watch for."""
        self.attention = watch_for

    def push_goal(self, goal: dict):
        """Push a sub-goal onto the goal stack."""
        self.goal_stack.append(goal)

    def pop_goal(self) -> Optional[dict]:
        """Pop the top goal from the stack."""
        return self.goal_stack.pop() if self.goal_stack else None

    def peek_goal(self) -> Optional[dict]:
        """Peek at the top goal without removing it."""
        return self.goal_stack[-1] if self.goal_stack else None

    @property
    def utilization(self) -> float:
        """How full is working memory (0.0-1.0)."""
        return len(self.slots) / self.capacity

    @property
    def is_full(self) -> bool:
        return len(self.slots) >= self.capacity

    def clear(self):
        """Clear all working memory."""
        self.slots.clear()
        self._priority_queue.clear()
        self.context_window.clear()
        self.goal_stack.clear()
        self.attention.clear()

    def get_stats(self) -> dict:
        return {
            "slots_used": len(self.slots),
            "capacity": self.capacity,
            "utilization": self.utilization,
            "context_size": len(self.context_window),
            "goal_depth": len(self.goal_stack),
            "attention_items": len(self.attention),
        }


# ═══════════════════════════════════════════════════════════════════
# NEURAL MEMORY SYSTEM (combines all layers)
# ═══════════════════════════════════════════════════════════════════

class NeuralMemory:
    """
    Complete multi-layer cognitive memory system.

    Integrates:
    - Episodic: What happened (time-ordered experiences)
    - Semantic: What things mean (generalized concepts)
    - Procedural: How to do things (action sequences)
    - Working: Current focus (active processing)

    Automatic processes:
    - Consolidation: episodic → semantic (over time/repetition)
    - Decay: unused memories fade
    - Reinforcement: successful memories strengthen
    - Association: related memories link together
    """

    def __init__(self, config: dict = None):
        config = config or {}
        self.episodic = EpisodicMemory(
            capacity=config.get("episodic_capacity", 5000)
        )
        self.semantic = SemanticMemory(
            similarity_threshold=config.get("semantic_threshold", 0.75),
            min_members=config.get("semantic_min_members", 3),
        )
        self.procedural = ProceduralMemory(
            max_sequences=config.get("procedural_capacity", 1000)
        )
        self.working = WorkingMemory(
            capacity=config.get("working_capacity", 7)
        )
        self._consolidation_counter = 0
        self._consolidation_interval = config.get("consolidation_interval", 50)

    def observe(self, observation: Observation, importance: float = 0.5,
                agent: str = "") -> str:
        """
        Process a new observation through all memory layers.

        1. Store in episodic memory
        2. Add to working memory context
        3. Learn concept in semantic memory
        4. Check for consolidation trigger
        """
        # Episodic
        entry_id = self.episodic.store(observation, importance, agent=agent)

        # Working memory context
        self.working.add_context(observation)

        # Semantic learning
        self.semantic.learn(observation, entry_id)

        # Periodic consolidation
        self._consolidation_counter += 1
        if self._consolidation_counter >= self._consolidation_interval:
            self.consolidate()
            self._consolidation_counter = 0

        return entry_id

    def recall(self, query: Observation, top_k: int = 5) -> dict:
        """
        Multi-layer recall — find relevant memories across all layers.

        Returns:
        {
            "episodic": [similar past experiences],
            "semantic": [matching concepts],
            "procedural": [relevant action sequences],
            "working": [current context items],
        }
        """
        result = {
            "episodic": self.episodic.recall_similar(query, top_k),
            "semantic": self.semantic.classify(query),
            "procedural": [],
            "working": list(self.working.context_window)[-5:],
        }

        # Find relevant procedures based on observation type
        vuln_type = query.metadata.get("vuln_type", "")
        if vuln_type:
            result["procedural"] = self.procedural.recall_for_context(
                vuln_type=vuln_type
            )

        return result

    def learn_procedure(self, actions: list[Action], outcome: str,
                        vuln_type: str = "", tech: str = "",
                        defense: str = "") -> str:
        """Store a learned action sequence."""
        return self.procedural.store_sequence(
            actions, outcome, vuln_type, tech, defense
        )

    def reinforce(self, entry_id: str, strength: float = 0.1):
        """Reinforce a memory that proved useful."""
        self.episodic.reinforce(entry_id, strength)

    def consolidate(self):
        """
        Consolidation: episodic → semantic.

        Reviews recent episodic memories and strengthens semantic
        concepts that have enough supporting evidence.
        """
        recent = self.episodic.recall_recent(20)
        for entry in recent:
            if isinstance(entry.content, Observation):
                concept_id = self.semantic.learn(entry.content, entry.id)
                # Associate concepts that appear in the same episode
                for other in recent:
                    if other.id != entry.id and isinstance(other.content, Observation):
                        other_concepts = self.semantic.classify(other.content)
                        if other_concepts:
                            self.semantic.associate(
                                concept_id, other_concepts[0][0], 0.1
                            )

    def end_episode(self):
        """Mark the end of a testing episode."""
        self.episodic.end_episode()

    def get_stats(self) -> dict:
        """Get comprehensive memory statistics."""
        return {
            "episodic": {
                "size": self.episodic.size,
                "episodes": self.episodic.episode_count,
            },
            "semantic": {
                "concepts": self.semantic.concept_count,
                "strong_concepts": len(self.semantic.get_strong_concepts()),
            },
            "procedural": self.procedural.get_stats(),
            "working": self.working.get_stats(),
        }
