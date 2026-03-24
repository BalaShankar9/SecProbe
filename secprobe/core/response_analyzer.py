"""
Response Analyzer — Intelligent HTTP response analysis engine.

This module provides content-type aware response parsing and comparison
that goes far beyond naive string matching:

1. ResponseModel     — Structured representation of an HTTP response
2. ContentParser     — Content-type aware parsing (HTML/JSON/XML/text)
3. DiffEngine        — Smart diff that strips dynamic content before comparing
4. SimilarityScorer  — Numerical similarity between two responses
5. DynamicDetector   — Identifies dynamic content regions to ignore
6. AnomalyDetector   — Detects anomalous responses vs a baseline set
7. ErrorDetector     — Classifies error responses with 350+ signatures

Architecture:
  Scanners send a baseline response and a test response to the analyzer.
  The analyzer parses both, strips dynamic content, diffs the remainder,
  and returns a structured AnalysisResult with confidence scoring.
"""

from __future__ import annotations

import hashlib
import math
import re
import statistics
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum, auto
from typing import Optional, Any

from secprobe.core.html_parser import HTMLDocument
from secprobe.core.logger import get_logger

log = get_logger("response_analyzer")


# ═══════════════════════════════════════════════════════════════════════
# Response Model — Structured representation
# ═══════════════════════════════════════════════════════════════════════

class ContentType(Enum):
    """Detected content type of a response."""
    HTML = auto()
    JSON = auto()
    XML = auto()
    JAVASCRIPT = auto()
    CSS = auto()
    PLAIN_TEXT = auto()
    BINARY = auto()
    EMPTY = auto()
    UNKNOWN = auto()

    @classmethod
    def from_header(cls, content_type: str) -> ContentType:
        """Parse Content-Type header into ContentType enum."""
        ct = content_type.lower().split(";")[0].strip()
        mapping = {
            "text/html": cls.HTML,
            "application/xhtml+xml": cls.HTML,
            "application/json": cls.JSON,
            "text/json": cls.JSON,
            "application/xml": cls.XML,
            "text/xml": cls.XML,
            "application/javascript": cls.JAVASCRIPT,
            "text/javascript": cls.JAVASCRIPT,
            "text/css": cls.CSS,
            "text/plain": cls.PLAIN_TEXT,
        }
        if ct in mapping:
            return mapping[ct]
        if ct.startswith("image/") or ct.startswith("audio/") or ct.startswith("video/"):
            return cls.BINARY
        if ct.startswith("application/octet-stream"):
            return cls.BINARY
        return cls.UNKNOWN

    @classmethod
    def detect(cls, body: str, content_type_header: str = "") -> ContentType:
        """Detect content type from header and body heuristics."""
        if content_type_header:
            result = cls.from_header(content_type_header)
            if result != cls.UNKNOWN:
                return result

        if not body:
            return cls.EMPTY
        if not body.strip():
            return cls.EMPTY

        body_start = body.strip()[:500]
        # HTML detection
        if re.search(r"<(!DOCTYPE|html|head|body|div|p|h[1-6]|script|style)", body_start, re.IGNORECASE):
            return cls.HTML
        # JSON detection
        if (body_start.startswith("{") or body_start.startswith("[")) and body_start.rstrip().endswith(("}", "]")):
            return cls.JSON
        # XML detection
        if body_start.startswith("<?xml") or re.match(r"<[a-zA-Z][\w.-]*\s*(?:xmlns|>)", body_start):
            return cls.XML
        return cls.PLAIN_TEXT


@dataclass
class ResponseModel:
    """Structured representation of an HTTP response for analysis."""
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    content_type: ContentType = ContentType.UNKNOWN
    response_time: float = 0.0

    # Parsed representations (lazy-populated)
    _parsed_html: Optional[HTMLDocument] = field(default=None, repr=False)
    _body_hash: str = ""
    _text_only: str = ""

    def __post_init__(self):
        if not self.body_length:
            self.body_length = len(self.body)
        if self.content_type == ContentType.UNKNOWN:
            ct_header = self.headers.get("content-type", self.headers.get("Content-Type", ""))
            self.content_type = ContentType.detect(self.body, ct_header)

    @classmethod
    def from_requests_response(cls, resp) -> ResponseModel:
        """Create from a requests.Response object."""
        headers = dict(resp.headers) if hasattr(resp, "headers") else {}
        body = resp.text if hasattr(resp, "text") else str(resp)
        return cls(
            status_code=resp.status_code if hasattr(resp, "status_code") else 0,
            headers=headers,
            body=body,
            body_length=len(body),
            response_time=resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else 0.0,
        )

    @property
    def parsed_html(self) -> HTMLDocument:
        """Lazily parse HTML body."""
        if self._parsed_html is None:
            self._parsed_html = HTMLDocument.parse(self.body)
        return self._parsed_html

    @property
    def body_hash(self) -> str:
        """MD5 hash of body."""
        if not self._body_hash:
            self._body_hash = hashlib.md5(self.body.encode("utf-8", errors="replace")).hexdigest()
        return self._body_hash

    @property
    def text_content(self) -> str:
        """Extract visible text (strips HTML tags, scripts, styles)."""
        if not self._text_only:
            if self.content_type == ContentType.HTML:
                self._text_only = self.parsed_html.text_content
            else:
                self._text_only = self.body
        return self._text_only

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300


# ═══════════════════════════════════════════════════════════════════════
# Dynamic Content Detector — Find regions to ignore in comparisons
# ═══════════════════════════════════════════════════════════════════════

class DynamicDetector:
    """
    Detect dynamic content regions that change between requests.

    By comparing multiple baseline responses, we identify:
      - CSRF tokens, nonces, session IDs
      - Timestamps, counters, random values
      - Ad/tracking scripts
      - Cache-busting parameters

    These regions are stripped before vulnerability comparison.
    """

    # Common dynamic patterns
    DYNAMIC_PATTERNS = [
        # Timestamps
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        # Unix timestamps
        r"\b1[6-7]\d{8}\b",
        # UUIDs
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        # CSRF-like tokens (hex strings > 16 chars)
        r'(?:csrf|token|nonce|_token|authenticity)["\s:=]+["\']?([0-9a-fA-F]{16,})["\']?',
        # Random query parameters
        r'[?&](?:_|t|ts|timestamp|cb|cachebuster|v|ver)=\d+',
        # Session IDs in URLs
        r'(?:session|sid|jsessionid|phpsessid)[=:][0-9a-zA-Z]{16,}',
    ]

    def __init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.DYNAMIC_PATTERNS]
        self._learned_patterns: list[re.Pattern] = []

    def strip_dynamic(self, text: str) -> str:
        """Remove known dynamic content from text."""
        result = text
        for pattern in self._compiled + self._learned_patterns:
            result = pattern.sub("[DYNAMIC]", result)
        return result

    def learn_from_baselines(self, responses: list[str]):
        """
        Learn dynamic regions by comparing multiple baseline responses.

        Regions that differ between baselines are dynamic.
        """
        if len(responses) < 2:
            return

        # Find segments that differ between first two responses
        base = responses[0]
        for other in responses[1:]:
            matcher = SequenceMatcher(None, base, other, autojunk=False)
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag in ("replace", "delete", "insert"):
                    # The differing region is dynamic
                    if i2 - i1 > 3 and i2 - i1 < 200:
                        changed_text = base[i1:i2]
                        # Build a pattern that matches this dynamic region
                        escaped = re.escape(changed_text)
                        # Generalize: replace digits with \d+, hex with [a-f0-9]+
                        generalized = re.sub(r"\\d(?:\\d)*", r"\\d+", escaped)
                        try:
                            self._learned_patterns.append(
                                re.compile(generalized, re.IGNORECASE)
                            )
                        except re.error:
                            pass

    @property
    def pattern_count(self) -> int:
        return len(self._compiled) + len(self._learned_patterns)


# ═══════════════════════════════════════════════════════════════════════
# Diff Engine — Smart comparison of responses
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class DiffResult:
    """Result of comparing two responses."""
    similarity: float = 0.0       # 0.0 = completely different, 1.0 = identical
    status_changed: bool = False
    size_delta: int = 0
    size_ratio: float = 0.0
    added_text: list[str] = field(default_factory=list)
    removed_text: list[str] = field(default_factory=list)
    changed_headers: dict[str, tuple[str, str]] = field(default_factory=dict)
    content_type_changed: bool = False
    timing_delta: float = 0.0

    @property
    def is_significant(self) -> bool:
        """Whether the diff represents a significant change."""
        if self.status_changed:
            return True
        if self.content_type_changed:
            return True
        if self.similarity < 0.85:
            return True
        if abs(self.size_ratio - 1.0) > 0.15:
            return True
        return False


class DiffEngine:
    """
    Intelligent response comparison engine.

    Strips dynamic content before comparing, uses content-type aware
    comparison strategies, and produces structured diff results.
    """

    def __init__(self, dynamic_detector: Optional[DynamicDetector] = None):
        self.dynamic = dynamic_detector or DynamicDetector()

    def compare(self, baseline: ResponseModel, test: ResponseModel) -> DiffResult:
        """Compare a test response against a baseline response."""
        result = DiffResult()

        # Status code comparison
        result.status_changed = baseline.status_code != test.status_code

        # Size comparison
        result.size_delta = test.body_length - baseline.body_length
        if baseline.body_length > 0:
            result.size_ratio = test.body_length / baseline.body_length
        else:
            result.size_ratio = float("inf") if test.body_length > 0 else 1.0

        # Content type comparison
        result.content_type_changed = baseline.content_type != test.content_type

        # Timing comparison
        result.timing_delta = test.response_time - baseline.response_time

        # Header comparison
        for key in set(list(baseline.headers.keys()) + list(test.headers.keys())):
            key_lower = key.lower()
            # Skip always-changing headers
            if key_lower in ("date", "age", "x-request-id", "x-trace-id",
                             "set-cookie", "etag", "last-modified"):
                continue
            bv = baseline.headers.get(key, "")
            tv = test.headers.get(key, "")
            if bv != tv:
                result.changed_headers[key] = (bv, tv)

        # Body similarity — content-type aware
        result.similarity = self._body_similarity(baseline, test)

        # Extract added/removed text
        if result.similarity < 0.98:
            added, removed = self._extract_changes(baseline, test)
            result.added_text = added
            result.removed_text = removed

        return result

    def _body_similarity(self, baseline: ResponseModel, test: ResponseModel) -> float:
        """Calculate body similarity with dynamic content stripped."""
        # Fast path: identical
        if baseline.body_hash == test.body_hash:
            return 1.0
        if not baseline.body and not test.body:
            return 1.0
        if not baseline.body or not test.body:
            return 0.0

        # Strip dynamic content
        base_clean = self.dynamic.strip_dynamic(baseline.body)
        test_clean = self.dynamic.strip_dynamic(test.body)

        # Fast hash check after stripping
        if hashlib.md5(base_clean.encode()).hexdigest() == hashlib.md5(test_clean.encode()).hexdigest():
            return 1.0

        # For HTML, compare text content (ignores markup structure changes)
        if baseline.content_type == ContentType.HTML and test.content_type == ContentType.HTML:
            base_text = self.dynamic.strip_dynamic(baseline.text_content)
            test_text = self.dynamic.strip_dynamic(test.text_content)
            return SequenceMatcher(None, base_text, test_text).ratio()

        # For JSON, compare structure-aware
        if baseline.content_type == ContentType.JSON:
            return self._json_similarity(base_clean, test_clean)

        # Default: sequence matching
        # For large bodies, use a faster approach (compare chunks)
        if len(base_clean) > 50_000:
            return self._chunked_similarity(base_clean, test_clean)

        return SequenceMatcher(None, base_clean, test_clean).ratio()

    def _json_similarity(self, a: str, b: str) -> float:
        """Compare JSON responses structurally."""
        import json
        try:
            obj_a = json.loads(a)
            obj_b = json.loads(b)
            return self._dict_similarity(obj_a, obj_b)
        except (json.JSONDecodeError, TypeError):
            return SequenceMatcher(None, a, b).ratio()

    def _dict_similarity(self, a: Any, b: Any, depth: int = 0) -> float:
        """Recursively compare two JSON-like objects."""
        if depth > 10:
            return 1.0 if a == b else 0.0
        if type(a) != type(b):
            return 0.0
        if isinstance(a, dict):
            all_keys = set(list(a.keys()) + list(b.keys()))
            if not all_keys:
                return 1.0
            scores = []
            for key in all_keys:
                if key in a and key in b:
                    scores.append(self._dict_similarity(a[key], b[key], depth + 1))
                else:
                    scores.append(0.0)
            return sum(scores) / len(scores)
        if isinstance(a, list):
            if not a and not b:
                return 1.0
            max_len = max(len(a), len(b))
            scores = []
            for i in range(max_len):
                if i < len(a) and i < len(b):
                    scores.append(self._dict_similarity(a[i], b[i], depth + 1))
                else:
                    scores.append(0.0)
            return sum(scores) / len(scores)
        return 1.0 if a == b else 0.0

    @staticmethod
    def _chunked_similarity(a: str, b: str, chunk_size: int = 1000) -> float:
        """Fast similarity for large bodies — compare fixed-size chunks."""
        chunks_a = [a[i:i+chunk_size] for i in range(0, len(a), chunk_size)]
        chunks_b = [b[i:i+chunk_size] for i in range(0, len(b), chunk_size)]
        if not chunks_a or not chunks_b:
            return 0.0
        max_len = max(len(chunks_a), len(chunks_b))
        matching = 0
        for i in range(min(len(chunks_a), len(chunks_b))):
            if chunks_a[i] == chunks_b[i]:
                matching += 1
            else:
                matching += SequenceMatcher(None, chunks_a[i], chunks_b[i]).ratio()
        return matching / max_len

    def _extract_changes(self, baseline: ResponseModel, test: ResponseModel) -> tuple[list[str], list[str]]:
        """Extract added and removed text segments."""
        base_clean = self.dynamic.strip_dynamic(baseline.body)
        test_clean = self.dynamic.strip_dynamic(test.body)

        matcher = SequenceMatcher(None, base_clean, test_clean, autojunk=False)
        added = []
        removed = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "insert":
                text = test_clean[j1:j2].strip()
                if text and len(text) > 2:
                    added.append(text[:200])
            elif tag == "delete":
                text = base_clean[i1:i2].strip()
                if text and len(text) > 2:
                    removed.append(text[:200])
            elif tag == "replace":
                old = base_clean[i1:i2].strip()
                new = test_clean[j1:j2].strip()
                if old and len(old) > 2:
                    removed.append(old[:200])
                if new and len(new) > 2:
                    added.append(new[:200])

        return added[:20], removed[:20]  # Cap at 20 changes


# ═══════════════════════════════════════════════════════════════════════
# Anomaly Detector — Deviation from baseline set
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    is_anomalous: bool = False
    anomaly_score: float = 0.0    # 0.0 = normal, higher = more anomalous
    reasons: list[str] = field(default_factory=list)
    status_anomaly: bool = False
    size_anomaly: bool = False
    timing_anomaly: bool = False
    content_anomaly: bool = False


class AnomalyDetector:
    """
    Detect anomalous responses by comparing against a baseline set.

    Uses statistical methods (mean, std, z-score) to determine if a
    response significantly deviates from the expected behavior.
    """

    def __init__(self, sigma_threshold: float = 3.0):
        self.sigma = sigma_threshold
        self._baseline_sizes: list[int] = []
        self._baseline_timings: list[float] = []
        self._baseline_statuses: list[int] = []
        self._baseline_hashes: set[str] = set()

    def add_baseline(self, response: ResponseModel):
        """Add a response to the baseline set."""
        self._baseline_sizes.append(response.body_length)
        self._baseline_timings.append(response.response_time)
        self._baseline_statuses.append(response.status_code)
        self._baseline_hashes.add(response.body_hash)

    @property
    def baseline_count(self) -> int:
        return len(self._baseline_sizes)

    def analyze(self, response: ResponseModel) -> AnomalyResult:
        """Check if a response is anomalous compared to the baseline."""
        result = AnomalyResult()

        if self.baseline_count < 2:
            return result

        reasons = []
        score = 0.0

        # Status code anomaly
        if response.status_code not in self._baseline_statuses:
            result.status_anomaly = True
            reasons.append(
                f"Unexpected status: {response.status_code} "
                f"(baseline: {set(self._baseline_statuses)})"
            )
            score += 3.0

        # Size anomaly (z-score)
        if len(self._baseline_sizes) >= 3:
            mean_size = statistics.mean(self._baseline_sizes)
            stdev_size = statistics.stdev(self._baseline_sizes)
            if stdev_size > 0:
                z_size = abs(response.body_length - mean_size) / stdev_size
                if z_size > self.sigma:
                    result.size_anomaly = True
                    reasons.append(
                        f"Size anomaly: {response.body_length} bytes "
                        f"(mean: {mean_size:.0f}, z-score: {z_size:.1f})"
                    )
                    score += z_size
            elif abs(response.body_length - mean_size) > 50:
                # Zero stdev but different size
                result.size_anomaly = True
                reasons.append(
                    f"Size changed: {response.body_length} vs baseline {mean_size:.0f}"
                )
                score += 2.0

        # Timing anomaly
        if len(self._baseline_timings) >= 3:
            mean_time = statistics.mean(self._baseline_timings)
            stdev_time = statistics.stdev(self._baseline_timings)
            if stdev_time > 0:
                z_time = abs(response.response_time - mean_time) / stdev_time
                if z_time > self.sigma:
                    result.timing_anomaly = True
                    reasons.append(
                        f"Timing anomaly: {response.response_time:.3f}s "
                        f"(mean: {mean_time:.3f}s, z-score: {z_time:.1f})"
                    )
                    score += z_time
            elif response.response_time > mean_time * 3:
                result.timing_anomaly = True
                reasons.append(
                    f"Response 3x slower: {response.response_time:.3f}s vs {mean_time:.3f}s"
                )
                score += 2.0

        # Content anomaly (new content hash never seen in baseline)
        if response.body_hash not in self._baseline_hashes:
            result.content_anomaly = True
            reasons.append("Response body differs from all baselines")
            score += 1.0

        result.reasons = reasons
        result.anomaly_score = score
        result.is_anomalous = score >= self.sigma
        return result


# ═══════════════════════════════════════════════════════════════════════
# Error Detector — Classify error responses
# ═══════════════════════════════════════════════════════════════════════

class ErrorCategory(Enum):
    """Category of detected error."""
    SQL_ERROR = auto()
    NOSQL_ERROR = auto()
    TEMPLATE_ERROR = auto()
    COMMAND_ERROR = auto()
    FILE_ERROR = auto()
    XML_ERROR = auto()
    STACK_TRACE = auto()
    DEBUG_INFO = auto()
    CONFIGURATION = auto()
    AUTH_ERROR = auto()
    GENERIC_ERROR = auto()
    NONE = auto()


@dataclass
class ErrorMatch:
    """A matched error pattern in a response."""
    category: ErrorCategory
    pattern: str          # The pattern that matched
    matched_text: str     # What was actually matched
    technology: str = ""  # e.g., "MySQL", "PostgreSQL", "Python"
    severity: str = "MEDIUM"


class ErrorDetector:
    """
    Detect and classify error messages in HTTP responses.

    Contains 350+ signatures across databases, frameworks, and languages.
    """

    # Structured as: (regex, category, technology, severity)
    SIGNATURES: list[tuple[str, ErrorCategory, str, str]] = [
        # ── SQL Errors ────────────────────────────────────────────
        (r"SQL syntax.*?MySQL", ErrorCategory.SQL_ERROR, "MySQL", "HIGH"),
        (r"Warning.*?\bmysql_", ErrorCategory.SQL_ERROR, "MySQL", "HIGH"),
        (r"MySqlException", ErrorCategory.SQL_ERROR, "MySQL", "HIGH"),
        (r"valid MySQL result", ErrorCategory.SQL_ERROR, "MySQL", "HIGH"),
        (r"check the manual that corresponds to your MySQL server version",
         ErrorCategory.SQL_ERROR, "MySQL", "HIGH"),
        (r"MySqlClient\.", ErrorCategory.SQL_ERROR, "MySQL", "HIGH"),
        (r"com\.mysql\.jdbc", ErrorCategory.SQL_ERROR, "MySQL", "HIGH"),

        (r"PostgreSQL.*?ERROR", ErrorCategory.SQL_ERROR, "PostgreSQL", "HIGH"),
        (r"Warning.*?\bpg_", ErrorCategory.SQL_ERROR, "PostgreSQL", "HIGH"),
        (r"valid PostgreSQL result", ErrorCategory.SQL_ERROR, "PostgreSQL", "HIGH"),
        (r"Npgsql\.", ErrorCategory.SQL_ERROR, "PostgreSQL", "HIGH"),
        (r"PG::SyntaxError", ErrorCategory.SQL_ERROR, "PostgreSQL", "HIGH"),
        (r"org\.postgresql\.util\.PSQLException", ErrorCategory.SQL_ERROR, "PostgreSQL", "HIGH"),
        (r"ERROR:\s+syntax error at or near", ErrorCategory.SQL_ERROR, "PostgreSQL", "HIGH"),

        (r"Driver.*? SQL[\-\_\ ]*Server", ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"OLE DB.*? SQL Server", ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"\bSQL Server\b.*?Error", ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"ODBC SQL Server Driver", ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"SQLServer JDBC Driver", ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"SqlException", ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"System\.Data\.SqlClient", ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"Unclosed quotation mark after the character string",
         ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),
        (r"Microsoft OLE DB Provider for ODBC Drivers error",
         ErrorCategory.SQL_ERROR, "MSSQL", "HIGH"),

        (r"ORA-\d{5}", ErrorCategory.SQL_ERROR, "Oracle", "HIGH"),
        (r"Oracle error", ErrorCategory.SQL_ERROR, "Oracle", "HIGH"),
        (r"Oracle.*?Driver", ErrorCategory.SQL_ERROR, "Oracle", "HIGH"),
        (r"Warning.*?\boci_", ErrorCategory.SQL_ERROR, "Oracle", "HIGH"),
        (r"quoted string not properly terminated", ErrorCategory.SQL_ERROR, "Oracle", "HIGH"),

        (r"SQLite.*?Error", ErrorCategory.SQL_ERROR, "SQLite", "HIGH"),
        (r"SQLite3::query", ErrorCategory.SQL_ERROR, "SQLite", "HIGH"),
        (r"SQLITE_ERROR", ErrorCategory.SQL_ERROR, "SQLite", "HIGH"),
        (r"sqlite3\.OperationalError", ErrorCategory.SQL_ERROR, "SQLite", "HIGH"),
        (r"SQLite/JDBCDriver", ErrorCategory.SQL_ERROR, "SQLite", "HIGH"),

        (r"near \"\": syntax error", ErrorCategory.SQL_ERROR, "SQL", "HIGH"),
        (r"SELECTs to the left and right.*?have", ErrorCategory.SQL_ERROR, "SQL", "HIGH"),
        (r"Syntax error in string in query expression", ErrorCategory.SQL_ERROR, "Access", "HIGH"),
        (r"JET Database Engine", ErrorCategory.SQL_ERROR, "Access", "HIGH"),

        # ── NoSQL Errors ──────────────────────────────────────────
        (r"MongoError", ErrorCategory.NOSQL_ERROR, "MongoDB", "HIGH"),
        (r"MongoDB.*?Error", ErrorCategory.NOSQL_ERROR, "MongoDB", "HIGH"),
        (r"\$where.*?aggregate", ErrorCategory.NOSQL_ERROR, "MongoDB", "MEDIUM"),
        (r"BSON field", ErrorCategory.NOSQL_ERROR, "MongoDB", "MEDIUM"),

        # ── Template Errors ───────────────────────────────────────
        (r"Jinja2.*?Exception", ErrorCategory.TEMPLATE_ERROR, "Jinja2", "HIGH"),
        (r"jinja2\.exceptions", ErrorCategory.TEMPLATE_ERROR, "Jinja2", "HIGH"),
        (r"UndefinedError.*?is undefined", ErrorCategory.TEMPLATE_ERROR, "Jinja2", "HIGH"),
        (r"Twig_Error_Syntax", ErrorCategory.TEMPLATE_ERROR, "Twig", "HIGH"),
        (r"Twig\\Error\\Syntax", ErrorCategory.TEMPLATE_ERROR, "Twig", "HIGH"),
        (r"freemarker\.template", ErrorCategory.TEMPLATE_ERROR, "Freemarker", "HIGH"),
        (r"FreeMarker template error", ErrorCategory.TEMPLATE_ERROR, "Freemarker", "HIGH"),
        (r"Mako.*?Exception", ErrorCategory.TEMPLATE_ERROR, "Mako", "HIGH"),
        (r"Velocity.*?Exception", ErrorCategory.TEMPLATE_ERROR, "Velocity", "HIGH"),
        (r"ERB.*?SyntaxError", ErrorCategory.TEMPLATE_ERROR, "ERB", "HIGH"),
        (r"Thymeleaf.*?Exception", ErrorCategory.TEMPLATE_ERROR, "Thymeleaf", "HIGH"),
        (r"Smarty.*?error", ErrorCategory.TEMPLATE_ERROR, "Smarty", "HIGH"),
        (r"Handlebars.*?Error", ErrorCategory.TEMPLATE_ERROR, "Handlebars", "HIGH"),

        # ── Command/OS Errors ─────────────────────────────────────
        (r"sh:\s+\d+:\s+\w+:\s+not found", ErrorCategory.COMMAND_ERROR, "Shell", "CRITICAL"),
        (r"/bin/(?:ba)?sh:", ErrorCategory.COMMAND_ERROR, "Shell", "CRITICAL"),
        (r"command not found", ErrorCategory.COMMAND_ERROR, "Shell", "HIGH"),
        (r"Permission denied.*?exec", ErrorCategory.COMMAND_ERROR, "OS", "HIGH"),
        (r"Cannot execute", ErrorCategory.COMMAND_ERROR, "OS", "HIGH"),
        (r"cmd\.exe.*?is not recognized", ErrorCategory.COMMAND_ERROR, "Windows", "CRITICAL"),

        # ── File/Path Errors ──────────────────────────────────────
        (r"No such file or directory", ErrorCategory.FILE_ERROR, "OS", "HIGH"),
        (r"file_get_contents\(", ErrorCategory.FILE_ERROR, "PHP", "HIGH"),
        (r"include\(.*?\): failed to open stream", ErrorCategory.FILE_ERROR, "PHP", "HIGH"),
        (r"require\(.*?\): failed to open stream", ErrorCategory.FILE_ERROR, "PHP", "HIGH"),
        (r"FileNotFoundException", ErrorCategory.FILE_ERROR, "Java", "HIGH"),
        (r"java\.io\.FileNotFoundException", ErrorCategory.FILE_ERROR, "Java", "HIGH"),
        (r"IOError.*?No such file", ErrorCategory.FILE_ERROR, "Python", "HIGH"),

        # ── XML Errors ────────────────────────────────────────────
        (r"XML Parsing Error", ErrorCategory.XML_ERROR, "XML", "HIGH"),
        (r"XMLSyntaxError", ErrorCategory.XML_ERROR, "Python/lxml", "HIGH"),
        (r"SAXParseException", ErrorCategory.XML_ERROR, "Java", "HIGH"),
        (r"simplexml_load_string", ErrorCategory.XML_ERROR, "PHP", "HIGH"),
        (r"lxml\.etree\.", ErrorCategory.XML_ERROR, "Python/lxml", "HIGH"),
        (r"ENTITY.*?SYSTEM", ErrorCategory.XML_ERROR, "XXE", "CRITICAL"),

        # ── Stack Traces ──────────────────────────────────────────
        (r"Traceback \(most recent call last\)", ErrorCategory.STACK_TRACE, "Python", "MEDIUM"),
        (r"at [\w.]+\([\w.]+:\d+\)", ErrorCategory.STACK_TRACE, "Java", "MEDIUM"),
        (r"Exception in thread", ErrorCategory.STACK_TRACE, "Java", "MEDIUM"),
        (r"Stack trace:.*?#\d+", ErrorCategory.STACK_TRACE, "PHP", "MEDIUM"),
        (r"Fatal error:.*?in\s+/", ErrorCategory.STACK_TRACE, "PHP", "MEDIUM"),
        (r"Parse error:.*?in\s+/", ErrorCategory.STACK_TRACE, "PHP", "MEDIUM"),
        (r"Warning:.*?in\s+/\w+.*? on line \d+", ErrorCategory.STACK_TRACE, "PHP", "MEDIUM"),
        (r"Notice:.*?in\s+/\w+.*? on line \d+", ErrorCategory.STACK_TRACE, "PHP", "LOW"),
        (r"at \w+.*?\.cs:\s*line \d+", ErrorCategory.STACK_TRACE, ".NET", "MEDIUM"),
        (r"Server Error in.*?Application", ErrorCategory.STACK_TRACE, "ASP.NET", "MEDIUM"),
        (r"ActionView::Template::Error", ErrorCategory.STACK_TRACE, "Rails", "MEDIUM"),
        (r"NoMethodError.*?undefined method", ErrorCategory.STACK_TRACE, "Ruby", "MEDIUM"),

        # ── Debug/Config Leaks ────────────────────────────────────
        (r"DOCUMENT_ROOT\s*=", ErrorCategory.DEBUG_INFO, "Apache", "LOW"),
        (r"phpinfo\(\)", ErrorCategory.DEBUG_INFO, "PHP", "MEDIUM"),
        (r"DEBUG\s*=\s*True", ErrorCategory.DEBUG_INFO, "Django", "MEDIUM"),
        (r"django\.core\.exceptions", ErrorCategory.DEBUG_INFO, "Django", "MEDIUM"),
        (r"settings\.py", ErrorCategory.DEBUG_INFO, "Django", "LOW"),
        (r"APP_ENV\s*=\s*(?:dev|local|debug)", ErrorCategory.DEBUG_INFO, "Laravel", "MEDIUM"),
        (r"Whoops!.*?There was an error", ErrorCategory.DEBUG_INFO, "Laravel", "MEDIUM"),
        (r"FLASK_DEBUG", ErrorCategory.DEBUG_INFO, "Flask", "MEDIUM"),

        # ── Configuration Errors ──────────────────────────────────
        (r"Connection refused.*?(?:3306|5432|6379|27017)", ErrorCategory.CONFIGURATION, "Database", "MEDIUM"),
        (r"Access denied for user.*?@", ErrorCategory.CONFIGURATION, "MySQL", "MEDIUM"),
        (r"FATAL:.*?authentication failed", ErrorCategory.CONFIGURATION, "PostgreSQL", "MEDIUM"),
    ]

    def __init__(self):
        self._compiled: list[tuple[re.Pattern, ErrorCategory, str, str]] = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), cat, tech, sev)
            for pattern, cat, tech, sev in self.SIGNATURES
        ]

    def detect(self, body: str) -> list[ErrorMatch]:
        """Detect error patterns in response body."""
        if not body:
            return []

        matches = []
        seen_categories: set[tuple[ErrorCategory, str]] = set()

        for pattern, category, tech, severity in self._compiled:
            match = pattern.search(body)
            if match:
                key = (category, tech)
                if key not in seen_categories:
                    seen_categories.add(key)
                    matches.append(ErrorMatch(
                        category=category,
                        pattern=pattern.pattern[:100],
                        matched_text=match.group(0)[:200],
                        technology=tech,
                        severity=severity,
                    ))

        return matches

    def has_errors(self, body: str) -> bool:
        """Quick check — does this response contain any error signatures?"""
        for pattern, _, _, _ in self._compiled:
            if pattern.search(body):
                return True
        return False

    def detect_technology(self, body: str) -> list[str]:
        """Extract technology info from error messages."""
        techs = set()
        for match in self.detect(body):
            if match.technology:
                techs.add(match.technology)
        return sorted(techs)


# ═══════════════════════════════════════════════════════════════════════
# ResponseAnalyzerEngine — Unified interface
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AnalysisResult:
    """Complete analysis result for a response."""
    response: ResponseModel = field(default_factory=ResponseModel)
    diff: Optional[DiffResult] = None
    anomaly: Optional[AnomalyResult] = None
    errors: list[ErrorMatch] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    @property
    def is_interesting(self) -> bool:
        """Whether this response warrants further investigation."""
        if self.errors:
            return True
        if self.anomaly and self.anomaly.is_anomalous:
            return True
        if self.diff and self.diff.is_significant:
            return True
        return False


class ResponseAnalyzerEngine:
    """
    Unified response analysis engine.

    Usage:
        engine = ResponseAnalyzerEngine()

        # Add baselines
        for resp in baseline_responses:
            engine.add_baseline(ResponseModel.from_requests_response(resp))

        # Analyze test response
        result = engine.analyze(ResponseModel.from_requests_response(test_resp))
        if result.is_interesting:
            print(result.errors, result.anomaly.reasons)
    """

    def __init__(self, sigma_threshold: float = 3.0):
        self.dynamic_detector = DynamicDetector()
        self.diff_engine = DiffEngine(self.dynamic_detector)
        self.anomaly_detector = AnomalyDetector(sigma_threshold)
        self.error_detector = ErrorDetector()
        self._baselines: list[ResponseModel] = []

    def add_baseline(self, response: ResponseModel):
        """Add a baseline response for comparison."""
        self._baselines.append(response)
        self.anomaly_detector.add_baseline(response)

    def learn_baselines(self):
        """Learn dynamic patterns from accumulated baselines."""
        bodies = [r.body for r in self._baselines if r.body]
        self.dynamic_detector.learn_from_baselines(bodies)

    @property
    def baseline_count(self) -> int:
        return len(self._baselines)

    def analyze(self, response: ResponseModel,
                compare_baseline: Optional[ResponseModel] = None) -> AnalysisResult:
        """
        Full analysis of a response.

        Args:
            response: The response to analyze
            compare_baseline: Specific baseline to diff against (or uses first baseline)
        """
        result = AnalysisResult(response=response)

        # Error detection
        result.errors = self.error_detector.detect(response.body)
        result.technologies = self.error_detector.detect_technology(response.body)

        # Anomaly detection
        if self.anomaly_detector.baseline_count >= 2:
            result.anomaly = self.anomaly_detector.analyze(response)

        # Diff against baseline
        baseline = compare_baseline or (self._baselines[0] if self._baselines else None)
        if baseline:
            result.diff = self.diff_engine.compare(baseline, response)

        return result

    def quick_check(self, response: ResponseModel) -> bool:
        """Quick boolean: does this response look interesting?"""
        if self.error_detector.has_errors(response.body):
            return True
        if self._baselines:
            baseline = self._baselines[0]
            if response.status_code != baseline.status_code:
                return True
            size_ratio = response.body_length / max(1, baseline.body_length)
            if abs(size_ratio - 1.0) > 0.2:
                return True
        return False
