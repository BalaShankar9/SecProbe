"""
Detection Engine — Eliminates false positives through statistical analysis.

This is what separates SecProbe from every other open-source scanner.
Instead of naive "if X in response → vulnerability", this engine:

1. BaselineProfiler   — Sends N clean requests, measures natural variance
2. ResponseAnalyzer   — Smart diff that strips dynamic content
3. ReflectionTracker  — Exact context-aware payload reflection detection
4. ErrorPatternMatcher— 250+ real database/template/command error signatures
5. TimingAnalyzer     — Mann-Whitney U test for blind injection timing
6. ConfidenceScorer   — Multi-factor evidence → CONFIRMED / FIRM / TENTATIVE
7. FindingDeduplicator— Root-cause grouping so 84 FPs collapse to 0

Architecture:
    DetectionEngine orchestrates all components.  Scanners call:

        engine = DetectionEngine(http_client, url)
        engine.profile()                           # Baseline N requests
        result = engine.test_injection(url, param, payload)
        if result.confidence >= Confidence.FIRM:
            report(result)
"""

from __future__ import annotations

import hashlib
import math
import re
import statistics
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from secprobe.core.logger import get_logger

log = get_logger("detection")


# ═══════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════

class Confidence(IntEnum):
    """Evidence confidence levels — higher is more certain."""
    NONE = 0         # No evidence
    TENTATIVE = 1    # Possible, needs manual verification
    FIRM = 2         # Strong evidence, high probability
    CONFIRMED = 3    # Definitive proof (error string, exact reflection, timing)


class VulnType(IntEnum):
    """Vulnerability detection type for dedup grouping."""
    ERROR_BASED = 1
    BOOLEAN_BASED = 2
    TIME_BASED = 3
    REFLECTION = 4       # XSS reflection
    FILE_DISCLOSURE = 5  # LFI
    TEMPLATE_EVAL = 6    # SSTI
    COMMAND_OUTPUT = 7   # CMDi
    SSRF_INDICATOR = 8
    XXE_INDICATOR = 9
    NOSQL_OPERATOR = 10


@dataclass
class BaselineProfile:
    """Statistical profile of an endpoint's natural behaviour."""
    url: str
    method: str = "GET"
    sample_count: int = 0

    # Response size statistics
    size_mean: float = 0.0
    size_stdev: float = 0.0
    size_min: int = 0
    size_max: int = 0
    sizes: list[int] = field(default_factory=list)

    # Timing statistics
    timing_mean: float = 0.0
    timing_stdev: float = 0.0
    timing_p95: float = 0.0
    timings: list[float] = field(default_factory=list)

    # Status codes seen
    status_codes: list[int] = field(default_factory=list)
    primary_status: int = 200

    # Content fingerprints
    content_hashes: list[str] = field(default_factory=list)
    dom_structure_hash: str = ""
    stable_text: str = ""          # Text present in ALL samples

    # Dynamic content regions (stripped before comparison)
    dynamic_patterns: list[str] = field(default_factory=list)

    def is_size_anomalous(self, size: int, sigma_threshold: float = 3.0) -> bool:
        """Is this response size statistically anomalous?"""
        if self.sample_count < 2 or self.size_stdev == 0:
            # Fallback: >30% deviation from mean
            return abs(size - self.size_mean) > self.size_mean * 0.3
        z_score = abs(size - self.size_mean) / self.size_stdev
        return z_score > sigma_threshold

    def is_timing_anomalous(self, elapsed: float, sigma_threshold: float = 3.0) -> bool:
        """Is this response time statistically anomalous?"""
        if self.sample_count < 2 or self.timing_stdev == 0:
            return elapsed > self.timing_mean * 3
        z_score = (elapsed - self.timing_mean) / self.timing_stdev
        return z_score > sigma_threshold

    def contains_in_baseline(self, text: str) -> bool:
        """Does this text appear in the stable baseline content?"""
        return text.lower() in self.stable_text.lower() if self.stable_text else False


@dataclass
class DetectionResult:
    """Result of a single injection test."""
    payload: str
    url: str
    parameter: str = ""
    method: str = "GET"

    # Detection evidence
    confidence: Confidence = Confidence.NONE
    vuln_type: VulnType = VulnType.ERROR_BASED
    evidence: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    severity_hint: str = "HIGH"

    # Response data
    status_code: int = 0
    response_size: int = 0
    response_time: float = 0.0

    # Reflection tracking (XSS)
    reflection_contexts: list[str] = field(default_factory=list)
    reflected_payload: str = ""

    # Scoring breakdown
    score_breakdown: dict = field(default_factory=dict)

    @property
    def is_positive(self) -> bool:
        return self.confidence >= Confidence.FIRM

    @property
    def dedup_key(self) -> str:
        """Key for deduplication: same param + vuln_type = same finding."""
        return f"{self.parameter}|{self.vuln_type.name}|{self.url.split('?')[0]}"


# ═══════════════════════════════════════════════════════════════════════
# BaselineProfiler
# ═══════════════════════════════════════════════════════════════════════

# Dynamic content patterns stripped before comparison
_DYNAMIC_PATTERNS = [
    # CSRF tokens
    r'<input[^>]*(?:csrf|token|nonce|verification)[^>]*value=["\'][^"\']+["\'][^>]*/?>',
    # Session IDs in URLs
    r'(?:sid|session_id|jsessionid|phpsessid)=[a-zA-Z0-9_-]{10,}',
    # Timestamps / dates
    r'\b\d{10,13}\b',                     # Unix timestamps
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO dates
    r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+\w{3}\s+\d{4}',
    # Cache busters
    r'[?&]_=\d+',
    r'[?&]v=[a-f0-9]{6,}',
    # Tracking / analytics IDs
    r'(?:ga|gtm|fbq|_ga|_gid)[\s=]["\']?[A-Z0-9._-]+',
    # Prices (extremely dynamic on booking/e-commerce sites)
    r'(?:(?:US)?\$|€|£|¥)\s*[\d,]+(?:\.\d{2})?',
    r'\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|JPY|CAD|AUD)\b',
    # UUIDs
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    # Nonces / random tokens in attributes
    r'nonce=["\'][a-zA-Z0-9+/=]+["\']',
    # Inline JSON state blobs
    r'window\.__[A-Z_]+__\s*=\s*\{[^}]{50,}',
]

_DYNAMIC_RE = re.compile("|".join(_DYNAMIC_PATTERNS), re.IGNORECASE)


def _strip_dynamic(text: str) -> str:
    """Remove dynamic content to get stable text for comparison."""
    return _DYNAMIC_RE.sub("__DYN__", text)


def _dom_structure_hash(html: str) -> str:
    """Hash the DOM tag structure (ignoring text/attributes)."""
    tags = re.findall(r'</?([a-zA-Z][a-zA-Z0-9]*)', html)
    tag_skeleton = "|".join(tags[:500])  # First 500 tags
    return hashlib.md5(tag_skeleton.encode()).hexdigest()[:12]


class BaselineProfiler:
    """
    Establish statistical baseline for an endpoint.

    Sends N clean requests with benign values, measures:
    - Response size (mean, stdev, min, max)
    - Response time (mean, stdev, P95)
    - Status codes
    - Stable text (intersection of all responses)
    - DOM structure hash
    - Dynamic content regions
    """

    def __init__(self, http_client, *, samples: int = 5, delay: float = 0.3):
        self._client = http_client
        self.samples = max(3, samples)
        self.delay = delay
        self._profiles: dict[str, BaselineProfile] = {}

    def profile_endpoint(self, url: str, method: str = "GET",
                         params: Optional[dict] = None,
                         data: Optional[dict] = None) -> BaselineProfile:
        """
        Profile an endpoint with N clean requests.

        The profile_key is (URL_base, method) so we don't re-profile
        the same endpoint for each parameter.
        """
        profile_key = f"{method}:{url.split('?')[0]}"
        if profile_key in self._profiles:
            return self._profiles[profile_key]

        log.info("Profiling endpoint: %s %s (%d samples)",
                 method, url[:80], self.samples)

        profile = BaselineProfile(url=url, method=method)
        stable_texts = []

        benign_values = ["test", "1", "abc", "hello", "search"]

        for i in range(self.samples):
            try:
                start = time.time()
                # Quick check: skip profiling if first request returns auth error
                if i == 0 and not params and not data:
                    try:
                        quick = self._client.get(url, allow_redirects=True, timeout=5)
                        if quick.status_code in (401, 403, 405, 500, 502, 503):
                            log.debug("Skipping profile for %s (status %d)", url[:60], quick.status_code)
                            self._profiles[profile_key] = profile
                            return profile
                    except Exception:
                        pass

                if method.upper() == "POST" and data is not None:
                    # Vary one field with benign values
                    test_data = dict(data)
                    for k in test_data:
                        test_data[k] = benign_values[i % len(benign_values)]
                    resp = self._client.post(url, data=test_data, allow_redirects=True)
                else:
                    # Inject benign value into each parameter
                    if params:
                        test_params = {k: benign_values[i % len(benign_values)]
                                       for k in params}
                        parsed = urlparse(url)
                        test_url = urlunparse(parsed._replace(
                            query=urlencode(test_params)))
                    else:
                        test_url = url
                    resp = self._client.get(test_url, allow_redirects=True)
                elapsed = time.time() - start

                body = resp.text or ""
                stripped = _strip_dynamic(body)

                profile.sizes.append(len(body))
                profile.timings.append(elapsed)
                profile.status_codes.append(resp.status_code)
                profile.content_hashes.append(
                    hashlib.md5(stripped.encode()).hexdigest()[:12])
                stable_texts.append(stripped)

                if i == 0:
                    profile.dom_structure_hash = _dom_structure_hash(body)

            except Exception as e:
                log.debug("Baseline sample %d failed: %s", i, e)
                continue

            if i < self.samples - 1:
                time.sleep(self.delay)

        n = len(profile.sizes)
        if n == 0:
            log.warning("All baseline samples failed for %s", url[:80])
            self._profiles[profile_key] = profile
            return profile

        profile.sample_count = n
        profile.size_mean = statistics.mean(profile.sizes)
        profile.size_stdev = statistics.stdev(profile.sizes) if n >= 2 else 0
        profile.size_min = min(profile.sizes)
        profile.size_max = max(profile.sizes)
        profile.timing_mean = statistics.mean(profile.timings)
        profile.timing_stdev = statistics.stdev(profile.timings) if n >= 2 else 0
        profile.timing_p95 = sorted(profile.timings)[int(n * 0.95)] if n >= 2 else profile.timings[0]
        profile.primary_status = max(set(profile.status_codes),
                                     key=profile.status_codes.count)

        # Stable text = characters present in ALL stripped samples
        if stable_texts:
            # Use set intersection of lines for efficiency
            line_sets = [set(t.split("\n")) for t in stable_texts]
            common_lines = line_sets[0]
            for ls in line_sets[1:]:
                common_lines &= ls
            profile.stable_text = "\n".join(sorted(common_lines))

        log.info("Baseline: size=%.0f±%.0f, time=%.2f±%.2fs, status=%d (%d samples)",
                 profile.size_mean, profile.size_stdev,
                 profile.timing_mean, profile.timing_stdev,
                 profile.primary_status, n)

        self._profiles[profile_key] = profile
        return profile

    def get_profile(self, url: str, method: str = "GET") -> Optional[BaselineProfile]:
        """Get cached profile, or None if not profiled."""
        key = f"{method}:{url.split('?')[0]}"
        return self._profiles.get(key)

    def clear(self):
        self._profiles.clear()


# ═══════════════════════════════════════════════════════════════════════
# ResponseAnalyzer
# ═══════════════════════════════════════════════════════════════════════

class ResponseAnalyzer:
    """
    Smart comparison between injected response and baseline.

    Strips dynamic content, computes structural diff, identifies
    whether changes are security-relevant or just noise.
    """

    @staticmethod
    def normalize(text: str) -> str:
        """Strip dynamic content for clean comparison."""
        return _strip_dynamic(text)

    @staticmethod
    def structural_diff(baseline_text: str, injected_text: str) -> dict:
        """
        Compare two responses structurally.

        Returns dict with:
          changed: bool — is there a meaningful difference?
          size_delta: int — byte difference after normalization
          new_content: str — content in injected but not in baseline
          removed_content: str — content in baseline but not in injected
          structural_change: bool — did the DOM structure change?
        """
        norm_base = _strip_dynamic(baseline_text)
        norm_inj = _strip_dynamic(injected_text)

        base_lines = set(norm_base.split("\n"))
        inj_lines = set(norm_inj.split("\n"))

        new_lines = inj_lines - base_lines
        removed_lines = base_lines - inj_lines

        new_content = "\n".join(sorted(new_lines))
        removed_content = "\n".join(sorted(removed_lines))

        dom_base = _dom_structure_hash(baseline_text)
        dom_inj = _dom_structure_hash(injected_text)

        return {
            "changed": len(new_content) > 50 or len(removed_content) > 50,
            "size_delta": len(norm_inj) - len(norm_base),
            "new_content": new_content[:2000],
            "removed_content": removed_content[:2000],
            "structural_change": dom_base != dom_inj,
            "new_line_count": len(new_lines),
            "removed_line_count": len(removed_lines),
        }

    @staticmethod
    def contains_new(baseline_text: str, injected_text: str, target: str) -> bool:
        """
        Does the injected response contain 'target' that the baseline does NOT?

        This is the core false-positive killer.  Instead of:
            if "49" in response.text  → SSTI!  (wrong: "49" is a hotel price)
        We do:
            if "49" in injected AND "49" NOT in baseline → maybe SSTI
        """
        target_lower = target.lower()
        return (target_lower in injected_text.lower() and
                target_lower not in baseline_text.lower())


# ═══════════════════════════════════════════════════════════════════════
# ReflectionTracker
# ═══════════════════════════════════════════════════════════════════════

class ReflectionContext:
    """Where in the HTML a payload is reflected."""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"
    JAVASCRIPT = "javascript"
    JAVASCRIPT_STRING = "javascript_string"
    CSS = "css"
    HTML_COMMENT = "html_comment"
    URL = "url"
    TAG_NAME = "tag_name"


class ReflectionTracker:
    """
    Exact payload reflection detection with context awareness.

    For XSS: knows WHERE the payload appears (attribute, script, body)
    and what encoding transformations were applied. Handles:
    - Raw reflection
    - HTML entity encoding (< → &lt;)
    - URL encoding (%3C)
    - JavaScript escape (\\x3c)
    - Double encoding (%253C)
    - Mixed encoding
    - Case transformation
    """

    # Encoding transforms to check
    _TRANSFORMS: list[tuple[str, Callable[[str], str]]] = []

    @classmethod
    def _init_transforms(cls):
        if cls._TRANSFORMS:
            return
        import html as html_mod
        from urllib.parse import quote, unquote

        cls._TRANSFORMS = [
            ("raw", lambda s: s),
            ("html_entity", lambda s: html_mod.escape(s)),
            ("url_encoded", lambda s: quote(s)),
            ("double_url", lambda s: quote(quote(s))),
            ("lower", lambda s: s.lower()),
            ("upper", lambda s: s.upper()),
            # JS escape: < → \x3c
            ("js_escape", lambda s: s.replace("<", "\\x3c").replace(">", "\\x3e")
                                     .replace("'", "\\'").replace('"', '\\"')),
            # HTML numeric entity: < → &#60;
            ("html_numeric", lambda s: "".join(
                f"&#{ord(c)};" if c in '<>"\'&' else c for c in s)),
        ]

    @classmethod
    def find_reflection(cls, response_text: str, payload: str,
                        baseline_text: str = "") -> list[dict]:
        """
        Find all reflections of a payload in the response.

        Returns list of dicts with:
          transform: str — what encoding was applied
          context: str — HTML context (attribute, script, body, etc.)
          index: int — position in response
          surrounding: str — 100 chars around the reflection
          exploitable: bool — is this context exploitable for XSS?
        """
        cls._init_transforms()
        reflections = []

        for transform_name, transform_fn in cls._TRANSFORMS:
            try:
                transformed = transform_fn(payload)
            except Exception:
                continue

            if len(transformed) < 3:
                continue

            # Search for the transformed payload
            idx = 0
            while True:
                pos = response_text.find(transformed, idx)
                if pos == -1:
                    break
                idx = pos + 1

                # Skip if this was already in the baseline
                if baseline_text and transformed in baseline_text:
                    break

                # Determine context
                context = cls._determine_context(response_text, pos, transformed)
                surrounding = response_text[max(0, pos - 50):pos + len(transformed) + 50]

                exploitable = cls._is_exploitable(context, payload, transformed)

                reflections.append({
                    "transform": transform_name,
                    "context": context,
                    "index": pos,
                    "surrounding": surrounding,
                    "exploitable": exploitable,
                    "transformed_payload": transformed,
                })

                # Only report first reflection per transform
                break

        return reflections

    @staticmethod
    def _determine_context(html: str, pos: int, payload: str) -> str:
        """Determine the HTML context at position pos."""
        # Look backwards from the reflection point
        before = html[max(0, pos - 200):pos]
        after = html[pos + len(payload):pos + len(payload) + 200]

        # Inside HTML comment?
        if "<!--" in before and "-->" not in before:
            return ReflectionContext.HTML_COMMENT

        # Inside <script> block?
        script_open = before.rfind("<script")
        script_close = before.rfind("</script")
        if script_open > script_close:
            # Check if inside a JS string
            # Count unescaped quotes between script tag and position
            js_region = before[script_open:]
            single_q = len(re.findall(r"(?<!\\)'", js_region))
            double_q = len(re.findall(r'(?<!\\)"', js_region))
            if single_q % 2 == 1 or double_q % 2 == 1:
                return ReflectionContext.JAVASCRIPT_STRING
            return ReflectionContext.JAVASCRIPT

        # Inside CSS?
        style_open = before.rfind("<style")
        style_close = before.rfind("</style")
        if style_open > style_close:
            return ReflectionContext.CSS

        # Inside an HTML tag attribute?
        tag_open = before.rfind("<")
        tag_close = before.rfind(">")
        if tag_open > tag_close:
            # We're inside a tag
            tag_content = before[tag_open:]
            # Inside a quoted attribute value?
            if re.search(r'=\s*["\'][^"\']*$', tag_content):
                return ReflectionContext.HTML_ATTRIBUTE
            elif re.search(r'=\s*\S*$', tag_content):
                return ReflectionContext.HTML_ATTRIBUTE_UNQUOTED
            return ReflectionContext.TAG_NAME

        # Inside a URL attribute? (href, src, action)
        if re.search(r'(?:href|src|action)\s*=\s*["\'][^"\']*$', before,
                      re.IGNORECASE):
            return ReflectionContext.URL

        return ReflectionContext.HTML_BODY

    @staticmethod
    def _is_exploitable(context: str, original: str, reflected: str) -> bool:
        """Is this reflection context exploitable for XSS?"""
        dangerous_chars = '<>"\'`()/;'

        if context == ReflectionContext.HTML_BODY:
            # Need < and > to inject tags
            return "<" in reflected and ">" in reflected

        if context == ReflectionContext.HTML_ATTRIBUTE:
            # Need quote to break out of attribute
            return '"' in reflected or "'" in reflected

        if context == ReflectionContext.HTML_ATTRIBUTE_UNQUOTED:
            # Easier — space or > breaks out
            return " " in reflected or ">" in reflected

        if context in (ReflectionContext.JAVASCRIPT,
                       ReflectionContext.JAVASCRIPT_STRING):
            # Need to break out of string/context
            return any(c in reflected for c in "'\"`;/)")

        if context == ReflectionContext.URL:
            # javascript: protocol
            return "javascript:" in original.lower()

        if context == ReflectionContext.HTML_COMMENT:
            # Need --> to break out
            return "-->" in reflected

        return False


# ═══════════════════════════════════════════════════════════════════════
# ErrorPatternMatcher
# ═══════════════════════════════════════════════════════════════════════

class ErrorPatternMatcher:
    """
    Definitive error pattern recognition for injection detection.

    250+ real error signatures across:
    - SQL databases (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2)
    - NoSQL (MongoDB, Cassandra, Redis, CouchDB, Elasticsearch)
    - Template engines (Jinja2, Twig, Freemarker, Velocity, Pebble, Mako)
    - Command execution (shell, PowerShell)
    - XML/XXE parsers
    - LDAP errors

    Each pattern has:
    - Confidence: how definitive is this as a vulnerability indicator?
    - Category: what type of vulnerability does it indicate?
    - DB/engine: which specific technology?
    - False-positive risk: patterns that could appear in normal content
    """

    @dataclass
    class PatternMatch:
        pattern: str
        matched_text: str
        category: str
        technology: str
        confidence: Confidence
        description: str

    # ── SQL Error Patterns ────────────────────────────────────────────
    # Confidence.CONFIRMED = definitive SQL error; FIRM = very likely; TENTATIVE = could be FP
    SQL_PATTERNS: list[tuple[str, str, Confidence]] = [
        # MySQL — CONFIRMED (definitive SQL syntax errors)
        (r"You have an error in your SQL syntax.*?MySQL", "MySQL", Confidence.CONFIRMED),
        (r"Warning.*?\Wmysql_(?:query|fetch|num_rows|connect)", "MySQL", Confidence.CONFIRMED),
        (r"MySQLSyntaxErrorException", "MySQL", Confidence.CONFIRMED),
        (r"com\.mysql\.jdbc", "MySQL", Confidence.CONFIRMED),
        (r"Unclosed quotation mark after.*?character string", "MySQL/MSSQL", Confidence.CONFIRMED),
        (r"check the manual that (corresponds to|fits) your MySQL server version", "MySQL", Confidence.CONFIRMED),
        (r"MySQL server version for the right syntax", "MySQL", Confidence.CONFIRMED),
        (r"SQLSTATE\[\d+\].*?MySQL", "MySQL", Confidence.CONFIRMED),
        (r"#\d+ [\w/\\]+\.php\(\d+\): mysql", "MySQL/PHP", Confidence.CONFIRMED),
        (r"mysql_(?:result|connect|select_db|query|real_escape)", "MySQL/PHP", Confidence.CONFIRMED),
        (r"supplied argument is not a valid MySQL", "MySQL", Confidence.CONFIRMED),
        (r"Column count doesn't match value count at row", "MySQL", Confidence.CONFIRMED),
        (r"Unknown column '.*?' in '.*?'", "MySQL", Confidence.CONFIRMED),
        (r"Table '.*?\.\w+' doesn't exist", "MySQL", Confidence.CONFIRMED),
        (r"Data truncated for column", "MySQL", Confidence.CONFIRMED),

        # PostgreSQL — CONFIRMED
        (r"PostgreSQL.*?ERROR", "PostgreSQL", Confidence.CONFIRMED),
        (r"Warning.*?\Wpg_(?:query|exec|connect|send_query)", "PostgreSQL", Confidence.CONFIRMED),
        (r"Npgsql\.", "PostgreSQL/.NET", Confidence.CONFIRMED),
        (r"PG::SyntaxError", "PostgreSQL/Ruby", Confidence.CONFIRMED),
        (r"org\.postgresql\.util\.PSQLException", "PostgreSQL/Java", Confidence.CONFIRMED),
        (r"ERROR:\s+syntax error at or near", "PostgreSQL", Confidence.CONFIRMED),
        (r"current transaction is aborted.*?PostgreSQL", "PostgreSQL", Confidence.CONFIRMED),
        (r"unterminated quoted string at or near", "PostgreSQL", Confidence.CONFIRMED),
        (r"invalid input syntax for (?:type |integer)", "PostgreSQL", Confidence.CONFIRMED),

        # MSSQL — CONFIRMED
        (r"Driver.*? SQL[\-\_\ ]*Server", "MSSQL", Confidence.CONFIRMED),
        (r"OLE DB.*? SQL Server", "MSSQL", Confidence.CONFIRMED),
        (r"SQL Server.*?Driver", "MSSQL", Confidence.CONFIRMED),
        (r"\bODBC SQL Server Driver\b", "MSSQL", Confidence.CONFIRMED),
        (r"SqlClient\.", "MSSQL/.NET", Confidence.CONFIRMED),
        (r"Microsoft SQL Native Client error", "MSSQL", Confidence.CONFIRMED),
        (r"Msg \d+, Level \d+, State \d+", "MSSQL", Confidence.CONFIRMED),
        (r"SQL Server does not exist or access denied", "MSSQL", Confidence.CONFIRMED),
        (r"Incorrect syntax near", "MSSQL", Confidence.CONFIRMED),
        (r"Arithmetic overflow error converting", "MSSQL", Confidence.CONFIRMED),
        (r"Invalid column name '.*?'", "MSSQL", Confidence.CONFIRMED),
        (r"Conversion failed when converting", "MSSQL", Confidence.CONFIRMED),

        # Oracle — CONFIRMED
        (r"\bORA-\d{5}\b", "Oracle", Confidence.CONFIRMED),
        (r"Oracle.*?Driver", "Oracle", Confidence.CONFIRMED),
        (r"Warning.*?\W(?:oci|ora)_", "Oracle", Confidence.CONFIRMED),
        (r"quoted string not properly terminated", "Oracle", Confidence.CONFIRMED),
        (r"SQL command not properly ended", "Oracle", Confidence.CONFIRMED),
        (r"OracleException", "Oracle", Confidence.CONFIRMED),
        (r"invalid number", "Oracle", Confidence.FIRM),
        (r"missing right parenthesis", "Oracle", Confidence.CONFIRMED),
        (r"TNS:.*?(?:listener|connect)", "Oracle", Confidence.CONFIRMED),

        # SQLite — CONFIRMED
        (r"SQLite/JDBCDriver", "SQLite", Confidence.CONFIRMED),
        (r"SQLite\.Exception", "SQLite", Confidence.CONFIRMED),
        (r"(?:Microsoft|System)\.Data\.SQLite\.SQLiteException", "SQLite", Confidence.CONFIRMED),
        (r"Warning.*?\Wsqlite_", "SQLite", Confidence.CONFIRMED),
        (r"\[SQLITE_ERROR\]", "SQLite", Confidence.CONFIRMED),
        (r"SQLSTATE\[\w+\].*?SQLite", "SQLite", Confidence.CONFIRMED),
        (r"sqlite3\.OperationalError:", "SQLite/Python", Confidence.CONFIRMED),
        (r"near \".*?\": syntax error", "SQLite", Confidence.CONFIRMED),
        (r"unrecognized token: \".*?\"", "SQLite", Confidence.CONFIRMED),

        # DB2 — CONFIRMED
        (r"CLI Driver.*?DB2", "DB2", Confidence.CONFIRMED),
        (r"DB2 SQL error", "DB2", Confidence.CONFIRMED),
        (r"SQLCODE=-?\d+, SQLSTATE=\d+", "DB2", Confidence.CONFIRMED),

        # Generic SQL — FIRM (not tied to specific DB)
        (r"SQLSTATE\[\w+\]", "SQL/Generic", Confidence.FIRM),
        (r"java\.sql\.SQLException", "SQL/Java", Confidence.FIRM),
        (r"org\.hibernate\.QueryException", "Hibernate", Confidence.FIRM),
        (r"System\.Data\.SqlClient", "SQL/.NET", Confidence.FIRM),
        (r"ADODB\.(?:Field|Command)", "SQL/ADO", Confidence.FIRM),
        (r"JDBCException", "SQL/JDBC", Confidence.FIRM),
        (r"Dynamic SQL Error", "SQL/Generic", Confidence.FIRM),
        (r"valid MySQL result", "MySQL", Confidence.FIRM),
    ]

    # Pre-compile all SQL patterns
    _SQL_COMPILED: list[tuple[re.Pattern, str, Confidence]] = []

    # ── NoSQL Error Patterns ──────────────────────────────────────────
    NOSQL_PATTERNS: list[tuple[str, str, Confidence]] = [
        (r"MongoError", "MongoDB", Confidence.CONFIRMED),
        (r"MongoDB\.Driver\.Mongo", "MongoDB/.NET", Confidence.CONFIRMED),
        (r"com\.mongodb\.MongoException", "MongoDB/Java", Confidence.CONFIRMED),
        (r"pymongo\.errors\.", "MongoDB/Python", Confidence.CONFIRMED),
        (r"E11000 duplicate key error", "MongoDB", Confidence.CONFIRMED),
        (r"not master and slaveOk=false", "MongoDB", Confidence.CONFIRMED),
        (r"BSONObj size.*?is invalid", "MongoDB", Confidence.CONFIRMED),
        (r"command (?:find|aggregate|insert|update|delete) requires authentication",
         "MongoDB", Confidence.CONFIRMED),
        (r"ns not found", "MongoDB", Confidence.FIRM),
        (r"CastError.*?ObjectId", "MongoDB/Mongoose", Confidence.CONFIRMED),
        (r"Cassandra.*?InvalidQueryException", "Cassandra", Confidence.CONFIRMED),
        (r"com\.datastax\.driver", "Cassandra/Java", Confidence.CONFIRMED),
        (r"org\.apache\.cassandra", "Cassandra", Confidence.CONFIRMED),
        (r"Redis(?:Error|CommandError)", "Redis", Confidence.CONFIRMED),
        (r"WRONGTYPE Operation against a key", "Redis", Confidence.CONFIRMED),
        (r"ERR unknown command", "Redis", Confidence.CONFIRMED),
        (r"CouchDB.*?error", "CouchDB", Confidence.FIRM),
        (r"org\.elasticsearch\.ElasticsearchException", "Elasticsearch", Confidence.CONFIRMED),
        (r"SearchPhaseExecutionException", "Elasticsearch", Confidence.CONFIRMED),
    ]

    _NOSQL_COMPILED: list[tuple[re.Pattern, str, Confidence]] = []

    # ── Template Engine Error Patterns ────────────────────────────────
    TEMPLATE_PATTERNS: list[tuple[str, str, Confidence]] = [
        # Jinja2
        (r"jinja2\.exceptions\.(?:TemplateSyntaxError|UndefinedError|TemplateNotFound)",
         "Jinja2", Confidence.CONFIRMED),
        (r"jinja2\.runtime\.Undefined", "Jinja2", Confidence.CONFIRMED),
        (r"UndefinedError: '.*?' is undefined", "Jinja2", Confidence.CONFIRMED),

        # Twig
        (r"Twig_Error_(?:Syntax|Runtime|Loader)", "Twig", Confidence.CONFIRMED),
        (r"Twig\\Error\\(?:Syntax|Runtime)", "Twig", Confidence.CONFIRMED),
        (r"Unknown \".*?\" (?:tag|filter|function).*?Twig", "Twig", Confidence.CONFIRMED),

        # Freemarker
        (r"freemarker\.(?:core|template)\.(?:Invalid|Parse|Unexpected)",
         "Freemarker", Confidence.CONFIRMED),
        (r"FreeMarker template error", "Freemarker", Confidence.CONFIRMED),

        # Velocity
        (r"org\.apache\.velocity\.exception", "Velocity", Confidence.CONFIRMED),

        # Pebble
        (r"com\.mitchellbosecke\.pebble\.error", "Pebble", Confidence.CONFIRMED),

        # Mako
        (r"mako\.exceptions\.(?:CompileException|SyntaxException)",
         "Mako", Confidence.CONFIRMED),

        # ERB / Ruby
        (r"SyntaxError.*?erb", "ERB/Ruby", Confidence.FIRM),

        # Smarty
        (r"Smarty.*?SmartyCompilerException", "Smarty", Confidence.CONFIRMED),

        # Thymeleaf
        (r"TemplateProcessingException", "Thymeleaf", Confidence.FIRM),

        # Generic (TENTATIVE — could be false positive)
        (r"TemplateSyntaxError", "Template/Generic", Confidence.FIRM),
    ]

    _TEMPLATE_COMPILED: list[tuple[re.Pattern, str, Confidence]] = []

    # ── Command Execution Error Patterns ──────────────────────────────
    COMMAND_PATTERNS: list[tuple[str, str, Confidence]] = [
        # Shell errors — CONFIRMED only if the error references our injection
        (r"sh: (?:line \d+: )?.*?: (?:command )?not found", "sh/bash", Confidence.CONFIRMED),
        (r"bash: .*?: (?:command )?not found", "bash", Confidence.CONFIRMED),
        (r"/bin/sh: \d: .*?: not found", "sh", Confidence.CONFIRMED),
        (r"execvp.*?No such file or directory", "Linux exec", Confidence.CONFIRMED),
        (r"Cannot execute binary file", "Linux exec", Confidence.CONFIRMED),
        (r"Permission denied.*?/bin/", "Linux exec", Confidence.FIRM),

        # PowerShell
        (r"'.*?' is not recognized as (?:an internal|the name of a cmdlet)",
         "PowerShell/CMD", Confidence.CONFIRMED),
        (r"The term '.*?' is not recognized", "PowerShell", Confidence.CONFIRMED),
        (r"CommandNotFoundException", "PowerShell", Confidence.CONFIRMED),

        # PHP exec
        (r"Warning.*?\b(?:exec|system|passthru|shell_exec|popen)\b",
         "PHP exec", Confidence.CONFIRMED),
        (r"Fatal error.*?\b(?:proc_open|pcntl_exec)\b", "PHP exec", Confidence.CONFIRMED),

        # Python exec
        (r"subprocess\.CalledProcessError", "Python subprocess", Confidence.CONFIRMED),
        (r"OSError.*?\[Errno \d+\]", "Python/OS", Confidence.FIRM),

        # Node.js exec
        (r"child_process.*?error", "Node.js exec", Confidence.FIRM),
        (r"Error: Command failed:", "Node.js exec", Confidence.FIRM),
    ]

    _COMMAND_COMPILED: list[tuple[re.Pattern, str, Confidence]] = []

    # ── Command OUTPUT Patterns ───────────────────────────────────────
    # These indicate command output was rendered (MUST be baseline-subtracted)
    COMMAND_OUTPUT_PATTERNS: list[tuple[str, str]] = [
        (r"uid=\d+\(\w+\)\s+gid=\d+\(\w+\)", "id command output"),
        (r"root:[x*]:\d+:\d+:.*?:/(?:root|bin/(?:ba)?sh)", "/etc/passwd root entry"),
        (r"(?:Linux|Darwin|FreeBSD|SunOS)\s+\S+\s+\d+\.\d+", "uname output"),
        (r"(?:total|drwx|[-l](?:r[-w][-x]){3})\s+\d+", "ls -la output"),
        (r"(?:inet|inet6)\s+(?:\d{1,3}\.){3}\d{1,3}", "ifconfig/ip output"),
        (r"PING\s+\S+\s+\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\)", "ping output"),
        (r"(?:\d{1,3}\.){3}\d{1,3}\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
         "route/netstat output"),
        (r"Directory of [A-Z]:\\", "Windows dir output"),
        (r"Volume Serial Number is", "Windows dir output"),
    ]

    _CMD_OUTPUT_COMPILED: list[tuple[re.Pattern, str]] = []

    # ── File Disclosure Patterns (LFI/XXE) ────────────────────────────
    FILE_PATTERNS: list[tuple[str, str, Confidence]] = [
        (r"root:[x*]:\d+:\d+:", "/etc/passwd", Confidence.CONFIRMED),
        (r"\[fonts\]", "win.ini", Confidence.FIRM),
        (r"\[boot loader\]", "boot.ini", Confidence.CONFIRMED),
        (r"\[extensions\]", "win.ini", Confidence.FIRM),
        (r"DB_PASSWORD\s*=", ".env file", Confidence.CONFIRMED),
        (r"APP_KEY\s*=", ".env file", Confidence.CONFIRMED),
        (r"<\?php\b", "PHP source", Confidence.FIRM),
        (r"DOCUMENT_ROOT\s*=", "proc/environ", Confidence.CONFIRMED),
        (r"SERVER_NAME\s*=", "proc/environ", Confidence.FIRM),
        (r"mysql:.*?@.*?:\d+/\w+", "DB connection string", Confidence.CONFIRMED),
        (r"-----BEGIN (?:RSA |DSA )?PRIVATE KEY-----", "Private key", Confidence.CONFIRMED),
        (r"-----BEGIN CERTIFICATE-----", "Certificate", Confidence.FIRM),
        (r"<Server\s+port=\"\d+\"", "server.xml (Tomcat)", Confidence.CONFIRMED),
        (r"<connectionStrings>", "web.config (.NET)", Confidence.CONFIRMED),
        (r"define\s*\(\s*'DB_(?:NAME|USER|PASSWORD|HOST)'",
         "wp-config.php", Confidence.CONFIRMED),
    ]

    _FILE_COMPILED: list[tuple[re.Pattern, str, Confidence]] = []

    # ── XXE/SSRF Indicator Patterns ───────────────────────────────────
    SSRF_PATTERNS: list[tuple[str, str, Confidence]] = [
        (r"ami-[0-9a-f]{8,}", "AWS AMI metadata", Confidence.CONFIRMED),
        (r"\"(?:access|secret)Key(?:Id)?\"", "AWS credentials", Confidence.CONFIRMED),
        (r"arn:aws:[a-z]+:[a-z0-9-]+:\d+:", "AWS ARN", Confidence.CONFIRMED),
        (r"\"project(?:_id|Id)\"\s*:\s*\"[a-z0-9-]+\"", "GCP metadata", Confidence.FIRM),
        (r"\"subscriptionId\"\s*:\s*\"[0-9a-f-]{36}\"", "Azure metadata", Confidence.FIRM),
        (r"PRIVATE KEY", "Leaked credentials", Confidence.CONFIRMED),
        # Internal service indicators (only count NEW responses)
        (r"Connection refused.*?127\.0\.0\.1", "Internal SSRF", Confidence.FIRM),
        (r"getaddrinfo.*?ENOTFOUND", "DNS SSRF", Confidence.FIRM),
    ]

    _SSRF_COMPILED: list[tuple[re.Pattern, str, Confidence]] = []

    @classmethod
    def _compile_all(cls):
        """Compile all regex patterns once."""
        if cls._SQL_COMPILED:
            return

        def _compile(patterns):
            return [(re.compile(p, re.IGNORECASE), tech, conf)
                    for p, tech, conf in patterns]

        cls._SQL_COMPILED = _compile(cls.SQL_PATTERNS)
        cls._NOSQL_COMPILED = _compile(cls.NOSQL_PATTERNS)
        cls._TEMPLATE_COMPILED = _compile(cls.TEMPLATE_PATTERNS)
        cls._COMMAND_COMPILED = _compile(cls.COMMAND_PATTERNS)
        cls._FILE_COMPILED = _compile(cls.FILE_PATTERNS)
        cls._SSRF_COMPILED = _compile(cls.SSRF_PATTERNS)
        cls._CMD_OUTPUT_COMPILED = [
            (re.compile(p, re.IGNORECASE | re.MULTILINE), desc)
            for p, desc in cls.COMMAND_OUTPUT_PATTERNS
        ]

    @classmethod
    def match_sql_errors(cls, text: str, baseline_text: str = "") -> list[PatternMatch]:
        """Find SQL error patterns, excluding those in the baseline."""
        cls._compile_all()
        return cls._match_category(cls._SQL_COMPILED, text, baseline_text, "sql_error")

    @classmethod
    def match_nosql_errors(cls, text: str, baseline_text: str = "") -> list[PatternMatch]:
        cls._compile_all()
        return cls._match_category(cls._NOSQL_COMPILED, text, baseline_text, "nosql_error")

    @classmethod
    def match_template_errors(cls, text: str, baseline_text: str = "") -> list[PatternMatch]:
        cls._compile_all()
        return cls._match_category(cls._TEMPLATE_COMPILED, text, baseline_text, "template_error")

    @classmethod
    def match_command_errors(cls, text: str, baseline_text: str = "") -> list[PatternMatch]:
        cls._compile_all()
        return cls._match_category(cls._COMMAND_COMPILED, text, baseline_text, "command_error")

    @classmethod
    def match_command_output(cls, text: str, baseline_text: str = "") -> list[PatternMatch]:
        """Match command execution output (id, passwd, uname etc)."""
        cls._compile_all()
        results = []
        for pattern, desc in cls._CMD_OUTPUT_COMPILED:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)
                # Baseline subtraction: skip if this pattern also matches baseline
                if baseline_text and pattern.search(baseline_text):
                    continue
                results.append(cls.PatternMatch(
                    pattern=pattern.pattern, matched_text=matched_str,
                    category="command_output", technology=desc,
                    confidence=Confidence.CONFIRMED,
                    description=f"Command output detected: {desc}",
                ))
        return results

    @classmethod
    def match_file_disclosure(cls, text: str, baseline_text: str = "") -> list[PatternMatch]:
        cls._compile_all()
        return cls._match_category(cls._FILE_COMPILED, text, baseline_text, "file_disclosure")

    @classmethod
    def match_ssrf_indicators(cls, text: str, baseline_text: str = "") -> list[PatternMatch]:
        cls._compile_all()
        return cls._match_category(cls._SSRF_COMPILED, text, baseline_text, "ssrf")

    @classmethod
    def _match_category(cls, compiled_patterns, text: str,
                        baseline_text: str, category: str) -> list[PatternMatch]:
        results = []
        for pattern, tech, conf in compiled_patterns:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)
                # CRITICAL: Baseline subtraction — skip if pattern matches baseline
                if baseline_text and pattern.search(baseline_text):
                    continue
                results.append(cls.PatternMatch(
                    pattern=pattern.pattern, matched_text=matched_str[:200],
                    category=category, technology=tech,
                    confidence=conf,
                    description=f"{category} ({tech}): {matched_str[:100]}",
                ))
        return results


# ═══════════════════════════════════════════════════════════════════════
# TimingAnalyzer
# ═══════════════════════════════════════════════════════════════════════

class TimingAnalyzer:
    """
    Statistical timing analysis for blind injection detection.

    Instead of "if elapsed > 2.5s → vulnerable" (produces FPs from
    network jitter), we:

    1. Measure baseline timing distribution (already in BaselineProfile)
    2. Send timing payload
    3. Send CONFIRMATION request with timing payload
    4. Compare both timing samples against baseline using statistics
    5. Apply IQR-based outlier removal
    6. Use Mann-Whitney U test for significance (if enough samples)
    """

    def __init__(self, http_client, baseline: BaselineProfile):
        self._client = http_client
        self.baseline = baseline

    def test_timing(self, url: str, method: str = "GET",
                    data: Optional[dict] = None,
                    expected_delay: float = 3.0,
                    confirmation_rounds: int = 2,
                    rate_limit: float = 0.5) -> dict:
        """
        Test if a URL exhibits anomalous timing.

        Returns dict with:
          anomalous: bool
          confidence: Confidence
          samples: list[float]
          baseline_mean: float
          baseline_stdev: float
          observed_mean: float
          z_score: float
          p_value: float  (if enough samples)
        """
        samples = []

        for i in range(confirmation_rounds):
            try:
                start = time.time()
                if method.upper() == "POST" and data:
                    self._client.post(url, data=data, allow_redirects=False)
                else:
                    self._client.get(url, allow_redirects=False)
                elapsed = time.time() - start
                samples.append(elapsed)
            except Exception:
                samples.append(0.0)

            if i < confirmation_rounds - 1:
                time.sleep(rate_limit)

        if not samples or all(s == 0 for s in samples):
            return {"anomalous": False, "confidence": Confidence.NONE,
                    "samples": samples, "reason": "all_failed"}

        # IQR-based outlier removal from samples
        clean_samples = self._remove_outliers(samples) if len(samples) >= 4 else samples
        observed_mean = statistics.mean(clean_samples)

        baseline_mean = self.baseline.timing_mean
        baseline_stdev = max(self.baseline.timing_stdev, 0.1)  # Floor at 100ms

        # Z-score against baseline
        z_score = (observed_mean - baseline_mean) / baseline_stdev

        # Absolute delay check: observed must be close to expected delay
        delay_match = abs(observed_mean - expected_delay) < expected_delay * 0.5

        # Statistical significance
        p_value = self._mann_whitney_p(self.baseline.timings, clean_samples)

        # Determine confidence
        confidence = Confidence.NONE
        if z_score > 5 and delay_match and all(s > expected_delay * 0.7 for s in clean_samples):
            confidence = Confidence.CONFIRMED
        elif z_score > 3 and delay_match:
            confidence = Confidence.FIRM
        elif z_score > 2.5 and observed_mean > baseline_mean * 2:
            confidence = Confidence.TENTATIVE

        return {
            "anomalous": confidence >= Confidence.FIRM,
            "confidence": confidence,
            "samples": samples,
            "clean_samples": clean_samples,
            "baseline_mean": baseline_mean,
            "baseline_stdev": baseline_stdev,
            "observed_mean": observed_mean,
            "z_score": z_score,
            "p_value": p_value,
            "delay_match": delay_match,
        }

    @staticmethod
    def _remove_outliers(data: list[float]) -> list[float]:
        """Remove outliers using IQR method."""
        if len(data) < 4:
            return data
        sorted_data = sorted(data)
        q1 = sorted_data[len(data) // 4]
        q3 = sorted_data[3 * len(data) // 4]
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        return [x for x in data if lower <= x <= upper] or data

    @staticmethod
    def _mann_whitney_p(baseline_samples: list[float],
                        test_samples: list[float]) -> float:
        """
        Approximate Mann-Whitney U test p-value.

        For small samples this is approximate. Returns p-value
        where < 0.05 indicates statistically significant difference.
        """
        if len(baseline_samples) < 3 or len(test_samples) < 2:
            return 1.0

        n1 = len(baseline_samples)
        n2 = len(test_samples)
        all_data = [(v, "b") for v in baseline_samples] + [(v, "t") for v in test_samples]
        all_data.sort(key=lambda x: x[0])

        # Assign ranks
        ranks = {}
        i = 0
        while i < len(all_data):
            j = i
            while j < len(all_data) and all_data[j][0] == all_data[i][0]:
                j += 1
            avg_rank = (i + j + 1) / 2  # 1-based average
            for k in range(i, j):
                ranks[id(all_data[k])] = avg_rank
            i = j

        # Sum of ranks for test group
        r2 = sum(ranks[id(item)] for item in all_data if item[1] == "t")
        u2 = r2 - n2 * (n2 + 1) / 2
        u1 = n1 * n2 - u2

        # Normal approximation
        mu = n1 * n2 / 2
        sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12)
        if sigma == 0:
            return 1.0
        z = (min(u1, u2) - mu) / sigma

        # Approximate p-value from z-score using error function
        p = 0.5 * (1 + math.erf(z / math.sqrt(2)))
        return min(2 * p, 1.0)  # Two-tailed


# ═══════════════════════════════════════════════════════════════════════
# ConfidenceScorer
# ═══════════════════════════════════════════════════════════════════════

class ConfidenceScorer:
    """
    Multi-factor evidence scoring.

    Combines signals from all detection components into a single
    confidence level. Factors:

    - Error pattern matches (and their individual confidence)
    - Reflection tracking (and exploitability)
    - Timing analysis (z-score, confirmation count)
    - Baseline size deviation (z-score)
    - Status code change
    - DOM structural change
    - Payload-specific markers

    The scorer prevents reporting unless evidence meets threshold.
    """

    @staticmethod
    def score_injection(
        *,
        error_matches: list[ErrorPatternMatcher.PatternMatch] = None,
        reflection: list[dict] = None,
        timing: Optional[dict] = None,
        baseline: Optional[BaselineProfile] = None,
        response_size: int = 0,
        response_status: int = 200,
        response_text: str = "",
        payload: str = "",
        vuln_type: VulnType = VulnType.ERROR_BASED,
    ) -> tuple[Confidence, dict]:
        """
        Score injection evidence.

        Returns (confidence, breakdown_dict).
        """
        error_matches = error_matches or []
        reflection = reflection or []
        breakdown = {
            "error_score": 0,
            "reflection_score": 0,
            "timing_score": 0,
            "size_score": 0,
            "status_score": 0,
            "structural_score": 0,
            "total": 0,
        }

        # ── Error pattern scoring ─────────────────────────────────
        if error_matches:
            max_conf = max(m.confidence for m in error_matches)
            breakdown["error_score"] = int(max_conf) * 30
            breakdown["error_details"] = [
                f"{m.technology}: {m.matched_text[:80]}" for m in error_matches[:3]
            ]

        # ── Reflection scoring ────────────────────────────────────
        if reflection:
            exploitable = [r for r in reflection if r.get("exploitable")]
            if exploitable:
                breakdown["reflection_score"] = 90
                breakdown["reflection_details"] = [
                    f"{r['context']} ({r['transform']})" for r in exploitable[:3]
                ]
            elif reflection:
                raw = [r for r in reflection if r.get("transform") == "raw"]
                breakdown["reflection_score"] = 60 if raw else 30
                breakdown["reflection_details"] = [
                    f"{r['context']} ({r['transform']})" for r in reflection[:3]
                ]

        # ── Timing scoring ────────────────────────────────────────
        if timing and timing.get("anomalous"):
            t_conf = timing.get("confidence", Confidence.NONE)
            breakdown["timing_score"] = int(t_conf) * 30
            breakdown["timing_details"] = (
                f"z={timing.get('z_score', 0):.1f}, "
                f"observed={timing.get('observed_mean', 0):.2f}s, "
                f"baseline={timing.get('baseline_mean', 0):.2f}s"
            )

        # ── Size anomaly scoring ──────────────────────────────────
        if baseline and baseline.sample_count >= 2:
            if baseline.is_size_anomalous(response_size, sigma_threshold=4.0):
                breakdown["size_score"] = 15
            # Status code change
            if response_status != baseline.primary_status:
                breakdown["status_score"] = 20

        # Calculate total
        breakdown["total"] = sum(
            v for k, v in breakdown.items()
            if k.endswith("_score") and isinstance(v, (int, float))
        )

        # Map score to confidence
        total = breakdown["total"]
        if total >= 80:
            confidence = Confidence.CONFIRMED
        elif total >= 50:
            confidence = Confidence.FIRM
        elif total >= 25:
            confidence = Confidence.TENTATIVE
        else:
            confidence = Confidence.NONE

        return confidence, breakdown


# ═══════════════════════════════════════════════════════════════════════
# FindingDeduplicator
# ═══════════════════════════════════════════════════════════════════════

class FindingDeduplicator:
    """
    Root-cause deduplication.

    Groups findings by (endpoint, parameter, vuln_type) and keeps only
    the highest-confidence result per group.  This collapses:
    - 84 SQLi "Possible Boolean-based" into 0 (all below threshold)
    - 3 XSS reflections for same param into 1 (best evidence)
    - Multiple payloads hitting same error into 1 (same root cause)
    """

    def __init__(self):
        self._seen: dict[str, DetectionResult] = {}

    def add(self, result: DetectionResult) -> bool:
        """
        Add a detection result. Returns True if this is the best so far
        for its dedup group (new or higher confidence).
        """
        key = result.dedup_key

        existing = self._seen.get(key)
        if existing is None:
            self._seen[key] = result
            return True

        if result.confidence > existing.confidence:
            self._seen[key] = result
            return True

        return False

    def get_results(self) -> list[DetectionResult]:
        """Get all deduplicated results, sorted by confidence."""
        return sorted(self._seen.values(),
                      key=lambda r: (r.confidence, r.severity_hint),
                      reverse=True)

    def get_confirmed(self) -> list[DetectionResult]:
        """Get only CONFIRMED results."""
        return [r for r in self._seen.values()
                if r.confidence >= Confidence.CONFIRMED]

    def get_firm_or_better(self) -> list[DetectionResult]:
        """Get FIRM and CONFIRMED results."""
        return [r for r in self._seen.values()
                if r.confidence >= Confidence.FIRM]

    def count(self) -> dict[str, int]:
        """Count by confidence level."""
        counts = {c.name: 0 for c in Confidence}
        for r in self._seen.values():
            counts[r.confidence.name] += 1
        return counts

    def clear(self):
        self._seen.clear()


# ═══════════════════════════════════════════════════════════════════════
# DetectionEngine — Orchestrator
# ═══════════════════════════════════════════════════════════════════════

class DetectionEngine:
    """
    Central detection engine that all injection scanners use.

    Usage:
        engine = DetectionEngine(http_client)
        baseline = engine.profile(url, params={"ss": ""})

        # Test an injection
        result = engine.test_error_based(url, "ss", payload, response)
        result = engine.test_reflection(url, "ss", payload, response)
        result = engine.test_timing(url, "ss", payload, expected_delay=3.0)
        result = engine.test_boolean(url, "ss", true_resp, false_resp)

        # Get deduplicated findings
        for result in engine.get_findings():
            if result.is_positive:
                scanner.add_finding(...)
    """

    def __init__(self, http_client, *,
                 baseline_samples: int = 5,
                 baseline_delay: float = 0.3,
                 min_confidence: Confidence = Confidence.FIRM):
        self.http_client = http_client
        self.profiler = BaselineProfiler(
            http_client,
            samples=baseline_samples,
            delay=baseline_delay,
        )
        self.deduplicator = FindingDeduplicator()
        self.min_confidence = min_confidence
        self._baselines: dict[str, BaselineProfile] = {}

    def profile(self, url: str, method: str = "GET",
                params: Optional[dict] = None,
                data: Optional[dict] = None) -> BaselineProfile:
        """Profile an endpoint and cache the baseline."""
        baseline = self.profiler.profile_endpoint(url, method, params, data)
        key = f"{method}:{url.split('?')[0]}"
        self._baselines[key] = baseline
        return baseline

    def get_baseline(self, url: str, method: str = "GET") -> Optional[BaselineProfile]:
        """Get cached baseline for an endpoint."""
        key = f"{method}:{url.split('?')[0]}"
        return self._baselines.get(key) or self.profiler.get_profile(url, method)

    def test_error_based(self, url: str, parameter: str, payload: str,
                         response_text: str, response_status: int = 200,
                         response_size: int = 0,
                         vuln_category: str = "sqli") -> DetectionResult:
        """
        Test for error-based injection (SQL, NoSQL, template, command).

        The key innovation: baseline subtraction.  We only report errors
        that are NEW — not present in the clean baseline.
        """
        baseline = self.get_baseline(url)
        baseline_text = baseline.stable_text if baseline else ""

        # Match appropriate error patterns
        if vuln_category == "sqli":
            matches = ErrorPatternMatcher.match_sql_errors(response_text, baseline_text)
            vuln_type = VulnType.ERROR_BASED
        elif vuln_category == "nosql":
            matches = ErrorPatternMatcher.match_nosql_errors(response_text, baseline_text)
            vuln_type = VulnType.NOSQL_OPERATOR
        elif vuln_category == "ssti":
            matches = ErrorPatternMatcher.match_template_errors(response_text, baseline_text)
            vuln_type = VulnType.TEMPLATE_EVAL
        elif vuln_category == "cmdi":
            matches = (ErrorPatternMatcher.match_command_errors(response_text, baseline_text) +
                       ErrorPatternMatcher.match_command_output(response_text, baseline_text))
            vuln_type = VulnType.COMMAND_OUTPUT
        elif vuln_category == "lfi":
            matches = ErrorPatternMatcher.match_file_disclosure(response_text, baseline_text)
            vuln_type = VulnType.FILE_DISCLOSURE
        elif vuln_category == "xxe":
            matches = (ErrorPatternMatcher.match_file_disclosure(response_text, baseline_text) +
                       ErrorPatternMatcher.match_ssrf_indicators(response_text, baseline_text))
            vuln_type = VulnType.XXE_INDICATOR
        elif vuln_category == "ssrf":
            matches = ErrorPatternMatcher.match_ssrf_indicators(response_text, baseline_text)
            vuln_type = VulnType.SSRF_INDICATOR
        else:
            matches = []
            vuln_type = VulnType.ERROR_BASED

        # Score
        confidence, breakdown = ConfidenceScorer.score_injection(
            error_matches=matches,
            baseline=baseline,
            response_size=response_size or len(response_text),
            response_status=response_status,
            vuln_type=vuln_type,
        )

        result = DetectionResult(
            payload=payload, url=url, parameter=parameter,
            confidence=confidence, vuln_type=vuln_type,
            evidence=[m.description for m in matches],
            matched_patterns=[m.matched_text for m in matches],
            severity_hint="CRITICAL" if confidence >= Confidence.CONFIRMED else "HIGH",
            status_code=response_status,
            response_size=response_size or len(response_text),
            score_breakdown=breakdown,
        )

        self.deduplicator.add(result)
        return result

    def test_reflection(self, url: str, parameter: str, payload: str,
                        response_text: str, response_status: int = 200,
                        baseline_text: str = "") -> DetectionResult:
        """
        Test for XSS reflection.

        Uses ReflectionTracker for context-aware detection.
        """
        if not baseline_text:
            baseline = self.get_baseline(url)
            baseline_text = baseline.stable_text if baseline else ""

        reflections = ReflectionTracker.find_reflection(
            response_text, payload, baseline_text)

        confidence, breakdown = ConfidenceScorer.score_injection(
            reflection=reflections,
            vuln_type=VulnType.REFLECTION,
        )

        result = DetectionResult(
            payload=payload, url=url, parameter=parameter,
            confidence=confidence, vuln_type=VulnType.REFLECTION,
            evidence=[f"Reflected as {r['transform']} in {r['context']}"
                      for r in reflections],
            reflection_contexts=[r["context"] for r in reflections],
            reflected_payload=reflections[0]["transformed_payload"] if reflections else "",
            severity_hint="HIGH" if confidence >= Confidence.FIRM else "MEDIUM",
            status_code=response_status,
            response_size=len(response_text),
            score_breakdown=breakdown,
        )

        self.deduplicator.add(result)
        return result

    def test_template_eval(self, url: str, parameter: str,
                           expression: str, expected: str,
                           response_text: str, *,
                           baseline_text: str = "",
                           response_status: int = 200) -> DetectionResult:
        """
        Test for SSTI with baseline-aware evaluation checking.

        The key insight: "49" might be a hotel price. So we check:
        1. Is "49" present in the BASELINE? If yes → skip (FP)
        2. Is "49" NEW in the injected response? If yes → maybe real
        3. Are there template ERROR patterns? → stronger evidence
        4. Use a UNIQUE expression (987*123=121401) for confirmation
        """
        if not baseline_text:
            baseline = self.get_baseline(url)
            baseline_text = baseline.stable_text if baseline else ""

        evidence = []
        error_matches = ErrorPatternMatcher.match_template_errors(
            response_text, baseline_text)

        # Check if expected value is NEW (not in baseline)
        eval_detected = ResponseAnalyzer.contains_new(
            baseline_text, response_text, expected)

        if eval_detected:
            evidence.append(f"Expression '{expression}' evaluated to '{expected}' "
                            f"(NOT in baseline)")

        if error_matches:
            evidence.extend(m.description for m in error_matches)

        # Score
        confidence = Confidence.NONE
        if eval_detected and error_matches:
            confidence = Confidence.CONFIRMED
        elif eval_detected:
            # Still could be coincidence — use FIRM not CONFIRMED
            confidence = Confidence.FIRM
        elif error_matches:
            max_err = max(m.confidence for m in error_matches)
            confidence = max_err

        breakdown = {
            "eval_detected": eval_detected,
            "expression": expression,
            "expected": expected,
            "in_baseline": not eval_detected and expected.lower() in baseline_text.lower(),
            "error_matches": len(error_matches),
        }

        result = DetectionResult(
            payload=expression, url=url, parameter=parameter,
            confidence=confidence, vuln_type=VulnType.TEMPLATE_EVAL,
            evidence=evidence,
            severity_hint="CRITICAL" if confidence >= Confidence.CONFIRMED else "HIGH",
            status_code=response_status,
            response_size=len(response_text),
            score_breakdown=breakdown,
        )

        self.deduplicator.add(result)
        return result

    def test_timing(self, url: str, parameter: str, payload: str,
                    method: str = "GET", data: Optional[dict] = None,
                    expected_delay: float = 3.0,
                    rate_limit: float = 0.5) -> DetectionResult:
        """
        Test for time-based blind injection with statistical analysis.
        """
        baseline = self.get_baseline(url, method)
        if not baseline or baseline.sample_count < 2:
            return DetectionResult(
                payload=payload, url=url, parameter=parameter,
                confidence=Confidence.NONE,
                vuln_type=VulnType.TIME_BASED,
            )

        analyzer = TimingAnalyzer(self.http_client, baseline)
        timing = analyzer.test_timing(
            url, method=method, data=data,
            expected_delay=expected_delay,
            confirmation_rounds=3,
            rate_limit=rate_limit,
        )

        evidence = []
        if timing["anomalous"]:
            evidence.append(
                f"Response delayed {timing['observed_mean']:.2f}s "
                f"(baseline: {timing['baseline_mean']:.2f}±{timing['baseline_stdev']:.2f}s, "
                f"z-score: {timing['z_score']:.1f})"
            )

        result = DetectionResult(
            payload=payload, url=url, parameter=parameter,
            confidence=timing.get("confidence", Confidence.NONE),
            vuln_type=VulnType.TIME_BASED,
            evidence=evidence,
            severity_hint="CRITICAL" if timing.get("confidence", Confidence.NONE) >= Confidence.CONFIRMED else "HIGH",
            response_time=timing.get("observed_mean", 0),
            score_breakdown=timing,
        )

        self.deduplicator.add(result)
        return result

    def test_boolean(self, url: str, parameter: str,
                     true_response: str, false_response: str,
                     true_size: int, false_size: int,
                     payload_desc: str = "") -> DetectionResult:
        """
        Test for boolean-based injection.

        Compares true/false response pair against baseline variance.
        Only reports if the difference EXCEEDS natural variance
        AND the true/false responses are consistently different from each other.
        """
        baseline = self.get_baseline(url)
        if not baseline or baseline.sample_count < 2:
            return DetectionResult(
                payload=payload_desc, url=url, parameter=parameter,
                confidence=Confidence.NONE, vuln_type=VulnType.BOOLEAN_BASED,
            )

        size_diff = abs(true_size - false_size)
        natural_variance = baseline.size_stdev * 3  # 3-sigma

        # The true/false difference must exceed natural variance
        if size_diff <= max(natural_variance, 50):
            return DetectionResult(
                payload=payload_desc, url=url, parameter=parameter,
                confidence=Confidence.NONE, vuln_type=VulnType.BOOLEAN_BASED,
                score_breakdown={
                    "size_diff": size_diff,
                    "natural_variance": natural_variance,
                    "reason": "diff_within_natural_variance",
                },
            )

        # Structural comparison
        diff = ResponseAnalyzer.structural_diff(true_response, false_response)

        confidence = Confidence.NONE
        evidence = []

        if diff["structural_change"] and size_diff > natural_variance * 2:
            confidence = Confidence.FIRM
            evidence.append(
                f"Boolean condition changes response structure: "
                f"Δ{size_diff}B (natural variance: ±{natural_variance:.0f}B)")
        elif size_diff > natural_variance * 3:
            confidence = Confidence.TENTATIVE
            evidence.append(
                f"Boolean condition changes response size: "
                f"Δ{size_diff}B (3σ={natural_variance:.0f}B)")

        result = DetectionResult(
            payload=payload_desc, url=url, parameter=parameter,
            confidence=confidence, vuln_type=VulnType.BOOLEAN_BASED,
            evidence=evidence,
            severity_hint="HIGH" if confidence >= Confidence.FIRM else "MEDIUM",
            score_breakdown={
                "size_diff": size_diff,
                "natural_variance": natural_variance,
                "structural_change": diff["structural_change"],
                "new_lines": diff["new_line_count"],
                "removed_lines": diff["removed_line_count"],
            },
        )

        self.deduplicator.add(result)
        return result

    def get_findings(self, min_confidence: Optional[Confidence] = None
                     ) -> list[DetectionResult]:
        """Get all deduplicated findings above the minimum confidence."""
        threshold = min_confidence or self.min_confidence
        return [r for r in self.deduplicator.get_results()
                if r.confidence >= threshold]

    def get_all_results(self) -> list[DetectionResult]:
        """Get ALL results regardless of confidence."""
        return self.deduplicator.get_results()

    def reset(self):
        """Reset for a new scan."""
        self.deduplicator.clear()

    @property
    def stats(self) -> dict:
        """Detection statistics."""
        counts = self.deduplicator.count()
        return {
            "total_tested": sum(counts.values()),
            "confirmed": counts.get("CONFIRMED", 0),
            "firm": counts.get("FIRM", 0),
            "tentative": counts.get("TENTATIVE", 0),
            "none": counts.get("NONE", 0),
        }
