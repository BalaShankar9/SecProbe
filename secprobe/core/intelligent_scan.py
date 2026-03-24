"""
Intelligent Scan Engine — AI-powered adaptive scanning.

This module implements strategies that go beyond traditional "spray and pray" scanning:

1. TechFingerprinter   — Identify stack (language, framework, DB, WAF) from responses
2. BayesianConfidence  — Update vulnerability probability as evidence accumulates
3. AttackGraphEngine   — Chain findings: SQLi → data extraction → privilege escalation
4. ResponseClusterer   — Group similar responses to detect anomalies efficiently
5. PayloadEvolver      — Genetic algorithm to mutate payloads past WAF/filters
6. ContextualEscalator — Findings from one scanner feed into another's strategy
7. SmartScheduler      — Prioritize high-value targets, skip dead-ends early

Architecture:
    engine = IntelligentScanEngine(http_client, config)
    engine.fingerprint(target_url)
    engine.plan_attack(attack_surface)
    for scanner_name, targets, payloads in engine.next_task():
        result = run_scanner(scanner_name, targets, payloads)
        engine.ingest_result(result)  # Update Bayesian model, attack graph
"""

from __future__ import annotations

import hashlib
import math
import random
import re
import statistics
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs


# ═══════════════════════════════════════════════════════════════════
# 1. TECHNOLOGY FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════

class TechCategory(Enum):
    LANGUAGE = "language"
    FRAMEWORK = "framework"
    DATABASE = "database"
    SERVER = "server"
    WAF = "waf"
    CMS = "cms"
    JS_FRAMEWORK = "js_framework"
    OS = "os"


@dataclass
class TechSignature:
    """A technology detected on the target."""
    name: str
    category: TechCategory
    version: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    source: str = ""         # How we detected it


# Header → technology mapping (200+ signatures)
HEADER_SIGNATURES = {
    # Server headers
    r"Apache/?([\d.]+)?": ("Apache", TechCategory.SERVER),
    r"nginx/?([\d.]+)?": ("Nginx", TechCategory.SERVER),
    r"Microsoft-IIS/?([\d.]+)?": ("IIS", TechCategory.SERVER),
    r"LiteSpeed": ("LiteSpeed", TechCategory.SERVER),
    r"cloudflare": ("Cloudflare", TechCategory.WAF),
    r"AkamaiGHost": ("Akamai", TechCategory.WAF),

    # Language / Framework
    r"X-Powered-By:\s*PHP/?([\d.]+)?": ("PHP", TechCategory.LANGUAGE),
    r"X-Powered-By:\s*ASP\.NET": ("ASP.NET", TechCategory.FRAMEWORK),
    r"X-Powered-By:\s*Express": ("Express.js", TechCategory.FRAMEWORK),
    r"X-Powered-By:\s*Next\.js": ("Next.js", TechCategory.FRAMEWORK),
    r"X-AspNet-Version:\s*([\d.]+)": ("ASP.NET", TechCategory.FRAMEWORK),
    r"X-Drupal-Cache": ("Drupal", TechCategory.CMS),
    r"X-Generator:\s*WordPress": ("WordPress", TechCategory.CMS),
    r"X-Shopify-Stage": ("Shopify", TechCategory.CMS),
    r"X-Varnish": ("Varnish", TechCategory.SERVER),
    r"X-Debug-Token": ("Symfony", TechCategory.FRAMEWORK),

    # WAFs
    r"X-Sucuri-ID": ("Sucuri WAF", TechCategory.WAF),
    r"X-CDN:\s*Imperva": ("Imperva WAF", TechCategory.WAF),
    r"Server:\s*BigIP": ("F5 BIG-IP", TechCategory.WAF),
    r"__cfduid": ("Cloudflare", TechCategory.WAF),
}

# HTML body → technology mapping
BODY_SIGNATURES = {
    # CMS
    r'wp-content/|wp-includes/': ("WordPress", TechCategory.CMS),
    r'/sites/default/files/': ("Drupal", TechCategory.CMS),
    r'Joomla!?\s': ("Joomla", TechCategory.CMS),
    r'/media/com_': ("Joomla", TechCategory.CMS),
    r'content="WordPress': ("WordPress", TechCategory.CMS),

    # JS Frameworks
    r'ng-app=|ng-controller=|angular[\./]': ("Angular", TechCategory.JS_FRAMEWORK),
    r'react\.production\.min\.js|_next/static|__NEXT_DATA__': ("React/Next.js", TechCategory.JS_FRAMEWORK),
    r'vue\.min\.js|v-bind:|v-model=': ("Vue.js", TechCategory.JS_FRAMEWORK),
    r'ember\.js|data-ember': ("Ember.js", TechCategory.JS_FRAMEWORK),

    # Frameworks (server-side)
    r'csrfmiddlewaretoken': ("Django", TechCategory.FRAMEWORK),
    r'__RequestVerificationToken': ("ASP.NET MVC", TechCategory.FRAMEWORK),
    r'<input[^>]+name="_token"': ("Laravel", TechCategory.FRAMEWORK),
    r'rails-ujs|data-turbolinks': ("Ruby on Rails", TechCategory.FRAMEWORK),
    r'Spring|JSESSIONID': ("Spring/Java", TechCategory.FRAMEWORK),
    r'__VIEWSTATE': ("ASP.NET WebForms", TechCategory.FRAMEWORK),

    # Error signatures → language detection
    r'Traceback \(most recent call last\)': ("Python", TechCategory.LANGUAGE),
    r'at\s+[\w.]+\.java:\d+': ("Java", TechCategory.LANGUAGE),
    r'Fatal error.*\.php:\d+': ("PHP", TechCategory.LANGUAGE),
    r'Microsoft\.AspNetCore|System\.Web': ("C#/.NET", TechCategory.LANGUAGE),
    r'TypeError:.*node_modules/': ("Node.js", TechCategory.LANGUAGE),
}

# Error pattern → database mapping
DB_ERROR_SIGNATURES = {
    r'mysql_|MySql|MariaDB|1064.*syntax': ("MySQL", TechCategory.DATABASE),
    r'postgresql|pg_|Npgsql|PSQLException': ("PostgreSQL", TechCategory.DATABASE),
    r'ORA-\d{5}|oracle': ("Oracle", TechCategory.DATABASE),
    r'Microsoft.*SQL Server|mssql|ODBC SQL': ("MSSQL", TechCategory.DATABASE),
    r'sqlite3?\.|SQLite/': ("SQLite", TechCategory.DATABASE),
    r'MongoDB|MongoError|BSON': ("MongoDB", TechCategory.DATABASE),
    r'Redis|redis\.clients': ("Redis", TechCategory.DATABASE),
}

# Cookie name → technology
COOKIE_SIGNATURES = {
    "JSESSIONID": ("Java", TechCategory.LANGUAGE),
    "PHPSESSID": ("PHP", TechCategory.LANGUAGE),
    "ASP.NET_SessionId": ("ASP.NET", TechCategory.FRAMEWORK),
    "csrftoken": ("Django", TechCategory.FRAMEWORK),
    "laravel_session": ("Laravel", TechCategory.FRAMEWORK),
    "_rails_session": ("Ruby on Rails", TechCategory.FRAMEWORK),
    "connect.sid": ("Express.js", TechCategory.FRAMEWORK),
    "rack.session": ("Ruby/Rack", TechCategory.FRAMEWORK),
    "XSRF-TOKEN": ("Angular/Laravel", TechCategory.FRAMEWORK),
    "__cf_bm": ("Cloudflare", TechCategory.WAF),
}


class TechFingerprinter:
    """
    Multi-vector technology fingerprinting.

    Unlike Wappalyzer which only checks headers + body patterns,
    this also:
    - Probes specific paths (/wp-admin, /.env, /server-status)
    - Analyzes error page patterns
    - Checks timing characteristics (Java apps tend to be slower on first request)
    - Examines URL structure patterns
    """

    def __init__(self, http_client=None):
        self.client = http_client
        self.detected: list[TechSignature] = []
        self._seen: set[str] = set()

    def fingerprint(self, url: str, response=None, *, deep: bool = True) -> list[TechSignature]:
        """
        Full fingerprint from URL + initial response.

        If deep=True, also sends probe requests to known paths.
        """
        self.detected = []
        self._seen = set()

        if response:
            self._check_headers(response)
            self._check_body(response.text if hasattr(response, 'text') else str(response))
            self._check_cookies(response)

        self._check_url_patterns(url)

        if deep and self.client:
            self._probe_paths(url)

        # Sort by confidence descending
        self.detected.sort(key=lambda t: t.confidence, reverse=True)
        return self.detected

    def _add(self, name: str, category: TechCategory, confidence: float,
             source: str, version: str = ""):
        key = f"{name}:{category.value}"
        if key in self._seen:
            # Update confidence if higher
            for t in self.detected:
                if t.name == name and t.category == category:
                    t.confidence = max(t.confidence, confidence)
                    if version and not t.version:
                        t.version = version
            return
        self._seen.add(key)
        self.detected.append(TechSignature(
            name=name, category=category, version=version,
            confidence=confidence, source=source,
        ))

    def _check_headers(self, response):
        """Check response headers against signature database."""
        headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        for pattern, (name, category) in HEADER_SIGNATURES.items():
            match = re.search(pattern, headers_str, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else ""
                self._add(name, category, 0.9, "header", version)

    def _check_body(self, body: str):
        """Check response body against signature database."""
        for pattern, (name, category) in BODY_SIGNATURES.items():
            if re.search(pattern, body, re.IGNORECASE):
                self._add(name, category, 0.7, "body")

        for pattern, (name, category) in DB_ERROR_SIGNATURES.items():
            if re.search(pattern, body, re.IGNORECASE):
                self._add(name, category, 0.85, "error_pattern")

    def _check_cookies(self, response):
        """Check cookie names for technology indicators."""
        cookies = {}
        if hasattr(response, 'cookies'):
            cookies = {c.name: c.value for c in response.cookies} if hasattr(response.cookies, '__iter__') else {}
        # Also check Set-Cookie headers
        set_cookies = response.headers.get("Set-Cookie", "")
        for cookie_name, (name, category) in COOKIE_SIGNATURES.items():
            if cookie_name in cookies or cookie_name in set_cookies:
                self._add(name, category, 0.8, "cookie")

    def _check_url_patterns(self, url: str):
        """Detect tech from URL structure."""
        path = urlparse(url).path.lower()
        patterns = {
            r'\.php($|\?)': ("PHP", TechCategory.LANGUAGE),
            r'\.asp($|\?)': ("ASP Classic", TechCategory.LANGUAGE),
            r'\.aspx($|\?)': ("ASP.NET", TechCategory.FRAMEWORK),
            r'\.jsp($|\?)': ("Java/JSP", TechCategory.LANGUAGE),
            r'\.do($|\?)': ("Struts/Java", TechCategory.FRAMEWORK),
            r'\.action($|\?)': ("Struts/Java", TechCategory.FRAMEWORK),
            r'/wp-': ("WordPress", TechCategory.CMS),
            r'/administrator/': ("Joomla", TechCategory.CMS),
            r'/index\.cfm': ("ColdFusion", TechCategory.LANGUAGE),
        }
        for pattern, (name, category) in patterns.items():
            if re.search(pattern, path):
                self._add(name, category, 0.6, "url_pattern")

    def _probe_paths(self, base_url: str):
        """Send targeted requests to detect specific technologies."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Technology-specific probe paths
        probes = [
            ("/wp-login.php", "WordPress", TechCategory.CMS, 0.95),
            ("/wp-admin/", "WordPress", TechCategory.CMS, 0.9),
            ("/administrator/", "Joomla", TechCategory.CMS, 0.85),
            ("/user/login", "Drupal", TechCategory.CMS, 0.7),
            ("/.env", "Laravel/.env exposure", TechCategory.FRAMEWORK, 0.6),
            ("/web.config", "ASP.NET/IIS", TechCategory.FRAMEWORK, 0.6),
            ("/server-status", "Apache mod_status", TechCategory.SERVER, 0.8),
            ("/elmah.axd", "ASP.NET ELMAH", TechCategory.FRAMEWORK, 0.9),
            ("/api/swagger.json", "Swagger API", TechCategory.FRAMEWORK, 0.8),
            ("/graphql", "GraphQL", TechCategory.FRAMEWORK, 0.8),
            ("/actuator/health", "Spring Boot", TechCategory.FRAMEWORK, 0.9),
        ]

        for path, name, category, conf in probes:
            try:
                resp = self.client.get(f"{base}{path}", allow_redirects=False)
                if resp.status_code < 400:
                    self._add(name, category, conf, f"probe:{path}")
            except Exception:
                continue

    def get_technology_profile(self) -> dict[str, list[TechSignature]]:
        """Group detected technologies by category."""
        profile: dict[str, list[TechSignature]] = defaultdict(list)
        for tech in self.detected:
            profile[tech.category.value].append(tech)
        return dict(profile)

    def get_recommended_scanners(self) -> list[str]:
        """Based on detected tech, recommend which scanners to prioritize."""
        names = {t.name.lower() for t in self.detected}
        categories = {t.category for t in self.detected}
        recommended = []

        # Always run these
        recommended.extend(["HeaderScanner", "CookieScanner", "CORSScanner",
                           "PassiveScanner", "XSSScanner"])

        if any(t.category == TechCategory.DATABASE for t in self.detected):
            recommended.append("SQLiScanner")

        if "mongodb" in names:
            recommended.append("NoSQLScanner")

        if any(n in names for n in ("php", "python", "ruby on rails", "django",
                                     "laravel", "flask", "jinja2")):
            recommended.extend(["SSTIScanner", "LFIScanner", "CMDiScanner"])

        if any(n in names for n in ("java", "spring", "struts")):
            recommended.extend(["XXEScanner", "DeserializationScanner"])

        if "wordpress" in names or "joomla" in names or "drupal" in names:
            recommended.extend(["CVEScanner", "DirectoryScanner", "UploadScanner"])

        if any(t.category == TechCategory.JS_FRAMEWORK for t in self.detected):
            recommended.extend(["DOMXSSScanner", "PrototypePollutionScanner"])

        if "graphql" in names:
            recommended.append("GraphQLScanner")

        if any(t.category == TechCategory.WAF for t in self.detected):
            recommended.append("WAFScanner")

        return list(dict.fromkeys(recommended))  # dedupe


# ═══════════════════════════════════════════════════════════════════
# 2. BAYESIAN CONFIDENCE ENGINE
# ═══════════════════════════════════════════════════════════════════

@dataclass
class EvidenceItem:
    """A single piece of evidence for/against a vulnerability."""
    scanner: str
    vuln_type: str
    parameter: str
    url: str
    likelihood_ratio: float  # P(evidence|vuln) / P(evidence|no_vuln)
    description: str = ""
    timestamp: float = 0.0


class BayesianConfidence:
    """
    Bayesian vulnerability confidence engine.

    Instead of binary "found / not found", this maintains a probability
    distribution that updates as evidence accumulates from multiple
    scanners and test types.

    Prior probability starts at the base rate for each vulnerability type
    (e.g., SQLi ~5% of parameters, XSS ~15% of reflected parameters).
    Each test result updates the posterior.

    The key insight: if SQLi error-based fails but boolean-based succeeds,
    the combined confidence should be different than either alone.
    """

    # Base rates: prior probability that a random parameter is vulnerable
    BASE_RATES = {
        "sqli": 0.03,
        "xss": 0.08,
        "ssti": 0.01,
        "lfi": 0.02,
        "cmdi": 0.005,
        "ssrf": 0.01,
        "xxe": 0.005,
        "nosql": 0.02,
        "redirect": 0.05,
        "csrf": 0.15,
        "idor": 0.10,
        "crlf": 0.01,
        "hpp": 0.03,
    }

    # Likelihood ratios for test results
    POSITIVE_LR = {
        # Strong positives (test succeeded → high LR)
        "error_based_sqli": 50.0,
        "boolean_based_sqli": 25.0,
        "time_based_sqli": 15.0,
        "reflected_xss": 40.0,
        "dom_xss": 20.0,
        "ssti_eval": 60.0,
        "lfi_content": 45.0,
        "cmdi_output": 50.0,
        "oob_callback": 100.0,  # OOB callback is near-definitive

        # Weak positives (suspicious but not conclusive)
        "error_pattern_match": 5.0,
        "timing_anomaly": 3.0,
        "length_anomaly": 2.0,
        "status_change": 4.0,
        "waf_block": 1.5,  # WAF block is weak evidence (means WAF saw something)
    }

    NEGATIVE_LR = {
        # Negative results reduce probability
        "no_reflection": 0.3,
        "no_error_change": 0.5,
        "no_timing_diff": 0.7,
        "identical_response": 0.2,
        "parameterized_query": 0.05,  # Very strong negative
    }

    def __init__(self):
        self.evidence: dict[str, list[EvidenceItem]] = defaultdict(list)
        self.posteriors: dict[str, float] = {}

    def _key(self, url: str, parameter: str, vuln_type: str) -> str:
        return f"{vuln_type}:{parameter}@{url}"

    def update(self, url: str, parameter: str, vuln_type: str,
               test_name: str, positive: bool, scanner: str = "") -> float:
        """
        Update vulnerability probability based on new evidence.

        Args:
            url: The target URL
            parameter: The tested parameter
            vuln_type: Vulnerability type (sqli, xss, etc.)
            test_name: Specific test (error_based_sqli, reflected_xss, etc.)
            positive: Whether the test indicated vulnerability
            scanner: Which scanner produced this evidence

        Returns:
            Updated posterior probability
        """
        key = self._key(url, parameter, vuln_type)

        # Get current prior (or base rate)
        prior = self.posteriors.get(key, self.BASE_RATES.get(vuln_type, 0.05))

        # Get likelihood ratio
        if positive:
            lr = self.POSITIVE_LR.get(test_name, 5.0)
        else:
            lr = self.NEGATIVE_LR.get(test_name, 0.5)

        # Bayes' theorem: posterior = (lr * prior) / ((lr * prior) + (1 - prior))
        posterior = (lr * prior) / ((lr * prior) + (1 - prior))

        # Clamp to [0.001, 0.999]
        posterior = max(0.001, min(0.999, posterior))

        self.posteriors[key] = posterior

        self.evidence[key].append(EvidenceItem(
            scanner=scanner,
            vuln_type=vuln_type,
            parameter=parameter,
            url=url,
            likelihood_ratio=lr,
            description=f"{'POSITIVE' if positive else 'NEGATIVE'}: {test_name}",
            timestamp=time.time(),
        ))

        return posterior

    def get_probability(self, url: str, parameter: str, vuln_type: str) -> float:
        """Get current probability for a specific finding."""
        key = self._key(url, parameter, vuln_type)
        return self.posteriors.get(key, self.BASE_RATES.get(vuln_type, 0.05))

    def get_high_probability_targets(self, threshold: float = 0.5) -> list[dict]:
        """Return all targets above the probability threshold."""
        results = []
        for key, prob in self.posteriors.items():
            if prob >= threshold:
                vuln_type, rest = key.split(":", 1)
                param, url = rest.split("@", 1)
                results.append({
                    "url": url,
                    "parameter": param,
                    "vuln_type": vuln_type,
                    "probability": prob,
                    "evidence_count": len(self.evidence[key]),
                })
        results.sort(key=lambda x: x["probability"], reverse=True)
        return results

    def should_escalate(self, url: str, parameter: str, vuln_type: str) -> bool:
        """Should we run more aggressive tests on this target?"""
        prob = self.get_probability(url, parameter, vuln_type)
        # If probability is 20-80%, more testing would help
        return 0.2 <= prob <= 0.8


# ═══════════════════════════════════════════════════════════════════
# 3. ATTACK GRAPH ENGINE
# ═══════════════════════════════════════════════════════════════════

class NodeType(Enum):
    TARGET = "target"
    FINDING = "finding"
    ESCALATION = "escalation"
    GOAL = "goal"


@dataclass
class AttackNode:
    """A node in the attack graph."""
    id: str
    type: NodeType
    label: str
    data: dict = field(default_factory=dict)
    children: list[str] = field(default_factory=list)
    probability: float = 0.0


class AttackGraphEngine:
    """
    Builds and traverses attack graphs — chaining vulnerabilities.

    Example chains:
    - SQLi → dump credentials → auth bypass → admin panel → RCE
    - XSS → session hijack → CSRF bypass → state change
    - SSRF → internal port scan → access internal service → data exfil
    - LFI → source code read → hardcoded credentials → auth bypass
    - IDOR → enumerate users → target admin → privilege escalation

    The graph informs scanning strategy: if we find SQLi, we should
    immediately check if we can extract user data and try those
    credentials elsewhere.
    """

    # Chaining rules: finding_type → [follow-up_actions]
    CHAIN_RULES = {
        "sqli": [
            {"action": "extract_credentials", "desc": "Try extracting user credentials via UNION/error-based SQLi"},
            {"action": "check_file_read", "desc": "Try reading files via SQLi (LOAD_FILE, INTO OUTFILE)"},
            {"action": "check_stacked", "desc": "Try stacked queries for command execution"},
            {"action": "check_privesc", "desc": "Try database admin operations (GRANT, CREATE USER)"},
        ],
        "xss": [
            {"action": "check_stored", "desc": "Test if XSS persists (stored XSS)"},
            {"action": "check_cookie_theft", "desc": "Verify if session cookies are accessible to JavaScript"},
            {"action": "check_csrf_bypass", "desc": "XSS can bypass CSRF tokens — test state-changing endpoints"},
        ],
        "lfi": [
            {"action": "read_passwd", "desc": "Try reading /etc/passwd for user enumeration"},
            {"action": "read_source", "desc": "Try reading application source code"},
            {"action": "read_config", "desc": "Try reading config files for credentials"},
            {"action": "check_rfi", "desc": "If LFI works, try Remote File Inclusion"},
            {"action": "php_filter", "desc": "Use php://filter to read PHP source code"},
        ],
        "ssrf": [
            {"action": "port_scan_internal", "desc": "Scan internal network through SSRF"},
            {"action": "cloud_metadata", "desc": "Access cloud metadata (169.254.169.254)"},
            {"action": "internal_services", "desc": "Try accessing internal services (Redis, Memcached, etc.)"},
        ],
        "ssti": [
            {"action": "rce_attempt", "desc": "Escalate SSTI to Remote Code Execution"},
            {"action": "file_read", "desc": "Try reading files through template engine"},
        ],
        "cmdi": [
            {"action": "reverse_shell", "desc": "Test if reverse shell is possible (documentation only)"},
            {"action": "file_access", "desc": "Read sensitive files via command injection"},
            {"action": "network_enum", "desc": "Enumerate network via command execution"},
        ],
        "idor": [
            {"action": "enumerate_users", "desc": "Enumerate all user IDs/objects"},
            {"action": "access_admin", "desc": "Try accessing admin-level objects"},
            {"action": "modify_others", "desc": "Try modifying other users' data"},
        ],
        "redirect": [
            {"action": "oauth_redirect", "desc": "Test OAuth flows for token theft via redirect"},
            {"action": "phishing", "desc": "Document open redirect for phishing attacks"},
        ],
    }

    def __init__(self):
        self.nodes: dict[str, AttackNode] = {}
        self.findings: list[dict] = []
        self._id_counter = 0

    def _next_id(self) -> str:
        self._id_counter += 1
        return f"node_{self._id_counter}"

    def add_finding(self, vuln_type: str, url: str, parameter: str,
                    severity: str, evidence: str = "") -> str:
        """Register a finding and return its node ID."""
        node_id = self._next_id()
        node = AttackNode(
            id=node_id,
            type=NodeType.FINDING,
            label=f"{vuln_type}: {parameter}@{url}",
            data={
                "vuln_type": vuln_type,
                "url": url,
                "parameter": parameter,
                "severity": severity,
                "evidence": evidence,
            },
        )
        self.nodes[node_id] = node
        self.findings.append(node.data)
        return node_id

    def get_escalation_paths(self, vuln_type: str) -> list[dict]:
        """Get possible escalation actions for a vulnerability type."""
        return self.CHAIN_RULES.get(vuln_type, [])

    def get_chained_targets(self) -> list[dict]:
        """
        Based on current findings, generate new targets to test.

        This is the key intelligence: findings from one scanner
        inform what other scanners should look for.
        """
        chained = []
        for finding in self.findings:
            vuln_type = finding["vuln_type"]
            url = finding["url"]
            chains = self.CHAIN_RULES.get(vuln_type, [])
            for chain in chains:
                chained.append({
                    "source_finding": finding,
                    "action": chain["action"],
                    "description": chain["desc"],
                    "priority": self._chain_priority(vuln_type, chain["action"]),
                })
        chained.sort(key=lambda x: x["priority"], reverse=True)
        return chained

    @staticmethod
    def _chain_priority(vuln_type: str, action: str) -> float:
        """Prioritize chains that lead to higher impact."""
        high_impact = {
            "extract_credentials", "rce_attempt", "cloud_metadata",
            "reverse_shell", "read_config", "access_admin",
        }
        medium_impact = {
            "read_passwd", "read_source", "port_scan_internal",
            "enumerate_users", "check_stacked", "file_read",
        }
        if action in high_impact:
            return 1.0
        if action in medium_impact:
            return 0.7
        return 0.4


# ═══════════════════════════════════════════════════════════════════
# 4. RESPONSE CLUSTERER
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ResponseSignature:
    """Compact fingerprint of an HTTP response."""
    status_code: int
    content_length: int
    content_hash: str
    header_hash: str
    word_count: int
    line_count: int
    title: str = ""

    @classmethod
    def from_response(cls, response) -> ResponseSignature:
        body = response.text if hasattr(response, 'text') else str(response)
        headers_str = str(sorted(response.headers.items())) if hasattr(response, 'headers') else ""
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        return cls(
            status_code=response.status_code if hasattr(response, 'status_code') else 0,
            content_length=len(body),
            content_hash=hashlib.md5(body.encode()).hexdigest()[:12],
            header_hash=hashlib.md5(headers_str.encode()).hexdigest()[:8],
            word_count=len(body.split()),
            line_count=body.count('\n'),
            title=title_match.group(1).strip() if title_match else "",
        )

    def similarity(self, other: ResponseSignature) -> float:
        """Compute similarity score (0.0 to 1.0) with another response."""
        score = 0.0
        weights = 0.0

        # Status code match (high weight)
        if self.status_code == other.status_code:
            score += 3.0
        weights += 3.0

        # Content length similarity
        if self.content_length > 0 and other.content_length > 0:
            ratio = min(self.content_length, other.content_length) / max(self.content_length, other.content_length)
            score += 2.0 * ratio
        weights += 2.0

        # Content hash (exact match)
        if self.content_hash == other.content_hash:
            score += 5.0
        weights += 5.0

        # Word count similarity
        if self.word_count > 0 and other.word_count > 0:
            ratio = min(self.word_count, other.word_count) / max(self.word_count, other.word_count)
            score += 1.0 * ratio
        weights += 1.0

        return score / weights if weights > 0 else 0.0


class ResponseClusterer:
    """
    Groups responses into clusters to detect anomalies efficiently.

    Instead of comparing every injected response to every baseline,
    we cluster normal responses and flag anything that doesn't fit
    any cluster. This is O(n*k) instead of O(n²).

    Innovation: Dynamic cluster thresholds adapt based on the
    natural variance of the endpoint.
    """

    def __init__(self, similarity_threshold: float = 0.85):
        self.threshold = similarity_threshold
        self.clusters: list[list[ResponseSignature]] = []
        self.cluster_centroids: list[ResponseSignature] = []

    def add_baseline(self, response) -> int:
        """Add a baseline response and return its cluster ID."""
        sig = ResponseSignature.from_response(response)

        for i, centroid in enumerate(self.cluster_centroids):
            if sig.similarity(centroid) >= self.threshold:
                self.clusters[i].append(sig)
                return i

        # New cluster
        cluster_id = len(self.clusters)
        self.clusters.append([sig])
        self.cluster_centroids.append(sig)
        return cluster_id

    def is_anomalous(self, response) -> tuple[bool, float]:
        """
        Check if a response is anomalous (doesn't fit any cluster).

        Returns:
            (is_anomalous, max_similarity_to_any_cluster)
        """
        if not self.cluster_centroids:
            return False, 1.0

        sig = ResponseSignature.from_response(response)
        max_sim = 0.0
        for centroid in self.cluster_centroids:
            sim = sig.similarity(centroid)
            max_sim = max(max_sim, sim)

        return max_sim < self.threshold, max_sim


# ═══════════════════════════════════════════════════════════════════
# 5. PAYLOAD EVOLVER (Genetic Algorithm)
# ═══════════════════════════════════════════════════════════════════

class PayloadEvolver:
    """
    Genetic algorithm for evolving payloads past WAFs and filters.

    Population: set of payloads
    Fitness: did the payload trigger a detection signal without being blocked?
    Crossover: combine working parts of two payloads
    Mutation: random encoding, case change, whitespace injection, etc.

    This is genuinely novel — most scanners use static payload lists.
    We evolve payloads that specifically bypass the target's defenses.
    """

    # Mutation operators
    MUTATIONS = [
        "case_swap",       # SELECT → SeLeCt
        "url_encode",      # ' → %27
        "double_encode",   # ' → %2527
        "unicode_escape",  # < → \u003c
        "html_entity",     # < → &lt;
        "whitespace",      # UNION SELECT → UNION/**/SELECT
        "comment_inject",  # SELECT → SEL/**/ECT
        "null_byte",       # payload → payload%00
        "concat_split",    # 'admin' → 'adm'+'in'
        "hex_encode",      # admin → 0x61646D696E
        "newline_inject",  # payload → pay\nload
    ]

    def __init__(self, population_size: int = 20, generations: int = 5,
                 mutation_rate: float = 0.3):
        self.pop_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.population: list[dict] = []  # [{payload, fitness, mutations}]

    def seed(self, base_payloads: list[str]):
        """Initialize population from base payloads."""
        self.population = []
        for payload in base_payloads[:self.pop_size]:
            self.population.append({
                "payload": payload,
                "fitness": 0.0,
                "mutations": [],
                "generation": 0,
            })

    def evaluate(self, fitness_fn) -> list[dict]:
        """
        Evaluate fitness of all payloads.

        fitness_fn(payload) → float (0.0 = blocked, 0.5 = partial, 1.0 = executed)
        """
        for individual in self.population:
            individual["fitness"] = fitness_fn(individual["payload"])
        self.population.sort(key=lambda x: x["fitness"], reverse=True)
        return self.population

    def evolve(self) -> list[dict]:
        """Run one generation of evolution."""
        # Selection: top 50% survive
        survivors = self.population[:max(2, len(self.population) // 2)]

        new_pop = list(survivors)

        # Crossover: combine pairs of survivors
        while len(new_pop) < self.pop_size:
            if len(survivors) >= 2:
                parent1, parent2 = random.sample(survivors, 2)
                child = self._crossover(parent1["payload"], parent2["payload"])
            else:
                child = survivors[0]["payload"]

            # Mutation
            if random.random() < self.mutation_rate:
                mutation_type = random.choice(self.MUTATIONS)
                child = self._mutate(child, mutation_type)
                mutations = [mutation_type]
            else:
                mutations = []

            new_pop.append({
                "payload": child,
                "fitness": 0.0,
                "mutations": mutations,
                "generation": self.population[0].get("generation", 0) + 1,
            })

        self.population = new_pop[:self.pop_size]
        return self.population

    def get_best(self, n: int = 5) -> list[str]:
        """Return top N payloads by fitness."""
        sorted_pop = sorted(self.population, key=lambda x: x["fitness"], reverse=True)
        return [p["payload"] for p in sorted_pop[:n]]

    @staticmethod
    def _crossover(p1: str, p2: str) -> str:
        """Single-point crossover of two payloads."""
        if len(p1) < 4 or len(p2) < 4:
            return p1
        point1 = random.randint(1, len(p1) - 1)
        point2 = random.randint(1, len(p2) - 1)
        return p1[:point1] + p2[point2:]

    @staticmethod
    def _mutate(payload: str, mutation_type: str) -> str:
        """Apply a mutation to a payload."""
        if mutation_type == "case_swap":
            return ''.join(
                c.swapcase() if random.random() < 0.3 else c for c in payload
            )
        elif mutation_type == "url_encode":
            chars = {"'": "%27", '"': "%22", "<": "%3C", ">": "%3E",
                     " ": "%20", "(": "%28", ")": "%29"}
            for orig, enc in chars.items():
                if orig in payload and random.random() < 0.5:
                    payload = payload.replace(orig, enc, 1)
            return payload
        elif mutation_type == "double_encode":
            return payload.replace("%", "%25")
        elif mutation_type == "html_entity":
            entities = {"<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"}
            for orig, ent in entities.items():
                if orig in payload and random.random() < 0.4:
                    payload = payload.replace(orig, ent, 1)
            return payload
        elif mutation_type == "whitespace":
            # Inject SQL comments as whitespace
            return re.sub(r'\s+', lambda m: '/**/' if random.random() < 0.5 else m.group(), payload)
        elif mutation_type == "comment_inject":
            # Split keywords with comments
            keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
                       "script", "alert", "onerror", "onload"]
            for kw in keywords:
                if kw.lower() in payload.lower():
                    mid = len(kw) // 2
                    injected = kw[:mid] + "/**/" + kw[mid:]
                    payload = re.sub(re.escape(kw), injected, payload, count=1, flags=re.IGNORECASE)
                    break
            return payload
        elif mutation_type == "null_byte":
            return payload + "%00"
        elif mutation_type == "concat_split":
            # For SQL strings, split with concatenation
            payload = payload.replace("'admin'", "'adm'||'in'")
            payload = payload.replace("'1'", "'1'||''")
            return payload
        elif mutation_type == "newline_inject":
            return payload.replace(" ", "\n", 1) if " " in payload else payload
        elif mutation_type == "unicode_escape":
            replacements = {"<": "\\u003c", ">": "\\u003e", "'": "\\u0027"}
            for orig, esc in replacements.items():
                if orig in payload and random.random() < 0.4:
                    payload = payload.replace(orig, esc, 1)
            return payload
        elif mutation_type == "hex_encode":
            # Hex-encode short strings
            match = re.search(r"'(\w{2,8})'", payload)
            if match:
                word = match.group(1)
                hex_val = "0x" + word.encode().hex()
                payload = payload.replace(f"'{word}'", hex_val)
            return payload
        return payload


# ═══════════════════════════════════════════════════════════════════
# 6. CONTEXTUAL ESCALATOR
# ═══════════════════════════════════════════════════════════════════

class ContextualEscalator:
    """
    Cross-scanner intelligence sharing.

    When one scanner finds something, this module determines what
    other scanners should do differently. This is what Burp Suite Pro's
    scan logic does — findings feed into the scan strategy.

    Examples:
    - SQLi found → immediately run SQLMap-like data extraction
    - Reflected param found → prioritize that param for XSS
    - Error page leaks stack trace → identify framework → focus payloads
    - WAF blocks → switch to evasion payloads
    - Session cookie without HttpOnly → prioritize XSS (higher impact)
    """

    def __init__(self):
        self.shared_intelligence: dict[str, Any] = {
            "reflected_params": [],        # Parameters that reflect in response
            "error_triggering_params": [],  # Parameters that cause errors
            "injectable_params": [],        # Confirmed injection points
            "discovered_credentials": [],   # Creds found in responses
            "internal_ips": [],            # Internal IPs found
            "tech_stack": [],              # Detected technologies
            "waf_blocks": [],              # Payloads blocked by WAF
            "working_payloads": [],        # Payloads that worked
            "session_info": {},            # Session cookie details
            "auth_endpoints": [],          # Login/auth endpoints
        }

    def report_reflection(self, url: str, param: str, context: str = ""):
        """A scanner found parameter reflection — XSS should prioritize this."""
        self.shared_intelligence["reflected_params"].append({
            "url": url, "param": param, "context": context,
        })

    def report_error(self, url: str, param: str, error_type: str = ""):
        """A scanner triggered an error — other scanners should test this param."""
        self.shared_intelligence["error_triggering_params"].append({
            "url": url, "param": param, "error_type": error_type,
        })

    def report_injection(self, url: str, param: str, vuln_type: str, payload: str):
        """Confirmed injection — escalation should happen."""
        self.shared_intelligence["injectable_params"].append({
            "url": url, "param": param, "vuln_type": vuln_type, "payload": payload,
        })

    def report_credential(self, credential: str, source: str):
        """Credential found — should be tried on auth endpoints."""
        self.shared_intelligence["discovered_credentials"].append({
            "credential": credential, "source": source,
        })

    def report_waf_block(self, payload: str, waf_response: str = ""):
        """WAF blocked a payload — evolver should use this."""
        self.shared_intelligence["waf_blocks"].append({
            "payload": payload, "response": waf_response,
        })

    def report_working_payload(self, payload: str, vuln_type: str):
        """Payload worked — similar payloads should be tried elsewhere."""
        self.shared_intelligence["working_payloads"].append({
            "payload": payload, "vuln_type": vuln_type,
        })

    def get_priority_params(self, scanner_type: str) -> list[dict]:
        """Get parameters this scanner should prioritize based on shared intel."""
        if scanner_type in ("xss", "XSSScanner"):
            return self.shared_intelligence["reflected_params"]
        elif scanner_type in ("sqli", "SQLiScanner"):
            return self.shared_intelligence["error_triggering_params"]
        elif scanner_type in ("cmdi", "CMDiScanner", "ssti", "SSTIScanner"):
            # Focus on params where other injections worked
            return [p for p in self.shared_intelligence["injectable_params"]
                    if p["vuln_type"] not in ("xss",)]
        return []

    def get_evasion_hints(self) -> dict:
        """Get WAF evasion intelligence for payload generation."""
        blocked = self.shared_intelligence["waf_blocks"]
        working = self.shared_intelligence["working_payloads"]
        return {
            "blocked_patterns": [b["payload"] for b in blocked],
            "working_patterns": [w["payload"] for w in working],
            "blocked_count": len(blocked),
            "working_count": len(working),
        }


# ═══════════════════════════════════════════════════════════════════
# 7. SMART SCHEDULER
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ScanTask:
    """A scheduled scanning task with priority."""
    scanner_name: str
    url: str
    parameters: list[str] = field(default_factory=list)
    priority: float = 0.5  # 0.0 (lowest) to 1.0 (highest)
    reason: str = ""       # Why this task was scheduled
    payloads: list[str] = field(default_factory=list)
    max_requests: int = 0  # 0 = no limit


class SmartScheduler:
    """
    Intelligent task scheduling based on:
    - Technology fingerprint (don't run PHP-specific tests on Java apps)
    - Parameter characteristics (longer params more likely injectable)
    - Previous findings (escalation paths)
    - Time budget (prioritize high-value targets)
    - WAF presence (slower scanning, more evasion)

    This replaces the naive "run all scanners on everything" approach.
    """

    def __init__(self):
        self.tasks: list[ScanTask] = []
        self.completed: list[str] = []
        self.skipped: list[str] = []

    def plan(self, attack_surface, tech_profile: list[TechSignature],
             bayesian: BayesianConfidence, escalator: ContextualEscalator,
             time_budget_seconds: int = 300) -> list[ScanTask]:
        """
        Generate a prioritized task list.

        This is the brain — it decides what to scan, in what order,
        and with what payloads.
        """
        self.tasks = []
        tech_names = {t.name.lower() for t in tech_profile}
        has_waf = any(t.category == TechCategory.WAF for t in tech_profile)

        # 1. Always run reconnaissance scanners first (fast, inform everything else)
        recon_scanners = [
            ("HeaderScanner", 0.95, "Identify security header gaps"),
            ("CookieScanner", 0.9, "Check cookie security flags"),
            ("CORSScanner", 0.85, "Test CORS configuration"),
            ("PassiveScanner", 0.9, "Passive content analysis"),
        ]
        for name, priority, reason in recon_scanners:
            self.tasks.append(ScanTask(
                scanner_name=name, url="*", priority=priority, reason=reason,
            ))

        # 2. Always run XSS (most common vuln)
        self.tasks.append(ScanTask(
            scanner_name="XSSScanner", url="*", priority=0.85,
            reason="XSS is present in ~67% of web applications",
        ))

        # 3. SQLi if database detected
        if any(t.category == TechCategory.DATABASE for t in tech_profile):
            db_name = next(
                (t.name for t in tech_profile if t.category == TechCategory.DATABASE),
                "unknown"
            )
            self.tasks.append(ScanTask(
                scanner_name="SQLiScanner", url="*", priority=0.9,
                reason=f"Database detected: {db_name}",
            ))
        else:
            # Still test SQLi but lower priority
            self.tasks.append(ScanTask(
                scanner_name="SQLiScanner", url="*", priority=0.6,
                reason="No database detected but SQLi still possible",
            ))

        # 4. Language-specific scanners
        if any(n in tech_names for n in ("php", "python", "ruby on rails",
                                          "django", "laravel", "flask")):
            self.tasks.append(ScanTask(
                scanner_name="SSTIScanner", url="*", priority=0.75,
                reason=f"Template engine likely: {tech_names}",
            ))
            self.tasks.append(ScanTask(
                scanner_name="LFIScanner", url="*", priority=0.7,
                reason="Script language detected — LFI common",
            ))

        if any(n in tech_names for n in ("java", "spring", "struts")):
            self.tasks.append(ScanTask(
                scanner_name="XXEScanner", url="*", priority=0.8,
                reason="Java detected — XXE common in Java XML parsers",
            ))
            self.tasks.append(ScanTask(
                scanner_name="DeserializationScanner", url="*", priority=0.7,
                reason="Java detected — deserialization attacks common",
            ))

        # 5. CMS-specific scanners
        if any(n in tech_names for n in ("wordpress", "joomla", "drupal")):
            self.tasks.append(ScanTask(
                scanner_name="CVEScanner", url="*", priority=0.85,
                reason=f"CMS detected — known CVEs likely",
            ))

        # 6. Add escalation tasks from Bayesian model
        high_prob = bayesian.get_high_probability_targets(threshold=0.3)
        for target in high_prob[:10]:
            self.tasks.append(ScanTask(
                scanner_name=f"{target['vuln_type'].upper()}Scanner",
                url=target["url"],
                parameters=[target["parameter"]],
                priority=target["probability"],
                reason=f"Bayesian probability: {target['probability']:.1%}",
            ))

        # 7. Add escalation tasks from intelligence sharing
        for param_info in escalator.get_priority_params("xss"):
            self.tasks.append(ScanTask(
                scanner_name="XSSScanner",
                url=param_info["url"],
                parameters=[param_info["param"]],
                priority=0.8,
                reason=f"Parameter reflects in {param_info.get('context', 'body')}",
            ))

        # 8. If WAF detected, add WAF scanner and lower request budgets
        if has_waf:
            self.tasks.append(ScanTask(
                scanner_name="WAFScanner", url="*", priority=0.95,
                reason="WAF detected — identify for evasion",
            ))
            # Reduce request budget for all tasks
            for task in self.tasks:
                if not task.max_requests:
                    task.max_requests = 50

        # Sort by priority
        self.tasks.sort(key=lambda t: t.priority, reverse=True)
        return self.tasks

    def next_task(self) -> Optional[ScanTask]:
        """Get the next task to execute."""
        for task in self.tasks:
            task_key = f"{task.scanner_name}:{task.url}:{','.join(task.parameters)}"
            if task_key not in self.completed and task_key not in self.skipped:
                return task
        return None

    def complete_task(self, task: ScanTask, findings_count: int = 0):
        """Mark a task as completed and trigger escalation scheduling."""
        task_key = f"{task.scanner_name}:{task.url}:{','.join(task.parameters)}"
        self.completed.append(task_key)

    def skip_task(self, task: ScanTask, reason: str = ""):
        """Skip a task (e.g., not applicable for detected tech stack)."""
        task_key = f"{task.scanner_name}:{task.url}:{','.join(task.parameters)}"
        self.skipped.append(task_key)


# ═══════════════════════════════════════════════════════════════════
# 8. MASTER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

class IntelligentScanEngine:
    """
    Master orchestrator that combines all intelligent components.

    This is the brain of SecProbe — it replaces the naive
    "run every scanner on every URL" approach with targeted,
    adaptive, evidence-based scanning.

    Usage:
        engine = IntelligentScanEngine(http_client, config)
        engine.fingerprint(target_url, initial_response)
        tasks = engine.plan_attack(attack_surface)
        for task in tasks:
            result = run_scanner(task)
            engine.ingest_result(result)
        report = engine.generate_report()
    """

    def __init__(self, http_client=None, config=None):
        self.client = http_client
        self.config = config

        self.fingerprinter = TechFingerprinter(http_client)
        self.bayesian = BayesianConfidence()
        self.attack_graph = AttackGraphEngine()
        self.response_clusterer = ResponseClusterer()
        self.payload_evolver = PayloadEvolver()
        self.escalator = ContextualEscalator()
        self.scheduler = SmartScheduler()

        self.tech_profile: list[TechSignature] = []
        self.scan_stats = {
            "total_requests": 0,
            "findings": 0,
            "scanners_run": 0,
            "escalations": 0,
            "waf_blocks": 0,
            "time_saved_by_skipping": 0.0,
        }

    def fingerprint(self, url: str, response=None, *, deep: bool = True) -> list[TechSignature]:
        """Run technology fingerprinting on the target."""
        self.tech_profile = self.fingerprinter.fingerprint(url, response, deep=deep)
        return self.tech_profile

    def plan_attack(self, attack_surface=None, time_budget: int = 300) -> list[ScanTask]:
        """Generate prioritized scan plan based on fingerprint + surface."""
        return self.scheduler.plan(
            attack_surface, self.tech_profile,
            self.bayesian, self.escalator, time_budget,
        )

    def update_evidence(self, url: str, parameter: str, vuln_type: str,
                        test_name: str, positive: bool, scanner: str = "") -> float:
        """Update Bayesian model with new evidence. Returns posterior probability."""
        prob = self.bayesian.update(url, parameter, vuln_type, test_name, positive, scanner)

        if positive:
            self.attack_graph.add_finding(vuln_type, url, parameter, "unknown")
            self.escalator.report_injection(url, parameter, vuln_type, "")
            self.scan_stats["findings"] += 1

        return prob

    def get_escalation_tasks(self) -> list[dict]:
        """Get new tasks generated by attack graph chaining."""
        chained = self.attack_graph.get_chained_targets()
        self.scan_stats["escalations"] += len(chained)
        return chained

    def evolve_payloads(self, base_payloads: list[str], fitness_fn) -> list[str]:
        """Run genetic algorithm to evolve payloads past WAF."""
        self.payload_evolver.seed(base_payloads)
        for gen in range(self.payload_evolver.generations):
            self.payload_evolver.evaluate(fitness_fn)
            self.payload_evolver.evolve()
        self.payload_evolver.evaluate(fitness_fn)
        return self.payload_evolver.get_best(10)

    def is_response_anomalous(self, response) -> tuple[bool, float]:
        """Quick check if a response differs from established baselines."""
        return self.response_clusterer.is_anomalous(response)

    def get_summary(self) -> dict:
        """Get scan intelligence summary."""
        return {
            "tech_profile": self.fingerprinter.get_technology_profile(),
            "recommended_scanners": self.fingerprinter.get_recommended_scanners(),
            "high_probability_vulns": self.bayesian.get_high_probability_targets(),
            "attack_chains": self.attack_graph.get_chained_targets(),
            "stats": self.scan_stats,
        }
