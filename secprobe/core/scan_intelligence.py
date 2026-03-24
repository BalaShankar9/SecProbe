"""
Scan Intelligence Engine — Adaptive scanning behavior modeled after Burp Suite.

What makes Burp Suite's scanner smart:
1. **Technology Fingerprinting** → Only run relevant scanners
2. **Insertion Point Prioritization** → Test most likely vuln params first
3. **Adaptive Payload Ordering** → Success on one param → prioritize similar ones
4. **Finding Correlation** → Link related findings into attack chains
5. **Duplicate Suppression** → Don't re-report same vuln type on same endpoint
6. **Scan Scorecard** → Track scanner effectiveness for tuning

This module provides:
  - TechProfile: What technologies are running (server, language, framework, WAF)
  - ScanPlanner: Decides which scanners to run & in what order
  - InsertionPointScorer: Ranks parameters by vulnerability likelihood
  - ScanScorecard: Tracks scan effectiveness metrics
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
from collections import Counter

from secprobe.core.logger import get_logger

log = get_logger("scan_intelligence")


# ═══════════════════════════════════════════════════════════════════════
# Technology Profile — Know your target
# ═══════════════════════════════════════════════════════════════════════

class ServerType(Enum):
    APACHE = "Apache"
    NGINX = "Nginx"
    IIS = "IIS"
    TOMCAT = "Tomcat"
    GUNICORN = "Gunicorn"
    UNKNOWN = "Unknown"


class Language(Enum):
    PHP = "PHP"
    PYTHON = "Python"
    JAVA = "Java"
    DOTNET = ".NET"
    NODEJS = "Node.js"
    RUBY = "Ruby"
    GO = "Go"
    UNKNOWN = "Unknown"


class Framework(Enum):
    DJANGO = "Django"
    FLASK = "Flask"
    LARAVEL = "Laravel"
    WORDPRESS = "WordPress"
    RAILS = "Rails"
    SPRING = "Spring"
    EXPRESS = "Express"
    ASP_NET = "ASP.NET"
    UNKNOWN = "Unknown"


@dataclass
class TechProfile:
    """
    Technology fingerprint of target.
    Built from response headers, error pages, cookies, etc.
    """
    server: ServerType = ServerType.UNKNOWN
    language: Language = Language.UNKNOWN
    framework: Framework = Framework.UNKNOWN
    waf_detected: bool = False
    waf_name: str = ""
    cms: str = ""
    js_frameworks: list[str] = field(default_factory=list)
    headers_seen: dict[str, str] = field(default_factory=dict)
    cookies_seen: list[str] = field(default_factory=list)
    
    # Detection evidence
    confidence: float = 0.0  # 0-1 overall confidence
    evidence: list[str] = field(default_factory=list)

    @classmethod
    def from_response(cls, headers: dict, body: str = "", 
                      cookies: list[str] = None) -> TechProfile:
        """Build a tech profile from an HTTP response."""
        profile = cls()
        profile.headers_seen = dict(headers)
        profile.cookies_seen = cookies or []
        
        # Server detection
        server_header = headers.get("Server", headers.get("server", ""))
        profile.server = cls._detect_server(server_header)
        
        # Language detection from headers
        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        profile.language = cls._detect_language(powered_by, headers, body)
        
        # Framework detection
        profile.framework = cls._detect_framework(headers, body, cookies or [])
        
        # WAF detection from headers
        profile.waf_detected, profile.waf_name = cls._detect_waf(headers)
        
        # JS framework detection from body
        if body:
            profile.js_frameworks = cls._detect_js_frameworks(body)
        
        profile.confidence = cls._calc_confidence(profile)
        return profile

    @staticmethod
    def _detect_server(server_header: str) -> ServerType:
        h = server_header.lower()
        if "apache" in h:
            return ServerType.APACHE
        if "nginx" in h:
            return ServerType.NGINX
        if "iis" in h or "microsoft" in h:
            return ServerType.IIS
        if "tomcat" in h:
            return ServerType.TOMCAT
        if "gunicorn" in h:
            return ServerType.GUNICORN
        return ServerType.UNKNOWN

    @staticmethod
    def _detect_language(powered_by: str, headers: dict, body: str) -> Language:
        pb = powered_by.lower()
        if "php" in pb:
            return Language.PHP
        if "asp.net" in pb:
            return Language.DOTNET
        if "express" in pb:
            return Language.NODEJS
        
        # Header-based clues
        if "x-aspnet-version" in {k.lower() for k in headers}:
            return Language.DOTNET
        
        # Body-based clues
        if body:
            bl = body.lower()
            if "wp-content" in bl or "wordpress" in bl:
                return Language.PHP
            if "csrfmiddlewaretoken" in bl:
                return Language.PYTHON
            if "jsessionid" in bl.lower():
                return Language.JAVA
        
        return Language.UNKNOWN

    @staticmethod
    def _detect_framework(headers: dict, body: str, cookies: list[str]) -> Framework:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        cookies_str = " ".join(cookies).lower()
        body_lower = body.lower() if body else ""
        
        # Django
        if "csrfmiddlewaretoken" in body_lower or "csrftoken" in cookies_str:
            return Framework.DJANGO
        
        # Flask
        if "werkzeug" in headers_lower.get("server", "").lower():
            return Framework.FLASK
        
        # Laravel
        if "laravel_session" in cookies_str or "xsrf-token" in cookies_str:
            return Framework.LARAVEL
        
        # WordPress
        if "wp-content" in body_lower or "wp-json" in body_lower:
            return Framework.WORDPRESS
        
        # Rails
        if "_rails_session" in cookies_str or "x-request-id" in headers_lower:
            return Framework.RAILS
        
        # Spring
        if "jsessionid" in cookies_str and "x-application-context" in headers_lower:
            return Framework.SPRING
        
        # ASP.NET
        if "asp.net_sessionid" in cookies_str or "__viewstate" in body_lower:
            return Framework.ASP_NET
        
        # Express
        if "express" in headers_lower.get("x-powered-by", "").lower():
            return Framework.EXPRESS
        
        return Framework.UNKNOWN

    @staticmethod
    def _detect_waf(headers: dict) -> tuple[bool, str]:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        all_headers = " ".join(f"{k}: {v}" for k, v in headers_lower.items())
        
        waf_signatures = {
            "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
            "akamai": ["x-akamai-", "akamai-"],
            "aws-waf": ["x-amzn-waf-", "awselb"],
            "imperva": ["x-iinfo", "incap_ses"],
            "f5-big-ip": ["x-wa-info", "bigipserver"],
            "sucuri": ["x-sucuri-id"],
            "wordfence": ["wordfence"],
        }
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in all_headers:
                    return True, waf_name
        return False, ""

    @staticmethod
    def _detect_js_frameworks(body: str) -> list[str]:
        frameworks = []
        checks = {
            "React": [r'react(?:\.min)?\.js', r'data-reactroot', r'__NEXT_DATA__'],
            "Angular": [r'ng-(?:app|controller|model)', r'angular(?:\.min)?\.js'],
            "Vue.js": [r'vue(?:\.min)?\.js', r'v-(?:if|for|model|bind)', r'__VUE__'],
            "jQuery": [r'jquery(?:\.min)?\.js', r'\$\(document\)\.ready'],
            "Bootstrap": [r'bootstrap(?:\.min)?\.(?:js|css)'],
        }
        for name, patterns in checks.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    frameworks.append(name)
                    break
        return frameworks

    @staticmethod
    def _calc_confidence(profile: TechProfile) -> float:
        score = 0.0
        if profile.server != ServerType.UNKNOWN:
            score += 0.2
        if profile.language != Language.UNKNOWN:
            score += 0.3
        if profile.framework != Framework.UNKNOWN:
            score += 0.3
        if profile.js_frameworks:
            score += 0.1
        if profile.waf_detected:
            score += 0.1
        return min(1.0, score)


# ═══════════════════════════════════════════════════════════════════════
# Scan Planner — Decide what to scan and in what order
# ═══════════════════════════════════════════════════════════════════════

# Scanner relevance by technology (which scanners to prioritize)
SCANNER_RELEVANCE = {
    Language.PHP: {
        "high": ["sqli", "lfi", "xss", "ssti", "upload", "deserialization"],
        "medium": ["xxe", "cmdi", "csrf", "crlf"],
        "low": ["nosql", "graphql", "websocket"],
    },
    Language.PYTHON: {
        "high": ["ssti", "cmdi", "sqli", "xss", "ssrf"],
        "medium": ["nosql", "deserialization", "lfi"],
        "low": ["xxe", "upload"],
    },
    Language.JAVA: {
        "high": ["sqli", "xxe", "deserialization", "ssti", "ssrf"],
        "medium": ["xss", "cmdi", "lfi"],
        "low": ["nosql", "prototype_pollution"],
    },
    Language.DOTNET: {
        "high": ["sqli", "xss", "xxe", "deserialization"],
        "medium": ["cmdi", "ssrf", "lfi"],
        "low": ["ssti", "nosql"],
    },
    Language.NODEJS: {
        "high": ["xss", "nosql", "ssti", "prototype_pollution", "ssrf"],
        "medium": ["cmdi", "sqli", "deserialization"],
        "low": ["xxe", "lfi"],
    },
    Language.RUBY: {
        "high": ["sqli", "xss", "ssti", "cmdi", "deserialization"],
        "medium": ["ssrf", "lfi", "csrf"],
        "low": ["nosql", "xxe"],
    },
}


@dataclass
class ScanPlan:
    """Ordered list of scanners to run with rationale."""
    ordered_scanners: list[str] = field(default_factory=list)
    skipped_scanners: list[tuple[str, str]] = field(default_factory=list)  # (name, reason)
    tech_profile: Optional[TechProfile] = None
    priority_reasons: dict[str, str] = field(default_factory=dict)


class ScanPlanner:
    """
    Decides which scanners to run and in what order based on target intelligence.
    
    Like Burp's scan strategy — adapts to the target instead of blindly
    running everything in alphabetical order.
    """

    # Always run these regardless of technology
    ALWAYS_RUN = {
        "header", "cookie", "cors", "ssl", "passive",
        "directory", "tech", "waf",
    }

    # Don't run these if WAF is detected (waste of time)
    SKIP_IF_WAF = {
        "fuzzer",  # WAF will block fuzzing
    }

    @classmethod
    def plan(cls, tech_profile: TechProfile,
             available_scanners: list[str],
             skip_passive: bool = False) -> ScanPlan:
        """
        Create an optimized scan plan based on target technology.
        
        Args:
            tech_profile: Technology fingerprint
            available_scanners: All scanner names available
            skip_passive: Skip passive/info-gathering scanners
            
        Returns:
            ScanPlan with ordered scanner list
        """
        plan = ScanPlan(tech_profile=tech_profile)
        
        # Categorize scanners by priority
        high_priority = []
        medium_priority = []
        low_priority = []
        always_run = []
        skipped = []
        
        relevance = SCANNER_RELEVANCE.get(tech_profile.language, {})
        high_relevant = set(relevance.get("high", []))
        medium_relevant = set(relevance.get("medium", []))
        low_relevant = set(relevance.get("low", []))
        
        for scanner_name in available_scanners:
            name_lower = scanner_name.lower().replace("scanner", "").strip()
            
            # Skip passive scanners if requested
            if skip_passive and name_lower in ("passive", "tech", "header", "cookie"):
                skipped.append((scanner_name, "passive skipped"))
                continue
            
            # Skip if WAF detected and scanner is in skip list
            if tech_profile.waf_detected and name_lower in cls.SKIP_IF_WAF:
                skipped.append((scanner_name, f"WAF ({tech_profile.waf_name}) detected"))
                continue
            
            # Always run
            if name_lower in cls.ALWAYS_RUN:
                always_run.append(scanner_name)
                plan.priority_reasons[scanner_name] = "always run"
                continue
            
            # Technology-based priority
            if name_lower in high_relevant or any(h in name_lower for h in high_relevant):
                high_priority.append(scanner_name)
                plan.priority_reasons[scanner_name] = f"high priority for {tech_profile.language.value}"
            elif name_lower in medium_relevant or any(m in name_lower for m in medium_relevant):
                medium_priority.append(scanner_name)
                plan.priority_reasons[scanner_name] = f"medium priority for {tech_profile.language.value}"
            elif name_lower in low_relevant or any(l in name_lower for l in low_relevant):
                low_priority.append(scanner_name)
                plan.priority_reasons[scanner_name] = f"low priority for {tech_profile.language.value}"
            else:
                medium_priority.append(scanner_name)
                plan.priority_reasons[scanner_name] = "default priority"
        
        # Build final ordered list
        plan.ordered_scanners = always_run + high_priority + medium_priority + low_priority
        plan.skipped_scanners = skipped
        
        return plan


# ═══════════════════════════════════════════════════════════════════════
# Insertion Point Scorer — Rank parameters by vuln likelihood
# ═══════════════════════════════════════════════════════════════════════

# Parameter names that are historically more vulnerable
SUSPICIOUS_PARAMS = {
    # SQL injection magnets
    "id": 0.9, "uid": 0.9, "user_id": 0.9, "item_id": 0.9,
    "category": 0.8, "cat": 0.8, "page": 0.8, "num": 0.8,
    "sort": 0.7, "order": 0.7, "limit": 0.7, "offset": 0.7,
    "filter": 0.7, "where": 0.9, "column": 0.8,
    
    # XSS / reflection magnets
    "q": 0.9, "query": 0.9, "search": 0.9, "s": 0.8,
    "keyword": 0.8, "term": 0.8, "name": 0.7, "title": 0.7,
    "message": 0.8, "msg": 0.8, "comment": 0.8, "text": 0.7,
    "content": 0.7, "body": 0.7, "desc": 0.7, "description": 0.7,
    
    # Redirect magnets
    "url": 0.95, "redirect": 0.95, "return": 0.9, "next": 0.9,
    "goto": 0.95, "dest": 0.9, "destination": 0.9, "rurl": 0.9,
    "return_to": 0.9, "continue": 0.8, "returnurl": 0.9,
    
    # LFI/path traversal magnets  
    "file": 0.95, "path": 0.9, "template": 0.9, "page": 0.85,
    "include": 0.95, "dir": 0.9, "document": 0.8, "folder": 0.8,
    "root": 0.8, "pg": 0.7, "style": 0.6, "lang": 0.7,
    
    # SSRF magnets
    "url": 0.95, "uri": 0.9, "host": 0.85, "link": 0.8,
    "src": 0.8, "img": 0.7, "load": 0.7, "fetch": 0.8,
    
    # Command injection magnets
    "cmd": 0.95, "exec": 0.95, "command": 0.95, "run": 0.9,
    "ping": 0.9, "ip": 0.8, "host": 0.8, "domain": 0.7,
}


@dataclass
class ScoredParam:
    """Parameter with vulnerability score."""
    name: str
    score: float  # 0.0 - 1.0
    reasons: list[str] = field(default_factory=list)
    vuln_types: list[str] = field(default_factory=list)  # predicted vuln types


class InsertionPointScorer:
    """
    Score and rank parameters by vulnerability likelihood.
    
    Like Burp's insertion point analysis — test the most likely
    vulnerable parameters first to find vulns faster.
    """

    @classmethod
    def score_param(cls, param_name: str, param_value: str = "",
                    context: str = "") -> ScoredParam:
        """Score a single parameter."""
        name_lower = param_name.lower().strip()
        scored = ScoredParam(name=param_name, score=0.0)
        
        # Name-based score
        if name_lower in SUSPICIOUS_PARAMS:
            scored.score = SUSPICIOUS_PARAMS[name_lower]
            scored.reasons.append(f"suspicious name: {name_lower}")
        
        # Value-based clues
        if param_value:
            val = str(param_value)
            
            # Numeric values → likely SQL injection target
            if val.isdigit():
                scored.score = max(scored.score, 0.7)
                scored.reasons.append("numeric value (SQLi target)")
                scored.vuln_types.append("sqli")
            
            # URL-like values → SSRF/redirect target
            if val.startswith(("http://", "https://", "//")):
                scored.score = max(scored.score, 0.9)
                scored.reasons.append("URL value (SSRF/redirect target)")
                scored.vuln_types.extend(["ssrf", "redirect"])
            
            # Path-like values → LFI target
            if "/" in val and not val.startswith("http"):
                scored.score = max(scored.score, 0.8)
                scored.reasons.append("path-like value (LFI target)")
                scored.vuln_types.append("lfi")
            
            # Email-like → email injection
            if "@" in val and "." in val:
                scored.score = max(scored.score, 0.5)
                scored.reasons.append("email value")
                scored.vuln_types.append("email_injection")
        
        # Context-based boosts
        if context:
            if "search" in context.lower() or "query" in context.lower():
                scored.score = max(scored.score, 0.8)
                scored.vuln_types.extend(["xss", "sqli"])
            if "login" in context.lower() or "auth" in context.lower():
                scored.score = max(scored.score, 0.7)
                scored.vuln_types.extend(["sqli", "auth_bypass"])
        
        # Minimum score for any parameter
        if scored.score == 0.0:
            scored.score = 0.3
            scored.reasons.append("unknown parameter")
        
        return scored

    @classmethod
    def rank_params(cls, params: dict[str, str],
                    context: str = "") -> list[ScoredParam]:
        """Score and rank all parameters, highest score first."""
        scored = [
            cls.score_param(name, value, context)
            for name, value in params.items()
        ]
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored


# ═══════════════════════════════════════════════════════════════════════
# Scan Scorecard — Track effectiveness
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ScanScorecard:
    """
    Tracks scan effectiveness metrics.
    Used for tuning and reporting.
    """
    total_requests: int = 0
    total_findings: int = 0
    findings_by_scanner: Counter = field(default_factory=Counter)
    findings_by_severity: Counter = field(default_factory=Counter)
    findings_by_type: Counter = field(default_factory=Counter)
    verified_findings: int = 0
    false_positives: int = 0
    scanner_durations: dict[str, float] = field(default_factory=dict)
    params_tested: int = 0
    params_vulnerable: int = 0
    
    @property
    def efficiency(self) -> float:
        """Findings per 100 requests."""
        if self.total_requests == 0:
            return 0.0
        return (self.total_findings / self.total_requests) * 100.0
    
    @property
    def false_positive_rate(self) -> float:
        """Percentage of findings that were false positives."""
        total = self.verified_findings + self.false_positives
        if total == 0:
            return 0.0
        return (self.false_positives / total) * 100.0
    
    @property
    def vulnerability_rate(self) -> float:
        """Percentage of tested parameters that were vulnerable."""
        if self.params_tested == 0:
            return 0.0
        return (self.params_vulnerable / self.params_tested) * 100.0

    def record_finding(self, scanner: str, severity: str, vuln_type: str = ""):
        """Record a new finding."""
        self.total_findings += 1
        self.findings_by_scanner[scanner] += 1
        self.findings_by_severity[severity.upper()] += 1
        if vuln_type:
            self.findings_by_type[vuln_type] += 1

    def record_scanner_duration(self, scanner: str, duration: float):
        """Record how long a scanner took."""
        self.scanner_durations[scanner] = duration

    def summary(self) -> dict:
        """Generate a summary report."""
        return {
            "total_requests": self.total_requests,
            "total_findings": self.total_findings,
            "efficiency": f"{self.efficiency:.1f} findings/100 requests",
            "false_positive_rate": f"{self.false_positive_rate:.1f}%",
            "vulnerability_rate": f"{self.vulnerability_rate:.1f}%",
            "top_scanners": dict(self.findings_by_scanner.most_common(5)),
            "severity_breakdown": dict(self.findings_by_severity),
            "vuln_types": dict(self.findings_by_type.most_common(10)),
        }
