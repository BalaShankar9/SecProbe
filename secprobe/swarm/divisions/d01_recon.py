"""
Division 1 — Reconnaissance & OSINT
=====================================
40 agents specializing in passive and active reconnaissance, subdomain
enumeration, service fingerprinting, web crawling, OSINT, and security
header analysis.  These agents run first, feeding intelligence to every
downstream division.
"""

from secprobe.swarm.agent import (
    AgentCapability as Cap,
    AgentPriority as Pri,
    AgentSpec,
    OperationalMode as Mode,
)


def _s(id: str, name: str, div: int, caps: set, **kw) -> AgentSpec:
    return AgentSpec(id=id, name=name, division=div, capabilities=frozenset(caps), **kw)


# ═══════════════════════════════════════════════════════════════════════
# DNS & Subdomain Enumeration (6)
# ═══════════════════════════════════════════════════════════════════════

_dns_subdomain = [
    _s("recon-dns-brute", "DNS Subdomain Brute-Forcer", 1,
       {Cap.DNS_ENUM, Cap.PATTERN_MATCHING},
       description="Dictionary-based subdomain enumeration using common wordlists and permutation engines",
       attack_types=("recon",), target_technologies=(),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=500, timeout=600,
       detection_patterns=(r"NXDOMAIN", r"NOERROR"),
       tags=("dns", "subdomain", "brute-force")),

    _s("recon-dns-zone", "DNS Zone Transfer Tester", 1,
       {Cap.DNS_ENUM},
       description="Attempts AXFR/IXFR zone transfers against authoritative nameservers",
       attack_types=("recon", "misconfiguration"), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=120,
       detection_patterns=(r"Transfer failed", r"XFR size"),
       tags=("dns", "zone-transfer", "axfr")),

    _s("recon-dns-records", "DNS Record Enumerator", 1,
       {Cap.DNS_ENUM, Cap.PATTERN_MATCHING},
       description="Enumerates A, AAAA, CNAME, MX, TXT, SRV, NS, SOA, CAA, and PTR records",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=200, timeout=300,
       tags=("dns", "records", "enumeration")),

    _s("recon-dns-takeover", "Subdomain Takeover Detector", 1,
       {Cap.DNS_ENUM, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Identifies dangling CNAME records pointing to deprovisioned cloud services",
       attack_types=("subdomain-takeover",), cwe_ids=("CWE-284",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=300, timeout=600,
       detection_patterns=(
           r"There isn't a GitHub Pages site here",
           r"NoSuchBucket",
           r"NXDOMAIN",
           r"herokucdn\.com.*not found",
       ),
       tags=("dns", "subdomain-takeover", "cloud")),

    _s("recon-dns-wildcard", "DNS Wildcard Detector", 1,
       {Cap.DNS_ENUM, Cap.STATISTICAL_ANALYSIS},
       description="Detects wildcard DNS entries that inflate subdomain counts and filters false positives",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=50, timeout=120,
       tags=("dns", "wildcard", "filtering")),

    _s("recon-dns-reverse", "Reverse DNS Mapper", 1,
       {Cap.DNS_ENUM, Cap.PATTERN_MATCHING},
       description="Maps IP ranges back to hostnames via PTR records to discover hidden assets",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=500, timeout=600,
       tags=("dns", "reverse", "ptr")),
]

# ═══════════════════════════════════════════════════════════════════════
# Port & Service Scanning (4)
# ═══════════════════════════════════════════════════════════════════════

_port_service = [
    _s("recon-port-tcp", "TCP Port Scanner", 1,
       {Cap.PORT_SCAN, Cap.PATTERN_MATCHING},
       description="SYN/connect scans across configurable port ranges with service version probing",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=1000, timeout=900,
       tags=("port", "tcp", "scan")),

    _s("recon-port-udp", "UDP Service Prober", 1,
       {Cap.PORT_SCAN},
       description="Targeted UDP probing for DNS, SNMP, NTP, TFTP, and other common UDP services",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=200, timeout=600,
       tags=("port", "udp", "scan")),

    _s("recon-service-version", "Service Version Fingerprinter", 1,
       {Cap.PORT_SCAN, Cap.TECH_FINGERPRINT, Cap.PATTERN_MATCHING},
       description="Banner grabbing and protocol handshake analysis to determine exact service versions",
       attack_types=("recon",), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=300, timeout=600,
       detection_patterns=(r"Server:\s+", r"X-Powered-By:\s+", r"SSH-\d"),
       tags=("service", "version", "banner")),

    _s("recon-tls-audit", "TLS Configuration Auditor", 1,
       {Cap.PORT_SCAN, Cap.TECH_FINGERPRINT, Cap.COMPLIANCE_MAPPING},
       description="Evaluates TLS versions, cipher suites, certificate chains, HSTS, and OCSP stapling",
       attack_types=("tls-misconfiguration",), cwe_ids=("CWE-295", "CWE-326"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=300,
       detection_patterns=(r"SSLv[23]", r"TLSv1\.0", r"RC4", r"DES", r"NULL"),
       tags=("tls", "ssl", "certificate", "compliance")),
]

# ═══════════════════════════════════════════════════════════════════════
# Web Crawling & Discovery (8)
# ═══════════════════════════════════════════════════════════════════════

_web_crawl = [
    _s("recon-crawl-spider", "Web Spider", 1,
       {Cap.CRAWL, Cap.HTTP_PROBE},
       description="Recursive link-following spider that maps the full site structure respecting scope and robots.txt",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=2000, timeout=1200,
       tags=("crawl", "spider", "sitemap")),

    _s("recon-crawl-dirbrute", "Directory Brute-Forcer", 1,
       {Cap.CRAWL, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Wordlist-driven path discovery for hidden directories, backups, and admin panels",
       attack_types=("recon",), cwe_ids=("CWE-538",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=5000, timeout=1800,
       payloads=("wordlists/dirs_common.txt", "wordlists/dirs_extended.txt"),
       detection_patterns=(r"200 OK", r"301 Moved", r"403 Forbidden"),
       tags=("crawl", "directory", "brute-force")),

    _s("recon-crawl-filebrute", "Sensitive File Finder", 1,
       {Cap.CRAWL, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Probes for backup files, config files, .git, .env, .DS_Store, and other sensitive artifacts",
       attack_types=("recon", "information-disclosure"), cwe_ids=("CWE-538", "CWE-548"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=1000, timeout=600,
       payloads=("wordlists/sensitive_files.txt",),
       detection_patterns=(r"root:x:", r"\[database\]", r"DB_PASSWORD", r"BEGIN RSA PRIVATE"),
       tags=("crawl", "sensitive-file", "backup")),

    _s("recon-crawl-robots", "Robots & Sitemap Analyzer", 1,
       {Cap.CRAWL, Cap.HTTP_PROBE},
       description="Parses robots.txt and sitemap.xml to discover disallowed paths and hidden endpoints",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=120,
       detection_patterns=(r"Disallow:", r"<sitemap>", r"<urlset"),
       tags=("crawl", "robots", "sitemap")),

    _s("recon-crawl-js", "JavaScript File Analyzer", 1,
       {Cap.CRAWL, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Extracts API endpoints, secrets, tokens, and internal URLs from JavaScript bundles",
       attack_types=("recon", "information-disclosure"), cwe_ids=("CWE-200", "CWE-798"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=500, timeout=600,
       detection_patterns=(
           r"api[Kk]ey\s*[:=]\s*['\"]",
           r"(Bearer|token)\s+[A-Za-z0-9\-._~+/]+=*",
           r"/api/v\d+/",
       ),
       tags=("crawl", "javascript", "secrets")),

    _s("recon-crawl-param", "Parameter Discovery Agent", 1,
       {Cap.CRAWL, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Discovers hidden GET/POST parameters via reflection analysis and common-name brute-force",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=2000, timeout=900,
       payloads=("wordlists/params_common.txt",),
       tags=("crawl", "parameter", "discovery")),

    _s("recon-crawl-api", "API Endpoint Discoverer", 1,
       {Cap.CRAWL, Cap.HTTP_PROBE, Cap.API_INTERACTION},
       description="Finds REST/GraphQL/WebSocket endpoints by probing common paths and analyzing JS bundles",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=1000, timeout=600,
       payloads=("wordlists/api_endpoints.txt",),
       detection_patterns=(r"/api/", r"/graphql", r"/v\d+/", r"swagger", r"openapi"),
       tags=("crawl", "api", "endpoint")),

    _s("recon-crawl-wayback", "Wayback Machine Scraper", 1,
       {Cap.CRAWL, Cap.OSINT},
       description="Queries the Wayback Machine CDX API for historical URLs, parameters, and removed pages",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=100, timeout=300,
       tags=("crawl", "wayback", "archive", "osint")),
]

# ═══════════════════════════════════════════════════════════════════════
# Technology Fingerprinting (8)
# ═══════════════════════════════════════════════════════════════════════

_tech_fp = [
    _s("recon-fp-wappalyzer", "Wappalyzer-Style Fingerprinter", 1,
       {Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Identifies web technologies via header, cookie, meta-tag, and script-src pattern matching",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=120,
       detection_patterns=(r"X-Powered-By", r"X-Generator", r"<meta name=\"generator\""),
       tags=("fingerprint", "technology", "wappalyzer")),

    _s("recon-fp-cms", "CMS Detector", 1,
       {Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Identifies WordPress, Drupal, Joomla, Magento, and other CMS platforms with version detection",
       attack_types=("recon",), target_technologies=("wordpress", "drupal", "joomla", "magento"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(
           r"wp-content", r"wp-includes", r"Drupal\.settings",
           r"Joomla!", r"/skin/frontend/",
       ),
       tags=("fingerprint", "cms", "wordpress", "drupal")),

    _s("recon-fp-framework", "Web Framework Identifier", 1,
       {Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Detects server-side frameworks (Django, Rails, Spring, Laravel, Express) via error pages and headers",
       attack_types=("recon",),
       target_technologies=("django", "rails", "spring", "laravel", "express", "flask", "aspnet"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=100, timeout=300,
       detection_patterns=(
           r"csrfmiddlewaretoken", r"__RequestVerificationToken",
           r"X-Rails", r"laravel_session", r"JSESSIONID",
       ),
       tags=("fingerprint", "framework", "backend")),

    _s("recon-fp-waf", "WAF/CDN Fingerprinter", 1,
       {Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Identifies WAF and CDN products (Cloudflare, Akamai, AWS WAF, Imperva) by response patterns",
       attack_types=("recon",),
       target_technologies=("cloudflare", "akamai", "imperva", "aws-waf", "f5-bigip"),
       min_mode=Mode.RECON, priority=Pri.CRITICAL, max_requests=30, timeout=120,
       detection_patterns=(
           r"cf-ray", r"akamai", r"x-sucuri", r"__cfduid",
           r"x-amz-cf-id", r"bigipserver",
       ),
       tags=("fingerprint", "waf", "cdn", "evasion")),

    _s("recon-fp-cloud", "Cloud Provider Detector", 1,
       {Cap.TECH_FINGERPRINT, Cap.DNS_ENUM},
       description="Identifies cloud hosting provider (AWS, GCP, Azure, DO) from IP ranges, DNS, and headers",
       attack_types=("recon",),
       target_technologies=("aws", "gcp", "azure", "digitalocean"),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=50, timeout=180,
       detection_patterns=(r"amazonaws\.com", r"googleusercontent\.com", r"azure\.com"),
       tags=("fingerprint", "cloud", "infrastructure")),

    _s("recon-fp-jslib", "JavaScript Library Profiler", 1,
       {Cap.TECH_FINGERPRINT, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Identifies frontend libraries and versions (React, Angular, Vue, jQuery) with known-CVE mapping",
       attack_types=("recon",),
       target_technologies=("react", "angular", "vue", "jquery"),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=50, timeout=180,
       detection_patterns=(r"React\.version", r"angular\.version", r"Vue\.version", r"jQuery\.fn\.jquery"),
       tags=("fingerprint", "javascript", "frontend", "cve")),

    _s("recon-fp-server", "Web Server Fingerprinter", 1,
       {Cap.TECH_FINGERPRINT, Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Identifies web server software and version through header analysis and behavioral quirks",
       attack_types=("recon",),
       target_technologies=("nginx", "apache", "iis", "tomcat", "caddy", "lighttpd"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=30, timeout=120,
       detection_patterns=(r"Server:\s+(Apache|nginx|Microsoft-IIS|LiteSpeed)", r"X-AspNet-Version"),
       tags=("fingerprint", "server", "webserver")),

    _s("recon-fp-api-style", "API Architecture Classifier", 1,
       {Cap.TECH_FINGERPRINT, Cap.API_INTERACTION, Cap.HTTP_PROBE},
       description="Classifies API architecture (REST, GraphQL, gRPC-web, SOAP, JSON-RPC) from response patterns",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=50, timeout=180,
       detection_patterns=(r"application/graphql", r"application/grpc", r"text/xml.*Envelope"),
       tags=("fingerprint", "api", "architecture")),
]

# ═══════════════════════════════════════════════════════════════════════
# OSINT & Intelligence (6)
# ═══════════════════════════════════════════════════════════════════════

_osint = [
    _s("recon-osint-certlog", "Certificate Transparency Monitor", 1,
       {Cap.OSINT, Cap.DNS_ENUM},
       description="Queries CT logs (crt.sh) to discover subdomains and certificates for the target domain",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=20, timeout=180,
       tags=("osint", "certificate", "ct-log", "subdomain")),

    _s("recon-osint-whois", "WHOIS Intelligence Analyst", 1,
       {Cap.OSINT},
       description="Extracts registrant information, nameservers, creation dates, and related domains from WHOIS",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=10, timeout=120,
       tags=("osint", "whois", "registrant")),

    _s("recon-osint-email", "Email Address Harvester", 1,
       {Cap.OSINT, Cap.CRAWL, Cap.PATTERN_MATCHING},
       description="Discovers employee email addresses from public sources for social engineering assessment",
       attack_types=("recon", "osint"),
       min_mode=Mode.RECON, priority=Pri.LOW, max_requests=50, timeout=300,
       detection_patterns=(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",),
       tags=("osint", "email", "harvest")),

    _s("recon-osint-github", "GitHub Reconnaissance Agent", 1,
       {Cap.OSINT, Cap.PATTERN_MATCHING},
       description="Searches GitHub repos and gists for leaked credentials, API keys, and internal URLs",
       attack_types=("recon", "information-disclosure"), cwe_ids=("CWE-798", "CWE-200"),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=50, timeout=300,
       detection_patterns=(r"password\s*=", r"api_key\s*=", r"secret\s*="),
       tags=("osint", "github", "secrets", "leaks")),

    _s("recon-osint-shodan", "Shodan/Censys Intelligence Agent", 1,
       {Cap.OSINT, Cap.PORT_SCAN},
       description="Queries Shodan and Censys for historical port data, banners, and known vulnerabilities",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=20, timeout=180,
       tags=("osint", "shodan", "censys", "passive")),

    _s("recon-osint-breach", "Breach Data Correlator", 1,
       {Cap.OSINT, Cap.PATTERN_MATCHING},
       description="Checks if target domain emails appear in known breach datasets (Have I Been Pwned API)",
       attack_types=("recon", "credential-exposure"), cwe_ids=("CWE-521",),
       min_mode=Mode.RECON, priority=Pri.LOW, max_requests=20, timeout=180,
       tags=("osint", "breach", "credentials")),
]

# ═══════════════════════════════════════════════════════════════════════
# Header & Security Analysis (5)
# ═══════════════════════════════════════════════════════════════════════

_header_security = [
    _s("recon-header-security", "Security Header Auditor", 1,
       {Cap.HTTP_PROBE, Cap.COMPLIANCE_MAPPING, Cap.PATTERN_MATCHING},
       description="Evaluates presence and correctness of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more",
       attack_types=("misconfiguration",), cwe_ids=("CWE-693", "CWE-1021"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=20, timeout=120,
       detection_patterns=(
           r"Strict-Transport-Security", r"Content-Security-Policy",
           r"X-Frame-Options", r"X-Content-Type-Options",
       ),
       tags=("header", "security", "csp", "hsts", "compliance")),

    _s("recon-header-cors", "CORS Misconfiguration Detector", 1,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Tests CORS configuration for overly permissive origins, credentials leakage, and null origin bypass",
       attack_types=("cors-misconfiguration",), cwe_ids=("CWE-346", "CWE-942"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=30, timeout=180,
       detection_patterns=(
           r"Access-Control-Allow-Origin:\s*\*",
           r"Access-Control-Allow-Credentials:\s*true",
       ),
       tags=("header", "cors", "origin", "misconfiguration")),

    _s("recon-header-cookie", "Cookie Security Analyzer", 1,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Checks cookies for missing Secure, HttpOnly, SameSite attributes and overly broad paths/domains",
       attack_types=("session-misconfiguration",), cwe_ids=("CWE-614", "CWE-1004"),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=20, timeout=120,
       detection_patterns=(r"Set-Cookie:", r"Secure", r"HttpOnly", r"SameSite"),
       tags=("header", "cookie", "session", "security")),

    _s("recon-header-csp", "CSP Deep Analyzer", 1,
       {Cap.HTTP_PROBE, Cap.JS_ANALYSIS, Cap.PATTERN_MATCHING},
       description="Parses Content-Security-Policy for unsafe-inline, unsafe-eval, wildcard sources, and bypass vectors",
       attack_types=("csp-bypass",), cwe_ids=("CWE-693",),
       min_mode=Mode.RECON, priority=Pri.HIGH, max_requests=10, timeout=120,
       detection_patterns=(r"unsafe-inline", r"unsafe-eval", r"\*\."),
       tags=("header", "csp", "bypass", "xss")),

    _s("recon-header-info-leak", "Information Leakage Detector", 1,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING},
       description="Identifies server version disclosure, debug headers, stack traces, and internal IPs in responses",
       attack_types=("information-disclosure",), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=30, timeout=180,
       detection_patterns=(
           r"X-Debug", r"X-AspNet-Version", r"X-Powered-By",
           r"10\.\d+\.\d+\.\d+", r"192\.168\.\d+\.\d+",
           r"Traceback \(most recent call last\)",
       ),
       tags=("header", "information-leak", "debug")),
]

# ═══════════════════════════════════════════════════════════════════════
# Commander + Passive Recon Specialists (3)
# ═══════════════════════════════════════════════════════════════════════

_command_and_passive = [
    _s("recon-commander", "Recon Division Commander", 1,
       {Cap.COORDINATION, Cap.KNOWLEDGE_SHARING, Cap.CONSENSUS_VOTING},
       description="Orchestrates all Division 1 agents, prioritizes targets, deduplicates findings, and feeds intel downstream",
       attack_types=(),
       min_mode=Mode.RECON, priority=Pri.CRITICAL, max_requests=0, timeout=3600,
       tags=("commander", "coordination", "division-1")),

    _s("recon-passive-metadata", "Metadata Extraction Specialist", 1,
       {Cap.HTTP_PROBE, Cap.PATTERN_MATCHING, Cap.OSINT},
       description="Extracts EXIF data from images, PDF metadata, and office document properties for intelligence gathering",
       attack_types=("recon", "information-disclosure"), cwe_ids=("CWE-200",),
       min_mode=Mode.RECON, priority=Pri.LOW, max_requests=100, timeout=300,
       detection_patterns=(r"<xmp:CreatorTool>", r"<pdf:Producer>"),
       tags=("passive", "metadata", "exif")),

    _s("recon-passive-traffic", "Passive Traffic Analyzer", 1,
       {Cap.HTTP_PROBE, Cap.BASELINE_PROFILING, Cap.STATISTICAL_ANALYSIS},
       description="Passively analyzes response timing, size distributions, and behavioral baselines without active probing",
       attack_types=("recon",),
       min_mode=Mode.RECON, priority=Pri.NORMAL, max_requests=0, timeout=1800,
       tags=("passive", "traffic", "baseline")),
]


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def agents() -> list[AgentSpec]:
    """Return all 40 Division 1 (Reconnaissance & OSINT) agents."""
    all_agents = (
        _dns_subdomain
        + _port_service
        + _web_crawl
        + _tech_fp
        + _osint
        + _header_security
        + _command_and_passive
    )
    assert len(all_agents) == 40, f"Division 1 must have exactly 40 agents, got {len(all_agents)}"
    return all_agents
