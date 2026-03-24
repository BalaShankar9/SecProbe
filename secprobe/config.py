"""
Global configuration for SecProbe.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanConfig:
    """Configuration object for a scan session."""

    target: str = ""
    scan_types: list[str] = field(default_factory=lambda: ["all"])
    ports: str = "1-1024"
    threads: int = 50
    timeout: int = 10
    output_format: str = "console"
    output_file: Optional[str] = None
    verbose: bool = False
    follow_redirects: bool = True
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    custom_headers: dict = field(default_factory=dict)
    wordlist: Optional[str] = None
    rate_limit: float = 0.0  # seconds between requests

    # ── v2.0 Enterprise Features ─────────────────────────────────
    proxy: Optional[str] = None          # http://127.0.0.1:8080 or socks5://...
    auth: Optional[str] = None           # basic:user:pass | bearer:token | header:X-Key:val
    crawl: bool = False                  # Enable spider/crawl before scanning
    crawl_depth: int = 3                 # Max crawl depth
    crawl_max_pages: int = 100           # Max pages to crawl
    waf_evasion: bool = False            # Enable WAF evasion payloads
    template_dirs: list[str] = field(default_factory=list)  # Extra template dirs
    template_tags: list[str] = field(default_factory=list)  # Filter templates by tag
    compliance: bool = False             # Enable compliance mapping
    attack_chains: bool = True           # Enable attack chain analysis
    ssl_verify: bool = False             # Verify SSL certificates
    dedup: bool = True                   # Deduplicate findings

    # Directories
    BASE_DIR: str = field(default_factory=lambda: os.path.dirname(os.path.abspath(__file__)))
    WORDLIST_DIR: str = field(default_factory=lambda: os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "wordlists"
    ))
    REPORT_DIR: str = field(default_factory=lambda: os.path.join(os.getcwd(), "reports"))


# Severity levels
class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    COLORS = {
        "CRITICAL": "\033[91m\033[1m",  # Bold Red
        "HIGH": "\033[91m",              # Red
        "MEDIUM": "\033[93m",            # Yellow
        "LOW": "\033[94m",               # Blue
        "INFO": "\033[96m",              # Cyan
    }


# Common ports and their services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS header missing - site may be vulnerable to protocol downgrade attacks",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "CSP header missing - site may be vulnerable to XSS and data injection attacks",
        "recommendation": "Implement a Content-Security-Policy header with restrictive directives",
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Content-Type-Options missing - browser may MIME-sniff responses",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options missing - site may be vulnerable to clickjacking",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection header missing (legacy but still useful for older browsers)",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy missing - full URL may be sent in Referer header",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy missing - browser features not restricted",
        "recommendation": "Add a Permissions-Policy header to control browser feature access",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": Severity.LOW,
        "description": "Cross-domain policy header missing",
        "recommendation": "Add 'X-Permitted-Cross-Domain-Policies: none' header",
    },
}


# Headers that should NOT be present (information leakage)
INSECURE_HEADERS = {
    "Server": {
        "severity": Severity.LOW,
        "description": "Server header exposes web server software version",
        "recommendation": "Remove or obfuscate the Server header",
    },
    "X-Powered-By": {
        "severity": Severity.LOW,
        "description": "X-Powered-By header exposes backend technology",
        "recommendation": "Remove the X-Powered-By header",
    },
    "X-AspNet-Version": {
        "severity": Severity.MEDIUM,
        "description": "ASP.NET version exposed in headers",
        "recommendation": "Remove X-AspNet-Version header in web.config",
    },
    "X-AspNetMvc-Version": {
        "severity": Severity.MEDIUM,
        "description": "ASP.NET MVC version exposed in headers",
        "recommendation": "Remove X-AspNetMvc-Version header",
    },
}
