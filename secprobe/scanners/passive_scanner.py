"""
Passive Scanner — Analyzes HTTP responses for information disclosure
without sending any attack payloads.

This scanner inspects every response gathered during crawling/scanning for:
  - Server version banners and technology fingerprints
  - Debug/error messages and stack traces
  - Internal IP addresses and hostnames
  - Sensitive data patterns (emails, API keys, tokens, passwords)
  - Missing security headers
  - Source code / backup file exposure
  - Interesting comments in HTML
  - Directory listings
  - Misconfigured CORS / cache / content-type headers
"""

from __future__ import annotations

import re
from typing import Optional

from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.config import Severity


# ═══════════════════════════════════════════════════════════════════
#  Pattern databases
# ═══════════════════════════════════════════════════════════════════

# Internal IP / hostname patterns
INTERNAL_IP_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Sensitive data patterns: (name, regex, severity, cwe)
SENSITIVE_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    # API keys / tokens
    (
        "AWS Access Key",
        re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}", re.ASCII),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "AWS Secret Key",
        re.compile(r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})"""),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,72}"),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "GitHub Token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        Severity.HIGH,
        "CWE-798",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,99}"),
        Severity.CRITICAL,
        "CWE-798",
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "CWE-321",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        Severity.MEDIUM,
        "CWE-200",
    ),
    (
        "Generic Password Assignment",
        re.compile(
            r"""(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)\s*[=:]\s*['"][^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "CWE-798",
    ),
    # Database connection strings
    (
        "Database Connection String",
        re.compile(
            r"(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|oracle)://[^\s'\"<>]+",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "CWE-200",
    ),
    # Email addresses (informational)
    (
        "Email Address Disclosure",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        Severity.INFO,
        "CWE-200",
    ),
    # Social Security Numbers (US)
    (
        "Social Security Number",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        Severity.CRITICAL,
        "CWE-359",
    ),
    # Credit card numbers (basic Luhn-check not performed, pattern only)
    (
        "Credit Card Number Pattern",
        re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        Severity.CRITICAL,
        "CWE-359",
    ),
]

# Stack trace / error message patterns
ERROR_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "PHP Error/Warning",
        re.compile(
            r"(?:Fatal error|Parse error|Warning|Notice):\s+.+?\s+in\s+\S+\.php\s+on\s+line\s+\d+",
            re.IGNORECASE,
        ),
        "PHP",
    ),
    (
        "Python Traceback",
        re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
        "Python",
    ),
    (
        "Java Exception",
        re.compile(
            r"(?:java\.\w+\.[\w.]+Exception|at\s+[\w.$]+\([\w.]+:\d+\))",
            re.IGNORECASE,
        ),
        "Java",
    ),
    (
        ".NET Exception",
        re.compile(
            r"(?:System\.\w+Exception|Server Error in|Stack Trace:.*at\s+\w+)",
            re.IGNORECASE | re.DOTALL,
        ),
        ".NET",
    ),
    (
        "Ruby Error",
        re.compile(r"(?:NoMethodError|NameError|RuntimeError).*\.rb:\d+", re.IGNORECASE),
        "Ruby",
    ),
    (
        "Node.js Error",
        re.compile(r"(?:TypeError|ReferenceError|SyntaxError).*?at\s+\w+\s+\(.*?\.js:\d+:\d+\)", re.DOTALL),
        "Node.js",
    ),
    (
        "SQL Error Message",
        re.compile(
            r"(?:SQL syntax.*MySQL|ORA-\d{5}|PG::Error|SQLite3::.*Exception"
            r"|ODBC SQL Server Driver|Unclosed quotation mark"
            r"|pg_query\(\)|mysql_fetch|sqlite_query|mssql_query"
            r"|syntax error at or near|unterminated quoted string)",
            re.IGNORECASE,
        ),
        "SQL",
    ),
    (
        "Debug Mode Enabled",
        re.compile(
            r"(?:DJANGO_DEBUG|DEBUG\s*=\s*True|app\.debug\s*=\s*True"
            r"|Werkzeug Debugger|Laravel.*APP_DEBUG.*true"
            r"|<title>Django REST framework</title>)",
            re.IGNORECASE,
        ),
        "Framework Debug",
    ),
]

# Security headers that should be present
SECURITY_HEADERS: list[tuple[str, str, str]] = [
    # (header_name, description, severity)
    ("Strict-Transport-Security", "HSTS header prevents protocol downgrade attacks", Severity.MEDIUM),
    ("X-Content-Type-Options", "Prevents MIME-type sniffing attacks", Severity.LOW),
    ("X-Frame-Options", "Prevents clickjacking attacks", Severity.MEDIUM),
    ("Content-Security-Policy", "Prevents XSS and data injection attacks", Severity.MEDIUM),
    ("X-XSS-Protection", "Legacy XSS filter (backup defense)", Severity.INFO),
    ("Referrer-Policy", "Controls referrer information leakage", Severity.LOW),
    ("Permissions-Policy", "Restricts browser feature access", Severity.LOW),
]

# Headers that leak server info
INFO_LEAK_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-WordPress",
    "X-Redirect-By",
    "X-Debug-Token",
    "X-Debug-Token-Link",
    "X-Request-Id",
    "X-Amz-Cf-Id",
    "Via",
]

# Directory listing patterns
DIR_LISTING_RE = re.compile(
    r"(?:<title>Index of /|<h1>Index of /|Directory listing for|"
    r"Parent Directory</a>|<title>Directory Listing|"
    r"\[To Parent Directory\])",
    re.IGNORECASE,
)

# Source code patterns in responses
SOURCE_CODE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("PHP Source", re.compile(r"<\?php\s", re.IGNORECASE)),
    ("ASP Source", re.compile(r"<%\s*(?:@|=|Response|Request|Server)", re.IGNORECASE)),
    ("JSP Source", re.compile(r"<%(?:@|=|!)\s", re.IGNORECASE)),
    ("Server Config", re.compile(r"<(?:VirtualHost|Directory|Location)\s", re.IGNORECASE)),
]

# HTML comment patterns that leak info
INTERESTING_COMMENT_RE = re.compile(
    r"<!--\s*(?:"
    r"TODO|FIXME|HACK|BUG|XXX|TEMP|DEBUG"
    r"|password|secret|token|key|admin"
    r"|version|build|deploy|staging|internal"
    r"|username|credential|api[_-]?key"
    r").*?-->",
    re.IGNORECASE | re.DOTALL,
)

# Backup / leftover files to probe (relative to URL path)
BACKUP_EXTENSIONS: list[str] = [
    ".bak", ".old", ".orig", ".save", ".swp", ".swo",
    "~", ".copy", ".tmp", ".temp", ".dist",
    ".bkp", ".backup",
]

# Well-known API / config discovery paths
API_DISCOVERY_PATHS: list[tuple[str, str, str]] = [
    # (path, title, severity)
    ("/swagger.json", "Swagger/OpenAPI Specification Exposed", Severity.MEDIUM),
    ("/openapi.json", "OpenAPI Specification Exposed", Severity.MEDIUM),
    ("/swagger-ui.html", "Swagger UI Exposed", Severity.MEDIUM),
    ("/api-docs", "API Documentation Exposed", Severity.MEDIUM),
    ("/.well-known/openid-configuration", "OpenID Configuration Exposed", Severity.LOW),
    ("/graphql", "GraphQL Endpoint Exposed", Severity.MEDIUM),
    ("/graphiql", "GraphiQL IDE Exposed", Severity.HIGH),
    ("/.env", "Environment File Exposed", Severity.CRITICAL),
    ("/.git/HEAD", "Git Repository Exposed", Severity.CRITICAL),
    ("/.svn/entries", "SVN Repository Exposed", Severity.CRITICAL),
    ("/.DS_Store", "macOS DS_Store File Exposed", Severity.LOW),
    ("/wp-config.php.bak", "WordPress Config Backup", Severity.CRITICAL),
    ("/server-status", "Apache Server Status Exposed", Severity.MEDIUM),
    ("/server-info", "Apache Server Info Exposed", Severity.MEDIUM),
    ("/elmah.axd", "ELMAH Error Log Exposed", Severity.HIGH),
    ("/phpinfo.php", "PHP Info Page Exposed", Severity.HIGH),
    ("/actuator", "Spring Actuator Exposed", Severity.HIGH),
    ("/actuator/health", "Spring Actuator Health Exposed", Severity.MEDIUM),
    ("/actuator/env", "Spring Actuator Env Exposed", Severity.CRITICAL),
    ("/_debug", "Debug Endpoint Exposed", Severity.HIGH),
    ("/debug/pprof/", "Go pprof Debug Exposed", Severity.HIGH),
    ("/trace", "Spring Trace Endpoint Exposed", Severity.HIGH),
    ("/metrics", "Metrics Endpoint Exposed", Severity.MEDIUM),
    ("/health", "Health Check Exposed", Severity.INFO),
    ("/robots.txt", "Robots.txt (mapped for analysis)", Severity.INFO),
    ("/sitemap.xml", "Sitemap XML Found", Severity.INFO),
    ("/crossdomain.xml", "Flash Crossdomain Policy", Severity.LOW),
    ("/clientaccesspolicy.xml", "Silverlight Client Access Policy", Severity.LOW),
]

# Source map file patterns
SOURCE_MAP_RE = re.compile(
    r"//[#@]\s*sourceMappingURL=(\S+\.map)",
    re.IGNORECASE,
)

# Subresource Integrity missing check
SRI_SCRIPT_RE = re.compile(
    r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>',
    re.IGNORECASE,
)
SRI_CHECK_RE = re.compile(r'\bintegrity\s*=', re.IGNORECASE)

# Mixed content patterns
MIXED_CONTENT_RE = re.compile(
    r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
    re.IGNORECASE,
)


class PassiveScanner(SmartScanner):
    """
    Passively analyzes HTTP responses for information disclosure.

    No attack payloads are sent — this scanner only inspects
    responses already gathered during crawling and active scanning.
    """

    name = "Passive Analysis Scanner"
    description = "Analyzes responses for info disclosure, missing headers, sensitive data"

    def scan(self):
        """Run all passive analysis checks against crawled URLs."""
        target = self.config.target
        urls = self._get_scan_urls()

        if not urls:
            urls = [target]

        found_issues: set[str] = set()  # Deduplicate by (check_type, url, detail)

        for url in urls[:200]:  # Cap at 200 URLs to keep runtime reasonable
            try:
                resp = self.http_client.get(url, timeout=self.config.timeout)
            except Exception:
                continue

            body = getattr(resp, "text", "") or ""
            headers = getattr(resp, "headers", {}) or {}

            # Run all passive checks
            self._check_security_headers(url, headers, found_issues)
            self._check_info_leak_headers(url, headers, found_issues)
            self._check_error_messages(url, body, found_issues)
            self._check_internal_ips(url, body, headers, found_issues)
            self._check_sensitive_data(url, body, found_issues)
            self._check_directory_listing(url, body, found_issues)
            self._check_source_code_exposure(url, body, found_issues)
            self._check_interesting_comments(url, body, found_issues)
            self._check_cors_misconfiguration(url, headers, found_issues)
            self._check_cache_headers(url, headers, found_issues)
            self._check_content_type(url, headers, body, found_issues)
            self._check_source_maps(url, body, found_issues)
            self._check_mixed_content(url, body, headers, found_issues)
            self._check_sri_missing(url, body, found_issues)
            self._check_cookie_scope(url, headers, found_issues)
            self._check_insecure_form_action(url, body, found_issues)
            self._check_autocomplete_sensitive(url, body, found_issues)
            self._check_csp_details(url, headers, found_issues)
            self._check_hsts_details(url, headers, found_issues)

        # Run once-only checks (not per-URL)
        self._check_api_discovery(found_issues)
        self._check_backup_files(urls, found_issues)

    # ── URL collection ───────────────────────────────────────────

    def _get_scan_urls(self) -> list[str]:
        """Collect URLs from attack surface + context."""
        urls = []
        if self.context:
            urls.extend(self.context.get_crawled_urls())
            urls.extend(self.context.get_injection_urls())
        # Add target itself
        if self.config.target not in urls:
            urls.insert(0, self.config.target)
        return list(dict.fromkeys(urls))  # Deduplicate preserving order

    # ── Check: Missing security headers ──────────────────────────

    def _check_security_headers(self, url: str, headers: dict,
                                found: set[str]):
        """Check for missing security headers (only on first URL)."""
        # Only report missing headers once (on the main target)
        if url != self.config.target:
            return

        for header_name, desc, severity in SECURITY_HEADERS:
            key = f"missing_header:{header_name}"
            if key in found:
                continue
            # Case-insensitive header lookup
            if not self._get_header(headers, header_name):
                found.add(key)
                self.add_finding(
                    title=f"Missing Security Header: {header_name}",
                    severity=severity,
                    description=f"The response does not include the {header_name} header. {desc}.",
                    recommendation=f"Add the {header_name} header to all responses.",
                    evidence=f"URL: {url}\nHeader '{header_name}' not present",
                    category="Security Misconfiguration",
                    url=url,
                    cwe="CWE-693",
                )

    # ── Check: Information leaking headers ───────────────────────

    def _check_info_leak_headers(self, url: str, headers: dict,
                                 found: set[str]):
        """Check for headers that disclose server/framework versions."""
        for header_name in INFO_LEAK_HEADERS:
            value = self._get_header(headers, header_name)
            if not value:
                continue
            # Skip generic values
            if value.lower() in ("", "close", "keep-alive"):
                continue
            key = f"info_header:{header_name}:{value}"
            if key in found:
                continue
            found.add(key)
            self.add_finding(
                title=f"Information Disclosure via {header_name} Header",
                severity=Severity.LOW,
                description=f"The {header_name} header reveals: {value}",
                recommendation=f"Remove or obfuscate the {header_name} header in production.",
                evidence=f"URL: {url}\n{header_name}: {value}",
                category="Information Disclosure",
                url=url,
                cwe="CWE-200",
            )

    # ── Check: Error messages / stack traces ─────────────────────

    def _check_error_messages(self, url: str, body: str,
                              found: set[str]):
        """Detect error messages and stack traces in responses."""
        for name, pattern, tech in ERROR_PATTERNS:
            match = pattern.search(body)
            if not match:
                continue
            snippet = match.group()[:200]
            key = f"error:{tech}:{url}"
            if key in found:
                continue
            found.add(key)
            self.add_finding(
                title=f"{tech} Error/Debug Information Disclosed",
                severity=Severity.MEDIUM,
                description=(
                    f"A {tech} error message or debug information was found in the response. "
                    f"This can reveal internal paths, database structure, or framework details."
                ),
                recommendation="Configure proper error handling. Never expose raw errors to users.",
                evidence=f"URL: {url}\nPattern: {name}\nSnippet: {snippet}",
                category="Information Disclosure",
                url=url,
                cwe="CWE-209",
            )

    # ── Check: Internal IP addresses ─────────────────────────────

    def _check_internal_ips(self, url: str, body: str, headers: dict,
                            found: set[str]):
        """Detect internal IP addresses in responses and headers."""
        # Check body
        for match in INTERNAL_IP_RE.finditer(body):
            ip = match.group()
            key = f"internal_ip:{ip}"
            if key in found:
                continue
            found.add(key)
            self.add_finding(
                title=f"Internal IP Address Disclosed: {ip}",
                severity=Severity.LOW,
                description=f"An internal IP address ({ip}) was found in the response body.",
                recommendation="Remove internal infrastructure details from public responses.",
                evidence=f"URL: {url}\nIP: {ip}",
                category="Information Disclosure",
                url=url,
                cwe="CWE-200",
            )

        # Check headers
        for header_name, header_value in headers.items():
            for match in INTERNAL_IP_RE.finditer(str(header_value)):
                ip = match.group()
                key = f"internal_ip_header:{ip}:{header_name}"
                if key in found:
                    continue
                found.add(key)
                self.add_finding(
                    title=f"Internal IP in {header_name} Header: {ip}",
                    severity=Severity.LOW,
                    description=f"Internal IP ({ip}) disclosed in {header_name} header.",
                    recommendation="Remove internal IP addresses from response headers.",
                    evidence=f"URL: {url}\n{header_name}: {header_value}",
                    category="Information Disclosure",
                    url=url,
                    cwe="CWE-200",
                )

    # ── Check: Sensitive data patterns ───────────────────────────

    def _check_sensitive_data(self, url: str, body: str,
                              found: set[str]):
        """Detect API keys, tokens, passwords, PII in responses."""
        for name, pattern, severity, cwe in SENSITIVE_PATTERNS:
            match = pattern.search(body)
            if not match:
                continue
            snippet = match.group()[:100]
            key = f"sensitive:{name}:{url}"
            if key in found:
                continue
            # Skip email disclosure unless it looks like a leak (not in mailto:)
            if name == "Email Address Disclosure":
                # Only report if more than 3 emails found (suggests data dump)
                all_emails = pattern.findall(body)
                if len(all_emails) < 3:
                    continue
            found.add(key)
            self.add_finding(
                title=f"Sensitive Data Exposure: {name}",
                severity=severity,
                description=f"{name} pattern detected in the response body.",
                recommendation="Remove sensitive data from responses. Rotate exposed credentials.",
                evidence=f"URL: {url}\nPattern: {name}\nMatch: {snippet}",
                category="Sensitive Data Exposure",
                url=url,
                cwe=cwe,
            )

    # ── Check: Directory listing ─────────────────────────────────

    def _check_directory_listing(self, url: str, body: str,
                                 found: set[str]):
        """Detect directory listing pages."""
        if not DIR_LISTING_RE.search(body):
            return
        key = f"dirlist:{url}"
        if key in found:
            return
        found.add(key)
        self.add_finding(
            title="Directory Listing Enabled",
            severity=Severity.MEDIUM,
            description="The server exposes a directory listing, revealing file structure.",
            recommendation="Disable directory listing in web server configuration.",
            evidence=f"URL: {url}\nDirectory listing pattern detected",
            category="Security Misconfiguration",
            url=url,
            cwe="CWE-548",
        )

    # ── Check: Source code exposure ──────────────────────────────

    def _check_source_code_exposure(self, url: str, body: str,
                                    found: set[str]):
        """Detect server-side source code exposed in responses."""
        content_type = ""
        for name, pattern in SOURCE_CODE_PATTERNS:
            if not pattern.search(body):
                continue
            key = f"source:{name}:{url}"
            if key in found:
                continue
            found.add(key)
            self.add_finding(
                title=f"Source Code Exposure: {name}",
                severity=Severity.HIGH,
                description=f"{name} source code was detected in the response, indicating misconfigured server.",
                recommendation="Ensure server-side code is processed by the interpreter, not served raw.",
                evidence=f"URL: {url}\nType: {name}",
                category="Information Disclosure",
                url=url,
                cwe="CWE-540",
            )

    # ── Check: Interesting HTML comments ─────────────────────────

    def _check_interesting_comments(self, url: str, body: str,
                                    found: set[str]):
        """Detect HTML comments that may contain sensitive info."""
        matches = INTERESTING_COMMENT_RE.findall(body)
        if not matches:
            return
        # Report once per URL
        key = f"comments:{url}"
        if key in found:
            return
        found.add(key)
        snippets = [m[:100] for m in matches[:5]]
        self.add_finding(
            title="Sensitive Information in HTML Comments",
            severity=Severity.LOW,
            description=f"Found {len(matches)} potentially sensitive HTML comments.",
            recommendation="Remove debug/sensitive comments from production HTML.",
            evidence=f"URL: {url}\nComments:\n" + "\n".join(snippets),
            category="Information Disclosure",
            url=url,
            cwe="CWE-615",
        )

    # ── Check: CORS misconfiguration ─────────────────────────────

    def _check_cors_misconfiguration(self, url: str, headers: dict,
                                     found: set[str]):
        """Detect overly permissive CORS headers."""
        acao = self._get_header(headers, "Access-Control-Allow-Origin")
        if not acao:
            return

        key = f"cors:{url}"
        if key in found:
            return

        if acao == "*":
            acac = self._get_header(headers, "Access-Control-Allow-Credentials")
            if acac and acac.lower() == "true":
                found.add(key)
                self.add_finding(
                    title="Dangerous CORS: Wildcard Origin with Credentials",
                    severity=Severity.HIGH,
                    description="CORS allows any origin with credentials, enabling cross-origin data theft.",
                    recommendation="Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.",
                    evidence=f"URL: {url}\nACAO: {acao}\nACAC: {acac}",
                    category="Security Misconfiguration",
                    url=url,
                    cwe="CWE-942",
                )

    # ── Check: Cache headers ─────────────────────────────────────

    def _check_cache_headers(self, url: str, headers: dict,
                             found: set[str]):
        """Detect sensitive pages without cache-control."""
        # Only check if the response likely contains sensitive content
        cc = self._get_header(headers, "Cache-Control") or ""
        pragma = self._get_header(headers, "Pragma") or ""

        if "no-store" in cc.lower() or "no-cache" in pragma.lower():
            return  # Properly configured

        # Check if URL looks like it serves sensitive content
        sensitive_paths = ("/account", "/profile", "/settings", "/admin",
                           "/dashboard", "/api/", "/user", "/login")
        if not any(p in url.lower() for p in sensitive_paths):
            return

        key = f"cache:{url}"
        if key in found:
            return
        found.add(key)

        self.add_finding(
            title="Sensitive Page Missing Cache-Control Headers",
            severity=Severity.LOW,
            description="A potentially sensitive page does not set Cache-Control: no-store.",
            recommendation="Add 'Cache-Control: no-store, no-cache, must-revalidate' to sensitive pages.",
            evidence=f"URL: {url}\nCache-Control: {cc or '(not set)'}",
            category="Security Misconfiguration",
            url=url,
            cwe="CWE-525",
        )

    # ── Check: Content-Type ──────────────────────────────────────

    def _check_content_type(self, url: str, headers: dict, body: str,
                            found: set[str]):
        """Detect missing or incorrect Content-Type headers."""
        ct = self._get_header(headers, "Content-Type") or ""

        if not ct:
            key = f"no_ct:{url}"
            if key not in found:
                found.add(key)
                self.add_finding(
                    title="Missing Content-Type Header",
                    severity=Severity.LOW,
                    description="Response lacks a Content-Type header, which may enable MIME sniffing attacks.",
                    recommendation="Always set an appropriate Content-Type header.",
                    evidence=f"URL: {url}",
                    category="Security Misconfiguration",
                    url=url,
                    cwe="CWE-16",
                )
            return

        # Check for charset in HTML responses
        if "text/html" in ct.lower() and "charset" not in ct.lower():
            key = f"no_charset:{url}"
            if key not in found:
                found.add(key)
                self.add_finding(
                    title="HTML Response Missing Charset",
                    severity=Severity.INFO,
                    description="HTML response does not specify charset, potentially enabling encoding-based XSS.",
                    recommendation="Include charset=utf-8 in Content-Type for HTML responses.",
                    evidence=f"URL: {url}\nContent-Type: {ct}",
                    category="Security Misconfiguration",
                    url=url,
                    cwe="CWE-16",
                )

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _get_header(headers: dict, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        name_lower = name.lower()
        for key, value in headers.items():
            if key.lower() == name_lower:
                return value
        return None

    # ═══════════════════════════════════════════════════════════════
    # NEW checks: Source maps, mixed content, SRI, forms, CSP, HSTS,
    # API discovery, backup files, cookie scope
    # ═══════════════════════════════════════════════════════════════

    def _check_source_maps(self, url: str, body: str, found: set[str]):
        """Detect JavaScript source map references that expose source code."""
        for match in SOURCE_MAP_RE.finditer(body):
            map_url = match.group(1)
            key = f"srcmap:{map_url}"
            if key in found:
                continue
            found.add(key)
            self.add_finding(
                title="JavaScript Source Map Exposed",
                severity=Severity.LOW,
                description=(
                    f"A JavaScript source map file reference was found ({map_url}). "
                    "Source maps reveal original source code, variable names, and file structure."
                ),
                recommendation="Remove source map references in production builds.",
                evidence=f"URL: {url}\nSource map: {map_url}",
                category="Information Disclosure",
                url=url,
                cwe="CWE-540",
            )

    def _check_mixed_content(self, url: str, body: str, headers: dict,
                             found: set[str]):
        """Detect HTTP resources loaded over HTTPS pages (mixed content)."""
        if not url.startswith("https://"):
            return
        matches = MIXED_CONTENT_RE.findall(body)
        if not matches:
            return
        key = f"mixed:{url}"
        if key in found:
            return
        found.add(key)
        samples = matches[:5]
        self.add_finding(
            title="Mixed Content: HTTP Resources on HTTPS Page",
            severity=Severity.MEDIUM,
            description=(
                f"Found {len(matches)} HTTP resource(s) loaded on an HTTPS page. "
                "Mixed content can be intercepted or modified by attackers."
            ),
            recommendation="Load all resources over HTTPS.",
            evidence=f"URL: {url}\nExamples:\n" + "\n".join(s[:120] for s in samples),
            category="Security Misconfiguration",
            url=url,
            cwe="CWE-319",
        )

    def _check_sri_missing(self, url: str, body: str, found: set[str]):
        """Detect external scripts loaded without Subresource Integrity."""
        scripts = SRI_SCRIPT_RE.findall(body)
        missing_sri = [s for s in scripts if not SRI_CHECK_RE.search(s)]
        if not missing_sri:
            return
        key = f"sri:{url}"
        if key in found:
            return
        found.add(key)
        self.add_finding(
            title="External Scripts Missing Subresource Integrity",
            severity=Severity.LOW,
            description=(
                f"Found {len(missing_sri)} external script(s) without integrity attributes. "
                "Without SRI, compromised CDNs can inject malicious code."
            ),
            recommendation="Add integrity and crossorigin attributes to external scripts.",
            evidence=f"URL: {url}\nScripts:\n" + "\n".join(s[:150] for s in missing_sri[:3]),
            category="Security Misconfiguration",
            url=url,
            cwe="CWE-353",
        )

    def _check_cookie_scope(self, url: str, headers: dict, found: set[str]):
        """Analyze Set-Cookie headers for scope and attribute issues."""
        from urllib.parse import urlparse
        for key_h, value in headers.items():
            if key_h.lower() != "set-cookie":
                continue
            cookie_parts = value.split(";")
            cookie_name = cookie_parts[0].split("=")[0].strip() if cookie_parts else ""
            lower_val = value.lower()

            # Check for overly broad domain scope
            domain_match = re.search(r"domain=\.?([^;\s]+)", lower_val)
            if domain_match:
                domain = domain_match.group(1)
                parsed = urlparse(url)
                host = parsed.hostname or ""
                # If cookie domain is a parent of the host, it's overly broad
                if domain != host and host.endswith(domain):
                    key = f"cookie_scope:{cookie_name}:{domain}"
                    if key not in found:
                        found.add(key)
                        self.add_finding(
                            title=f"Overly Broad Cookie Domain: {cookie_name}",
                            severity=Severity.LOW,
                            description=(
                                f"Cookie '{cookie_name}' is scoped to '{domain}' which is broader "
                                f"than the current host '{host}'. This shares the cookie with subdomains."
                            ),
                            recommendation="Scope cookies to the most specific domain needed.",
                            evidence=f"URL: {url}\nSet-Cookie: {value[:200]}",
                            category="Security Misconfiguration",
                            url=url,
                            cwe="CWE-1275",
                        )

            # Check path=/ on sensitive cookies
            is_sensitive = any(
                s in cookie_name.lower()
                for s in ("session", "token", "auth", "jwt", "api")
            )
            if is_sensitive and "path=/" in lower_val:
                key = f"cookie_path:{cookie_name}"
                if key not in found:
                    found.add(key)
                    self.add_finding(
                        title=f"Sensitive Cookie with Broad Path: {cookie_name}",
                        severity=Severity.INFO,
                        description=(
                            f"Sensitive cookie '{cookie_name}' has path=/ making it "
                            "accessible to all paths on the domain."
                        ),
                        recommendation="Restrict cookie paths to the minimum required scope.",
                        evidence=f"URL: {url}\nSet-Cookie: {value[:200]}",
                        category="Security Misconfiguration",
                        url=url,
                        cwe="CWE-1275",
                    )

    def _check_insecure_form_action(self, url: str, body: str,
                                    found: set[str]):
        """Detect forms with insecure action URLs or missing CSRF tokens."""
        if not url.startswith("https://"):
            return  # Only relevant for HTTPS pages
        form_re = re.compile(
            r'<form[^>]*action\s*=\s*["\']http://[^"\']+["\'][^>]*>',
            re.IGNORECASE,
        )
        for match in form_re.finditer(body):
            key = f"form_http:{url}:{match.start()}"
            if key in found:
                continue
            found.add(key)
            self.add_finding(
                title="Form Submits to Insecure HTTP URL",
                severity=Severity.MEDIUM,
                description="A form on an HTTPS page submits data over unencrypted HTTP.",
                recommendation="Use HTTPS URLs for all form actions.",
                evidence=f"URL: {url}\nForm: {match.group()[:200]}",
                category="Security Misconfiguration",
                url=url,
                cwe="CWE-319",
            )

    def _check_autocomplete_sensitive(self, url: str, body: str,
                                      found: set[str]):
        """Detect password/credit card fields without autocomplete=off."""
        sensitive_inputs = re.findall(
            r'<input[^>]*type\s*=\s*["\'](?:password|credit)["\'][^>]*>',
            body, re.IGNORECASE,
        )
        for inp in sensitive_inputs:
            if "autocomplete" in inp.lower():
                continue
            key = f"autocomplete:{url}:{hash(inp)}"
            if key in found:
                continue
            found.add(key)
            self.add_finding(
                title="Sensitive Input Missing autocomplete=off",
                severity=Severity.INFO,
                description="A password/sensitive input field lacks autocomplete=off.",
                recommendation='Add autocomplete="off" to sensitive input fields.',
                evidence=f"URL: {url}\nInput: {inp[:200]}",
                category="Security Misconfiguration",
                url=url,
                cwe="CWE-525",
            )

    def _check_csp_details(self, url: str, headers: dict, found: set[str]):
        """Deep CSP analysis beyond just presence check."""
        if url != self.config.target:
            return
        csp = self._get_header(headers, "Content-Security-Policy") or ""
        if not csp:
            return

        issues = []
        if "'unsafe-inline'" in csp:
            issues.append("unsafe-inline allows inline script execution (XSS risk)")
        if "'unsafe-eval'" in csp:
            issues.append("unsafe-eval allows eval() — common XSS vector")
        if "data:" in csp:
            issues.append("data: URIs can bypass CSP (script/style injection)")
        if "*" in csp and "*.googleapis.com" not in csp:
            issues.append("Wildcard sources weaken CSP protection")
        if "default-src" not in csp and "script-src" not in csp:
            issues.append("Missing default-src/script-src fallback")
        if "frame-ancestors" not in csp:
            issues.append("Missing frame-ancestors (clickjacking protection)")
        if "base-uri" not in csp:
            issues.append("Missing base-uri (base tag injection risk)")
        if "form-action" not in csp:
            issues.append("Missing form-action (form hijacking risk)")
        if "object-src" not in csp and "'none'" not in csp:
            issues.append("Missing object-src restriction (plugin abuse)")

        if not issues:
            return
        key = "csp_detail"
        if key in found:
            return
        found.add(key)
        self.add_finding(
            title="Content Security Policy Weaknesses",
            severity=Severity.MEDIUM,
            description=f"CSP header has {len(issues)} weakness(es):\n" + "\n".join(f"  - {i}" for i in issues),
            recommendation="Tighten CSP: remove unsafe-inline/eval, add missing directives.",
            evidence=f"URL: {url}\nCSP: {csp[:300]}\nIssues: {len(issues)}",
            category="Security Misconfiguration",
            url=url,
            cwe="CWE-693",
        )

    def _check_hsts_details(self, url: str, headers: dict,
                            found: set[str]):
        """Deep HSTS analysis: max-age, includeSubDomains, preload."""
        if url != self.config.target:
            return
        hsts = self._get_header(headers, "Strict-Transport-Security") or ""
        if not hsts:
            return

        issues = []
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                issues.append(f"max-age={max_age} is less than 1 year (31536000)")
        else:
            issues.append("max-age directive missing")

        if "includesubdomains" not in hsts.lower():
            issues.append("Missing includeSubDomains — subdomains not protected")
        if "preload" not in hsts.lower():
            issues.append("Missing preload — not eligible for browser HSTS preload list")

        if not issues:
            return
        key = "hsts_detail"
        if key in found:
            return
        found.add(key)
        self.add_finding(
            title="HSTS Configuration Weaknesses",
            severity=Severity.LOW,
            description=f"HSTS header has {len(issues)} issue(s):\n" + "\n".join(f"  - {i}" for i in issues),
            recommendation="Set max-age>=31536000; add includeSubDomains and preload.",
            evidence=f"URL: {url}\nHSTS: {hsts}",
            category="Security Misconfiguration",
            url=url,
            cwe="CWE-693",
        )

    def _check_api_discovery(self, found: set[str]):
        """Probe well-known API/config endpoints (low-impact GET requests)."""
        from urllib.parse import urljoin
        base = self.config.target.rstrip("/")

        for path, title, severity in API_DISCOVERY_PATHS:
            probe_url = urljoin(base + "/", path.lstrip("/"))
            key = f"api_discovery:{path}"
            if key in found:
                continue
            try:
                resp = self.http_client.get(probe_url, timeout=5,
                                            allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 10:
                    # Validate it's not a generic 404 page
                    if "not found" in resp.text.lower()[:200]:
                        continue
                    if "404" in resp.text[:200]:
                        continue
                    found.add(key)
                    self.add_finding(
                        title=title,
                        severity=severity,
                        description=f"The endpoint {path} returned a valid 200 response.",
                        recommendation=f"Restrict access to {path} or remove it from production.",
                        evidence=f"URL: {probe_url}\nStatus: {resp.status_code}\nBody preview: {resp.text[:200]}",
                        category="Information Disclosure",
                        url=probe_url,
                        cwe="CWE-200",
                    )
            except Exception:
                continue

    def _check_backup_files(self, urls: list[str], found: set[str]):
        """Probe for backup copies of discovered files."""
        from urllib.parse import urlparse
        # Collect unique paths (only files with extensions)
        paths_seen: set[str] = set()
        for url in urls[:50]:
            parsed = urlparse(url)
            path = parsed.path
            if "." in path.rsplit("/", 1)[-1]:
                paths_seen.add(path)

        base = self.config.target.rstrip("/")
        for path in list(paths_seen)[:30]:  # Cap to avoid excessive requests
            for ext in BACKUP_EXTENSIONS[:6]:  # Top 6 most common
                backup_path = path + ext
                probe_url = base + backup_path
                key = f"backup:{backup_path}"
                if key in found:
                    continue
                try:
                    resp = self.http_client.get(probe_url, timeout=5,
                                                allow_redirects=False)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        if "not found" in resp.text.lower()[:200]:
                            continue
                        found.add(key)
                        self.add_finding(
                            title=f"Backup File Found: {backup_path}",
                            severity=Severity.HIGH,
                            description=(
                                f"A backup file was found at {backup_path}. "
                                "Backup files may contain source code or credentials."
                            ),
                            recommendation="Remove backup and temporary files from the web root.",
                            evidence=f"URL: {probe_url}\nStatus: {resp.status_code}\nSize: {len(resp.text)} bytes",
                            category="Information Disclosure",
                            url=probe_url,
                            cwe="CWE-530",
                        )
                except Exception:
                    continue
