"""
JavaScript Secrets & Endpoint Scanner.

Analyzes JavaScript files for:
  - Leaked API keys, tokens, passwords, secrets
  - Hidden API endpoints and internal URLs
  - Source map files exposing original source
  - Hardcoded credentials and sensitive configuration
  - Dangerous function usage (eval, innerHTML, document.write)
  - Cloud service keys (AWS, GCP, Azure, Stripe, Twilio, etc.)
"""

import re
from urllib.parse import urljoin, urlparse

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# ── Secret patterns: (name, regex, severity, description) ────────
SECRET_PATTERNS = [
    # Cloud providers
    ("AWS Access Key", r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", Severity.CRITICAL,
     "AWS IAM access key ID found in JavaScript"),
    ("AWS Secret Key", r"(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", Severity.CRITICAL,
     "AWS secret access key found in JavaScript"),
    ("GCP API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH,
     "Google Cloud Platform API key found"),
    ("GCP Service Account", r'"type"\s*:\s*"service_account"', Severity.CRITICAL,
     "Google service account credentials found"),
    ("Azure Storage Key", r"(?:AccountKey|azure[_-]?storage[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{86,88})['\"]", Severity.CRITICAL,
     "Azure Storage account key found"),

    # Payment
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL,
     "Stripe live secret key found — can charge cards"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", Severity.MEDIUM,
     "Stripe publishable key found (limited risk but information leak)"),
    ("PayPal Braintree Token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", Severity.CRITICAL,
     "PayPal/Braintree production access token"),

    # Auth tokens
    ("Generic API Key", r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{16,64})['\"]", Severity.HIGH,
     "Generic API key found in JavaScript"),
    ("Generic Secret", r"(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,64})['\"]", Severity.HIGH,
     "Password or secret string found in JavaScript"),
    ("Bearer Token", r"(?:bearer|authorization)\s*[:=]\s*['\"](?:Bearer\s+)?([A-Za-z0-9\-_.~+/]+=*)['\"]", Severity.HIGH,
     "Bearer authentication token found"),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", Severity.HIGH,
     "JWT token found in JavaScript source"),
    ("Private Key", r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL,
     "Private key found in JavaScript!"),

    # Communication services
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", Severity.HIGH,
     "Twilio API key found"),
    ("SendGrid Key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", Severity.HIGH,
     "SendGrid API key found"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", Severity.HIGH,
     "Slack webhook URL found"),
    ("Slack Token", r"xox[bpars]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", Severity.HIGH,
     "Slack OAuth token found"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", Severity.MEDIUM,
     "Discord webhook URL found"),

    # Database
    ("MongoDB URI", r"mongodb(?:\+srv)?://[^\s'\"]+", Severity.CRITICAL,
     "MongoDB connection string found"),
    ("MySQL URI", r"mysql://[^\s'\"]+", Severity.CRITICAL,
     "MySQL connection string found"),
    ("PostgreSQL URI", r"postgres(?:ql)?://[^\s'\"]+", Severity.CRITICAL,
     "PostgreSQL connection string found"),
    ("Redis URI", r"redis://[^\s'\"]+", Severity.CRITICAL,
     "Redis connection string found"),

    # Firebase
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com", Severity.MEDIUM,
     "Firebase database URL found — check rules"),
    ("Firebase Config", r"apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]", Severity.HIGH,
     "Firebase configuration with API key"),

    # SaaS
    ("Mailgun Key", r"key-[0-9a-zA-Z]{32}", Severity.HIGH,
     "Mailgun API key found"),
    ("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", Severity.CRITICAL,
     "Square access token found"),
    ("Shopify Token", r"shpat_[a-fA-F0-9]{32}", Severity.HIGH,
     "Shopify admin API token found"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}", Severity.CRITICAL,
     "GitHub personal access token found"),
    ("Heroku API Key", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", Severity.MEDIUM,
     "Possible Heroku API key or UUID found"),
    ("Mapbox Token", r"pk\.eyJ1[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", Severity.LOW,
     "Mapbox public access token"),
]

# ── Endpoint patterns ──────────────────────────────────────────
ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']'),
    re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9/_-]+)["\']'),
    re.compile(r'["\'](/graphql)["\']'),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]+)["\']'),
    re.compile(r'["\'](/internal/[a-zA-Z0-9/_-]+)["\']'),
    re.compile(r'["\'](/admin/[a-zA-Z0-9/_-]+)["\']'),
    re.compile(r'["\'](/debug/[a-zA-Z0-9/_-]+)["\']'),
    re.compile(r'["\']https?://[^"\']+/api/[^"\']+["\']'),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'XMLHttpRequest.*?open\s*\([^,]*,\s*["\']([^"\']+)["\']'),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']'),
]

# ── Dangerous JS patterns ──────────────────────────────────────
DANGEROUS_PATTERNS = [
    (r'eval\s*\(', "eval() usage", "eval() can execute arbitrary code. Use JSON.parse() or safer alternatives."),
    (r'document\.write\s*\(', "document.write() usage", "document.write() can lead to DOM-based XSS."),
    (r'\.innerHTML\s*=', "innerHTML assignment", "Direct innerHTML assignment can lead to XSS. Use textContent instead."),
    (r'\.outerHTML\s*=', "outerHTML assignment", "outerHTML assignment can lead to XSS."),
    (r'window\.location\s*=.*(?:hash|search|href)', "Unvalidated redirect", "User-controlled redirect via location assignment."),
    (r'postMessage\s*\([^)]*\*', "Unrestricted postMessage", "postMessage with '*' origin allows any site to receive data."),
]


class JSScanner(SmartScanner):
    name = "JS Secrets Scanner"
    description = "Analyze JavaScript for leaked secrets, endpoints, and dangerous patterns"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"JavaScript analysis on {url}", "progress")

        try:
            resp = self.http_client.get(url)
        except Exception as e:
            self.result.error = str(e)
            return

        # ── Phase 1: Discover JavaScript files ────────────────────
        js_urls = self._discover_js_files(url, resp.text)
        print_status(f"Found {len(js_urls)} JavaScript file(s)", "info")

        if not js_urls:
            self.add_finding(
                title="No JavaScript files discovered",
                severity=Severity.INFO,
                description="No external JS files found to analyze.",
                category="JavaScript Security",
            )
            return

        # ── Phase 2: Download and analyze each JS file ────────────
        all_secrets = []
        all_endpoints = set()
        all_dangerous = []

        # Analyze inline scripts first
        inline_js = getattr(self, '_inline_js', "")
        if inline_js and len(inline_js) > 10:
            for name, pattern, severity, desc in SECRET_PATTERNS:
                matches = re.finditer(pattern, inline_js, re.IGNORECASE)
                for match in matches:
                    secret_value = match.group(0)[:80]
                    if self._is_false_positive(name, secret_value):
                        continue
                    all_secrets.append((name, severity, desc, f"{url} (inline)", secret_value))

            for pattern in ENDPOINT_PATTERNS:
                for match in pattern.finditer(inline_js):
                    endpoint = match.group(1) if match.lastindex else match.group(0)
                    endpoint = endpoint.strip("'\"")
                    all_endpoints.add((endpoint, f"{url} (inline)"))

            for pattern, name, rec in DANGEROUS_PATTERNS:
                if re.search(pattern, inline_js, re.IGNORECASE):
                    all_dangerous.append((name, rec, f"{url} (inline)"))

        for js_url in js_urls[:50]:  # Limit to 50 files
            try:
                js_resp = self.http_client.get(js_url)
                if js_resp.status_code != 200:
                    continue
                js_content = js_resp.text
                if len(js_content) < 10:
                    continue
            except Exception:
                continue

            # Check for source maps
            self._check_source_map(js_url, js_content)

            # Scan for secrets
            for name, pattern, severity, desc in SECRET_PATTERNS:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    secret_value = match.group(0)[:80]
                    # Skip common false positives
                    if self._is_false_positive(name, secret_value):
                        continue
                    all_secrets.append((name, severity, desc, js_url, secret_value))

            # Scan for hidden endpoints
            for pattern in ENDPOINT_PATTERNS:
                for match in pattern.finditer(js_content):
                    endpoint = match.group(1) if match.lastindex else match.group(0)
                    endpoint = endpoint.strip("'\"")
                    all_endpoints.add((endpoint, js_url))

            # Scan for dangerous patterns
            for pattern, name, rec in DANGEROUS_PATTERNS:
                if re.search(pattern, js_content, re.IGNORECASE):
                    all_dangerous.append((name, rec, js_url))

        # ── Phase 3: Report findings ──────────────────────────────
        # Secrets
        reported_secrets = set()
        for name, severity, desc, source, value in all_secrets:
            key = f"{name}:{value[:30]}"
            if key in reported_secrets:
                continue
            reported_secrets.add(key)
            self.add_finding(
                title=f"JS Secret: {name}",
                severity=severity,
                description=desc,
                recommendation="Remove secrets from client-side code. Use environment variables and backend proxies.",
                evidence=f"Source: {source}\nMatch: {value}",
                category="JavaScript Security",
                url=source,
                cwe="CWE-798",
            )
            print_finding(severity, f"JS Secret: {name} in {urlparse(source).path}")

        # Hidden endpoints
        interesting = [e for e in all_endpoints
                       if any(k in e[0].lower() for k in
                              ("admin", "internal", "debug", "private", "secret",
                               "config", "backup", "api", "graphql", "token",
                               "auth", "user", "password", "upload", "delete"))]
        if interesting:
            endpoints_list = "\n".join(f"  {e[0]}  (from {e[1]})" for e in list(interesting)[:20])
            self.add_finding(
                title=f"Hidden API endpoints discovered ({len(interesting)})",
                severity=Severity.MEDIUM,
                description=f"JavaScript source reveals API endpoints that may not be publicly documented.",
                recommendation="Review all exposed endpoints for proper authentication and authorization.",
                evidence=f"Endpoints found:\n{endpoints_list}",
                category="JavaScript Security",
                url=url,
                cwe="CWE-200",
            )
            print_finding(Severity.MEDIUM, f"Found {len(interesting)} hidden API endpoints")

        # Store all endpoints for other scanners
        self.result.raw_data["js_endpoints"] = [e[0] for e in all_endpoints]

        # Dangerous patterns
        reported_dangerous = set()
        for name, rec, source in all_dangerous:
            key = f"{name}:{source}"
            if key in reported_dangerous:
                continue
            reported_dangerous.add(key)
            self.add_finding(
                title=f"Dangerous JS pattern: {name}",
                severity=Severity.LOW,
                description=f"Potentially dangerous JavaScript pattern found: {name}",
                recommendation=rec,
                evidence=f"Source: {source}",
                category="JavaScript Security",
                url=source,
                cwe="CWE-79",
            )

        print_status(f"Analyzed {len(js_urls)} JS files: {len(reported_secrets)} secrets, "
                     f"{len(all_endpoints)} endpoints, {len(reported_dangerous)} dangerous patterns", "info")

    def _discover_js_files(self, base_url, html):
        """Extract JS file URLs from HTML and common paths."""
        js_urls = set()

        # Extract from script tags
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        for match in script_pattern.finditer(html):
            src = match.group(1)
            js_urls.add(urljoin(base_url, src))

        # Common JS paths
        common_js = [
            "/app.js", "/main.js", "/bundle.js", "/vendor.js",
            "/static/js/main.js", "/static/js/app.js",
            "/assets/js/app.js", "/dist/bundle.js",
            "/build/static/js/main.js",
            "/js/app.js", "/js/main.js", "/js/scripts.js",
            "/wp-includes/js/jquery/jquery.min.js",
            "/wp-content/themes/theme/assets/js/app.js",
        ]
        for path in common_js:
            js_urls.add(urljoin(base_url, path))

        # Also check inline scripts in HTML
        inline_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        inline_scripts = inline_pattern.findall(html)
        if inline_scripts:
            # Store inline content for analysis
            self._inline_js = "\n".join(inline_scripts)

        return list(js_urls)

    def _check_source_map(self, js_url, js_content):
        """Check for source map files that expose original source code."""
        # Check for sourceMappingURL comment
        map_match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_content)
        if map_match:
            map_url = urljoin(js_url, map_match.group(1))
            try:
                resp = self.http_client.get(map_url, allow_redirects=False)
                if resp.status_code == 200 and ("mappings" in resp.text or "sources" in resp.text):
                    self.add_finding(
                        title="JavaScript source map exposed",
                        severity=Severity.MEDIUM,
                        description="Source map file is publicly accessible, exposing original source code.",
                        recommendation="Remove source maps from production or restrict access.",
                        evidence=f"Source map: {map_url}\nSize: {len(resp.text)} bytes",
                        category="JavaScript Security",
                        url=map_url,
                        cwe="CWE-540",
                    )
                    print_finding(Severity.MEDIUM, f"Source map exposed: {map_url}")
            except Exception:
                pass

        # Also try .map extension
        map_url = js_url + ".map"
        try:
            resp = self.http_client.get(map_url, allow_redirects=False)
            if resp.status_code == 200 and len(resp.text) > 100:
                if "mappings" in resp.text or "sources" in resp.text:
                    self.add_finding(
                        title="JavaScript source map exposed (.map)",
                        severity=Severity.MEDIUM,
                        description=f"Source map at {map_url} exposes original source code.",
                        recommendation="Remove source maps from production.",
                        evidence=f"URL: {map_url}\nSize: {len(resp.text)} bytes",
                        category="JavaScript Security",
                        url=map_url,
                        cwe="CWE-540",
                    )
        except Exception:
            pass

    def _is_false_positive(self, secret_name, value):
        """Filter out common false positives."""
        value_lower = value.lower()
        # Skip placeholder values
        placeholders = ["example", "your_", "xxx", "placeholder", "change_me",
                        "insert_", "todo", "fixme", "replace_", "test_", "dummy",
                        "sample", "demo", "fake"]
        for p in placeholders:
            if p in value_lower:
                return True
        # Skip very common non-secrets
        if secret_name == "Heroku API Key" and value_lower.startswith("00000"):
            return True
        # Skip short generic matches
        if secret_name == "Generic Secret" and len(value) < 12:
            return True
        return False
