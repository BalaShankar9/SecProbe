"""
Cloud & Infrastructure Exposure Scanner.

Detects exposed cloud resources and infrastructure misconfigurations:
  - Git repository exposure (.git/HEAD, .git/config)
  - Environment file leaks (.env, .env.production, .env.local)
  - AWS S3 bucket misconfiguration
  - Docker/Kubernetes API exposure
  - CI/CD configuration leaks (.github, .gitlab-ci.yml, Jenkinsfile)
  - Backup file exposure (.bak, .old, .orig, .swp)
  - Debug/admin panel exposure
  - Source map file exposure
  - Database dump exposure
  - Server status/info pages
"""

import re
from urllib.parse import urljoin, urlparse

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# ── Sensitive file paths to check ─────────────────────────────────
SENSITIVE_PATHS = [
    # Git
    (".git/HEAD", Severity.CRITICAL, "Git repository exposed", "CWE-538",
     "refs/heads/", "Full source code can be reconstructed from exposed .git"),
    (".git/config", Severity.CRITICAL, "Git config exposed", "CWE-538",
     "[core]", "Git configuration may contain credentials and remote URLs"),
    (".git/logs/HEAD", Severity.HIGH, "Git logs exposed", "CWE-538",
     "commit", "Git history reveals developer activity and commit messages"),

    # Environment files
    (".env", Severity.CRITICAL, "Environment file exposed", "CWE-538",
     None, "Environment files often contain database credentials, API keys, secrets"),
    (".env.production", Severity.CRITICAL, "Production env file exposed", "CWE-538",
     None, "Production environment variables with live credentials"),
    (".env.local", Severity.HIGH, "Local env file exposed", "CWE-538",
     None, "Local environment file may contain development secrets"),
    (".env.backup", Severity.CRITICAL, "Env backup exposed", "CWE-538",
     None, "Backup of environment file with credentials"),
    ("env.js", Severity.HIGH, "JS environment config exposed", "CWE-538",
     None, "JavaScript environment configuration"),
    ("config.js", Severity.MEDIUM, "JS config exposed", "CWE-538",
     None, "JavaScript configuration file"),

    # CI/CD
    (".github/workflows/main.yml", Severity.HIGH, "GitHub Actions workflow exposed", "CWE-538",
     "on:", "CI/CD workflow may reveal build secrets and deployment targets"),
    (".gitlab-ci.yml", Severity.HIGH, "GitLab CI config exposed", "CWE-538",
     "stages:", "GitLab CI configuration with potential secrets"),
    ("Jenkinsfile", Severity.HIGH, "Jenkinsfile exposed", "CWE-538",
     "pipeline", "Jenkins pipeline with potential credentials"),
    (".circleci/config.yml", Severity.HIGH, "CircleCI config exposed", "CWE-538",
     "version:", "CircleCI configuration"),
    (".travis.yml", Severity.MEDIUM, "Travis CI config exposed", "CWE-538",
     "language:", "Travis CI configuration"),
    ("Dockerfile", Severity.MEDIUM, "Dockerfile exposed", "CWE-538",
     "FROM", "Docker build instructions may reveal architecture"),
    ("docker-compose.yml", Severity.HIGH, "Docker Compose exposed", "CWE-538",
     "services:", "Docker Compose with service topology and potential credentials"),

    # Backup / temp files
    ("wp-config.php.bak", Severity.CRITICAL, "WordPress config backup", "CWE-538",
     None, "WordPress configuration backup with database credentials"),
    ("wp-config.php~", Severity.CRITICAL, "WordPress config editor backup", "CWE-538",
     None, "Editor backup of WordPress configuration"),
    ("wp-config.php.old", Severity.CRITICAL, "WordPress config old version", "CWE-538",
     None, "Old WordPress configuration file"),
    ("config.php.bak", Severity.HIGH, "Config backup exposed", "CWE-538",
     None, "Configuration backup file"),
    ("database.sql", Severity.CRITICAL, "Database dump exposed", "CWE-538",
     None, "SQL database dump with potentially all application data"),
    ("dump.sql", Severity.CRITICAL, "Database dump exposed", "CWE-538",
     None, "SQL database dump"),
    ("backup.zip", Severity.CRITICAL, "Backup archive exposed", "CWE-538",
     None, "Full site backup archive"),
    ("backup.tar.gz", Severity.CRITICAL, "Backup archive exposed", "CWE-538",
     None, "Full site backup archive"),

    # Debug / Admin
    ("phpinfo.php", Severity.HIGH, "phpinfo() exposed", "CWE-200",
     "phpinfo()", "PHP configuration reveals server paths, extensions, and settings"),
    ("info.php", Severity.HIGH, "PHP info page exposed", "CWE-200",
     None, "PHP information page"),
    ("server-status", Severity.MEDIUM, "Apache server-status exposed", "CWE-200",
     "Apache Server Status", "Apache status page reveals request info and connections"),
    ("server-info", Severity.MEDIUM, "Apache server-info exposed", "CWE-200",
     "Apache Server Information", "Apache info page reveals server configuration"),
    ("nginx_status", Severity.MEDIUM, "Nginx status exposed", "CWE-200",
     "Active connections", "Nginx status reveals connection information"),
    ("debug", Severity.HIGH, "Debug endpoint exposed", "CWE-489",
     None, "Debug endpoint may reveal sensitive application data"),
    ("_debug", Severity.HIGH, "Debug endpoint exposed", "CWE-489",
     None, "Debug endpoint"),
    ("elmah.axd", Severity.HIGH, "ELMAH error log exposed", "CWE-209",
     "Error Log", "ASP.NET error log reveals stack traces and server info"),
    ("trace.axd", Severity.HIGH, "ASP.NET trace exposed", "CWE-209",
     None, "ASP.NET application trace"),

    # Cloud
    (".aws/credentials", Severity.CRITICAL, "AWS credentials exposed", "CWE-538",
     "aws_access_key", "AWS access keys and secret keys"),
    ("aws.yml", Severity.HIGH, "AWS config exposed", "CWE-538",
     None, "AWS configuration file"),
    (".gcloud/credentials.json", Severity.CRITICAL, "GCP credentials exposed", "CWE-538",
     None, "Google Cloud Platform service account credentials"),
    ("firebase.json", Severity.MEDIUM, "Firebase config exposed", "CWE-538",
     None, "Firebase project configuration"),
    ("terraform.tfstate", Severity.CRITICAL, "Terraform state exposed", "CWE-538",
     None, "Terraform state contains all infrastructure details and secrets"),

    # API docs (info disclosure)
    ("swagger.json", Severity.MEDIUM, "Swagger/OpenAPI spec exposed", "CWE-200",
     None, "API documentation reveals all endpoints and data models"),
    ("openapi.json", Severity.MEDIUM, "OpenAPI spec exposed", "CWE-200",
     None, "API specification"),
    ("api-docs", Severity.LOW, "API docs exposed", "CWE-200",
     None, "API documentation"),

    # Kubernetes
    (".kube/config", Severity.CRITICAL, "Kubernetes config exposed", "CWE-538",
     None, "Kubernetes configuration with cluster access"),

    # SSH
    (".ssh/id_rsa", Severity.CRITICAL, "SSH private key exposed", "CWE-538",
     "BEGIN RSA PRIVATE KEY", "SSH private key enables server access"),
    (".ssh/authorized_keys", Severity.HIGH, "SSH authorized keys exposed", "CWE-538",
     None, "SSH authorized keys list"),

    # Package files
    ("package.json", Severity.LOW, "Package.json exposed", "CWE-200",
     None, "Node.js dependencies revealed"),
    ("composer.json", Severity.LOW, "Composer.json exposed", "CWE-200",
     None, "PHP dependencies revealed"),
    ("requirements.txt", Severity.LOW, "Requirements.txt exposed", "CWE-200",
     None, "Python dependencies revealed"),
    ("Gemfile", Severity.LOW, "Gemfile exposed", "CWE-200",
     None, "Ruby dependencies revealed"),
]


class CloudScanner(SmartScanner):
    name = "Cloud & Infrastructure Scanner"
    description = "Detect exposed cloud resources, git repos, env files, backup files, debug panels"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Cloud/infrastructure exposure scan on {url}", "progress")

        # ── Phase 1: Sensitive file discovery ─────────────────────
        print_status("Phase 1: Sensitive file discovery", "progress")
        self._check_sensitive_paths(url)

        # ── Phase 2: S3 bucket detection ──────────────────────────
        print_status("Phase 2: Cloud storage bucket detection", "progress")
        self._check_s3_buckets(url)

        # ── Phase 3: Docker/K8s API detection ─────────────────────
        print_status("Phase 3: Container API detection", "progress")
        self._check_container_apis(url)

        # ── Phase 4: Source map analysis ──────────────────────────
        print_status("Phase 4: Source map exposure", "progress")
        self._check_source_maps(url)

        # ── Phase 5: Robots.txt / sitemap analysis ────────────────
        print_status("Phase 5: Robots.txt intelligence", "progress")
        self._analyze_robots(url)

        # ── Phase 6: Well-known paths ─────────────────────────────
        print_status("Phase 6: Well-known path analysis", "progress")
        self._check_well_known(url)

    def _check_sensitive_paths(self, url):
        """Check for exposed sensitive files."""
        found_count = 0

        for entry in SENSITIVE_PATHS:
            path, severity, title, cwe, fingerprint, description = entry
            test_url = urljoin(url, f"/{path}")

            try:
                resp = self.http_client.get(test_url, timeout=8, allow_redirects=False)

                if resp.status_code == 200:
                    # Verify it's not a custom 404 page
                    if self._is_real_file(resp, fingerprint, path):
                        found_count += 1

                        # Sanitize evidence (don't leak actual secrets)
                        evidence_text = resp.text[:200] if len(resp.text) < 500 else resp.text[:200] + "..."
                        # Mask potential credentials
                        evidence_text = re.sub(
                            r'(?i)(password|secret|key|token|credential)\s*[=:]\s*\S+',
                            r'\1=***REDACTED***',
                            evidence_text
                        )

                        self.add_finding(
                            title=f"Exposed: {title}",
                            severity=severity,
                            description=description,
                            recommendation=f"Remove or restrict access to /{path}. Add to .htaccess or nginx deny rules.",
                            evidence=f"URL: {test_url}\nStatus: 200\nContent preview:\n{evidence_text}",
                            category="Cloud/Infrastructure",
                            url=test_url,
                            cwe=cwe,
                        )
                        print_finding(severity, f"Exposed: {path}")

            except Exception:
                continue

        print_status(f"Found {found_count} exposed sensitive file(s)", "info")

    def _is_real_file(self, resp, fingerprint, path):
        """Verify a response is a real file, not a custom 404/redirect."""
        text = resp.text.lower()

        # Check for custom 404 indicators
        if any(k in text for k in ["page not found", "404", "not found", "does not exist"]):
            if len(resp.text) < 5000:  # Small page is likely 404
                return False

        # Check fingerprint if available
        if fingerprint and fingerprint.lower() not in text:
            return False

        # Check content type
        ct = resp.headers.get("Content-Type", "").lower()
        if path.endswith((".php", ".py", ".rb")):
            # These should not be served as text in production
            if "text/html" in ct and "<?php" not in resp.text:
                return False

        # Check for meaningful content
        if len(resp.text.strip()) < 10:
            return False

        return True

    def _check_s3_buckets(self, url):
        """Check for S3 bucket references and misconfiguration."""
        try:
            resp = self.http_client.get(url, timeout=10)
            html = resp.text

            # Find S3 bucket references
            s3_patterns = [
                r'([\w.-]+)\.s3\.amazonaws\.com',
                r's3\.amazonaws\.com/([\w.-]+)',
                r'([\w.-]+)\.s3[.-][\w-]+\.amazonaws\.com',
                r'([\w.-]+)\.storage\.googleapis\.com',
                r'([\w.-]+)\.blob\.core\.windows\.net',
            ]

            buckets = set()
            for pattern in s3_patterns:
                for match in re.finditer(pattern, html):
                    buckets.add(match.group(1))

            # Test each bucket for public access
            for bucket in list(buckets)[:5]:
                self._test_bucket_access(bucket, url)

        except Exception:
            pass

    def _test_bucket_access(self, bucket, url):
        """Test if an S3 bucket is publicly accessible."""
        test_urls = [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
        ]

        for test_url in test_urls:
            try:
                resp = self.http_client.get(test_url, timeout=10)
                if resp.status_code == 200 and "<ListBucketResult" in resp.text:
                    self.add_finding(
                        title=f"Public S3 bucket: {bucket}",
                        severity=Severity.HIGH,
                        description=f"S3 bucket '{bucket}' allows public listing of objects.",
                        recommendation="Set the bucket policy to deny public access. Enable S3 Block Public Access.",
                        evidence=f"URL: {test_url}\nBucket listing enabled",
                        category="Cloud/Infrastructure",
                        url=test_url,
                        cwe="CWE-284",
                    )
                    print_finding(Severity.HIGH, f"Public S3 bucket: {bucket}")
                    return
            except Exception:
                continue

    def _check_container_apis(self, url):
        """Check for exposed Docker and Kubernetes APIs."""
        container_endpoints = [
            ("/v2/_catalog", "Docker Registry API", Severity.CRITICAL, "Docker registry allows image listing"),
            ("/api/v1/pods", "Kubernetes API - Pods", Severity.CRITICAL, "K8s API exposes pod information"),
            ("/api/v1/namespaces", "Kubernetes API - Namespaces", Severity.CRITICAL, "K8s API exposes namespaces"),
            ("/api/v1/secrets", "Kubernetes API - Secrets", Severity.CRITICAL, "K8s API exposes secrets"),
            ("/_cluster/health", "Elasticsearch cluster health", Severity.HIGH, "Elasticsearch cluster exposed"),
            ("/_cat/indices", "Elasticsearch indices", Severity.HIGH, "Elasticsearch index listing"),
        ]

        for path, name, severity, desc in container_endpoints:
            test_url = urljoin(url, path)
            try:
                resp = self.http_client.get(test_url, timeout=8)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, (dict, list)) and len(str(data)) > 20:
                            self.add_finding(
                                title=f"Exposed: {name}",
                                severity=severity,
                                description=desc,
                                recommendation=f"Restrict access to {path}. Require authentication.",
                                evidence=f"URL: {test_url}\nResponse: {str(data)[:200]}",
                                category="Cloud/Infrastructure",
                                url=test_url,
                                cwe="CWE-284",
                            )
                            print_finding(severity, f"Exposed: {name}")
                    except Exception:
                        pass
            except Exception:
                continue

    def _check_source_maps(self, url):
        """Check for exposed JavaScript source maps."""
        try:
            resp = self.http_client.get(url, timeout=10)

            # Find JS files
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', resp.text, re.I)

            for js_file in js_files[:10]:
                map_url = urljoin(url, f"{js_file}.map")
                try:
                    map_resp = self.http_client.get(map_url, timeout=8)
                    if map_resp.status_code == 200:
                        try:
                            data = map_resp.json()
                            if "sources" in data or "mappings" in data:
                                sources = data.get("sources", [])
                                self.add_finding(
                                    title=f"Source map exposed: {js_file}.map",
                                    severity=Severity.MEDIUM,
                                    description=(
                                        f"JavaScript source map is publicly accessible, revealing original "
                                        f"source code.\nSource files: {len(sources)}"
                                    ),
                                    recommendation="Remove source maps from production or restrict access.",
                                    evidence=f"URL: {map_url}\nSources: {', '.join(sources[:5])}",
                                    category="Cloud/Infrastructure",
                                    url=map_url,
                                    cwe="CWE-540",
                                )
                                print_finding(Severity.MEDIUM, f"Source map: {js_file}.map")
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

    def _analyze_robots(self, url):
        """Analyze robots.txt for hidden paths."""
        try:
            resp = self.http_client.get(urljoin(url, "/robots.txt"), timeout=10)
            if resp.status_code == 200 and ("Disallow" in resp.text or "Allow" in resp.text):
                # Extract disallowed paths (potential sensitive paths)
                disallowed = re.findall(r'Disallow:\s*(.+)', resp.text)
                sensitive_paths = [p.strip() for p in disallowed if p.strip() and p.strip() != "/"]

                if sensitive_paths:
                    # Check if any disallowed paths are actually accessible
                    accessible = []
                    for path in sensitive_paths[:10]:
                        try:
                            check = self.http_client.get(urljoin(url, path), timeout=5, allow_redirects=False)
                            if check.status_code == 200:
                                accessible.append(path)
                        except Exception:
                            pass

                    if accessible:
                        self.add_finding(
                            title=f"Robots.txt disallowed paths accessible ({len(accessible)})",
                            severity=Severity.LOW,
                            description=(
                                f"Paths hidden from search engines via robots.txt are still accessible:\n"
                                + "\n".join(f"  • {p}" for p in accessible)
                            ),
                            recommendation="Use proper authentication/authorization instead of relying on robots.txt.",
                            evidence=f"Accessible disallowed paths: {', '.join(accessible)}",
                            category="Cloud/Infrastructure",
                            url=urljoin(url, "/robots.txt"),
                            cwe="CWE-200",
                        )

                self.result.raw_data["robots_disallowed"] = sensitive_paths
        except Exception:
            pass

    def _check_well_known(self, url):
        """Check .well-known paths for information disclosure."""
        well_known = [
            ("/.well-known/security.txt", "Security contact", Severity.INFO),
            ("/.well-known/openid-configuration", "OpenID configuration", Severity.LOW),
            ("/.well-known/jwks.json", "JWKS (JSON Web Key Set)", Severity.LOW),
            ("/.well-known/assetlinks.json", "Android asset links", Severity.INFO),
            ("/.well-known/apple-app-site-association", "Apple app association", Severity.INFO),
            ("/.well-known/change-password", "Password change endpoint", Severity.INFO),
        ]

        for path, name, severity in well_known:
            test_url = urljoin(url, path)
            try:
                resp = self.http_client.get(test_url, timeout=8)
                if resp.status_code == 200 and len(resp.text.strip()) > 5:
                    self.result.raw_data.setdefault("well_known", {})[name] = test_url
            except Exception:
                continue
