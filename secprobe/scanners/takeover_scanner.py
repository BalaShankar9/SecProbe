"""
Subdomain Takeover Scanner.

Checks for dangling DNS records pointing to decommissioned cloud services:
  - AWS S3 / CloudFront / Elastic Beanstalk / ELB
  - Azure Blob / Azure websites / Traffic Manager
  - GitHub Pages / Heroku / Netlify / Vercel
  - Shopify / Tumblr / Fastly / Pantheon / Cargo
  - Google Cloud Storage / Firebase
  - Zendesk / Freshdesk / Help Scout
"""

import re
import socket
from urllib.parse import urlparse

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ── Fingerprints for takeover-vulnerable services ────────────────
# (service_name, cname_pattern, response_fingerprint, severity)
TAKEOVER_FINGERPRINTS = [
    # AWS
    ("AWS S3", r'\.s3[.-].*\.amazonaws\.com', "NoSuchBucket", Severity.CRITICAL),
    ("AWS S3 Website", r'\.s3-website[.-].*\.amazonaws\.com', "NoSuchBucket", Severity.CRITICAL),
    ("AWS CloudFront", r'\.cloudfront\.net', "Bad request", Severity.HIGH),
    ("AWS Elastic Beanstalk", r'\.elasticbeanstalk\.com', "NXDOMAIN", Severity.HIGH),
    ("AWS ELB", r'\.elb\.amazonaws\.com', "NXDOMAIN", Severity.HIGH),

    # Azure
    ("Azure Websites", r'\.azurewebsites\.net', "404 Web Site not found", Severity.CRITICAL),
    ("Azure Blob", r'\.blob\.core\.windows\.net', "BlobNotFound", Severity.HIGH),
    ("Azure CDN", r'\.azureedge\.net', "404", Severity.HIGH),
    ("Azure Traffic Manager", r'\.trafficmanager\.net', "NXDOMAIN", Severity.HIGH),

    # Google
    ("Google Cloud Storage", r'\.storage\.googleapis\.com', "NoSuchBucket", Severity.CRITICAL),
    ("Firebase", r'\.firebaseapp\.com', "Site Not Found", Severity.HIGH),
    ("Google App Engine", r'\.appspot\.com', "404", Severity.MEDIUM),

    # Hosting / CDN
    ("GitHub Pages", r'\.github\.io', "There isn't a GitHub Pages site here", Severity.HIGH),
    ("Heroku", r'\.herokuapp\.com', "No such app", Severity.CRITICAL),
    ("Netlify", r'\.netlify\.app', "Not Found", Severity.HIGH),
    ("Vercel", r'\.vercel\.app', "DEPLOYMENT_NOT_FOUND", Severity.HIGH),
    ("Surge.sh", r'\.surge\.sh', "project not found", Severity.HIGH),
    ("Fly.io", r'\.fly\.dev', "404", Severity.MEDIUM),

    # E-commerce / CMS
    ("Shopify", r'\.myshopify\.com', "Sorry, this shop is currently unavailable", Severity.HIGH),
    ("Tumblr", r'\.tumblr\.com', "There's nothing here", Severity.MEDIUM),
    ("WordPress.com", r'\.wordpress\.com', "doesn't exist", Severity.MEDIUM),
    ("Ghost", r'\.ghost\.io', "404", Severity.MEDIUM),

    # Support / SaaS
    ("Zendesk", r'\.zendesk\.com', "Help Center Closed", Severity.MEDIUM),
    ("Freshdesk", r'\.freshdesk\.com', "not served", Severity.MEDIUM),
    ("HelpScout", r'\.helpscoutdocs\.com', "No settings were found", Severity.MEDIUM),
    ("Intercom", r'\.intercom\.help', "Uh oh", Severity.MEDIUM),

    # CDN / Proxies
    ("Fastly", r'\.fastly\.net', "Fastly error: unknown domain", Severity.HIGH),
    ("Pantheon", r'\.pantheonsite\.io', "404 error unknown site", Severity.HIGH),
    ("Cargo", r'\.cargocollective\.com', "404 Not Found", Severity.MEDIUM),
    ("Unbounce", r'\.unbouncepages\.com', "The requested URL was not found", Severity.MEDIUM),

    # Other
    ("Bitbucket", r'\.bitbucket\.io', "Repository not found", Severity.HIGH),
    ("ReadTheDocs", r'\.readthedocs\.io', "unknown to Read the Docs", Severity.MEDIUM),
    ("Agile CRM", r'\.agilecrm\.com', "Sorry, this page is no longer available", Severity.MEDIUM),
]


class TakeoverScanner(SmartScanner):
    name = "Subdomain Takeover Scanner"
    description = "Detect dangling DNS records vulnerable to subdomain takeover"

    def scan(self):
        url = normalize_url(self.config.target)
        parsed = urlparse(url)
        domain = parsed.hostname
        print_status(f"Subdomain takeover analysis for {domain}", "progress")

        if not HAS_DNS:
            self.result.error = "dnspython not installed — required for takeover detection"
            return

        subdomains = set()
        subdomains.add(domain)

        # ── Phase 1: Discover subdomains ──────────────────────────
        print_status("Phase 1: Subdomain enumeration", "progress")
        self._enumerate_subdomains(domain, subdomains)
        print_status(f"Checking {len(subdomains)} subdomain(s)", "info")

        # ── Phase 2: Check each for takeover ──────────────────────
        print_status("Phase 2: Takeover vulnerability checks", "progress")
        vuln_count = 0
        for sub in sorted(subdomains):
            if self._check_takeover(sub, url):
                vuln_count += 1

        # ── Phase 3: Dangling CNAME detection ─────────────────────
        print_status("Phase 3: Dangling CNAME detection", "progress")
        for sub in sorted(subdomains):
            self._check_dangling_cname(sub, url)

        print_status(f"Subdomain takeover checks complete: {vuln_count} vulnerable", "info")

    def _enumerate_subdomains(self, domain, subdomains):
        """Enumerate subdomains via DNS brute force + common prefixes."""
        common_prefixes = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "beta", "demo", "app", "blog", "shop", "store",
            "cdn", "assets", "static", "media", "img", "images",
            "docs", "help", "support", "portal", "secure", "login",
            "dashboard", "panel", "cpanel", "webmail", "ns1", "ns2",
            "mx", "smtp", "pop", "imap", "vpn", "remote", "git",
            "ci", "jenkins", "jira", "confluence", "wiki", "status",
            "monitor", "grafana", "kibana", "elastic", "prometheus",
            "staging1", "staging2", "preprod", "uat", "qa",
            "sandbox", "internal", "intranet", "legacy", "old",
            "new", "v1", "v2", "m", "mobile",
        ]

        # Extract base domain for brute force
        parts = domain.split(".")
        if len(parts) >= 2:
            base = ".".join(parts[-2:])
        else:
            base = domain

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        for prefix in common_prefixes:
            sub = f"{prefix}.{base}"
            try:
                resolver.resolve(sub, "A")
                subdomains.add(sub)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    Exception):
                pass

        # Also check for CNAME records on discovered subdomains
        for sub in list(subdomains):
            try:
                answers = resolver.resolve(sub, "CNAME")
                for rdata in answers:
                    cname_target = str(rdata.target).rstrip(".")
                    self.result.raw_data.setdefault("cname_records", {})[sub] = cname_target
            except Exception:
                pass

    def _check_takeover(self, subdomain, base_url):
        """Check if a subdomain is vulnerable to takeover."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            # Get CNAME
            try:
                answers = resolver.resolve(subdomain, "CNAME")
                cname = str(list(answers)[0].target).rstrip(".")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return False
            except Exception:
                return False

            # Check CNAME against known vulnerable patterns
            for service, pattern, fingerprint, severity in TAKEOVER_FINGERPRINTS:
                if re.search(pattern, cname, re.I):
                    # Verify by checking if the service returns an error
                    is_vulnerable = False

                    if fingerprint == "NXDOMAIN":
                        # Check if CNAME target resolves
                        try:
                            resolver.resolve(cname, "A")
                        except dns.resolver.NXDOMAIN:
                            is_vulnerable = True
                        except Exception:
                            pass
                    else:
                        # Try HTTP request to check for takeover fingerprint
                        try:
                            resp = self.http_client.get(
                                f"http://{subdomain}",
                                timeout=10,
                                allow_redirects=True,
                            )
                            if fingerprint.lower() in resp.text.lower():
                                is_vulnerable = True
                        except Exception:
                            pass

                        # Also try HTTPS
                        if not is_vulnerable:
                            try:
                                resp = self.http_client.get(
                                    f"https://{subdomain}",
                                    timeout=10,
                                    allow_redirects=True,
                                )
                                if fingerprint.lower() in resp.text.lower():
                                    is_vulnerable = True
                            except Exception:
                                pass

                    if is_vulnerable:
                        self.add_finding(
                            title=f"Subdomain takeover: {subdomain} → {service}",
                            severity=severity,
                            description=(
                                f"Subdomain '{subdomain}' has a CNAME record pointing to "
                                f"{service} ({cname}), but the service appears unclaimed.\n"
                                f"An attacker could register this service and serve malicious "
                                f"content on {subdomain}."
                            ),
                            recommendation=(
                                f"Either remove the DNS record for {subdomain} or "
                                f"reclaim the {service} resource at {cname}."
                            ),
                            evidence=f"Subdomain: {subdomain}\nCNAME: {cname}\nService: {service}\nFingerprint: {fingerprint}",
                            category="Subdomain Takeover",
                            url=base_url,
                            cwe="CWE-284",
                        )
                        print_finding(severity, f"Takeover: {subdomain} → {service} ({cname})")
                        return True

        except Exception:
            pass
        return False

    def _check_dangling_cname(self, subdomain, base_url):
        """Check for dangling CNAME records (points to non-resolving host)."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            try:
                answers = resolver.resolve(subdomain, "CNAME")
                cname = str(list(answers)[0].target).rstrip(".")
            except Exception:
                return

            # Check if CNAME target actually resolves
            try:
                socket.getaddrinfo(cname, None, socket.AF_INET)
            except socket.gaierror:
                # CNAME target doesn't resolve — dangling!
                self.add_finding(
                    title=f"Dangling CNAME: {subdomain} → {cname}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The subdomain '{subdomain}' has a CNAME record pointing to "
                        f"'{cname}' which does not resolve to any IP address. "
                        f"This may indicate a decommissioned service and could be "
                        f"vulnerable to takeover."
                    ),
                    recommendation="Remove the DNS record or reclaim the target service.",
                    evidence=f"Subdomain: {subdomain}\nCNAME: {cname}\nStatus: NXDOMAIN / no A record",
                    category="Subdomain Takeover",
                    url=base_url,
                    cwe="CWE-284",
                )
                print_finding(Severity.MEDIUM, f"Dangling CNAME: {subdomain} → {cname}")

        except Exception:
            pass
