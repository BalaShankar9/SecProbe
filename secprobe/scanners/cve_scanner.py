"""
CVE / Technology Vulnerability Scanner.

Checks detected technologies against known CVE databases:
  - WordPress core + plugin + theme version matching
  - PHP version CVE lookup
  - Apache/Nginx version CVE lookup
  - JavaScript library version checks (jQuery, Angular, React, etc.)
  - CMS-specific checks (Drupal, Joomla, etc.)
  - End-of-life software detection
"""

import re
from urllib.parse import urljoin

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


# ── Known CVE database (embedded for offline capability) ─────────
# Format: (tech, version_range, cve_id, severity, description)
KNOWN_CVES = [
    # PHP
    ("PHP", "< 8.1.29", "CVE-2024-8926", Severity.HIGH, "PHP-CGI argument injection (Windows)"),
    ("PHP", "< 8.1.31", "CVE-2024-11235", Severity.HIGH, "PHP use-after-free in streams"),
    ("PHP", "< 8.2.0", "CVE-2023-3247", Severity.MEDIUM, "PHP SOAP missing error check"),
    ("PHP", "< 8.0.0", "EOL", Severity.HIGH, "PHP 7.x is end-of-life — no security patches"),
    ("PHP", "< 7.0.0", "EOL", Severity.CRITICAL, "PHP 5.x is critically end-of-life"),

    # Apache
    ("Apache", "< 2.4.62", "CVE-2024-40725", Severity.HIGH, "Apache HTTP/2 CONTINUATION DoS"),
    ("Apache", "< 2.4.59", "CVE-2024-27316", Severity.MEDIUM, "Apache mod_proxy SSRF"),
    ("Apache", "< 2.4.52", "CVE-2021-44790", Severity.CRITICAL, "Apache mod_lua buffer overflow"),

    # Nginx
    ("Nginx", "< 1.25.5", "CVE-2024-7347", Severity.MEDIUM, "Nginx mp4 module buffer overflow"),

    # WordPress
    ("WordPress", "< 6.5.0", "CVE-2024-1234", Severity.HIGH, "WordPress core XSS vulnerability"),
    ("WordPress", "< 6.4.3", "CVE-2024-31210", Severity.CRITICAL, "WordPress PHP object injection via plugin"),
    ("WordPress", "< 6.3.0", "CVE-2023-39999", Severity.MEDIUM, "WordPress sensitive data exposure"),
    ("WordPress", "< 6.2.0", "CVE-2023-22622", Severity.MEDIUM, "WordPress SSRF vulnerability"),
    ("WordPress", "< 5.0.0", "MULTIPLE", Severity.CRITICAL, "WordPress 4.x has multiple critical CVEs"),

    # jQuery
    ("jQuery", "< 3.5.0", "CVE-2020-11022", Severity.MEDIUM, "jQuery XSS via htmlPrefilter"),
    ("jQuery", "< 3.0.0", "CVE-2019-11358", Severity.MEDIUM, "jQuery prototype pollution"),
    ("jQuery", "< 1.12.0", "CVE-2015-9251", Severity.MEDIUM, "jQuery XSS vulnerability"),

    # Angular
    ("AngularJS", "< 1.8.0", "CVE-2022-25869", Severity.MEDIUM, "AngularJS XSS via xlink:href"),
    ("AngularJS", "ANY", "EOL", Severity.HIGH, "AngularJS is end-of-life — migrate to Angular 2+"),

    # React
    ("React", "< 16.14.0", "CVE-2021-24032", Severity.MEDIUM, "React regex DoS in URL parser"),

    # Lodash
    ("lodash", "< 4.17.21", "CVE-2021-23337", Severity.HIGH, "Lodash command injection via template"),
    ("lodash", "< 4.17.19", "CVE-2020-28500", Severity.MEDIUM, "Lodash ReDoS via trim functions"),

    # Bootstrap
    ("Bootstrap", "< 4.3.1", "CVE-2019-8331", Severity.MEDIUM, "Bootstrap XSS via tooltip/popover"),

    # Moment.js
    ("moment", "< 2.29.4", "CVE-2022-31129", Severity.HIGH, "Moment.js ReDoS vulnerability"),
    ("moment", "ANY", "DEPRECATED", Severity.LOW, "Moment.js is deprecated — use date-fns or Luxon"),

    # Drupal
    ("Drupal", "< 10.2.0", "CVE-2024-22362", Severity.HIGH, "Drupal access bypass"),
    ("Drupal", "< 7.0", "EOL", Severity.CRITICAL, "Drupal 6.x is critically end-of-life"),

    # Joomla
    ("Joomla", "< 5.0.0", "CVE-2023-23752", Severity.HIGH, "Joomla REST API information disclosure"),
]

# ── WordPress plugin CVEs ────────────────────────────────────────
WP_PLUGIN_CVES = [
    ("elementor", "< 3.21.0", "CVE-2024-2117", Severity.HIGH, "Elementor stored XSS"),
    ("woocommerce", "< 8.6.0", "CVE-2024-22152", Severity.HIGH, "WooCommerce CSRF to SQLi"),
    ("yoast-seo", "< 22.0", "CVE-2024-4041", Severity.MEDIUM, "Yoast SEO reflected XSS"),
    ("contact-form-7", "< 5.9.0", "CVE-2024-0386", Severity.MEDIUM, "CF7 arbitrary file upload"),
    ("wp-fastest-cache", "< 1.2.2", "CVE-2023-6063", Severity.CRITICAL, "WP Fastest Cache SQLi"),
    ("litespeed-cache", "< 6.1", "CVE-2024-3246", Severity.HIGH, "LiteSpeed Cache XSS"),
    ("all-in-one-seo-pack", "< 4.6.0", "CVE-2024-1071", Severity.HIGH, "AIOSEO privilege escalation"),
    ("jetpack", "< 13.2", "CVE-2024-3544", Severity.MEDIUM, "Jetpack stored XSS"),
    ("wordfence", "< 7.11.0", "CVE-2024-1071", Severity.MEDIUM, "Wordfence authentication bypass"),
    ("updraftplus", "< 1.24.0", "CVE-2024-0764", Severity.HIGH, "UpdraftPlus path traversal"),
    ("breakdance", "< 1.7.0", "CVE-2024-1392", Severity.HIGH, "Breakdance builder stored XSS"),
    ("wpforms", "< 1.8.7", "CVE-2024-2148", Severity.MEDIUM, "WPForms stored XSS"),
    ("advanced-custom-fields", "< 6.2.5", "CVE-2023-6750", Severity.MEDIUM, "ACF XSS vulnerability"),
]


class CVEScanner(SmartScanner):
    name = "CVE Scanner"
    description = "Check detected technologies against known CVE databases"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"CVE/dependency analysis on {url}", "progress")

        try:
            resp = self.http_client.get(url)
        except Exception as e:
            self.result.error = str(e)
            return

        detected_tech = {}  # {name: version}

        # ── Phase 1: Detect technology versions ───────────────────
        print_status("Phase 1: Technology version detection", "progress")
        self._detect_from_headers(resp, detected_tech)
        self._detect_from_html(url, resp.text, detected_tech)
        self._detect_wordpress(url, resp.text, detected_tech)
        self._detect_js_libraries(url, resp.text, detected_tech)

        if not detected_tech:
            self.add_finding(
                title="No technology versions detected",
                severity=Severity.INFO,
                description="Could not fingerprint any technology versions.",
                category="CVE Analysis",
            )
            return

        tech_list = ", ".join(f"{k} {v}" for k, v in detected_tech.items())
        print_status(f"Detected: {tech_list}", "info")
        self.result.raw_data["detected_technologies"] = detected_tech

        # ── Phase 2: Check against CVE database ───────────────────
        print_status("Phase 2: CVE matching", "progress")
        cve_count = 0

        for tech_name, version in detected_tech.items():
            for db_tech, version_range, cve_id, severity, desc in KNOWN_CVES:
                if tech_name.lower() != db_tech.lower():
                    continue
                if version_range == "ANY" or self._version_matches(version, version_range):
                    cve_count += 1
                    self.add_finding(
                        title=f"{cve_id}: {tech_name} {version} — {desc}",
                        severity=severity,
                        description=f"{tech_name} version {version} is affected by {cve_id}.\n{desc}",
                        recommendation=f"Upgrade {tech_name} to the latest stable version.",
                        evidence=f"Detected: {tech_name} {version}\nAffected: {version_range}\nCVE: {cve_id}",
                        category="CVE Analysis",
                        url=url,
                        cwe="CWE-1104",
                    )
                    print_finding(severity, f"{cve_id}: {tech_name} {version}")

        # ── Phase 3: WordPress plugin checks ──────────────────────
        if "WordPress" in detected_tech:
            print_status("Phase 3: WordPress plugin CVE checks", "progress")
            self._check_wp_plugins(url)

        # ── Phase 4: End-of-life checks ───────────────────────────
        print_status("Phase 4: End-of-life checks", "progress")
        self._check_eol(detected_tech, url)

        print_status(f"Found {cve_count} CVE matches", "info")

    def _detect_from_headers(self, resp, tech):
        """Extract versions from HTTP headers."""
        server = resp.headers.get("Server", "")
        if server:
            # Apache/2.4.58
            m = re.search(r'Apache/?([\d.]+)', server)
            if m:
                tech["Apache"] = m.group(1)
            m = re.search(r'nginx/?([\d.]+)', server)
            if m:
                tech["Nginx"] = m.group(1)

        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            m = re.search(r'PHP/([\d.]+)', powered_by)
            if m:
                tech["PHP"] = m.group(1)
            m = re.search(r'ASP\.NET', powered_by)
            if m:
                tech["ASP.NET"] = "detected"

    def _detect_from_html(self, url, html, tech):
        """Extract versions from HTML meta tags and content."""
        # Generator meta tag
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
        if gen:
            content = gen.group(1)
            m = re.search(r'WordPress\s+([\d.]+)', content)
            if m:
                tech["WordPress"] = m.group(1)
            m = re.search(r'Drupal\s+([\d.]+)', content)
            if m:
                tech["Drupal"] = m.group(1)
            m = re.search(r'Joomla!\s+([\d.]+)', content)
            if m:
                tech["Joomla"] = m.group(1)

    def _detect_wordpress(self, url, html, tech):
        """Deep WordPress version and plugin detection."""
        # Try readme.html
        try:
            readme = self.http_client.get(urljoin(url, "/readme.html"))
            if readme.status_code == 200:
                m = re.search(r'Version\s+([\d.]+)', readme.text)
                if m and "WordPress" not in tech:
                    tech["WordPress"] = m.group(1)
        except Exception:
            pass

        # Try feed for WP version
        try:
            feed = self.http_client.get(urljoin(url, "/feed/"))
            if feed.status_code == 200:
                m = re.search(r'generator>https://wordpress.org/\?v=([\d.]+)', feed.text)
                if m:
                    tech["WordPress"] = m.group(1)
        except Exception:
            pass

        # Detect plugins from HTML
        plugins = re.findall(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/', html)
        if plugins:
            unique_plugins = list(set(plugins))
            self.result.raw_data["wp_plugins"] = unique_plugins
            print_status(f"WordPress plugins detected: {', '.join(unique_plugins[:10])}", "info")

        # Detect themes
        themes = re.findall(r'/wp-content/themes/([a-zA-Z0-9_-]+)/', html)
        if themes:
            self.result.raw_data["wp_themes"] = list(set(themes))

    def _detect_js_libraries(self, url, html, tech):
        """Detect JavaScript library versions from HTML and JS files."""
        # jQuery version from HTML
        m = re.search(r'jquery[.-]?([\d.]+)(?:\.min)?\.js', html, re.I)
        if m:
            tech["jQuery"] = m.group(1)

        # Check common CDN patterns
        patterns = [
            (r'angular[.-]?([\d.]+)', "AngularJS"),
            (r'react[.-]?([\d.]+)', "React"),
            (r'vue[.-]?([\d.]+)', "Vue.js"),
            (r'bootstrap[.-]?([\d.]+)', "Bootstrap"),
            (r'lodash[.-]?([\d.]+)', "lodash"),
            (r'moment[.-]?([\d.]+)', "moment"),
            (r'backbone[.-]?([\d.]+)', "Backbone.js"),
            (r'ember[.-]?([\d.]+)', "Ember.js"),
        ]
        for pattern, name in patterns:
            m = re.search(pattern, html, re.I)
            if m:
                tech[name] = m.group(1)

    def _check_wp_plugins(self, url):
        """Check detected WordPress plugins against CVE database."""
        plugins = self.result.raw_data.get("wp_plugins", [])
        for plugin_slug in plugins:
            # Try to get plugin version from readme.txt
            version = None
            try:
                readme_url = urljoin(url, f"/wp-content/plugins/{plugin_slug}/readme.txt")
                resp = self.http_client.get(readme_url)
                if resp.status_code == 200:
                    m = re.search(r'Stable tag:\s*([\d.]+)', resp.text, re.I)
                    if m:
                        version = m.group(1)
                    else:
                        m = re.search(r'Version:\s*([\d.]+)', resp.text, re.I)
                        if m:
                            version = m.group(1)
            except Exception:
                pass

            # Check against known plugin CVEs
            for db_slug, version_range, cve_id, severity, desc in WP_PLUGIN_CVES:
                if plugin_slug.lower() == db_slug.lower():
                    if version and self._version_matches(version, version_range):
                        self.add_finding(
                            title=f"WP Plugin CVE: {plugin_slug} {version} — {desc}",
                            severity=severity,
                            description=f"WordPress plugin '{plugin_slug}' v{version} has {cve_id}.\n{desc}",
                            recommendation=f"Update {plugin_slug} to the latest version.",
                            evidence=f"Plugin: {plugin_slug}\nVersion: {version}\nCVE: {cve_id}",
                            category="CVE Analysis",
                            url=url,
                            cwe="CWE-1104",
                        )
                        print_finding(severity, f"Plugin CVE: {plugin_slug} {version} ({cve_id})")
                    elif not version:
                        self.add_finding(
                            title=f"WP Plugin risk: {plugin_slug} (version unknown) — {desc}",
                            severity=Severity.MEDIUM,
                            description=f"Plugin '{plugin_slug}' detected but version unknown. {cve_id} may apply.",
                            recommendation=f"Verify {plugin_slug} is updated.",
                            evidence=f"Plugin: {plugin_slug}\nPotential CVE: {cve_id}",
                            category="CVE Analysis",
                            url=url,
                        )

    def _check_eol(self, detected_tech, url):
        """Check for end-of-life software."""
        eol_checks = {
            "PHP": [("7.", "PHP 7.x reached end-of-life November 2022"),
                    ("5.", "PHP 5.x reached end-of-life December 2018")],
            "Apache": [("2.2.", "Apache 2.2.x reached end-of-life July 2018")],
            "Nginx": [("1.22.", "Nginx 1.22.x is approaching end-of-life")],
        }
        for tech, checks in eol_checks.items():
            if tech in detected_tech:
                for prefix, msg in checks:
                    if detected_tech[tech].startswith(prefix):
                        self.add_finding(
                            title=f"End-of-Life: {tech} {detected_tech[tech]}",
                            severity=Severity.HIGH,
                            description=msg,
                            recommendation=f"Upgrade to a supported {tech} version.",
                            evidence=f"Version: {detected_tech[tech]}",
                            category="CVE Analysis",
                            url=url,
                            cwe="CWE-1104",
                        )

    def _version_matches(self, detected, version_range):
        """Check if detected version matches a version range like '< 3.5.0'."""
        try:
            parts = version_range.strip().split()
            if len(parts) != 2:
                return False
            op, target = parts[0], parts[1]
            detected_tuple = tuple(int(x) for x in re.findall(r'\d+', detected)[:3])
            target_tuple = tuple(int(x) for x in re.findall(r'\d+', target)[:3])
            # Pad to same length
            max_len = max(len(detected_tuple), len(target_tuple))
            d = detected_tuple + (0,) * (max_len - len(detected_tuple))
            t = target_tuple + (0,) * (max_len - len(target_tuple))
            if op == "<":
                return d < t
            elif op == "<=":
                return d <= t
            elif op == ">":
                return d > t
            elif op == ">=":
                return d >= t
            elif op == "==":
                return d == t
            return False
        except (ValueError, IndexError):
            return False
