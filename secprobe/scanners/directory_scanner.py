"""
Directory / Path Brute-force Scanner — uses shared HTTPClient.

Features:
  - 785+ external wordlist paths
  - Threaded scanning via ThreadPoolExecutor
  - Smart 404 detection (custom error page fingerprint)
  - Status code classification
  - Backup file discovery (.bak, .old, ~, .swp)
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


def _load_directory_wordlist():
    try:
        from secprobe.payloads import load_payloads
        paths = load_payloads("directories")
        if paths:
            return paths
    except Exception:
        pass
    return [
        "admin", "login", "dashboard", "api", "config", "backup",
        ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
        "wp-admin", "wp-login.php", "phpmyadmin", "server-status",
        "console", "debug", ".svn", ".DS_Store", "web.config",
    ]


BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".save", "~", ".swp", ".copy", ".tmp"]


class DirectoryScanner(SmartScanner):
    name = "Directory Scanner"
    description = "Brute-force discover hidden files and directories"

    def scan(self):
        url = normalize_url(self.config.target)
        if not url.endswith("/"):
            url += "/"
        print_status(f"Directory brute-force on {url}", "progress")

        wordlist = _load_directory_wordlist()
        print_status(f"Loaded {len(wordlist)} paths", "info")

        # ── Detect custom 404 page ───────────────────────────────────
        custom_404_sig = self._detect_custom_404(url)

        found_count = 0
        threads = min(10, self.config.threads if hasattr(self.config, 'threads') else 5)

        def _check_path(path):
            if self.config.rate_limit:
                time.sleep(self.config.rate_limit)
            test_url = urljoin(url, path.lstrip("/"))
            try:
                resp = self.http_client.get(test_url, allow_redirects=False)
            except TargetUnreachableError:
                return None
            except Exception:
                return None

            if resp.status_code == 404:
                return None
            if custom_404_sig and custom_404_sig in resp.text:
                return None

            return (path, test_url, resp.status_code, len(resp.text))

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_check_path, p): p for p in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue

                path, test_url, status, length = result
                found_count += 1

                if status == 200:
                    severity = self._classify_severity(path)
                    self.add_finding(
                        title=f"Discovered: /{path} ({status})",
                        severity=severity,
                        description=f"Accessible path found: {test_url} [{length}B]",
                        recommendation="Restrict access to sensitive paths. Use authentication and authorization.",
                        evidence=f"URL: {test_url}\nStatus: {status}\nSize: {length}B",
                        category="Information Disclosure",
                        url=test_url,
                        cwe="CWE-538",
                    )
                    print_finding(severity, f"/{path} -> {status} [{length}B]")

                elif status in (301, 302, 307, 308):
                    self.add_finding(
                        title=f"Redirect: /{path} ({status})",
                        severity=Severity.LOW,
                        description=f"Path redirects: {test_url}",
                        recommendation="Review redirected paths for sensitive information.",
                        evidence=f"URL: {test_url}\nStatus: {status}",
                        category="Information Disclosure",
                        url=test_url,
                        cwe="CWE-538",
                    )

                elif status == 403:
                    self.add_finding(
                        title=f"Forbidden: /{path} ({status})",
                        severity=Severity.LOW,
                        description=f"Path exists but access denied: {test_url}",
                        recommendation="Hidden paths may leak information. Consider removing or restricting.",
                        evidence=f"URL: {test_url}\nStatus: {status}",
                        category="Information Disclosure",
                        url=test_url,
                        cwe="CWE-538",
                    )

                elif status == 401:
                    self.add_finding(
                        title=f"Auth Required: /{path} ({status})",
                        severity=Severity.MEDIUM,
                        description=f"Authentication-protected path discovered: {test_url}",
                        recommendation="Ensure strong authentication and rate limiting.",
                        evidence=f"URL: {test_url}\nStatus: {status}",
                        category="Authentication",
                        url=test_url,
                        cwe="CWE-287",
                    )

        # ── Backup file discovery ────────────────────────────────────
        print_status("Checking for backup files...", "info")
        # Get baseline response size for SPA false-positive filtering
        baseline_size = None
        try:
            baseline_resp = self.http_client.get(url, allow_redirects=False)
            if baseline_resp.status_code == 200:
                baseline_size = len(baseline_resp.text)
        except Exception:
            pass
        self._check_backup_files(url, custom_404_sig, baseline_size)

        if found_count == 0:
            print_status("No hidden paths discovered.", "success")
            self.add_finding(
                title="No hidden paths found",
                severity=Severity.INFO,
                description="Directory brute-force did not discover accessible hidden paths.",
                category="Information Disclosure",
            )

    def _detect_custom_404(self, url):
        try:
            resp = self.http_client.get(urljoin(url, "th1s-p4th-d03s-n0t-3x1st-f0r-sur3"))
            if resp.status_code != 404:
                return resp.text[:200]
        except Exception:
            pass
        return None

    def _classify_severity(self, path):
        critical_paths = {".env", ".git/config", "web.config", ".htpasswd", "id_rsa", ".ssh"}
        high_paths = {"admin", "phpmyadmin", "wp-admin", "server-status", "server-info", "console", "debug", ".git"}
        medium_paths = {"login", "dashboard", "api", "config", "backup", ".svn", ".DS_Store"}

        path_lower = path.lower().rstrip("/")
        if path_lower in critical_paths:
            return Severity.CRITICAL
        if path_lower in high_paths:
            return Severity.HIGH
        if path_lower in medium_paths:
            return Severity.MEDIUM
        return Severity.LOW

    def _check_backup_files(self, base_url, custom_404_sig=None, baseline_size=None):
        common_files = ["index", "config", "database", "settings", "application", "web"]
        for fname in common_files:
            for ext in BACKUP_EXTENSIONS:
                test_url = urljoin(base_url, f"{fname}{ext}")
                try:
                    resp = self.http_client.get(test_url, allow_redirects=False)
                    if resp.status_code != 200 or len(resp.text) == 0:
                        continue
                    # Filter out custom 404 pages (SPA catch-all)
                    if custom_404_sig and custom_404_sig in resp.text:
                        continue
                    # Filter out responses identical to homepage (SPA serving same page for all routes)
                    if baseline_size and abs(len(resp.text) - baseline_size) < 50:
                        continue
                    # Verify content looks like an actual backup (not HTML SPA shell)
                    content_type = resp.headers.get("Content-Type", "")
                    if "text/html" in content_type and len(resp.text) < 5000:
                        # Small HTML page is likely SPA shell, not a real backup
                        continue
                    self.add_finding(
                        title=f"Backup file found: {fname}{ext}",
                        severity=Severity.HIGH,
                        description=f"Backup/temp file accessible: {test_url}",
                        recommendation="Remove backup files from production. Block access to common extensions.",
                        evidence=f"URL: {test_url}\nSize: {len(resp.text)}B\nContent-Type: {content_type}",
                        category="Information Disclosure",
                        url=test_url,
                        cwe="CWE-530",
                    )
                    print_finding(Severity.HIGH, f"Backup: {fname}{ext}")
                except Exception:
                    continue
