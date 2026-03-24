"""
Technology Detection Scanner — uses shared HTTPClient.

Features:
  - YAML signature database matching (48+ technologies)
  - Header, body, cookie, and meta-tag inspection
  - Version extraction via regex
  - Known CVE flagging for detected versions
"""

import re

from secprobe.config import Severity
from secprobe.core.exceptions import TargetUnreachableError
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import normalize_url, print_status, print_finding


def _load_signatures():
    try:
        from secprobe.payloads import load_tech_signatures
        sigs = load_tech_signatures()
        if sigs:
            return sigs
    except Exception:
        pass
    return {
        "Apache": {"headers": {"Server": r"Apache(?:/(\d[\d.]+))?"}},
        "Nginx": {"headers": {"Server": r"nginx(?:/(\d[\d.]+))?"}},
        "PHP": {"headers": {"X-Powered-By": r"PHP(?:/(\d[\d.]+))?"}},
        "ASP.NET": {"headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"(\d[\d.]+)"}},
        "WordPress": {"body": [r'wp-content/', r'wp-includes/'], "meta": {"generator": r"WordPress\s*([\d.]+)?"}},
        "jQuery": {"body": [r'jquery[.-](\d[\d.]+)\.(?:min\.)?js']},
        "Bootstrap": {"body": [r'bootstrap[.-](\d[\d.]+)\.(?:min\.)?(?:css|js)']},
        "React": {"body": [r'react(?:\.production|\.development)\.min\.js', r'_reactRootContainer']},
        "Express": {"headers": {"X-Powered-By": r"Express"}},
        "Cloudflare": {"headers": {"Server": r"cloudflare", "CF-RAY": r".+"}},
    }


OUTDATED_VERSIONS = {
    "Apache": {"below": "2.4.58", "cve": "CVE-2023-43622"},
    "Nginx": {"below": "1.25.3", "cve": "CVE-2023-44487"},
    "PHP": {"below": "8.2.12", "cve": "CVE-2023-3824"},
    "jQuery": {"below": "3.5.0", "cve": "CVE-2020-11023"},
    "WordPress": {"below": "6.4", "cve": "CVE-2023-38000"},
    "Bootstrap": {"below": "5.3.2", "cve": "CVE-2024-6484"},
}


class TechScanner(SmartScanner):
    name = "Tech Scanner"
    description = "Detect technologies, frameworks, and versions"

    def scan(self):
        url = normalize_url(self.config.target)
        print_status(f"Technology detection on {url}", "progress")

        signatures = _load_signatures()
        print_status(f"Loaded {len(signatures)} tech signatures", "info")

        try:
            resp = self.http_client.get(url)
        except TargetUnreachableError as e:
            print_status(f"Cannot reach target: {e}", "error")
            self.result.error = str(e)
            return

        detected = {}

        # ── Header matching ──────────────────────────────────────────
        for tech_name, sig in signatures.items():
            version = None

            if "headers" in sig:
                for header_name, pattern in sig["headers"].items():
                    header_val = resp.headers.get(header_name, "")
                    if header_val:
                        match = re.search(pattern, header_val, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.lastindex else None
                            detected[tech_name] = version
                            break

            if "body" in sig and tech_name not in detected:
                for pattern in sig["body"]:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else None
                        detected[tech_name] = version
                        break

            if "meta" in sig and tech_name not in detected:
                for meta_name, pattern in sig["meta"].items():
                    meta_match = re.search(
                        rf'<meta[^>]*name=["\']?{re.escape(meta_name)}["\']?[^>]*content=["\']?([^"\']+)',
                        resp.text, re.IGNORECASE,
                    )
                    if meta_match:
                        match = re.search(pattern, meta_match.group(1), re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.lastindex else None
                            detected[tech_name] = version
                            break

            if "cookies" in sig and tech_name not in detected:
                for cookie_name in sig["cookies"]:
                    if cookie_name in resp.headers.get("Set-Cookie", ""):
                        detected[tech_name] = None
                        break

        # ── Additional header intelligence ───────────────────────────
        server = resp.headers.get("Server", "")
        if server and not any(t in detected for t in ("Apache", "Nginx", "IIS")):
            detected[f"Server: {server}"] = None

        powered = resp.headers.get("X-Powered-By", "")
        if powered and "X-Powered-By" not in str(detected):
            detected[f"X-Powered-By: {powered}"] = None

        # ── Report findings ──────────────────────────────────────────
        if detected:
            tech_list = []
            for tech, ver in sorted(detected.items()):
                label = f"{tech} {ver}" if ver else tech
                tech_list.append(label)
                print_finding(Severity.INFO, f"Detected: {label}")

            self.add_finding(
                title=f"Detected {len(detected)} technologies",
                severity=Severity.INFO,
                description=f"Technologies: {', '.join(tech_list)}",
                recommendation="Remove version headers in production (ServerTokens Prod, server_tokens off).",
                evidence=f"URL: {url}\n" + "\n".join(f"  - {t}" for t in tech_list),
                category="Technology Detection",
                url=url,
                cwe="CWE-200",
            )

            # ── Version vulnerability checks ─────────────────────────
            for tech, ver in detected.items():
                if ver and tech in OUTDATED_VERSIONS:
                    info = OUTDATED_VERSIONS[tech]
                    if self._version_below(ver, info["below"]):
                        self.add_finding(
                            title=f"Outdated {tech} {ver} (< {info['below']})",
                            severity=Severity.HIGH,
                            description=(
                                f"{tech} version {ver} is below {info['below']}.\n"
                                f"Known vulnerability: {info['cve']}"
                            ),
                            recommendation=f"Update {tech} to at least version {info['below']}.",
                            evidence=f"Detected: {tech}/{ver}\nCVE: {info['cve']}",
                            category="Outdated Software",
                            url=url,
                            cwe="CWE-1104",
                        )
                        print_finding(Severity.HIGH, f"Outdated: {tech} {ver} ({info['cve']})")

        else:
            print_status("No specific technologies detected.", "info")
            self.add_finding(
                title="No technologies detected",
                severity=Severity.INFO,
                description="Could not fingerprint specific technologies.",
                category="Technology Detection",
            )

    def _version_below(self, current, threshold):
        try:
            cur_parts = [int(x) for x in current.split(".")]
            thr_parts = [int(x) for x in threshold.split(".")]
            for c, t in zip(cur_parts, thr_parts):
                if c < t:
                    return True
                if c > t:
                    return False
            return len(cur_parts) < len(thr_parts)
        except (ValueError, AttributeError):
            return False
