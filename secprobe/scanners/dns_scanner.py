"""
DNS Scanner — Enterprise-grade subdomain enumeration and DNS analysis.

Features:
  - 3000+ external subdomain wordlist
  - Subdomain takeover detection
  - Zone transfer attempt
  - SPF / DMARC / DKIM checks
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import extract_hostname, print_status, print_finding, print_progress, Colors


def _load_subdomains() -> list[str]:
    """Load subdomains from external payload file with fallback."""
    try:
        from secprobe.payloads import load_payloads
        subs = load_payloads("subdomains")
        if subs:
            return subs
    except Exception:
        pass
    return [
        "www", "mail", "ftp", "api", "admin", "dev", "staging", "test",
        "blog", "vpn", "cdn", "ns1", "ns2", "mx", "portal", "git",
    ]


# Subdomains known to be risky / sensitive
RISKY_SUBDOMAINS = {
    "admin", "test", "testing", "staging", "stage", "dev", "development",
    "internal", "intranet", "debug", "backup", "old", "legacy",
    "jenkins", "ci", "cd", "git", "svn", "deploy", "build",
    "grafana", "kibana", "prometheus", "elastic", "phpmyadmin",
    "cpanel", "whm", "console", "demo", "sandbox", "alpha", "beta",
}

# CNAME targets that indicate potential subdomain takeover
TAKEOVER_CNAMES = [
    "s3.amazonaws.com", "github.io", "herokuapp.com",
    "azurewebsites.net", "cloudfront.net", "pantheon.io",
    "shopify.com", "fastly.net", "ghost.io", "surge.sh",
    "bitbucket.io", "zendesk.com", "tumblr.com",
    "wordpress.com", "smugmug.com", "strikingly.com",
    "helpjuice.com", "helpscout.net", "cargo.site",
    "feedpress.me", "freshdesk.com", "ghost.io",
    "cargocollective.com", "statuspage.io", "teamwork.com",
    "unbounce.com", "readme.io", "tictail.com",
]


class DNSScanner(SmartScanner):
    name = "DNS Scanner"
    description = "Enumerate subdomains and DNS records"

    # Two-part TLDs where the second-level is not the registrable domain
    MULTI_PART_TLDS = {
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz", "co.za", "org.za", "web.za",
        "co.in", "net.in", "org.in", "ac.in", "gov.in",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "ne.kr", "ac.kr",
        "com.br", "net.br", "org.br",
        "com.cn", "net.cn", "org.cn",
        "com.mx", "org.mx", "gob.mx",
        "co.il", "org.il", "ac.il",
        "com.sg", "org.sg", "edu.sg",
        "com.hk", "org.hk", "edu.hk",
        "co.id", "or.id", "ac.id",
        "com.tw", "org.tw", "edu.tw",
        "co.th", "or.th", "ac.th",
        "com.ng", "org.ng", "gov.ng",
        "com.tr", "org.tr", "gov.tr",
        "com.ar", "org.ar", "gov.ar",
    }

    def scan(self):
        hostname = extract_hostname(self.config.target)

        # Strip subdomains to get base domain (handle multi-part TLDs)
        parts = hostname.split(".")
        domain = hostname
        if len(parts) > 2:
            # Check if last two parts form a known multi-part TLD (e.g., co.uk)
            candidate_tld = ".".join(parts[-2:])
            if candidate_tld in self.MULTI_PART_TLDS and len(parts) >= 3:
                domain = ".".join(parts[-3:])  # e.g., carpoolnetwork.co.uk
            else:
                domain = ".".join(parts[-2:])  # e.g., example.com

        print_status(f"Enumerating subdomains for: {domain}", "progress")

        # ── Resolve main domain ──────────────────────────────────────
        try:
            main_ip = socket.gethostbyname(domain)
            print_status(f"Main domain {domain} → {main_ip}", "info")
        except socket.gaierror:
            print_status(f"Cannot resolve {domain}", "error")
            self.result.error = f"Cannot resolve {domain}"
            return

        # ── DNS record enumeration ───────────────────────────────────
        try:
            import dns.resolver
            has_dnspython = True
        except ImportError:
            has_dnspython = False

        if has_dnspython:
            self._enumerate_records(domain)
            self._check_zone_transfer(domain)

        # ── Subdomain brute-force ────────────────────────────────────
        subdomain_list = _load_subdomains()
        print_status(f"Loaded {len(subdomain_list)} subdomains to enumerate", "info")

        found_subdomains = []
        total = len(subdomain_list)
        scanned = 0

        def check_subdomain(sub: str):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                # Check CNAME for takeover detection
                cname = None
                if has_dnspython:
                    try:
                        answers = dns.resolver.resolve(fqdn, "CNAME")
                        cname = str(answers[0].target).rstrip(".")
                    except Exception:
                        pass
                return sub, fqdn, ip, cname
            except socket.gaierror:
                return sub, fqdn, None, None

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(check_subdomain, s): s for s in subdomain_list}
            for future in as_completed(futures):
                scanned += 1
                if scanned % 50 == 0 or scanned == total:
                    print_progress(scanned, total, "Resolving")

                sub, fqdn, ip, cname = future.result()
                if ip:
                    found_subdomains.append({
                        "subdomain": sub, "fqdn": fqdn, "ip": ip, "cname": cname,
                    })

        # ── Report ───────────────────────────────────────────────────
        found_subdomains.sort(key=lambda x: x["subdomain"])
        self.result.raw_data["subdomains"] = found_subdomains
        self.result.raw_data["domain"] = domain

        if found_subdomains:
            print(f"\n  {'SUBDOMAIN':<30}{'IP ADDRESS'}")
            print(f"  {'─' * 55}")
            for entry in found_subdomains:
                print(
                    f"  {Colors.GREEN}{entry['fqdn']:<30}{Colors.RESET}"
                    f"{entry['ip']}"
                )

            self.add_finding(
                title=f"{len(found_subdomains)} subdomain(s) discovered",
                severity=Severity.INFO,
                description=(
                    "Subdomains found:\n"
                    + "\n".join(f"  {e['fqdn']} → {e['ip']}" for e in found_subdomains)
                ),
                recommendation="Review all subdomains for unauthorized or forgotten services.",
                category="DNS",
            )

            # Check for potentially risky subdomains
            for entry in found_subdomains:
                if entry["subdomain"] in RISKY_SUBDOMAINS:
                    self.add_finding(
                        title=f"Potentially sensitive subdomain: {entry['fqdn']}",
                        severity=Severity.MEDIUM,
                        description=f"Subdomain '{entry['fqdn']}' may expose internal or development resources.",
                        recommendation=f"Verify that {entry['fqdn']} is intentionally public and properly secured.",
                        category="DNS",
                    )
                    print_finding(Severity.MEDIUM, f"Sensitive subdomain: {entry['fqdn']}")

                # Subdomain takeover detection
                if entry.get("cname"):
                    for takeover_target in TAKEOVER_CNAMES:
                        if entry["cname"].endswith(takeover_target):
                            # Verify: try to fetch and see if it returns provider error
                            self.add_finding(
                                title=f"Possible subdomain takeover: {entry['fqdn']}",
                                severity=Severity.HIGH,
                                description=(
                                    f"Subdomain '{entry['fqdn']}' has CNAME pointing to "
                                    f"'{entry['cname']}' which is a known takeover target."
                                ),
                                recommendation=(
                                    f"Verify the service at {entry['cname']} is still claimed. "
                                    "If not, an attacker can register the service and hijack the subdomain."
                                ),
                                evidence=f"CNAME: {entry['fqdn']} → {entry['cname']}",
                                category="DNS",
                            )
                            print_finding(Severity.HIGH, f"Takeover risk: {entry['fqdn']} → {entry['cname']}")
        else:
            print_status("No subdomains found.", "info")

    def _enumerate_records(self, domain: str):
        """Use dnspython to enumerate DNS records."""
        import dns.resolver

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        records = {}

        print_status("Querying DNS records…", "progress")

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                continue

        self.result.raw_data["dns_records"] = records

        if records:
            print(f"\n  {Colors.BOLD}DNS Records for {domain}:{Colors.RESET}")
            for rtype, values in records.items():
                for val in values:
                    print(f"    {Colors.CYAN}{rtype:<8}{Colors.RESET} {val}")

            # Check for SPF / DMARC
            txt_records = records.get("TXT", [])
            has_spf = any("v=spf1" in r for r in txt_records)
            if not has_spf:
                self.add_finding(
                    title="Missing SPF record",
                    severity=Severity.MEDIUM,
                    description="No SPF record found. Domain may be spoofable for email.",
                    recommendation="Add an SPF TXT record to prevent email spoofing.",
                    category="DNS",
                )

            # Check DMARC
            try:
                dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
                dmarc_records = [str(r) for r in dmarc]
                records["DMARC"] = dmarc_records
            except Exception:
                self.add_finding(
                    title="Missing DMARC record",
                    severity=Severity.MEDIUM,
                    description="No DMARC record found at _dmarc." + domain,
                    recommendation="Add a DMARC TXT record to protect against email spoofing.",
                    category="DNS",
                )

            # Check DKIM (common selectors)
            dkim_selectors = ["default", "google", "selector1", "selector2", "mail", "k1"]
            dkim_found = False
            for sel in dkim_selectors:
                try:
                    dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                    dkim_found = True
                    break
                except Exception:
                    continue
            if not dkim_found:
                self.add_finding(
                    title="No DKIM record found (common selectors)",
                    severity=Severity.LOW,
                    description="No DKIM record found for common selectors. Email authentication may be incomplete.",
                    recommendation="Configure DKIM signing and publish the public key in DNS.",
                    category="DNS",
                )

    def _check_zone_transfer(self, domain: str):
        """Attempt DNS zone transfer (AXFR) — a critical misconfiguration."""
        import dns.resolver
        import dns.query
        import dns.zone

        print_status("Attempting zone transfer…", "progress")

        try:
            ns_records = dns.resolver.resolve(domain, "NS")
        except Exception:
            return

        for ns in ns_records:
            ns_str = str(ns).rstrip(".")
            try:
                ns_ip = socket.gethostbyname(ns_str)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                names = [str(name) for name in zone.nodes.keys()]
                self.add_finding(
                    title=f"DNS Zone Transfer allowed on {ns_str}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Nameserver {ns_str} ({ns_ip}) allows zone transfer (AXFR). "
                        f"This exposes the entire DNS zone with {len(names)} records."
                    ),
                    recommendation="Disable zone transfers or restrict to authorized secondary nameservers only.",
                    evidence=f"NS: {ns_str}  |  Records: {', '.join(names[:20])}{'…' if len(names) > 20 else ''}",
                    category="DNS",
                )
                print_finding(Severity.CRITICAL, f"Zone transfer on {ns_str} — {len(names)} records exposed!")
                self.result.raw_data["zone_transfer"] = {
                    "ns": ns_str, "records": names,
                }
                return  # one is enough
            except Exception:
                continue
