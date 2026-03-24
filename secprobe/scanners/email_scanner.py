"""
Email Security Scanner (DMARC / DKIM / SPF / MTA-STS).

Comprehensive email security posture assessment:
  - SPF record validation and configuration analysis
  - DKIM selector discovery and record verification
  - DMARC policy evaluation and reporting
  - MTA-STS policy checks
  - BIMI record detection
  - Email spoofing risk assessment
"""

import re
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


# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "k1", "k2", "dkim", "mail",
    "selector1", "selector2",  # Microsoft 365
    "s1", "s2",  # Generic
    "mandrill", "amazonses", "sendgrid", "mailchimp",
    "smtp", "mg",  # Mailgun
    "protonmail", "zoho",
    "cm",  # Campaign Monitor
    "dk",  # Domain Keys
]


class EmailScanner(SmartScanner):
    name = "Email Security Scanner"
    description = "Validate DMARC, DKIM, SPF, MTA-STS email security configuration"

    def scan(self):
        url = normalize_url(self.config.target)
        domain = urlparse(url).hostname
        print_status(f"Email security analysis for {domain}", "progress")

        if not HAS_DNS:
            self.result.error = "dnspython not installed — required for email security checks"
            return

        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        # ── Phase 1: SPF ──────────────────────────────────────────
        print_status("Phase 1: SPF record analysis", "progress")
        self._check_spf(domain, resolver, url)

        # ── Phase 2: DKIM ─────────────────────────────────────────
        print_status("Phase 2: DKIM selector discovery", "progress")
        self._check_dkim(domain, resolver, url)

        # ── Phase 3: DMARC ────────────────────────────────────────
        print_status("Phase 3: DMARC policy analysis", "progress")
        self._check_dmarc(domain, resolver, url)

        # ── Phase 4: MTA-STS ──────────────────────────────────────
        print_status("Phase 4: MTA-STS policy check", "progress")
        self._check_mta_sts(domain, resolver, url)

        # ── Phase 5: BIMI ─────────────────────────────────────────
        print_status("Phase 5: BIMI record check", "progress")
        self._check_bimi(domain, resolver, url)

        # ── Phase 6: MX Security ──────────────────────────────────
        print_status("Phase 6: MX record security analysis", "progress")
        self._check_mx(domain, resolver, url)

        # ── Phase 7: Overall spoofing risk ────────────────────────
        print_status("Phase 7: Overall email spoofing risk assessment", "progress")
        self._assess_spoofing_risk(domain, url)

    def _check_spf(self, domain, resolver, url):
        """Check SPF (Sender Policy Framework) record."""
        try:
            answers = resolver.resolve(domain, "TXT")
            spf_records = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    spf_records.append(txt)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            spf_records = []
        except Exception:
            spf_records = []

        if not spf_records:
            self.add_finding(
                title="Missing SPF record",
                severity=Severity.HIGH,
                description=(
                    f"No SPF record found for {domain}. Without SPF, anyone can "
                    f"send emails appearing to come from {domain}."
                ),
                recommendation="Add an SPF record: v=spf1 include:<your-mail-provider> -all",
                evidence=f"Domain: {domain}\nSPF: Not found",
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )
            print_finding(Severity.HIGH, f"Missing SPF record for {domain}")
            self.result.raw_data["spf"] = None
            return

        spf = spf_records[0]
        self.result.raw_data["spf"] = spf

        if len(spf_records) > 1:
            self.add_finding(
                title="Multiple SPF records (invalid)",
                severity=Severity.MEDIUM,
                description=f"Found {len(spf_records)} SPF records. RFC 7208 requires exactly one.",
                recommendation="Merge all SPF mechanisms into a single record.",
                evidence=f"Records:\n" + "\n".join(spf_records),
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )

        # Check for weak policies
        if spf.endswith("+all"):
            self.add_finding(
                title="SPF allows all senders (+all)",
                severity=Severity.CRITICAL,
                description="SPF record ends with +all which allows ANY server to send as this domain.",
                recommendation="Change +all to -all (hard fail) or ~all (soft fail).",
                evidence=f"SPF: {spf}",
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )
            print_finding(Severity.CRITICAL, f"SPF +all — anyone can spoof {domain}")

        elif spf.endswith("~all"):
            self.add_finding(
                title="SPF uses soft fail (~all)",
                severity=Severity.MEDIUM,
                description="SPF record uses ~all (soft fail). Unauthorized emails may still be delivered.",
                recommendation="Consider using -all (hard fail) for stricter enforcement.",
                evidence=f"SPF: {spf}",
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )

        elif spf.endswith("?all"):
            self.add_finding(
                title="SPF neutral policy (?all)",
                severity=Severity.MEDIUM,
                description="SPF record uses ?all (neutral). This provides no protection.",
                recommendation="Change ?all to -all (hard fail).",
                evidence=f"SPF: {spf}",
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )

        # Check DNS lookup count (max 10 per RFC)
        lookups = len(re.findall(r'\b(?:include|a|mx|ptr|redirect)\b', spf))
        if lookups > 10:
            self.add_finding(
                title=f"SPF exceeds 10 DNS lookup limit ({lookups})",
                severity=Severity.MEDIUM,
                description=f"SPF record requires {lookups} DNS lookups (max 10 per RFC 7208).",
                recommendation="Flatten SPF includes or use fewer mechanisms.",
                evidence=f"SPF: {spf}\nLookups: {lookups}",
                category="Email Security",
                url=url,
            )

        # Check for overly broad includes
        broad_includes = re.findall(r'include:(\S+)', spf)
        if any("_spf.google.com" in i for i in broad_includes):
            pass  # Google is fine
        if "include:spf.protection.outlook.com" in spf:
            pass  # Microsoft is fine

        print_status(f"SPF: {spf}", "info")

    def _check_dkim(self, domain, resolver, url):
        """Discover and validate DKIM selectors."""
        found_selectors = []

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        found_selectors.append((selector, txt))
                        print_status(f"DKIM selector found: {selector}", "info")

                        # Check key strength
                        p_match = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
                        if p_match:
                            key_b64 = p_match.group(1)
                            key_bits = len(key_b64) * 6  # Rough estimate
                            if key_bits < 1024:
                                self.add_finding(
                                    title=f"Weak DKIM key: {selector} (~{key_bits} bits)",
                                    severity=Severity.HIGH,
                                    description=f"DKIM key for selector '{selector}' is approximately {key_bits} bits. Minimum 2048 bits recommended.",
                                    recommendation="Generate a new 2048-bit or 4096-bit DKIM key.",
                                    evidence=f"Selector: {selector}\nRecord: {txt[:100]}...",
                                    category="Email Security",
                                    url=url,
                                    cwe="CWE-326",
                                )

                        # Check for testing mode
                        if "t=y" in txt:
                            self.add_finding(
                                title=f"DKIM in testing mode: {selector}",
                                severity=Severity.LOW,
                                description=f"DKIM selector '{selector}' has t=y (testing mode). Verification failures are not enforced.",
                                recommendation="Remove t=y flag once DKIM signing is verified.",
                                evidence=f"Selector: {selector}\nRecord: {txt}",
                                category="Email Security",
                                url=url,
                            )
            except Exception:
                continue

        if not found_selectors:
            self.add_finding(
                title="No DKIM records found",
                severity=Severity.MEDIUM,
                description=f"No DKIM selectors found for {domain}. Checked: {', '.join(DKIM_SELECTORS)}",
                recommendation="Configure DKIM signing with your email provider.",
                evidence=f"Selectors checked: {', '.join(DKIM_SELECTORS)}",
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )
            print_finding(Severity.MEDIUM, f"No DKIM selectors found for {domain}")

        self.result.raw_data["dkim_selectors"] = [s[0] for s in found_selectors]

    def _check_dmarc(self, domain, resolver, url):
        """Check DMARC (Domain-based Message Authentication) policy."""
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_records.append(txt)
        except Exception:
            dmarc_records = []

        if not dmarc_records:
            self.add_finding(
                title="Missing DMARC record",
                severity=Severity.HIGH,
                description=(
                    f"No DMARC record found for {domain}. Without DMARC, email receivers "
                    f"cannot verify if emails from {domain} are legitimate."
                ),
                recommendation="Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
                evidence=f"Domain: _dmarc.{domain}\nDMARC: Not found",
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )
            print_finding(Severity.HIGH, f"Missing DMARC for {domain}")
            self.result.raw_data["dmarc"] = None
            return

        dmarc = dmarc_records[0]
        self.result.raw_data["dmarc"] = dmarc

        # Parse policy
        policy_match = re.search(r'p=(\w+)', dmarc)
        policy = policy_match.group(1) if policy_match else "none"

        if policy == "none":
            self.add_finding(
                title="DMARC policy is 'none' (monitoring only)",
                severity=Severity.HIGH,
                description="DMARC policy is set to 'none' — no enforcement against spoofing.",
                recommendation="Change p=none to p=quarantine or p=reject after monitoring.",
                evidence=f"DMARC: {dmarc}",
                category="Email Security",
                url=url,
                cwe="CWE-290",
            )
            print_finding(Severity.HIGH, f"DMARC p=none — no enforcement")

        elif policy == "quarantine":
            self.add_finding(
                title="DMARC policy is 'quarantine'",
                severity=Severity.LOW,
                description="DMARC policy quarantines suspicious emails. Consider upgrading to reject.",
                recommendation="Consider p=reject for maximum protection.",
                evidence=f"DMARC: {dmarc}",
                category="Email Security",
                url=url,
            )

        # Check percentage
        pct_match = re.search(r'pct=(\d+)', dmarc)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct < 100:
                self.add_finding(
                    title=f"DMARC applies to only {pct}% of emails",
                    severity=Severity.MEDIUM,
                    description=f"DMARC pct={pct} means only {pct}% of emails are evaluated.",
                    recommendation="Set pct=100 for full coverage.",
                    evidence=f"DMARC: {dmarc}",
                    category="Email Security",
                    url=url,
                )

        # Check for reporting
        if "rua=" not in dmarc:
            self.add_finding(
                title="DMARC has no aggregate reporting (rua)",
                severity=Severity.LOW,
                description="No rua= tag in DMARC. You won't receive aggregate reports about email authentication.",
                recommendation="Add rua=mailto:dmarc-reports@yourdomain.com",
                evidence=f"DMARC: {dmarc}",
                category="Email Security",
                url=url,
            )

        # Check subdomain policy
        sp_match = re.search(r'sp=(\w+)', dmarc)
        if not sp_match and policy != "reject":
            self.add_finding(
                title="No DMARC subdomain policy",
                severity=Severity.LOW,
                description="No sp= tag. Subdomains inherit the main policy which may not be restrictive enough.",
                recommendation="Add sp=reject to protect subdomains.",
                evidence=f"DMARC: {dmarc}",
                category="Email Security",
                url=url,
            )

        print_status(f"DMARC: {dmarc}", "info")

    def _check_mta_sts(self, domain, resolver, url):
        """Check MTA-STS (Mail Transfer Agent Strict Transport Security)."""
        # Check for _mta-sts DNS record
        try:
            answers = resolver.resolve(f"_mta-sts.{domain}", "TXT")
            mta_sts_dns = str(list(answers)[0]).strip('"')
            print_status(f"MTA-STS DNS: {mta_sts_dns}", "info")
        except Exception:
            self.add_finding(
                title="Missing MTA-STS DNS record",
                severity=Severity.LOW,
                description="No MTA-STS TXT record found. Email in transit may not be encrypted.",
                recommendation="Configure MTA-STS to enforce TLS for email transport.",
                evidence=f"_mta-sts.{domain}: Not found",
                category="Email Security",
                url=url,
            )
            return

        # Check for MTA-STS policy file
        try:
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            resp = self.http_client.get(policy_url, timeout=10)
            if resp.status_code == 200:
                policy = resp.text
                if "mode: enforce" in policy:
                    print_status("MTA-STS: enforce mode ✓", "info")
                elif "mode: testing" in policy:
                    self.add_finding(
                        title="MTA-STS in testing mode",
                        severity=Severity.LOW,
                        description="MTA-STS is in testing mode — TLS is not enforced.",
                        recommendation="Switch to mode: enforce after testing.",
                        evidence=f"Policy:\n{policy}",
                        category="Email Security",
                        url=url,
                    )
            else:
                self.add_finding(
                    title="MTA-STS policy file not accessible",
                    severity=Severity.LOW,
                    description=f"MTA-STS DNS record exists but policy file at {policy_url} returned {resp.status_code}.",
                    recommendation="Serve the MTA-STS policy at the correct URL.",
                    evidence=f"URL: {policy_url}\nStatus: {resp.status_code}",
                    category="Email Security",
                    url=url,
                )
        except Exception:
            pass

    def _check_bimi(self, domain, resolver, url):
        """Check BIMI (Brand Indicators for Message Identification) record."""
        try:
            answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
            bimi = str(list(answers)[0]).strip('"')
            if "v=BIMI1" in bimi:
                print_status(f"BIMI: {bimi[:80]}", "info")
                # BIMI is present — good!
                self.result.raw_data["bimi"] = bimi
        except Exception:
            # BIMI is optional, just note it
            self.result.raw_data["bimi"] = None

    def _check_mx(self, domain, resolver, url):
        """Check MX record security."""
        try:
            answers = resolver.resolve(domain, "MX")
            mx_records = [(str(r.exchange).rstrip("."), r.preference) for r in answers]
            self.result.raw_data["mx_records"] = mx_records

            for mx, pref in mx_records:
                # Check for null MX (domain doesn't send email)
                if mx == "." or mx == "":
                    print_status(f"Null MX — domain does not send email", "info")
                    return

                # Check if MX supports STARTTLS
                # (Can't easily test without SMTP connection, but flag missing MX)
                print_status(f"MX: {mx} (priority {pref})", "info")

        except dns.resolver.NoAnswer:
            self.add_finding(
                title="No MX records found",
                severity=Severity.LOW,
                description=f"No MX records for {domain}. If this domain sends email, MX should be configured.",
                recommendation="Add MX records pointing to your mail servers.",
                evidence=f"Domain: {domain}",
                category="Email Security",
                url=url,
            )
        except Exception:
            pass

    def _assess_spoofing_risk(self, domain, url):
        """Overall email spoofing risk assessment."""
        spf = self.result.raw_data.get("spf")
        dmarc = self.result.raw_data.get("dmarc")
        dkim = self.result.raw_data.get("dkim_selectors", [])

        risk_level = 0
        issues = []

        if not spf:
            risk_level += 3
            issues.append("No SPF record")
        elif "+all" in (spf or ""):
            risk_level += 3
            issues.append("SPF allows all senders")
        elif "~all" in (spf or ""):
            risk_level += 1
            issues.append("SPF soft fail only")

        if not dmarc:
            risk_level += 3
            issues.append("No DMARC record")
        elif "p=none" in (dmarc or ""):
            risk_level += 2
            issues.append("DMARC monitoring only (p=none)")

        if not dkim:
            risk_level += 2
            issues.append("No DKIM selectors found")

        if risk_level >= 6:
            severity = Severity.CRITICAL
            risk = "CRITICAL — domain is trivially spoofable"
        elif risk_level >= 4:
            severity = Severity.HIGH
            risk = "HIGH — significant spoofing risk"
        elif risk_level >= 2:
            severity = Severity.MEDIUM
            risk = "MEDIUM — partial protection"
        else:
            severity = Severity.LOW
            risk = "LOW — good email security posture"

        self.add_finding(
            title=f"Email spoofing risk: {risk}",
            severity=severity,
            description=(
                f"Overall email spoofing risk assessment for {domain}:\n"
                f"Risk Score: {risk_level}/8\n"
                f"Issues: {', '.join(issues) if issues else 'None'}\n\n"
                f"SPF: {'✓' if spf else '✗'}\n"
                f"DKIM: {'✓' if dkim else '✗'}\n"
                f"DMARC: {'✓' if dmarc else '✗'}"
            ),
            recommendation=(
                "Implement all three email authentication mechanisms:\n"
                "1. SPF with -all (hard fail)\n"
                "2. DKIM with 2048-bit keys\n"
                "3. DMARC with p=reject\n"
                "4. MTA-STS for transport encryption"
            ),
            evidence=f"SPF: {spf or 'missing'}\nDKIM selectors: {', '.join(dkim) or 'none'}\nDMARC: {dmarc or 'missing'}",
            category="Email Security",
            url=url,
            cwe="CWE-290",
        )
        print_finding(severity, f"Email spoofing risk: {risk}")
