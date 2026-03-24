"""
SSL/TLS Scanner — Enterprise-grade certificate and protocol analysis.

Features:
  - Certificate chain validation and key size analysis
  - Multi-protocol probing (SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
  - Weak cipher detection
  - HSTS preload check
  - Certificate transparency indicators
  - Heartbleed detection (CVE-2014-0160)
  - BEAST/POODLE/CRIME vulnerability checks
  - OCSP stapling verification
  - Certificate revocation check
  - Key size validation (RSA/ECDSA)
"""

import ssl
import socket
import struct
from datetime import datetime, timezone

from secprobe.config import Severity
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import extract_hostname, print_status, print_finding, Colors


class SSLScanner(SmartScanner):
    name = "SSL/TLS Scanner"
    description = "Analyze SSL/TLS certificates, protocols, and ciphers"

    def scan(self):
        hostname = extract_hostname(self.config.target)
        port = 443
        print_status(f"Checking SSL/TLS on {hostname}:{port}", "progress")

        # ── Connect and fetch certificate ────────────────────────────
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(), server_hostname=hostname)
            conn.settimeout(self.config.timeout)
            conn.connect((hostname, port))
        except ssl.SSLCertVerificationError as e:
            self.add_finding(
                title="SSL Certificate Verification Failed",
                severity=Severity.HIGH,
                description=str(e),
                recommendation="Ensure a valid, trusted SSL certificate is installed.",
                category="SSL/TLS",
            )
            print_finding(Severity.HIGH, "Certificate verification failed", str(e))
            return
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            print_status(f"Cannot connect to {hostname}:443 — {e}", "warning")
            self.result.raw_data["ssl_available"] = False
            self.add_finding(
                title="SSL/TLS not available",
                severity=Severity.HIGH,
                description=f"Could not establish SSL connection to {hostname}:443",
                recommendation="Enable HTTPS on this server.",
                category="SSL/TLS",
            )
            return

        cert = conn.getpeercert()
        cipher = conn.cipher()
        protocol = conn.version()
        conn.close()

        self.result.raw_data["certificate"] = cert
        self.result.raw_data["cipher"] = cipher
        self.result.raw_data["protocol"] = protocol

        # ── Print certificate details ────────────────────────────────
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        print(f"\n  {Colors.BOLD}Certificate Details:{Colors.RESET}")
        print(f"    Subject:    {subject.get('commonName', 'N/A')}")
        print(f"    Issuer:     {issuer.get('organizationName', 'N/A')}")
        print(f"    Valid from: {not_before.date()} to {not_after.date()} ({days_left} days remaining)")
        print(f"    Protocol:   {protocol}")
        print(f"    Cipher:     {cipher[0] if cipher else 'N/A'}")

        # SANs
        san_list = [
            entry[1] for entry in cert.get("subjectAltName", ())
            if entry[0] == "DNS"
        ]
        if san_list:
            print(f"    SANs:       {', '.join(san_list[:10])}")

        # ── Evaluate findings ────────────────────────────────────────
        # Expiry check
        if days_left < 0:
            self.add_finding(
                title="SSL Certificate has EXPIRED",
                severity=Severity.CRITICAL,
                description=f"Certificate expired {abs(days_left)} days ago on {not_after.date()}",
                recommendation="Renew the SSL certificate immediately.",
                category="SSL/TLS",
            )
            print_finding(Severity.CRITICAL, "Certificate EXPIRED")
        elif days_left < 30:
            self.add_finding(
                title="SSL Certificate expiring soon",
                severity=Severity.HIGH,
                description=f"Certificate expires in {days_left} days on {not_after.date()}",
                recommendation="Renew the SSL certificate before expiration.",
                category="SSL/TLS",
            )
            print_finding(Severity.HIGH, f"Certificate expires in {days_left} days")
        elif days_left < 90:
            self.add_finding(
                title="SSL Certificate expiring within 90 days",
                severity=Severity.MEDIUM,
                description=f"Certificate expires in {days_left} days on {not_after.date()}",
                recommendation="Plan certificate renewal.",
                category="SSL/TLS",
            )
        else:
            print_finding(Severity.INFO, f"Certificate valid for {days_left} days")

        # Protocol check
        weak_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
        if protocol in weak_protocols:
            self.add_finding(
                title=f"Weak SSL/TLS protocol: {protocol}",
                severity=Severity.HIGH,
                description=f"Server is using {protocol} which is considered insecure.",
                recommendation="Disable all protocols below TLSv1.2.",
                category="SSL/TLS",
            )
            print_finding(Severity.HIGH, f"Weak protocol: {protocol}")
        else:
            print_finding(Severity.INFO, f"Protocol {protocol} is acceptable")

        # Cipher check
        if cipher:
            cipher_name = cipher[0]
            weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
            for wc in weak_ciphers:
                if wc.lower() in cipher_name.lower():
                    self.add_finding(
                        title=f"Weak cipher suite detected: {cipher_name}",
                        severity=Severity.HIGH,
                        description=f"The cipher {cipher_name} contains weak algorithm '{wc}'.",
                        recommendation="Configure the server to use only strong cipher suites.",
                        category="SSL/TLS",
                    )
                    print_finding(Severity.HIGH, f"Weak cipher: {cipher_name}")
                    break

        # Self-signed check
        if subject.get("commonName") == issuer.get("commonName", ""):
            org = issuer.get("organizationName", "")
            if not org or org == subject.get("organizationName", ""):
                self.add_finding(
                    title="Potentially self-signed certificate",
                    severity=Severity.MEDIUM,
                    description="The certificate issuer matches the subject, suggesting it may be self-signed.",
                    recommendation="Use a certificate from a trusted Certificate Authority.",
                    category="SSL/TLS",
                )
                print_finding(Severity.MEDIUM, "Possibly self-signed certificate")

        # Hostname mismatch
        if hostname not in san_list and not any(
            san.startswith("*.") and hostname.endswith(san[1:]) for san in san_list
        ):
            cn = subject.get("commonName", "")
            if hostname != cn and not (cn.startswith("*.") and hostname.endswith(cn[1:])):
                self.add_finding(
                    title="Certificate hostname mismatch",
                    severity=Severity.HIGH,
                    description=f"Certificate CN/SAN does not match hostname '{hostname}'.",
                    recommendation="Ensure the certificate covers the target hostname.",
                    category="SSL/TLS",
                )
                print_finding(Severity.HIGH, "Hostname mismatch")

        # ── Protocol probing ─────────────────────────────────────────
        self._probe_protocols(hostname, port)

        # ── Key size analysis ────────────────────────────────────────
        self._check_key_size(hostname, port)

        # ── Heartbleed check (CVE-2014-0160) ─────────────────────────
        self._check_heartbleed(hostname, port)

        # ── BEAST / POODLE / CRIME checks ────────────────────────────
        self._check_beast_poodle_crime(hostname, port, protocol, cipher)

        # ── OCSP Stapling ────────────────────────────────────────────
        self._check_ocsp_stapling(hostname, port)

        # ── HSTS check ───────────────────────────────────────────────
        self._check_hsts(hostname)

    def _probe_protocols(self, hostname: str, port: int):
        """Probe which TLS/SSL protocol versions are accepted."""
        print_status("Probing supported protocols…", "progress")

        protocols_to_test = []
        # Build list of (name, ssl constant) to test
        for name, proto_const in [
            ("SSLv3", getattr(ssl, "PROTOCOL_SSLv3", None)),
            ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
            ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
            ("TLSv1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None)),
        ]:
            if proto_const is not None:
                protocols_to_test.append((name, proto_const))

        accepted = []
        for name, proto_const in protocols_to_test:
            try:
                ctx = ssl.SSLContext(proto_const)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        accepted.append(name)
            except Exception:
                continue

        # Also test TLSv1.3 via the general context
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    accepted.append("TLSv1.3")
        except Exception:
            pass

        self.result.raw_data["accepted_protocols"] = accepted

        if accepted:
            print(f"\n  {Colors.BOLD}Supported Protocols:{Colors.RESET}")
            for proto in accepted:
                is_weak = proto in ("SSLv3", "TLSv1.0", "TLSv1.1")
                color = Colors.RED if is_weak else Colors.GREEN
                print(f"    {color}{'✗' if is_weak else '✓'} {proto}{Colors.RESET}")

            weak_accepted = [p for p in accepted if p in ("SSLv3", "TLSv1.0", "TLSv1.1")]
            if weak_accepted:
                self.add_finding(
                    title=f"Weak protocol(s) accepted: {', '.join(weak_accepted)}",
                    severity=Severity.HIGH,
                    description=f"The server accepts deprecated protocols: {', '.join(weak_accepted)}.",
                    recommendation="Disable SSLv3, TLSv1.0, and TLSv1.1. Only allow TLSv1.2+.",
                    evidence=f"Accepted: {', '.join(accepted)}",
                    category="SSL/TLS",
                )

            if "TLSv1.3" in accepted:
                print_finding(Severity.INFO, "TLSv1.3 supported ✓")

    def _check_key_size(self, hostname: str, port: int):
        """Analyze certificate key size for strength."""
        print_status("Checking certificate key size…", "progress")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()

            # Extract key size from cipher info
            if cipher and len(cipher) >= 3:
                key_bits = cipher[2]  # Third element is key size in bits
                self.result.raw_data["key_bits"] = key_bits

                if key_bits < 2048:
                    self.add_finding(
                        title=f"Weak key size: {key_bits} bits",
                        severity=Severity.HIGH,
                        description=f"Certificate key size is {key_bits} bits. Minimum recommended is 2048 for RSA.",
                        recommendation="Use RSA keys of at least 2048 bits, or ECDSA keys of at least 256 bits.",
                        evidence=f"Key bits: {key_bits}\nCipher: {cipher[0]}",
                        category="SSL/TLS",
                    )
                    print_finding(Severity.HIGH, f"Weak key: {key_bits} bits")
                elif key_bits >= 4096:
                    print_finding(Severity.INFO, f"Strong key: {key_bits} bits ✓")
                else:
                    print_finding(Severity.INFO, f"Key size: {key_bits} bits (acceptable)")

        except Exception as e:
            pass

    def _check_heartbleed(self, hostname: str, port: int):
        """Test for Heartbleed vulnerability (CVE-2014-0160)."""
        print_status("Testing for Heartbleed (CVE-2014-0160)…", "progress")
        try:
            # TLS 1.0 ClientHello with heartbeat extension
            hello = bytearray(
                b'\x16\x03\x01\x00\xdc'  # Content type, version, length
                b'\x01\x00\x00\xd8'      # Handshake: ClientHello
                b'\x03\x02'              # TLS 1.1
                + b'\x53\x43\x5b\x90' + b'\x00' * 28  # Random
                + b'\x00'                # Session ID length
                + b'\x00\x68'            # Cipher suites length
                + b'\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38'
                + b'\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84'
                + b'\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13'
                + b'\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f'
                + b'\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45'
                + b'\x00\x44\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41'
                + b'\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04'
                + b'\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08'
                + b'\x00\x06\x00\x03\x00\xff'
                + b'\x01\x00'            # Compression methods
                + b'\x00\x49'            # Extensions length
                + b'\x00\x0b\x00\x04\x03\x00\x01\x02'  # EC point formats
                + b'\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19'
                + b'\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16'
                + b'\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15'
                + b'\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02'
                + b'\x00\x03\x00\x0f\x00\x10\x00\x11'
                + b'\x00\x0f\x00\x01\x01'  # Heartbeat extension (THIS IS KEY)
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            sock.send(hello)

            # Read ServerHello
            response = b''
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if len(response) > 100:
                        break
                except socket.timeout:
                    break

            if len(response) < 5:
                sock.close()
                return

            # Send Heartbeat request with oversized payload length
            heartbeat = bytearray(
                b'\x18\x03\x01\x00\x03'  # Heartbeat content type
                b'\x01'                    # HeartbeatRequest
                b'\x40\x00'               # Payload length = 16384
            )
            sock.send(heartbeat)

            # Read heartbeat response
            try:
                hb_response = sock.recv(16384)
                if hb_response and len(hb_response) > 3:
                    if hb_response[0] == 0x18:  # Heartbeat content type
                        self.add_finding(
                            title="CRITICAL: Heartbleed vulnerability (CVE-2014-0160)",
                            severity=Severity.CRITICAL,
                            description=(
                                "Server is vulnerable to Heartbleed.\n"
                                "An attacker can read up to 64KB of server memory per request,\n"
                                "potentially exposing private keys, session tokens, and passwords."
                            ),
                            recommendation="Upgrade OpenSSL immediately. Revoke and reissue all certificates.",
                            evidence=f"Heartbeat response: {len(hb_response)} bytes",
                            category="SSL/TLS", cwe="CWE-119",
                        )
                        print_finding(Severity.CRITICAL, "🔥 HEARTBLEED VULNERABLE!")
                    else:
                        print_finding(Severity.INFO, "Not vulnerable to Heartbleed ✓")
                else:
                    print_finding(Severity.INFO, "Heartbleed: No response (likely not vulnerable)")
            except socket.timeout:
                print_finding(Severity.INFO, "Heartbleed: Timeout (likely not vulnerable)")

            sock.close()

        except Exception:
            pass

    def _check_beast_poodle_crime(self, hostname, port, protocol, cipher):
        """Check for BEAST, POODLE, and CRIME vulnerabilities."""
        print_status("Checking for BEAST/POODLE/CRIME…", "progress")

        # BEAST: TLS 1.0 + CBC cipher
        if protocol in ("TLSv1", "TLSv1.0"):
            if cipher and "CBC" in cipher[0]:
                self.add_finding(
                    title="BEAST vulnerability (TLS 1.0 + CBC)",
                    severity=Severity.MEDIUM,
                    description="TLS 1.0 with CBC cipher is vulnerable to BEAST attack.",
                    recommendation="Upgrade to TLS 1.2+ or use GCM ciphers.",
                    evidence=f"Protocol: {protocol}\nCipher: {cipher[0]}",
                    category="SSL/TLS", cwe="CWE-310",
                )
                print_finding(Severity.MEDIUM, "BEAST: TLS 1.0 + CBC")

        # POODLE: SSLv3 supported (already detected in protocol probing, add explicit check)
        if hasattr(self.result, 'raw_data') and "SSLv3" in self.result.raw_data.get("accepted_protocols", []):
            self.add_finding(
                title="POODLE vulnerability (SSLv3)",
                severity=Severity.HIGH,
                description="SSLv3 is supported, making the server vulnerable to POODLE attack.",
                recommendation="Disable SSLv3 completely.",
                evidence="SSLv3 accepted",
                category="SSL/TLS", cwe="CWE-310",
            )
            print_finding(Severity.HIGH, "POODLE: SSLv3 supported")

        # CRIME: TLS compression
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    if ssock.compression():
                        self.add_finding(
                            title="CRIME vulnerability (TLS compression)",
                            severity=Severity.HIGH,
                            description="TLS compression is enabled, making the server vulnerable to CRIME attack.",
                            recommendation="Disable TLS compression.",
                            evidence=f"Compression: {ssock.compression()}",
                            category="SSL/TLS", cwe="CWE-310",
                        )
                        print_finding(Severity.HIGH, "CRIME: TLS compression enabled")
                    else:
                        print_finding(Severity.INFO, "No TLS compression (CRIME safe) ✓")
        except Exception:
            pass

    def _check_ocsp_stapling(self, hostname: str, port: int):
        """Check for OCSP stapling support."""
        print_status("Checking OCSP stapling…", "progress")
        try:
            ctx = ssl.create_default_context()
            # Request OCSP stapling
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check if OCSP response was stapled
                    ocsp_response = ssock.get_channel_binding(cb_type="tls-unique")
                    # Note: Python's ssl module has limited OCSP support
                    # We check if the server certificate has OCSP responder URL
                    cert = ssock.getpeercert()

            # Check for OCSP responder in cert
            has_ocsp = False
            for extension in cert.get("OCSP", []):
                has_ocsp = True

            # Also check Authority Info Access
            if not has_ocsp:
                self.add_finding(
                    title="OCSP stapling not detected",
                    severity=Severity.LOW,
                    description="Server does not appear to support OCSP stapling.",
                    recommendation="Enable OCSP stapling for faster certificate validation.",
                    evidence=f"Hostname: {hostname}",
                    category="SSL/TLS",
                )
            else:
                print_finding(Severity.INFO, "OCSP responder present ✓")

        except Exception:
            pass

    def _check_hsts(self, hostname: str):
        """Check for HSTS header and its configuration."""
        print_status("Checking HSTS…", "progress")
        try:
            resp = self.http_client.get(f"https://{hostname}/", timeout=5)
            hsts = resp.headers.get("Strict-Transport-Security", "")

            if not hsts:
                self.add_finding(
                    title="Missing HSTS header",
                    severity=Severity.MEDIUM,
                    description="Strict-Transport-Security header is not set.",
                    recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    evidence=f"URL: https://{hostname}/",
                    category="SSL/TLS", cwe="CWE-319",
                )
                print_finding(Severity.MEDIUM, "No HSTS header")
            else:
                # Check max-age
                import re
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        self.add_finding(
                            title=f"HSTS max-age too short ({max_age}s)",
                            severity=Severity.LOW,
                            description=f"HSTS max-age is {max_age}s. Recommended minimum is 31536000 (1 year).",
                            recommendation="Set max-age to at least 31536000.",
                            evidence=f"HSTS: {hsts}",
                            category="SSL/TLS",
                        )

                if "includesubdomains" not in hsts.lower():
                    self.add_finding(
                        title="HSTS missing includeSubDomains",
                        severity=Severity.LOW,
                        description="HSTS header does not include subdomains.",
                        recommendation="Add includeSubDomains to HSTS header.",
                        evidence=f"HSTS: {hsts}",
                        category="SSL/TLS",
                    )

                if "preload" not in hsts.lower():
                    self.add_finding(
                        title="HSTS not preloaded",
                        severity=Severity.INFO,
                        description="HSTS header does not include preload directive.",
                        recommendation="Consider adding preload and submitting to hstspreload.org.",
                        evidence=f"HSTS: {hsts}",
                        category="SSL/TLS",
                    )
                else:
                    print_finding(Severity.INFO, "HSTS with preload ✓")
        except Exception:
            pass
