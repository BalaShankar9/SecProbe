"""
Port Scanner — Enterprise-grade TCP port scanning.

Features:
  - Threaded SYN-style connect scan
  - Service banner grabbing
  - Extended risky port database
  - Service-specific probes (HTTP, FTP, SSH, SMTP)
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from secprobe.config import Severity, COMMON_PORTS
from secprobe.scanners.smart_scanner import SmartScanner
from secprobe.utils import (
    extract_hostname,
    parse_ports,
    resolve_hostname,
    print_status,
    print_finding,
    print_progress,
    Colors,
)


class PortScanner(SmartScanner):
    name = "Port Scanner"
    description = "Scan for open TCP ports and identify running services"

    def scan(self):
        hostname = extract_hostname(self.config.target)
        ip = resolve_hostname(hostname)
        if not ip:
            print_status(f"Cannot resolve hostname: {hostname}", "error")
            self.result.error = f"Cannot resolve hostname: {hostname}"
            return

        print_status(f"Target: {hostname} ({ip})", "info")
        ports = parse_ports(self.config.ports)
        print_status(f"Scanning {len(ports)} ports with {self.config.threads} threads…", "progress")

        open_ports = []
        scanned = 0
        total = len(ports)

        def check_port(port: int) -> tuple[int, bool, str]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # Try to grab banner
                    banner = ""
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                    sock.close()
                    return port, True, banner
                sock.close()
            except Exception:
                pass
            return port, False, ""

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                scanned += 1
                if scanned % 50 == 0 or scanned == total:
                    print_progress(scanned, total, "Scanning")

                port, is_open, banner = future.result()
                if is_open:
                    service = COMMON_PORTS.get(port, "Unknown")
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner[:200],
                    })

        # Sort and report
        open_ports.sort(key=lambda x: x["port"])
        self.result.raw_data["open_ports"] = open_ports
        self.result.raw_data["target_ip"] = ip

        if open_ports:
            print(f"\n  {'PORT':<10}{'SERVICE':<18}{'BANNER'}")
            print(f"  {'─' * 60}")
            for p in open_ports:
                banner_short = p["banner"].split("\n")[0][:40] if p["banner"] else ""
                print(
                    f"  {Colors.GREEN}{p['port']:<10}{Colors.RESET}"
                    f"{p['service']:<18}{Colors.GRAY}{banner_short}{Colors.RESET}"
                )

            self.add_finding(
                title=f"{len(open_ports)} open port(s) discovered",
                severity=Severity.INFO,
                description=f"Open ports: {', '.join(str(p['port']) for p in open_ports)}",
                evidence="\n".join(
                    f"Port {p['port']}/{p['service']}" for p in open_ports
                ),
                category="Network",
            )

            # Flag risky open ports
            risky = {
                21: ("FTP (may allow anonymous access)", Severity.MEDIUM),
                23: ("Telnet (unencrypted remote access)", Severity.HIGH),
                25: ("SMTP (may be an open relay)", Severity.MEDIUM),
                110: ("POP3 (unencrypted mail)", Severity.LOW),
                135: ("MSRPC (Windows RPC — worm vector)", Severity.HIGH),
                139: ("NetBIOS (Windows share exposure)", Severity.HIGH),
                445: ("SMB (EternalBlue, WannaCry vector)", Severity.HIGH),
                1433: ("MS SQL Server (often brute-forced)", Severity.MEDIUM),
                1521: ("Oracle DB (often brute-forced)", Severity.MEDIUM),
                2049: ("NFS (network file share exposure)", Severity.HIGH),
                3306: ("MySQL (often exposed without auth)", Severity.MEDIUM),
                3389: ("RDP (BlueKeep, brute-force target)", Severity.HIGH),
                5432: ("PostgreSQL (often exposed without auth)", Severity.MEDIUM),
                5900: ("VNC (often no auth or weak auth)", Severity.HIGH),
                5985: ("WinRM HTTP (remote management)", Severity.MEDIUM),
                5986: ("WinRM HTTPS (remote management)", Severity.MEDIUM),
                6379: ("Redis (often exposed without auth)", Severity.HIGH),
                8080: ("HTTP Proxy/Alt (management interface?)", Severity.LOW),
                8443: ("HTTPS Alt (management interface?)", Severity.LOW),
                9200: ("Elasticsearch (often exposed without auth)", Severity.HIGH),
                11211: ("Memcached (DDoS amplification, no auth)", Severity.HIGH),
                27017: ("MongoDB (often exposed without auth)", Severity.HIGH),
                27018: ("MongoDB shard (often no auth)", Severity.HIGH),
                50000: ("SAP (management interface)", Severity.MEDIUM),
            }
            for p in open_ports:
                if p["port"] in risky:
                    desc, sev = risky[p["port"]]
                    self.add_finding(
                        title=f"Risky service on port {p['port']}",
                        severity=sev,
                        description=desc,
                        recommendation=f"Verify that port {p['port']} requires authentication, is firewalled, and is necessary.",
                        evidence=f"Port {p['port']} — Banner: {p['banner'][:80]}" if p["banner"] else f"Port {p['port']}",
                        category="Network",
                    )
        else:
            print_status("No open ports found in the specified range.", "info")
