"""
Utility functions for SecProbe.
"""

import re
import sys
import socket
from urllib.parse import urlparse


# ── Terminal Colors ──────────────────────────────────────────────────

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

    @staticmethod
    def disable():
        Colors.RESET = ""
        Colors.BOLD = ""
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.CYAN = ""
        Colors.MAGENTA = ""
        Colors.GRAY = ""
        Colors.BG_RED = ""
        Colors.BG_GREEN = ""
        Colors.BG_YELLOW = ""


def severity_color(severity: str) -> str:
    mapping = {
        "CRITICAL": Colors.RED + Colors.BOLD,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.BLUE,
        "INFO": Colors.CYAN,
    }
    return mapping.get(severity, Colors.RESET)


# ── Pretty Printing ─────────────────────────────────────────────────

BANNER = rf"""
{Colors.CYAN}{Colors.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║   ███████╗███████╗ ██████╗██████╗ ██████╗  ██████╗ ██████╗  ║
  ║   ██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗ ║
  ║   ███████╗█████╗  ██║     ██████╔╝██████╔╝██║   ██║██████╔╝ ║
  ║   ╚════██║██╔══╝  ██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗ ║
  ║   ███████║███████╗╚██████╗██║     ██║  ██║╚██████╔╝██████╔╝ ║
  ║   ╚══════╝╚══════╝ ╚═════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ║
  ║                                                              ║
  ║        Enterprise Security Testing Toolkit v7.0.0            ║
  ║        ───────────────────────────────────────────            ║
  ╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""


def print_banner():
    print(BANNER)


def print_section(title: str):
    width = 60
    print(f"\n{Colors.CYAN}{'─' * width}")
    print(f"  ◆ {title}")
    print(f"{'─' * width}{Colors.RESET}")


def print_finding(severity: str, title: str, detail: str = ""):
    icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "ℹ️ ",
    }.get(severity, "•")
    color = severity_color(severity)
    print(f"  {icon} {color}[{severity}]{Colors.RESET} {title}")
    if detail:
        for line in detail.split("\n"):
            print(f"      {Colors.GRAY}{line}{Colors.RESET}")


def print_status(message: str, status: str = "info"):
    icons = {
        "info": f"{Colors.CYAN}[*]{Colors.RESET}",
        "success": f"{Colors.GREEN}[✓]{Colors.RESET}",
        "warning": f"{Colors.YELLOW}[!]{Colors.RESET}",
        "error": f"{Colors.RED}[✗]{Colors.RESET}",
        "progress": f"{Colors.MAGENTA}[→]{Colors.RESET}",
    }
    icon = icons.get(status, icons["info"])
    print(f"  {icon} {message}")


def print_progress(current: int, total: int, prefix: str = ""):
    bar_length = 40
    filled = int(bar_length * current / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_length - filled)
    percent = (current / total * 100) if total > 0 else 0
    sys.stdout.write(f"\r  {Colors.CYAN}{prefix}{Colors.RESET} [{bar}] {percent:.0f}% ({current}/{total})")
    sys.stdout.flush()
    if current >= total:
        print()


# ── URL & Network Helpers ────────────────────────────────────────────

def normalize_url(target: str) -> str:
    """Ensure the target has a proper URL scheme."""
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/")


def extract_hostname(target: str) -> str:
    """Extract hostname from a URL or raw input."""
    parsed = urlparse(normalize_url(target))
    return parsed.hostname or target


def resolve_hostname(hostname: str) -> str | None:
    """Resolve a hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def parse_ports(port_string: str) -> list[int]:
    """Parse a port specification string into a list of port numbers.

    Supports:
        - Single port: '80'
        - Range: '1-1024'
        - Comma-separated: '80,443,8080'
        - Mixed: '22,80,443,8000-8100'
    """
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def is_valid_target(target: str) -> bool:
    """Validate that the target is a valid hostname, IP, or URL."""
    hostname = extract_hostname(target)
    # Check IP
    try:
        socket.inet_aton(hostname)
        return True
    except socket.error:
        pass
    # Check hostname pattern
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(hostname))
