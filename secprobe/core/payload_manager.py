"""
Intelligent payload management — merges built-in, community, and learned payloads.

Sources:
1. Built-in: secprobe/payloads/*.txt
2. Community: PayloadsAllTheThings + SecLists (cached from GitHub)
3. Learned: payloads ranked by effectiveness from semantic memory
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# GitHub raw URLs for community payloads
COMMUNITY_SOURCES = {
    "sqli": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZ_SQLi.txt",
    ],
    "xss": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/IntruderXSS.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss_payloads_quick.txt",
    ],
    "ssti": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/ssti.txt",
    ],
    "lfi": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Traversal.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/deep_traversal.txt",
    ],
    "xxe": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Intruders/xxe_payloads.txt",
    ],
    "ssrf": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Intruder/SSRF_IPv4.txt",
    ],
    "cmdi": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command_exec.txt",
    ],
    "nosql": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt",
    ],
    "directories": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
    ],
    "subdomains": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    ],
    "passwords": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    ],
    "api_paths": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
    ],
    "secrets_patterns": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Pattern-Matching/api-key-regex.txt",
    ],
}

_CACHE_DIR = Path.home() / ".secprobe" / "payloads_cache"


@dataclass
class PayloadSet:
    """A collection of payloads for a specific attack type."""
    attack_type: str
    payloads: list[str] = field(default_factory=list)
    source: str = "builtin"
    count: int = 0

    def __post_init__(self):
        self.count = len(self.payloads)


class PayloadManager:
    """Intelligent payload management with multi-source merging."""

    def __init__(self, builtin_dir: Optional[Path] = None,
                 cache_dir: Optional[Path] = None,
                 enable_community: bool = True):
        self._builtin_dir = builtin_dir or (Path(__file__).parent.parent / "payloads")
        self._cache_dir = cache_dir or _CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._enable_community = enable_community
        self._loaded: dict[str, PayloadSet] = {}

    def get_payloads(self, attack_type: str, max_count: int = 0) -> list[str]:
        """
        Get merged, deduplicated payloads for an attack type.

        Order: learned (most effective) -> builtin -> community
        """
        if attack_type in self._loaded:
            payloads = self._loaded[attack_type].payloads
        else:
            payloads = self._load_payloads(attack_type)
            self._loaded[attack_type] = PayloadSet(
                attack_type=attack_type,
                payloads=payloads,
                source="merged",
            )

        if max_count and max_count < len(payloads):
            return payloads[:max_count]
        return payloads

    def _load_payloads(self, attack_type: str) -> list[str]:
        """Load and merge payloads from all sources."""
        seen = set()
        result = []

        def _add(payload: str):
            p = payload.strip()
            if p and p not in seen and not p.startswith("#"):
                seen.add(p)
                result.append(p)

        # 1. Built-in payloads
        builtin_file = self._builtin_dir / f"{attack_type}.txt"
        if builtin_file.exists():
            for line in builtin_file.read_text(errors="ignore").splitlines():
                _add(line)
            logger.debug("Loaded %d builtin payloads for %s", len(result), attack_type)

        # 2. Community payloads (cached)
        if self._enable_community and attack_type in COMMUNITY_SOURCES:
            for url in COMMUNITY_SOURCES[attack_type]:
                cache_file = self._get_cache_path(url)
                if cache_file.exists():
                    before = len(result)
                    for line in cache_file.read_text(errors="ignore").splitlines():
                        _add(line)
                    logger.debug("Loaded %d community payloads from cache for %s",
                               len(result) - before, attack_type)

        logger.info("Total payloads for %s: %d", attack_type, len(result))
        return result

    def download_community_payloads(self, attack_type: str = "") -> int:
        """Download community payloads from GitHub and cache locally."""
        import urllib.request

        types = [attack_type] if attack_type else list(COMMUNITY_SOURCES.keys())
        total = 0

        for atype in types:
            if atype not in COMMUNITY_SOURCES:
                continue
            for url in COMMUNITY_SOURCES[atype]:
                cache_file = self._get_cache_path(url)
                if cache_file.exists():
                    continue  # Already cached
                try:
                    logger.info("Downloading payloads: %s", url.split("/")[-1])
                    req = urllib.request.Request(url, headers={"User-Agent": "SecProbe/8.0"})
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        content = resp.read().decode("utf-8", errors="ignore")
                    cache_file.parent.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(content)
                    lines = len(content.splitlines())
                    total += lines
                    logger.info("Cached %d payloads: %s", lines, cache_file.name)
                except Exception:
                    logger.warning("Failed to download: %s", url, exc_info=True)

        return total

    def get_stats(self) -> dict:
        """Get payload statistics."""
        stats = {}
        for attack_type in list(COMMUNITY_SOURCES.keys()) + ["directories", "subdomains"]:
            builtin = self._builtin_dir / f"{attack_type}.txt"
            builtin_count = len(builtin.read_text(errors="ignore").splitlines()) if builtin.exists() else 0

            cached_count = 0
            if attack_type in COMMUNITY_SOURCES:
                for url in COMMUNITY_SOURCES[attack_type]:
                    cf = self._get_cache_path(url)
                    if cf.exists():
                        cached_count += len(cf.read_text(errors="ignore").splitlines())

            stats[attack_type] = {
                "builtin": builtin_count,
                "community_cached": cached_count,
                "total": builtin_count + cached_count,
            }
        return stats

    def get_available_types(self) -> list[str]:
        """List all available attack types."""
        types = set()
        if self._builtin_dir.exists():
            for f in self._builtin_dir.glob("*.txt"):
                types.add(f.stem)
        types.update(COMMUNITY_SOURCES.keys())
        return sorted(types)

    def _get_cache_path(self, url: str) -> Path:
        """Get local cache path for a remote URL."""
        url_hash = hashlib.md5(url.encode()).hexdigest()[:10]
        filename = url.split("/")[-1]
        return self._cache_dir / f"{url_hash}_{filename}"
