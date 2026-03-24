"""
Payload loader utility — loads external wordlists and signature databases.
Provides caching, filtering, and category-based payload selection.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

PAYLOAD_DIR = Path(__file__).parent

# ── Public API ───────────────────────────────────────────────────

@lru_cache(maxsize=32)
def load_payloads(name: str, *, strip_comments: bool = True) -> list[str]:
    """Load a payload file by name (without extension).
    
    Args:
        name: File stem — 'sqli', 'xss', 'directories', 'subdomains'
        strip_comments: If True, remove lines starting with #
    
    Returns:
        List of non-empty payload strings
    """
    path = PAYLOAD_DIR / f"{name}.txt"
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {path}")

    lines: list[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\n\r")
            if not line:
                continue
            if strip_comments and line.lstrip().startswith("#"):
                continue
            lines.append(line)
    return lines


def load_payloads_by_section(name: str) -> dict[str, list[str]]:
    """Load a payload file and group payloads by section header.
    
    Section headers are lines starting with '# ── <name> ──'
    
    Returns:
        Dict mapping section name → list of payloads
    """
    path = PAYLOAD_DIR / f"{name}.txt"
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {path}")

    sections: dict[str, list[str]] = {}
    current_section = "default"
    section_re = re.compile(r"^#\s*──\s*(.+?)\s*──")

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\n\r")
            if not line:
                continue

            m = section_re.match(line)
            if m:
                current_section = m.group(1).strip()
                if current_section not in sections:
                    sections[current_section] = []
                continue

            if line.lstrip().startswith("#"):
                continue

            if current_section not in sections:
                sections[current_section] = []
            sections[current_section].append(line)

    return sections


@lru_cache(maxsize=1)
def load_tech_signatures() -> dict:
    """Load the YAML technology fingerprint database.
    
    Returns:
        Parsed YAML dict with categories: web_servers, frameworks, cms, etc.
    """
    path = PAYLOAD_DIR / "tech_signatures.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Tech signatures not found: {path}")

    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except ImportError:
        # Fallback: minimal YAML parser for our simple structure
        return _parse_simple_yaml(path)


def get_payload_count(name: str) -> int:
    """Return the count of payloads in a file without loading all into memory."""
    path = PAYLOAD_DIR / f"{name}.txt"
    if not path.exists():
        return 0
    count = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                count += 1
    return count


def list_available_payloads() -> dict[str, int]:
    """List all available payload files and their line counts."""
    result = {}
    for f in PAYLOAD_DIR.glob("*.txt"):
        result[f.stem] = get_payload_count(f.stem)
    return result


def load_custom_wordlist(path: str | Path) -> list[str]:
    """Load a custom wordlist from an arbitrary path."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {p}")
    lines = []
    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


# ── Internal Helpers ─────────────────────────────────────────────

def _parse_simple_yaml(path: Path) -> dict:
    """Minimal YAML-like parser for our signatures file.
    Only handles our specific format — not a general YAML parser.
    Falls back to empty dict on parse failure.
    """
    try:
        data: dict = {}
        current_category: Optional[str] = None
        current_item: Optional[dict] = None
        current_list_key: Optional[str] = None

        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.rstrip()
                if not stripped or stripped.startswith("#"):
                    continue

                indent = len(line) - len(line.lstrip())

                if indent == 0 and stripped.endswith(":"):
                    current_category = stripped[:-1]
                    data[current_category] = []
                    current_item = None
                    current_list_key = None

                elif indent == 2 and stripped.startswith("- name:"):
                    name = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                    current_item = {"name": name}
                    if current_category and current_category in data:
                        data[current_category].append(current_item)
                    current_list_key = None

                elif current_item is not None and ":" in stripped:
                    key, _, val = stripped.partition(":")
                    key = key.strip().lstrip("- ")
                    val = val.strip()

                    if val.startswith("[") and val.endswith("]"):
                        items = val[1:-1].split(",")
                        current_item[key] = [
                            i.strip().strip('"').strip("'") for i in items if i.strip()
                        ]
                        current_list_key = None
                    elif val == "" or val == "[]":
                        current_item[key] = []
                        current_list_key = key if val == "" else None
                    elif val == "{}":
                        current_item[key] = {}
                        current_list_key = None
                    else:
                        current_item[key] = val.strip('"').strip("'")
                        current_list_key = None

                elif current_item is not None and stripped.startswith("- ") and current_list_key:
                    val = stripped[2:].strip().strip('"').strip("'")
                    if current_list_key in current_item:
                        if isinstance(current_item[current_list_key], list):
                            current_item[current_list_key].append(val)

        return data
    except Exception:
        return {}
