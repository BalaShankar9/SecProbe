"""
Structured logging framework for SecProbe.

Replaces all print()-based output with proper Python logging.
Supports:
    - Console output with color formatting
    - File logging with rotation
    - Structured JSON log output
    - Per-scanner log context
"""

import logging
import logging.handlers
import json
import os
import sys
from datetime import datetime
from typing import Optional


# ── Custom log levels ────────────────────────────────────────────────
FINDING = 25  # Between INFO (20) and WARNING (30)
logging.addLevelName(FINDING, "FINDING")


def _finding(self, message, *args, **kwargs):
    if self.isEnabledFor(FINDING):
        self._log(FINDING, message, args, **kwargs)


logging.Logger.finding = _finding


# ── Color formatter for console ──────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """Console formatter with ANSI colors and emoji icons."""

    COLORS = {
        logging.DEBUG: "\033[90m",       # Gray
        logging.INFO: "\033[96m",        # Cyan
        FINDING: "\033[93m",             # Yellow
        logging.WARNING: "\033[93m",     # Yellow
        logging.ERROR: "\033[91m",       # Red
        logging.CRITICAL: "\033[91m\033[1m",  # Bold Red
    }
    ICONS = {
        logging.DEBUG: "   ",
        logging.INFO: "[*]",
        FINDING: "[!]",
        logging.WARNING: "[!]",
        logging.ERROR: "[✗]",
        logging.CRITICAL: "[✗]",
    }
    RESET = "\033[0m"

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        icon = self.ICONS.get(record.levelno, "   ")
        msg = record.getMessage()

        # Add scanner context if present
        scanner = getattr(record, "scanner", "")
        prefix = f"[{scanner}] " if scanner else ""

        if self.use_color:
            color = self.COLORS.get(record.levelno, "")
            return f"  {color}{icon}{self.RESET} {prefix}{msg}"
        else:
            return f"  {icon} {prefix}{msg}"


# ── JSON formatter for structured logging ────────────────────────────

class JSONFormatter(logging.Formatter):
    """Outputs each log record as a JSON line (for SIEM ingestion)."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Add extra fields
        for key in ("scanner", "target", "finding_severity", "finding_title"):
            val = getattr(record, key, None)
            if val:
                log_entry[key] = val
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry, default=str)


# ── Logger factory ───────────────────────────────────────────────────

_configured = False


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_output: bool = False,
    use_color: bool = True,
):
    """Configure the root SecProbe logger. Call once at startup."""
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger("secprobe")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG)
    if json_output:
        console.setFormatter(JSONFormatter())
    else:
        console.setFormatter(ColorFormatter(use_color=use_color))
    root.addHandler(console)

    # File handler (rotating, 10 MB, 5 backups)
    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(file_handler)


def get_logger(name: str = "secprobe") -> logging.Logger:
    """Get a named logger under the secprobe namespace."""
    if not name.startswith("secprobe"):
        name = f"secprobe.{name}"
    return logging.getLogger(name)


class ScannerLogAdapter(logging.LoggerAdapter):
    """Adds scanner context to every log message automatically."""

    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {})
        kwargs["extra"]["scanner"] = self.extra.get("scanner", "")
        return msg, kwargs
