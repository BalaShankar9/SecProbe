"""
Custom exception hierarchy for SecProbe.

A proper exception tree lets callers handle errors precisely:
    SecProbeError
    ├── TargetUnreachableError
    ├── AuthenticationError
    ├── WAFBlockedError
    ├── ScannerError
    │   ├── PayloadLoadError
    │   └── ScanTimeoutError
    ├── CrawlerError
    └── TemplateError
        ├── TemplateParseError
        └── TemplateExecutionError
"""


class SecProbeError(Exception):
    """Root exception for all SecProbe errors."""

    def __init__(self, message: str = "", *, detail: str = ""):
        self.detail = detail
        super().__init__(message)


class TargetUnreachableError(SecProbeError):
    """Target host cannot be reached (DNS failure, connection refused, timeout)."""

    def __init__(self, target: str, reason: str = ""):
        self.target = target
        super().__init__(
            f"Target unreachable: {target}" + (f" — {reason}" if reason else ""),
            detail=reason,
        )


class AuthenticationError(SecProbeError):
    """Authentication to the target failed."""

    def __init__(self, message: str = "Authentication failed", *, url: str = ""):
        self.url = url
        super().__init__(message)


class WAFBlockedError(SecProbeError):
    """Request was blocked by a Web Application Firewall."""

    def __init__(self, waf_name: str = "Unknown", *, status_code: int = 0, url: str = ""):
        self.waf_name = waf_name
        self.status_code = status_code
        self.url = url
        super().__init__(f"Blocked by WAF: {waf_name} (HTTP {status_code})")


class ScannerError(SecProbeError):
    """Error within a scanner module."""

    def __init__(self, scanner_name: str, message: str):
        self.scanner_name = scanner_name
        super().__init__(f"[{scanner_name}] {message}")


class PayloadLoadError(ScannerError):
    """Could not load payload file."""

    def __init__(self, scanner_name: str, path: str):
        self.path = path
        super().__init__(scanner_name, f"Cannot load payload file: {path}")


class ScanTimeoutError(ScannerError):
    """Scanner exceeded its time budget."""

    def __init__(self, scanner_name: str, elapsed: float, limit: float):
        self.elapsed = elapsed
        self.limit = limit
        super().__init__(scanner_name, f"Timed out after {elapsed:.1f}s (limit: {limit:.1f}s)")


class CrawlerError(SecProbeError):
    """Error during web crawling."""
    pass


class TemplateError(SecProbeError):
    """Error in the vulnerability template engine."""
    pass


class TemplateParseError(TemplateError):
    """Template YAML could not be parsed."""

    def __init__(self, path: str, reason: str = ""):
        self.path = path
        super().__init__(f"Invalid template {path}: {reason}")


class TemplateExecutionError(TemplateError):
    """Template check failed during execution."""

    def __init__(self, template_id: str, reason: str = ""):
        self.template_id = template_id
        super().__init__(f"Template execution failed [{template_id}]: {reason}")
