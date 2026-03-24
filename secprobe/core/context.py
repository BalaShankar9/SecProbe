"""
Scan Context — Dependency injection container for shared scan services.

All scanners receive a ScanContext instead of creating their own
HTTP sessions, auth handlers, etc. This ensures:
  - One shared HTTPClient with connection pooling and rate limiting
  - Auth headers/cookies applied to every request automatically
  - WAF detection results available to all scanners
  - Crawler results (attack surface) consumed by injection scanners
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from secprobe.core.http_client import HTTPClient
    from secprobe.core.auth import AuthHandler
    from secprobe.core.waf import WAFDetector
    from secprobe.core.crawler import AttackSurface
    from secprobe.core.oob_server import CallbackServer


@dataclass
class ScanContext:
    """
    Dependency injection container passed to every scanner.

    Usage:
        ctx = ScanContext(http_client=client)
        scanner = SQLiScanner(config, ctx)
        scanner.run()
    """

    http_client: HTTPClient
    auth_handler: Optional[AuthHandler] = None
    waf_detector: Optional[WAFDetector] = None
    attack_surface: Optional[AttackSurface] = None
    oob_server: Optional[CallbackServer] = None

    # Runtime state populated during scanning
    waf_name: Optional[str] = None
    target_url: str = ""
    discovered_urls: list[str] = field(default_factory=list)
    discovered_forms: list[dict] = field(default_factory=list)
    discovered_params: list[str] = field(default_factory=list)

    def get_injection_urls(self) -> list[str]:
        """Return URLs with parameters suitable for injection testing."""
        urls = []
        if self.attack_surface:
            for endpoint in self.attack_surface.endpoints:
                if endpoint.params:
                    urls.append(endpoint.url)
            for url in self.attack_surface.urls:
                if "?" in url and url not in urls:
                    urls.append(url)
        urls.extend(self.discovered_urls)
        return list(dict.fromkeys(urls))  # dedupe preserving order

    def get_injectable_forms(self) -> list[dict]:
        """Return forms discovered by crawler for POST injection testing."""
        forms = []
        if self.attack_surface:
            for form in self.attack_surface.forms:
                forms.append({
                    "action": form.action,
                    "method": form.method,
                    "fields": {f: "" for f in form.field_names},
                })
        forms.extend(self.discovered_forms)
        return forms

    def get_crawled_urls(self) -> list[str]:
        """Return all discovered URLs for scanning."""
        if self.attack_surface:
            return list(self.attack_surface.urls)
        return []
