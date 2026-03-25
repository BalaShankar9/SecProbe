"""
API Path Discoverer.

Brute-forces common API paths against a target and auto-detects
Swagger/OpenAPI specifications to enumerate endpoints.

Usage:
    discoverer = APIDiscoverer()
    paths = discoverer.get_probe_paths()       # 500+ common API paths
    swagger_urls = discoverer.get_swagger_paths()  # known spec locations
    endpoints = discoverer.parse_openapi(spec)   # parse a spec dict
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from secprobe.core.logger import get_logger

log = get_logger("api_discoverer")

# HTTP methods recognized in OpenAPI specs
_OPENAPI_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}

# Status codes that indicate something interesting lives at a path
_INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503}

# Well-known Swagger / OpenAPI spec locations
_SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger",
    "/swagger/",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi",
    "/openapi/",
    "/openapi/v3",
    "/api-docs",
    "/api-docs/",
    "/api-docs/swagger.json",
    "/api-docs/swagger.yaml",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/docs/",
    "/docs/api",
    "/redoc",
    "/redoc/",
    "/api/docs",
    "/api/documentation",
    "/api/swagger",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/openapi",
    "/api/redoc",
    "/api/spec",
    "/api/schema",
    "/_doc",
    "/_docs",
    "/apidocs",
    "/apidocs/",
]


@dataclass
class DiscoveredAPI:
    """An API endpoint discovered through brute-force probing or spec parsing."""

    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    source: str = ""  # e.g. "probe", "openapi", "swagger"
    status_code: int = 0


class APIDiscoverer:
    """Discovers API endpoints by probing common paths and parsing OpenAPI specs."""

    def __init__(self) -> None:
        self._probe_paths: list[str] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_probe_paths(self) -> list[str]:
        """Return the full list of API paths to probe.

        Loads from ``secprobe/payloads/api_paths.txt`` on first call and
        caches the result.
        """
        if self._probe_paths is not None:
            return self._probe_paths

        wordlist = Path(__file__).resolve().parent.parent / "payloads" / "api_paths.txt"
        if not wordlist.exists():
            log.warning("api_paths.txt not found at %s", wordlist)
            self._probe_paths = []
            return self._probe_paths

        paths: list[str] = []
        with open(wordlist, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                # Skip empty lines and comments
                if stripped and not stripped.startswith("#"):
                    paths.append(stripped)

        self._probe_paths = paths
        log.info("Loaded %d probe paths from %s", len(paths), wordlist)
        return self._probe_paths

    def get_swagger_paths(self) -> list[str]:
        """Return well-known Swagger / OpenAPI spec locations."""
        return list(_SWAGGER_PATHS)

    @staticmethod
    def is_interesting_status(code: int) -> bool:
        """Return True if *code* indicates the path exists or is protected."""
        return code in _INTERESTING_STATUSES

    @staticmethod
    def parse_openapi(spec: dict) -> List[DiscoveredAPI]:
        """Parse an OpenAPI / Swagger spec dict and return discovered endpoints.

        Each path + method combination produces one :class:`DiscoveredAPI`.
        """
        paths = spec.get("paths")
        if not paths:
            return []

        endpoints: list[DiscoveredAPI] = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, _detail in methods.items():
                if method.lower() not in _OPENAPI_METHODS:
                    continue
                endpoints.append(
                    DiscoveredAPI(
                        url=path,
                        method=method.upper(),
                        source="openapi",
                    )
                )

        return endpoints
