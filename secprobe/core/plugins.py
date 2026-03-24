"""
Plugin Architecture — Hook-based extensible plugin system.

Allows custom scanners, reporters, transport layers, and middleware
to be loaded dynamically. Surpasses Burp's BApp store model by
providing a Pythonic, type-safe plugin API.

Plugin Types:
  - ScannerPlugin: Custom vulnerability scanners
  - ReporterPlugin: Custom output formats
  - TransportPlugin: Custom HTTP transports
  - MiddlewarePlugin: Request/response interceptors (pre/post hooks)

Discovery:
  - File-based: ~/.secprobe/plugins/*.py
  - Directory-based: ~/.secprobe/plugins/my_plugin/
  - Entry-point based: secprobe.plugins entry_points in pip packages
  - CLI: --plugin /path/to/plugin.py
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional


# ── Plugin Types ─────────────────────────────────────────────────────

class PluginType(Enum):
    SCANNER = "scanner"
    REPORTER = "reporter"
    TRANSPORT = "transport"
    MIDDLEWARE = "middleware"


class HookPoint(Enum):
    """Named hook points in the scan pipeline."""
    PRE_SCAN = "pre_scan"
    POST_SCAN = "post_scan"
    PRE_REQUEST = "pre_request"
    POST_RESPONSE = "post_response"
    PRE_REPORT = "pre_report"
    POST_REPORT = "post_report"
    ON_FINDING = "on_finding"
    ON_ERROR = "on_error"
    PRE_CRAWL = "pre_crawl"
    POST_CRAWL = "post_crawl"


# ── Plugin Metadata ──────────────────────────────────────────────────

@dataclass
class PluginMetadata:
    """Metadata describing a plugin."""
    name: str
    version: str
    author: str = ""
    description: str = ""
    plugin_type: PluginType = PluginType.SCANNER
    hooks: list[HookPoint] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    min_secprobe_version: str = "4.0.0"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "plugin_type": self.plugin_type.value,
            "hooks": [h.value for h in self.hooks],
            "dependencies": self.dependencies,
            "tags": self.tags,
        }


# ── Base Plugin Classes ──────────────────────────────────────────────

class BasePlugin(ABC):
    """Base class for all plugins."""

    metadata: PluginMetadata

    @abstractmethod
    def initialize(self, context: dict) -> None:
        """Called when the plugin is loaded. Receives scan context."""
        ...

    def cleanup(self) -> None:
        """Called when the plugin is unloaded."""
        pass


class ScannerPlugin(BasePlugin):
    """Plugin that adds a custom scanner."""

    @abstractmethod
    def scan(self, target: str, config: dict) -> list[dict]:
        """
        Execute the scanner.

        Returns list of finding dicts with keys:
            title, severity, description, recommendation, evidence, cwe
        """
        ...


class ReporterPlugin(BasePlugin):
    """Plugin that adds a custom report format."""

    @abstractmethod
    def generate(self, results: list[dict], target: str, output_file: Optional[str] = None) -> str:
        """Generate a report from scan results."""
        ...


class TransportPlugin(BasePlugin):
    """Plugin that provides a custom HTTP transport."""

    @abstractmethod
    def request(self, method: str, url: str, **kwargs) -> Any:
        """Make an HTTP request using custom transport."""
        ...


class MiddlewarePlugin(BasePlugin):
    """Plugin that intercepts and can modify requests/responses."""

    def on_request(self, method: str, url: str, headers: dict, body: Any) -> tuple[str, str, dict, Any]:
        """Called before each request. Return modified (method, url, headers, body)."""
        return method, url, headers, body

    def on_response(self, url: str, status: int, headers: dict, body: str) -> tuple[int, dict, str]:
        """Called after each response. Return modified (status, headers, body)."""
        return status, headers, body

    def on_finding(self, finding: dict) -> Optional[dict]:
        """Called when a finding is detected. Return None to suppress."""
        return finding


# ── Plugin Manager ───────────────────────────────────────────────────

class PluginManager:
    """
    Central plugin registry and lifecycle manager.

    Usage:
        manager = PluginManager()
        manager.discover()  # Find plugins in default locations
        manager.load_file("/path/to/my_plugin.py")  # Load specific plugin
        manager.initialize_all({"target": "example.com"})

        # Get plugins by type
        for scanner in manager.get_scanners():
            results = scanner.scan(target, config)

        # Fire hooks
        manager.fire_hook(HookPoint.ON_FINDING, finding=finding_dict)
    """

    def __init__(self):
        self._plugins: dict[str, BasePlugin] = {}
        self._hooks: dict[HookPoint, list[Callable]] = {hp: [] for hp in HookPoint}
        self._load_errors: list[dict] = []

    @property
    def plugins(self) -> dict[str, BasePlugin]:
        return dict(self._plugins)

    @property
    def load_errors(self) -> list[dict]:
        return list(self._load_errors)

    def discover(self) -> int:
        """
        Discover plugins from default locations.

        Searches:
            1. ~/.secprobe/plugins/
            2. ./secprobe_plugins/
            3. secprobe.plugins entry_points

        Returns count of discovered plugins.
        """
        count = 0

        # User plugin directory
        user_dir = Path.home() / ".secprobe" / "plugins"
        if user_dir.exists():
            count += self._load_directory(user_dir)

        # Local project plugin directory
        local_dir = Path.cwd() / "secprobe_plugins"
        if local_dir.exists():
            count += self._load_directory(local_dir)

        # Entry points (pip-installed plugins)
        count += self._load_entry_points()

        return count

    def _load_directory(self, directory: Path) -> int:
        """Load all plugins from a directory."""
        count = 0
        for item in directory.iterdir():
            try:
                if item.suffix == ".py" and not item.name.startswith("_"):
                    self.load_file(str(item))
                    count += 1
                elif item.is_dir() and (item / "__init__.py").exists():
                    self.load_file(str(item / "__init__.py"))
                    count += 1
            except Exception as e:
                self._load_errors.append({
                    "path": str(item),
                    "error": str(e),
                })
        return count

    def _load_entry_points(self) -> int:
        """Load plugins from pip entry_points."""
        count = 0
        try:
            if sys.version_info >= (3, 10):
                from importlib.metadata import entry_points
                eps = entry_points(group="secprobe.plugins")
            else:
                from importlib.metadata import entry_points
                all_eps = entry_points()
                eps = all_eps.get("secprobe.plugins", [])

            for ep in eps:
                try:
                    plugin_cls = ep.load()
                    if inspect.isclass(plugin_cls) and issubclass(plugin_cls, BasePlugin):
                        plugin = plugin_cls()
                        self._register_plugin(plugin)
                        count += 1
                except Exception as e:
                    self._load_errors.append({
                        "entry_point": ep.name,
                        "error": str(e),
                    })
        except Exception:
            pass
        return count

    def load_file(self, filepath: str) -> BasePlugin:
        """Load a plugin from a Python file."""
        filepath = os.path.abspath(filepath)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Plugin file not found: {filepath}")

        # Create a unique module name
        module_name = f"secprobe_plugin_{Path(filepath).stem}"

        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load plugin from: {filepath}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Find plugin classes in the module
        plugin_found = False
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, BasePlugin) and obj is not BasePlugin
                    and obj not in (ScannerPlugin, ReporterPlugin, TransportPlugin, MiddlewarePlugin)):
                plugin = obj()
                self._register_plugin(plugin)
                plugin_found = True

        if not plugin_found:
            raise ValueError(f"No plugin classes found in {filepath}")

        return plugin

    def _register_plugin(self, plugin: BasePlugin):
        """Register a plugin and its hooks."""
        meta = plugin.metadata
        self._plugins[meta.name] = plugin

        # Register hooks
        for hook_point in meta.hooks:
            handler = getattr(plugin, hook_point.value, None)
            if handler and callable(handler):
                self._hooks[hook_point].append(handler)
            elif isinstance(plugin, MiddlewarePlugin):
                # Auto-register middleware hooks
                hook_map = {
                    HookPoint.PRE_REQUEST: plugin.on_request,
                    HookPoint.POST_RESPONSE: plugin.on_response,
                    HookPoint.ON_FINDING: plugin.on_finding,
                }
                if hook_point in hook_map:
                    self._hooks[hook_point].append(hook_map[hook_point])

    def unload(self, plugin_name: str):
        """Unload a plugin."""
        if plugin_name in self._plugins:
            plugin = self._plugins[plugin_name]
            plugin.cleanup()

            # Remove hooks
            for hp in HookPoint:
                self._hooks[hp] = [
                    h for h in self._hooks[hp]
                    if not (hasattr(h, '__self__') and h.__self__ is plugin)
                ]

            del self._plugins[plugin_name]

    def initialize_all(self, context: dict):
        """Initialize all loaded plugins with the scan context."""
        for name, plugin in self._plugins.items():
            try:
                plugin.initialize(context)
            except Exception as e:
                self._load_errors.append({
                    "plugin": name,
                    "error": f"Initialization failed: {e}",
                })

    def fire_hook(self, hook_point: HookPoint, **kwargs) -> list[Any]:
        """Fire all handlers registered for a hook point."""
        results = []
        for handler in self._hooks.get(hook_point, []):
            try:
                result = handler(**kwargs)
                results.append(result)
            except Exception:
                pass
        return results

    def get_scanners(self) -> list[ScannerPlugin]:
        """Get all loaded scanner plugins."""
        return [p for p in self._plugins.values() if isinstance(p, ScannerPlugin)]

    def get_reporters(self) -> list[ReporterPlugin]:
        """Get all loaded reporter plugins."""
        return [p for p in self._plugins.values() if isinstance(p, ReporterPlugin)]

    def get_middleware(self) -> list[MiddlewarePlugin]:
        """Get all loaded middleware plugins."""
        return [p for p in self._plugins.values() if isinstance(p, MiddlewarePlugin)]

    def list_plugins(self) -> list[dict]:
        """List all loaded plugins with metadata."""
        return [p.metadata.to_dict() for p in self._plugins.values()]
