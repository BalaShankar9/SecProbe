"""
Tests for v4.0 engines: StealthClient, BrowserEngine, OOB, ScanState, SmartCrawler.

These test the engine infrastructure — NOT live targets.
We verify initialization, configuration, interfaces, and data models.
"""

import os
import json
import sqlite3
import tempfile
import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock
from urllib.parse import urlparse

import pytest


# ═══════════════════════════════════════════════════════════════════════
# StealthClient Tests
# ═══════════════════════════════════════════════════════════════════════

class TestStealthConfig:
    """Test StealthConfig dataclass."""

    def test_default_config(self):
        from secprobe.core.stealth_client import StealthConfig
        cfg = StealthConfig()
        assert cfg.timeout == 15
        assert cfg.max_retries == 3
        assert cfg.proxy is None
        assert cfg.verify_ssl is False
        assert cfg.follow_redirects is True
        assert cfg.rate_limit == 0.0
        assert cfg.rotate_profile is True
        assert cfg.impersonate == "chrome124"

    def test_custom_config(self):
        from secprobe.core.stealth_client import StealthConfig
        cfg = StealthConfig(
            timeout=30,
            proxy="http://127.0.0.1:8080",
            impersonate="firefox124",
            rate_limit=0.5,
        )
        assert cfg.timeout == 30
        assert cfg.proxy == "http://127.0.0.1:8080"
        assert cfg.impersonate == "firefox124"
        assert cfg.rate_limit == 0.5


class TestBrowserProfiles:
    """Test browser profile definitions."""

    def test_profiles_exist(self):
        from secprobe.core.stealth_client import BROWSER_PROFILES
        assert len(BROWSER_PROFILES) >= 6

    def test_profile_fields(self):
        from secprobe.core.stealth_client import BROWSER_PROFILES
        for profile in BROWSER_PROFILES:
            assert profile.name, f"Profile missing name"
            assert profile.impersonate, f"Profile {profile.name} missing impersonate"
            assert profile.user_agent, f"Profile {profile.name} missing user_agent"
            # Firefox and Safari don't use Client Hints — sec_ch_ua is empty
            if "Firefox" not in profile.name and "Safari" not in profile.name:
                assert profile.sec_ch_ua, f"Profile {profile.name} missing sec_ch_ua"

    def test_chrome_profile(self):
        from secprobe.core.stealth_client import BROWSER_PROFILES
        chrome = [p for p in BROWSER_PROFILES if "Chrome 124" in p.name]
        assert chrome, "Chrome 124 profile not found"
        assert "chrome" in chrome[0].impersonate

    def test_firefox_profile(self):
        from secprobe.core.stealth_client import BROWSER_PROFILES
        ff = [p for p in BROWSER_PROFILES if "Firefox" in p.name]
        assert ff, "Firefox profile not found"


class TestStealthClientInit:
    """Test StealthClient initialization."""

    def test_default_init(self):
        from secprobe.core.stealth_client import StealthClient
        client = StealthClient()
        assert client.config.impersonate == "chrome124"
        assert client._current_profile is not None
        assert client._session is not None

    def test_profile_selection(self):
        from secprobe.core.stealth_client import StealthClient, StealthConfig
        cfg = StealthConfig(profile="firefox")
        client = StealthClient(cfg)
        assert "Firefox" in client._current_profile.name

    def test_interface_methods(self):
        """StealthClient must have the same interface as HTTPClient."""
        from secprobe.core.stealth_client import StealthClient
        client = StealthClient()
        assert hasattr(client, "get")
        assert hasattr(client, "post")
        assert hasattr(client, "put")
        assert hasattr(client, "options")
        assert hasattr(client, "head")
        assert hasattr(client, "request")
        assert hasattr(client, "set_waf_detector")
        assert hasattr(client, "close")

    def test_context_manager(self):
        from secprobe.core.stealth_client import StealthClient
        with StealthClient() as client:
            assert client._session is not None


# ═══════════════════════════════════════════════════════════════════════
# BrowserEngine Tests
# ═══════════════════════════════════════════════════════════════════════

class TestBrowserConfig:
    """Test BrowserConfig dataclass."""

    def test_default_config(self):
        from secprobe.core.browser import BrowserConfig
        cfg = BrowserConfig()
        assert cfg.headless is True
        assert cfg.timeout == 30000
        assert cfg.viewport_width == 1920
        assert cfg.viewport_height == 1080
        assert cfg.locale == "en-US"
        assert cfg.intercept_network is True
        assert cfg.capture_console is True

    def test_custom_config(self):
        from secprobe.core.browser import BrowserConfig
        cfg = BrowserConfig(
            headless=False,
            proxy="http://127.0.0.1:8080",
            timeout=60000,
        )
        assert cfg.headless is False
        assert cfg.proxy == "http://127.0.0.1:8080"
        assert cfg.timeout == 60000


class TestPageResult:
    """Test PageResult dataclass."""

    def test_default_result(self):
        from secprobe.core.browser import PageResult
        r = PageResult(url="https://test.com", final_url="https://test.com",
                       status_code=200, html="<html>test</html>",
                       title="Test", text="test")
        assert r.url == "https://test.com"
        assert r.status_code == 200
        assert r.network_requests == []
        assert r.forms == []
        assert r.links == []
        assert r.api_endpoints == []


class TestNetworkRequest:
    """Test NetworkRequest dataclass."""

    def test_default(self):
        from secprobe.core.browser import NetworkRequest
        nr = NetworkRequest(
            url="https://test.com/api/data",
            method="GET",
            headers={"Accept": "application/json"},
        )
        assert nr.resource_type == ""
        assert nr.status == 0
        assert nr.post_data is None


class TestBrowserEngineInit:
    """Test BrowserEngine initialization (no actual browser launch)."""

    def test_default_init(self):
        from secprobe.core.browser import BrowserEngine
        engine = BrowserEngine()
        assert engine.config.headless is True
        assert not engine._started

    def test_context_manager_interface(self):
        from secprobe.core.browser import BrowserEngine
        engine = BrowserEngine()
        assert hasattr(engine, "__enter__")
        assert hasattr(engine, "__exit__")
        assert hasattr(engine, "start")
        assert hasattr(engine, "stop")
        assert hasattr(engine, "render_page")
        assert hasattr(engine, "solve_challenge")
        assert hasattr(engine, "discover_spa_routes")
        assert hasattr(engine, "capture_evidence")
        assert hasattr(engine, "extract_cookies")
        assert hasattr(engine, "inject_cookies")


# ═══════════════════════════════════════════════════════════════════════
# OOB CallbackServer Tests
# ═══════════════════════════════════════════════════════════════════════

class TestTokenRegistry:
    """Test the OOB token registry."""

    def test_generate_token(self):
        from secprobe.core.oob_server import TokenRegistry
        reg = TokenRegistry()
        token = reg.generate_token(
            scanner="sqli",
            target_url="https://target.com/login",
            parameter="username",
            payload_type="sqli_blind",
            payload="' OR 1=1--",
        )
        assert len(token) == 24
        assert reg.pending_count == 1

    def test_resolve_token(self):
        from secprobe.core.oob_server import TokenRegistry
        reg = TokenRegistry()
        token = reg.generate_token("sqli", "https://t.com", "user", "blind", "payload")
        resolved = reg.resolve_token(token)
        assert resolved is not None
        assert resolved.scanner == "sqli"
        assert resolved.target_url == "https://t.com"
        assert resolved.parameter == "user"

    def test_resolve_unknown_token(self):
        from secprobe.core.oob_server import TokenRegistry
        reg = TokenRegistry()
        assert reg.resolve_token("unknown_token_12345678") is None

    def test_token_expiry(self):
        from secprobe.core.oob_server import TokenRegistry
        reg = TokenRegistry()
        token = reg.generate_token("test", "url", "p", "t", "pl", ttl=0)
        time.sleep(0.1)
        assert reg.resolve_token(token) is None

    def test_record_callback(self):
        from secprobe.core.oob_server import TokenRegistry, OOBCallback
        reg = TokenRegistry()
        cb = OOBCallback(
            token="test123", callback_type="http",
            source_ip="1.2.3.4", source_port=12345,
            timestamp=time.time(), method="GET",
            path="/callback/test123", headers={},
        )
        reg.record_callback(cb)
        assert reg.callback_count == 1

    def test_callback_listener(self):
        from secprobe.core.oob_server import TokenRegistry, OOBCallback
        reg = TokenRegistry()
        received = []
        reg.on_callback(lambda cb: received.append(cb))
        cb = OOBCallback(
            token="t", callback_type="http",
            source_ip="1.1.1.1", source_port=1,
            timestamp=0, method="GET", path="/", headers={},
        )
        reg.record_callback(cb)
        assert len(received) == 1

    def test_cleanup_expired(self):
        from secprobe.core.oob_server import TokenRegistry
        reg = TokenRegistry()
        reg.generate_token("t", "u", "p", "t", "pl", ttl=0)
        reg.generate_token("t", "u", "p", "t", "pl", ttl=300)
        time.sleep(0.1)
        reg.cleanup_expired()
        assert reg.pending_count == 1

    def test_get_callbacks_filtered(self):
        from secprobe.core.oob_server import TokenRegistry, OOBCallback
        reg = TokenRegistry()
        reg.record_callback(OOBCallback(
            token="a", callback_type="http", source_ip="1.1.1.1",
            source_port=1, timestamp=0, method="GET", path="/",
            headers={}, scanner="sqli", target_url="https://a.com",
        ))
        reg.record_callback(OOBCallback(
            token="b", callback_type="http", source_ip="1.1.1.1",
            source_port=1, timestamp=0, method="GET", path="/",
            headers={}, scanner="xxe", target_url="https://b.com",
        ))
        assert len(reg.get_callbacks(scanner="sqli")) == 1
        assert len(reg.get_callbacks(target_url="https://b.com")) == 1


class TestCallbackServer:
    """Test the CallbackServer orchestrator."""

    def test_init(self):
        from secprobe.core.oob_server import CallbackServer
        server = CallbackServer(http_port=19876, enable_dns=False)
        assert server.http_port == 19876
        assert server.registry is not None
        assert server.callback_host  # Should auto-detect

    def test_generate_callback_url(self):
        from secprobe.core.oob_server import CallbackServer
        server = CallbackServer(http_port=9999, callback_host="10.0.0.1",
                                enable_dns=False)
        token = server.generate_token("sqli", "https://t.com", "id", "blind", "pay")
        url = server.get_callback_url(token)
        assert url.startswith("http://10.0.0.1:9999/callback/")
        assert token in url

    def test_generate_callback_domain(self):
        from secprobe.core.oob_server import CallbackServer
        server = CallbackServer(callback_host="attacker.com", enable_dns=False)
        token = server.generate_token("xxe", "url", "p", "t", "pl")
        domain = server.get_callback_domain(token)
        assert domain.endswith(".attacker.com")
        assert token in domain

    def test_generate_payloads(self):
        from secprobe.core.oob_server import CallbackServer
        server = CallbackServer(callback_host="10.0.0.1", http_port=8888,
                                enable_dns=False)
        payloads = server.generate_payloads("sqli", "https://t.com", "id")
        assert "sqli_mysql_load" in payloads
        assert "sqli_mssql_xp" in payloads
        assert "xxe_external_entity" in payloads
        assert "ssrf_http" in payloads
        assert "rce_curl" in payloads
        assert "ssti_jinja2" in payloads
        assert "10.0.0.1" in payloads["ssrf_http"]

    def test_start_stop(self):
        from secprobe.core.oob_server import CallbackServer
        server = CallbackServer(http_port=19877, enable_dns=False)
        server.start()
        assert server.is_running
        server.stop()
        assert not server.is_running

    def test_context_manager(self):
        from secprobe.core.oob_server import CallbackServer
        with CallbackServer(http_port=19878, enable_dns=False) as server:
            assert server.is_running
        assert not server.is_running


class TestOOBDataModels:
    """Test OOB data models."""

    def test_oob_token(self):
        from secprobe.core.oob_server import OOBToken
        tok = OOBToken(
            token="abc123",
            scanner="sqli",
            target_url="https://t.com",
            parameter="id",
            payload_type="sqli_blind",
            payload="' OR 1=1",
        )
        assert tok.ttl == 300
        assert tok.created_at > 0

    def test_oob_callback(self):
        from secprobe.core.oob_server import OOBCallback
        cb = OOBCallback(
            token="abc", callback_type="http",
            source_ip="10.0.0.1", source_port=12345,
            timestamp=time.time(), method="GET",
            path="/callback/abc", headers={"Host": "attacker.com"},
            scanner="sqli", target_url="https://t.com",
            parameter="id", payload_type="sqli_blind",
        )
        assert cb.callback_type == "http"
        assert cb.scanner == "sqli"


# ═══════════════════════════════════════════════════════════════════════
# ScanState Tests
# ═══════════════════════════════════════════════════════════════════════

class TestScanState:
    """Test SQLite-backed scan state."""

    @pytest.fixture
    def state(self, tmp_path):
        from secprobe.core.state import ScanState
        s = ScanState("https://test.com", db_dir=str(tmp_path))
        s.start_session("https://test.com")
        return s

    def test_db_creation(self, state):
        assert os.path.exists(state.db_path)

    def test_session_start(self, state):
        assert state.session_id
        assert len(state.session_id) == 16

    def test_coverage_tracking(self, state):
        state.mark_pending("https://test.com/login", "sqli")
        assert not state.is_scanned("https://test.com/login", "sqli")

        state.mark_running("https://test.com/login", "sqli")
        assert not state.is_scanned("https://test.com/login", "sqli")

        state.mark_completed("https://test.com/login", "sqli", findings_count=2)
        assert state.is_scanned("https://test.com/login", "sqli")

    def test_pending_scans(self, state):
        state.mark_pending("https://test.com/a", "sqli")
        state.mark_pending("https://test.com/b", "xss")
        state.mark_completed("https://test.com/a", "sqli")

        pending = state.get_pending_scans()
        assert len(pending) == 1
        assert pending[0] == ("https://test.com/b", "xss")

    def test_coverage_stats(self, state):
        state.mark_pending("https://test.com/a", "sqli")
        state.mark_pending("https://test.com/b", "xss")
        state.mark_completed("https://test.com/a", "sqli")
        state.mark_error("https://test.com/b", "xss")

        stats = state.get_coverage_stats()
        assert stats["total"] == 2
        assert stats["completed"] == 1
        assert stats["errors"] == 1

    def test_url_tracking(self, state):
        state.add_url("https://test.com/login", source="crawl")
        state.add_url("https://test.com/api/data", source="browser")

        urls = state.get_new_urls()
        assert len(urls) == 2

    def test_unscanned_urls(self, state):
        state.add_url("https://test.com/a")
        state.add_url("https://test.com/b")
        # mark_completed is UPDATE-only, so mark_pending first
        state.mark_pending("https://test.com/a", "sqli")
        state.mark_running("https://test.com/a", "sqli")
        state.mark_completed("https://test.com/a", "sqli")

        unscanned = state.get_unscanned_urls("sqli")
        assert "https://test.com/b" in unscanned
        assert "https://test.com/a" not in unscanned

    def test_finding_storage(self, state):
        finding = {
            "scanner": "sqli",
            "url": "https://test.com/login",
            "severity": "CRITICAL",
            "title": "SQL Injection in login",
            "description": "Test finding",
        }
        is_new = state.save_finding(finding)
        assert is_new

        # Duplicate should return False
        is_dup = state.save_finding(finding)
        assert not is_dup

    def test_get_findings(self, state):
        state.save_finding({"scanner": "sqli", "url": "u", "severity": "HIGH", "title": "A"})
        state.save_finding({"scanner": "xss", "url": "u", "severity": "MEDIUM", "title": "B"})

        all_f = state.get_findings()
        assert len(all_f) == 2

        sqli_f = state.get_findings(scanner="sqli")
        assert len(sqli_f) == 1

    def test_session_finish(self, state):
        state.mark_pending("u", "s")
        state.mark_completed("u", "s")
        state.save_finding({"scanner": "s", "url": "u", "severity": "HIGH", "title": "T"})

        state.finish_session()

        history = state.get_session_history()
        assert len(history) >= 1
        assert history[0]["status"] == "completed"
        assert history[0]["findings_count"] == 1

    def test_resume_session(self, tmp_path):
        from secprobe.core.state import ScanState
        # Create and interrupt a session
        s1 = ScanState("https://test.com", db_dir=str(tmp_path))
        sid = s1.start_session("https://test.com")
        s1.mark_pending("u1", "sqli")
        # Don't finish — simulate interruption

        # Resume
        s2 = ScanState("https://test.com", db_dir=str(tmp_path))
        resumed = s2.resume_session()
        assert resumed == sid
        pending = s2.get_pending_scans()
        assert len(pending) == 1

    def test_scan_summary(self, state):
        # Full lifecycle: pending → running → completed
        state.mark_pending("u1", "sqli")
        state.mark_running("u1", "sqli")
        state.mark_completed("u1", "sqli", 1)

        state.mark_pending("u2", "xss")
        state.mark_running("u2", "xss")
        state.mark_completed("u2", "xss", 0)

        state.save_finding({"scanner": "sqli", "url": "u1", "severity": "HIGH", "title": "T"})

        summary = state.get_scan_summary()
        assert summary["target"] == "https://test.com"
        assert summary["coverage"]["completed"] == 2
        assert "HIGH" in summary["findings_by_severity"]


# ═══════════════════════════════════════════════════════════════════════
# SmartCrawler Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSmartCrawlConfig:
    """Test SmartCrawlConfig defaults."""

    def test_defaults(self):
        from secprobe.core.smart_crawler import SmartCrawlConfig
        cfg = SmartCrawlConfig()
        assert cfg.max_depth == 3
        assert cfg.max_pages == 200
        assert cfg.use_browser is True
        assert cfg.spa_detection is True
        assert cfg.force_browser is False
        assert cfg.intercept_network is True


class TestSPADetection:
    """Test SPA detection heuristics."""

    def test_react_detection(self):
        from secprobe.core.smart_crawler import SPA_PATTERN
        react_html = '<html><body><div id="root"></div><script src="/main.abc123.js"></script></body></html>'
        assert SPA_PATTERN.search(react_html)

    def test_angular_detection(self):
        from secprobe.core.smart_crawler import SPA_PATTERN
        angular_html = '<html><body><app-root ng-version="15.0"></app-root></body></html>'
        assert SPA_PATTERN.search(angular_html)

    def test_vue_detection(self):
        from secprobe.core.smart_crawler import SPA_PATTERN
        vue_html = '<html><body><div id="app"></div><script>window.__vue__=true</script></body></html>'
        assert SPA_PATTERN.search(vue_html)

    def test_nextjs_detection(self):
        from secprobe.core.smart_crawler import SPA_PATTERN
        next_html = '<html><body><div id="__next"></div><script id="__NEXT_DATA__">{}</script></body></html>'
        assert SPA_PATTERN.search(next_html)

    def test_traditional_site(self):
        from secprobe.core.smart_crawler import SPA_PATTERN
        static_html = '<html><body><h1>Welcome</h1><p>This is a regular page.</p></body></html>'
        assert not SPA_PATTERN.search(static_html)


class TestSmartCrawlerInit:
    """Test SmartCrawler initialization."""

    def test_init(self):
        from secprobe.core.smart_crawler import SmartCrawler
        mock_client = MagicMock()
        crawler = SmartCrawler(mock_client, "https://test.com")
        assert crawler.base_url == "https://test.com"
        assert crawler.browser is None
        assert not crawler.is_spa


# ═══════════════════════════════════════════════════════════════════════
# BaseScanner WAF evasion integration
# ═══════════════════════════════════════════════════════════════════════

class TestBaseScannerEvade:
    """Test the _evade_payload method added to BaseScanner."""

    def test_no_waf_returns_original(self):
        from secprobe.scanners.base import BaseScanner
        from secprobe.config import ScanConfig

        config = ScanConfig(target="https://test.com")
        config.waf_evasion = False

        class TestScanner(BaseScanner):
            name = "Test"
            def scan(self): pass

        scanner = TestScanner(config, None)
        variants = scanner._evade_payload("test payload")
        assert variants == ["test payload"]

    def test_waf_evasion_expands_payloads(self):
        from secprobe.scanners.base import BaseScanner
        from secprobe.config import ScanConfig
        from secprobe.core.context import ScanContext

        config = ScanConfig(target="https://test.com")
        config.waf_evasion = True

        mock_client = MagicMock()
        mock_waf = MagicMock()
        mock_waf.evade.return_value = ["evaded1", "evaded2", "evaded3", "evaded4"]
        mock_waf.detected_waf = None

        context = ScanContext(http_client=mock_client, waf_detector=mock_waf)

        class TestScanner(BaseScanner):
            name = "Test"
            def scan(self): pass

        scanner = TestScanner(config, context)
        variants = scanner._evade_payload("' OR 1=1--")
        assert len(variants) >= 4  # original + legacy evasion + PayloadMutator
        assert variants[0] == "' OR 1=1--"
        mock_waf.evade.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════
# Context updates
# ═══════════════════════════════════════════════════════════════════════

class TestContextOOB:
    """Test that ScanContext supports oob_server field."""

    def test_context_has_oob(self):
        from secprobe.core.context import ScanContext
        ctx = ScanContext(http_client=MagicMock())
        assert ctx.oob_server is None

    def test_context_with_oob(self):
        from secprobe.core.context import ScanContext
        mock_oob = MagicMock()
        ctx = ScanContext(http_client=MagicMock(), oob_server=mock_oob)
        assert ctx.oob_server is mock_oob


# ═══════════════════════════════════════════════════════════════════════
# CLI argument parsing
# ═══════════════════════════════════════════════════════════════════════

class TestCLIArgs:
    """Test that new v4 CLI arguments are parsed correctly."""

    def test_stealth_flag(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["target.com", "--stealth"])
        assert args.stealth is True

    def test_browser_flag(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["target.com", "--browser"])
        assert args.browser is True

    def test_oob_flag(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["target.com", "--oob"])
        assert args.oob is True

    def test_oob_port(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["target.com", "--oob", "--oob-port", "9999"])
        assert args.oob_port == 9999

    def test_resume_flag(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["target.com", "--resume"])
        assert args.resume is True

    def test_impersonate(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["target.com", "--stealth", "--impersonate", "firefox124"])
        assert args.impersonate == "firefox124"

    def test_combined_v4_flags(self):
        from secprobe.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "target.com", "--stealth", "--browser", "--oob",
            "--waf-evasion", "--crawl", "-s", "sqli", "xss",
        ])
        assert args.stealth
        assert args.browser
        assert args.oob
        assert args.waf_evasion
        assert args.crawl
        assert args.scans == ["sqli", "xss"]
