"""
SecProbe v8.0 — CLI Entry Point

Enterprise security testing with advanced engines:
  - StealthClient: Browser-grade TLS impersonation (bypass Cloudflare/Akamai JA3)
  - BrowserEngine: Headless Chromium for SPA crawling & JS challenge solving
  - OOB CallbackServer: Blind injection detection (HTTP + DNS callbacks)
  - SmartCrawler: Hybrid static + browser-rendered crawling
  - ScanState: SQLite-backed resume & incremental scanning
  - WAF evasion integrated into ALL injection scanners
  - CVSS 3.1 scoring & OWASP/CWE/PCI-DSS/NIST compliance mapping
  - SARIF 2.1.0 / JUnit XML / JSON output for CI/CD pipelines
  - Intercepting proxy with Repeater & Intruder
  - Plugin architecture (scanner, reporter, transport, middleware)
  - API/GraphQL/WebSocket scanners
  - Full pipeline: Auth → WAF → Crawl → Scan → Report
  - 600-Agent Autonomous Swarm Mode (recon/audit/redteam)
"""

import argparse
import asyncio
import sys
import warnings
from datetime import datetime

from secprobe import __version__
from secprobe.config import ScanConfig
from secprobe.report import ReportGenerator
from secprobe.scanners import SCANNER_REGISTRY
from secprobe.utils import (
    print_banner,
    print_section,
    print_status,
    is_valid_target,
    normalize_url,
    Colors,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secprobe",
        description="SecProbe v8.0 — Enterprise Security Testing\n\n"
                     "Modes:\n"
                     "  Classic:  python -m secprobe target.com -s sqli xss\n"
                     "  Swarm:    python -m secprobe target.com --swarm --mode audit\n"
                     "  Redteam:  python -m secprobe target.com --swarm --mode redteam\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCAN TYPES:
  all        Run all scanners (default)
  ports      TCP port scanning
  ssl        SSL/TLS certificate & protocol analysis (Heartbleed, BEAST, POODLE, CRIME, HSTS)
  headers    HTTP security header checks
  sqli       SQL injection testing (500+ payloads, OOB blind, header/JSON injection)
  xss        Cross-Site Scripting testing (300+ payloads, OOB blind/stored)
  dirs       Directory brute-force (5000+ paths)
  dns        DNS enumeration & subdomain discovery (3000+)
  cookies    Cookie security analysis
  cors       CORS misconfiguration testing
  tech       Technology fingerprinting (YAML signatures)
  ssrf       Server-Side Request Forgery (OOB + header injection)
  ssti       Server-Side Template Injection (OOB blind)
  cmdi       OS Command Injection (OOB blind + header injection)
  redirect   Open Redirect testing
  jwt        JWT analysis (alg confusion, kid injection, x5u/x5c, embedded JWK, JWE downgrade)
  lfi        Local File Inclusion (OOB blind)
  xxe        XML External Entity (OOB blind)
  nosql      NoSQL injection
  hostheader Host Header injection
  csrf       Cross-Site Request Forgery
  smuggling  HTTP Request Smuggling
  api        REST API & OpenAPI testing (BOLA, mass assignment)
  graphql    GraphQL introspection, injection & DoS testing
  websocket  WebSocket CSWSH, injection & DoS testing
  upload     File Upload exploitation (extension bypass, polyglot, SVG XSS)
  deser      Deserialization attacks (Java, PHP, Python, .NET, Ruby)
  oauth      OAuth/OIDC misconfiguration (redirect_uri bypass, state, scope)
  race       Race Condition testing (concurrent request analysis)
  ldap       LDAP injection (error-based, boolean-based, auth bypass)
  xpath      XPath injection (error-based, boolean-based, auth bypass)
  crlf       CRLF injection (header injection, response splitting)
  hpp        HTTP Parameter Pollution (server-side, POST form)

v7.0 ADVANCED SCANNERS:
  js         JavaScript secrets, endpoints & dangerous patterns (28 secret patterns)
  cve        CVE/dependency vulnerability matching (WordPress, PHP, Apache, jQuery, etc.)
  takeover   Subdomain takeover detection (35+ cloud service fingerprints)
  domxss     DOM-based XSS source→sink analysis + active probing
  idor       IDOR/BOLA broken authorization testing (API, sequential ID, UUID)
  wafid      WAF fingerprinting & bypass intelligence (12 WAFs, rule coverage testing)
  email      Email security (SPF/DKIM/DMARC/MTA-STS/BIMI spoofing risk)
  bizlogic   Business logic flaws (rate limiting, account enum, price tampering)
  prototype  Prototype pollution (client + server side, static analysis)
  cloud      Cloud/infrastructure exposure (.git, .env, S3, Docker, K8s, source maps)
  fuzz       Smart fuzzer (boundary, format string, overflow, Unicode, type confusion)

ENTERPRISE FEATURES:
  --proxy     Route through Burp/ZAP/SOCKS proxy
  --auth      Authenticated scanning (basic:user:pass, bearer:token, cookie:name=val)
  --crawl     Spider the target before scanning
  --waf-evasion  Auto-detect WAF and apply evasion techniques
  --templates    Execute YAML vulnerability templates (nuclei-style)
  --compliance   Map findings to OWASP 2021 + PCI DSS v4.0
  --parallel     Run scanners in parallel for speed
ADVANCED v4 ENGINES:
  --stealth     Browser-grade TLS impersonation (bypass Cloudflare/Akamai JA3)
  --browser     Headless Chromium for SPA crawling & JS challenge solving
  --oob         Start OOB callback server for blind injection detection
  --resume      Resume a previously interrupted scan
v5.0 FEATURES:
  --sarif       SARIF 2.1.0 output for GitHub/GitLab/Azure DevOps
  --junit       JUnit XML output for CI test frameworks
  --fail-on     Exit non-zero on findings >= severity (critical/high/medium/low)
  --proxy-listen Start intercepting proxy on host:port
  --api-spec     Import OpenAPI/Swagger specification for API testing
  --plugin       Load external plugin file or directory
EXAMPLES:
  secprobe example.com
  secprobe example.com -s headers ssl cookies
  secprobe example.com -s sqli xss --waf-evasion --proxy http://127.0.0.1:8080
  secprobe example.com --crawl --templates --compliance -o html -f report.html
  secprobe example.com --auth basic:admin:password -s all
  secprobe example.com -s dirs --wordlist /path/to/custom.txt
  secprobe example.com -s ssrf ssti cmdi --crawl --parallel
  secprobe target.com --stealth --browser --crawl -s all
  secprobe target.com --stealth --oob -s sqli xss lfi xxe --waf-evasion
  secprobe target.com --resume  # resume interrupted scan
  secprobe target.com -o sarif -f results.sarif  # CI/CD pipeline
  secprobe target.com --fail-on high -o junit -f results.xml  # fail build on HIGH+
  secprobe target.com -s api --api-spec openapi.yaml  # API testing
  secprobe target.com -s graphql websocket  # modern app testing
  secprobe target.com --proxy-listen 127.0.0.1:8888  # intercepting proxy
        """,
    )

    parser.add_argument("target", help="Target URL, hostname, or IP address")

    parser.add_argument(
        "-s", "--scans",
        nargs="+",
        default=["all"],
        choices=list(SCANNER_REGISTRY.keys()) + ["all"],
        help="Scanner modules to run (default: all)",
    )

    scan_opts = parser.add_argument_group("Scanning options")
    scan_opts.add_argument("-p", "--ports", default="1-1024",
                           help="Port range (default: 1-1024)")
    scan_opts.add_argument("-t", "--threads", type=int, default=50,
                           help="Concurrent threads (default: 50)")
    scan_opts.add_argument("--timeout", type=int, default=10,
                           help="Request timeout in seconds (default: 10)")
    scan_opts.add_argument("--rate-limit", type=float, default=0.0,
                           help="Delay between requests in seconds (default: 0)")
    scan_opts.add_argument("--user-agent", default=None,
                           help="Custom User-Agent string")
    scan_opts.add_argument("--wordlist", default=None,
                           help="Custom wordlist file for directory scanning")
    scan_opts.add_argument("--no-redirect", action="store_true",
                           help="Do not follow HTTP redirects")

    enterprise = parser.add_argument_group("Enterprise features")
    enterprise.add_argument("--proxy", default=None,
                            help="HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    enterprise.add_argument("--auth", default=None,
                            help="Auth string: basic:user:pass | bearer:token | cookie:name=val")
    enterprise.add_argument("--crawl", action="store_true",
                            help="Spider the target to discover endpoints before scanning")
    enterprise.add_argument("--crawl-depth", type=int, default=3,
                            help="Maximum crawl depth (default: 3)")
    enterprise.add_argument("--crawl-max-pages", type=int, default=100,
                            help="Maximum pages to crawl (default: 100)")
    enterprise.add_argument("--waf-evasion", action="store_true",
                            help="Detect WAF and apply evasion techniques to payloads")
    enterprise.add_argument("--templates", action="store_true",
                            help="Run YAML vulnerability templates (nuclei-style)")
    enterprise.add_argument("--template-tags", nargs="+", default=[],
                            help="Filter templates by tags (e.g. cve misconfig)")
    enterprise.add_argument("--compliance", action="store_true",
                            help="Map findings to OWASP 2021 + PCI DSS v4.0")
    enterprise.add_argument("--no-attack-chains", action="store_true",
                            help="Disable attack chain correlation analysis")
    enterprise.add_argument("--no-dedup", action="store_true",
                            help="Disable finding deduplication")
    enterprise.add_argument("--parallel", action="store_true",
                            help="Run independent scanners in parallel")

    # ── v4.0 Advanced engines ────────────────────────────────────────
    advanced = parser.add_argument_group("Advanced engines (v4.0)")
    advanced.add_argument("--stealth", action="store_true",
                          help="Use StealthClient with browser TLS impersonation (bypasses JA3/Cloudflare)")
    advanced.add_argument("--browser", action="store_true",
                          help="Use headless Chromium for crawling (SPA/React/Angular support)")
    advanced.add_argument("--oob", action="store_true",
                          help="Start OOB callback server for blind injection detection")
    advanced.add_argument("--oob-port", type=int, default=8888,
                          help="OOB HTTP callback server port (default: 8888)")
    advanced.add_argument("--oob-host", default="",
                          help="OOB callback host/IP (auto-detected if not set)")
    advanced.add_argument("--resume", action="store_true",
                          help="Resume a previously interrupted scan")
    advanced.add_argument("--impersonate", default="chrome124",
                          help="Browser to impersonate for stealth (default: chrome124)")

    # ── v5.0 Enterprise features ─────────────────────────────────
    v5 = parser.add_argument_group("Enterprise v5.0 features")
    v5.add_argument("--sarif", default=None, metavar="FILE",
                    help="Also generate SARIF 2.1.0 report to FILE")
    v5.add_argument("--junit", default=None, metavar="FILE",
                    help="Also generate JUnit XML report to FILE")
    v5.add_argument("--fail-on", default=None,
                    choices=["critical", "high", "medium", "low"],
                    help="Exit non-zero if findings >= severity threshold")
    v5.add_argument("--proxy-listen", default=None, metavar="HOST:PORT",
                    help="Start intercepting proxy (e.g. 127.0.0.1:8888)")
    v5.add_argument("--api-spec", default=None, metavar="FILE",
                    help="OpenAPI/Swagger spec file for API scanner")
    v5.add_argument("--plugin", nargs="+", default=[],
                    help="Load external plugin files or directories")

    # ── v8.0 Safety & Orchestration ──────────────────────────────
    v8 = parser.add_argument_group("Safety & orchestration (v8.0)")
    v8.add_argument("--safe-mode", default=None,
                    choices=["stealth", "safe", "normal", "aggressive"],
                    help="Scan safety preset (stealth=passive-only, safe=non-destructive, normal=balanced, aggressive=full)")
    v8.add_argument("--max-requests", type=int, default=0,
                    help="Maximum total requests (0=unlimited)")
    v8.add_argument("--max-duration", type=float, default=0.0,
                    help="Maximum scan duration in seconds (0=unlimited)")

    # ── v8.0 Swarm mode ─────────────────────────────────────────
    swarm = parser.add_argument_group("Swarm mode (v8.0)")
    swarm.add_argument("--swarm", action="store_true",
                       help="Enable 600-agent swarm mode (default: classic scanner mode)")
    swarm.add_argument("--mode", default="audit",
                       choices=["recon", "audit", "redteam"],
                       help="Operational mode for swarm (default: audit)")
    swarm.add_argument("--divisions", nargs="+", type=int, default=None,
                       metavar="N",
                       help="Only deploy specific divisions (1-20)")
    swarm.add_argument("--max-agents", type=int, default=20,
                       help="Max concurrent agents (default: 20)")
    swarm.add_argument("--max-swarm-requests", type=int, default=10000,
                       help="Max total HTTP requests for swarm (default: 10000)")
    swarm.add_argument("--swarm-rate-limit", type=int, default=20,
                       help="Requests per second for swarm (default: 20)")
    swarm.add_argument("--consensus", type=int, default=3,
                       help="Min agents for finding confirmation (default: 3)")
    swarm.add_argument("--federated", action="store_true",
                       help="Enable federated learning (community intelligence)")
    swarm.add_argument("--stealth-preset", default=None,
                       choices=["ghost", "ninja", "shadow", "blitz", "normal"],
                       help="Stealth preset: ghost (max stealth), ninja (balanced), "
                            "shadow (low-and-slow), blitz (fast+evasion), normal (none)")

    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", choices=["console", "json", "html", "sarif", "junit"],
                        default="console", help="Report format (default: console)")
    output.add_argument("-f", "--file", help="Output file path for reports")
    output.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    output.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    output.add_argument("--version", action="version",
                        version=f"SecProbe v{__version__}")

    return parser


def _build_scan_context(config: ScanConfig, stealth: bool = False,
                        impersonate: str = "chrome124"):
    """Build a fully wired ScanContext from config."""
    from secprobe.core.auth import AuthHandler, AuthConfig
    from secprobe.core.waf import WAFDetector
    from secprobe.core.context import ScanContext

    # ── Select HTTP engine ───────────────────────────────────────
    if stealth:
        from secprobe.core.stealth_client import StealthClient, StealthConfig
        stealth_config = StealthConfig(
            timeout=config.timeout,
            max_retries=2,
            proxy=config.proxy,
            rate_limit=config.rate_limit,
            impersonate=impersonate,
        )
        http_client = StealthClient(stealth_config)
        print_status(f"StealthClient active — impersonating {impersonate}", "success")
    else:
        from secprobe.core.http_client import HTTPClient, HTTPClientConfig
        http_config = HTTPClientConfig(
            timeout=config.timeout,
            max_retries=2,
            backoff_factor=0.5,
            rate_limit=config.rate_limit,
            user_agent=config.user_agent,
            proxy=config.proxy,
            verify_ssl=config.ssl_verify,
            follow_redirects=config.follow_redirects,
        )
        http_client = HTTPClient(http_config)

    auth_handler = None
    if config.auth:
        try:
            auth_config = AuthConfig.from_string(config.auth)
            auth_handler = AuthHandler(auth_config, http_client)
            auth_headers = auth_handler.get_headers()
            if auth_headers:
                http_client._session.headers.update(auth_headers)
            auth_cookies = auth_handler.get_cookies()
            if auth_cookies:
                for name, value in auth_cookies.items():
                    http_client._session.cookies.set(name, value)
            if auth_config.auth_type.value == "form":
                auth_handler.perform_form_login()
            print_status(f"Authentication configured: {auth_config.auth_type.value}", "success")
        except Exception as e:
            print_status(f"Auth configuration error: {e}", "warning")

    waf_detector = WAFDetector()
    http_client.set_waf_detector(waf_detector)

    context = ScanContext(
        http_client=http_client,
        auth_handler=auth_handler,
        waf_detector=waf_detector,
        target_url=normalize_url(config.target),
    )
    return context


def _run_waf_detection(context, config: ScanConfig):
    """Pre-scan WAF detection using the shared HTTPClient."""
    print_section("WAF Detection")
    target_url = normalize_url(config.target)
    try:
        waf_result = context.waf_detector.detect(context.http_client, target_url)
        if waf_result.detected:
            context.waf_name = waf_result.waf_name
            print_status(
                f"WAF Detected: {waf_result.waf_name} "
                f"(confidence: {waf_result.confidence:.0%}) — evasion enabled",
                "warning",
            )
            for ev in waf_result.evidence:
                print_status(f"  {ev}", "info")
        else:
            print_status("No WAF detected", "info")
    except Exception as e:
        print_status(f"WAF detection error: {e}", "warning")


def _run_crawl(context, config: ScanConfig, use_browser: bool = False):
    """Pre-scan crawl using SmartCrawler (with optional BrowserEngine)."""
    print_section("Attack Surface Crawl")
    target_url = normalize_url(config.target)

    browser_engine = None
    if use_browser:
        try:
            from secprobe.core.browser import BrowserEngine, BrowserConfig
            browser_config = BrowserConfig(
                proxy=config.proxy,
                timeout=30000,
            )
            browser_engine = BrowserEngine(browser_config)
            browser_engine.start()
            print_status("BrowserEngine active — Chromium headless", "success")
        except Exception as e:
            print_status(f"BrowserEngine init failed: {e}", "warning")
            print_status("Falling back to static crawl", "info")

    try:
        from secprobe.core.smart_crawler import SmartCrawler, SmartCrawlConfig
        crawl_config = SmartCrawlConfig(
            max_depth=config.crawl_depth,
            max_pages=config.crawl_max_pages,
            use_browser=use_browser and browser_engine is not None,
        )
        crawler = SmartCrawler(
            http_client=context.http_client,
            base_url=target_url,
            browser_engine=browser_engine,
            config=crawl_config,
        )
        attack_surface = crawler.crawl()
        context.attack_surface = attack_surface

        stats = crawler.stats
        spa_note = " (SPA detected!)" if stats.get("spa_detected") else ""
        browser_note = f", {stats.get('browser_pages', 0)} browser-rendered" if stats.get('browser_pages') else ""
        api_note = f", {stats.get('api_endpoints', 0)} API endpoints" if stats.get('api_endpoints') else ""

        print_status(
            f"Discovered {len(attack_surface.urls)} URLs, "
            f"{len(attack_surface.forms)} forms, "
            f"{len(attack_surface.endpoints)} endpoints"
            f"{browser_note}{api_note}{spa_note}",
            "success",
        )
    except Exception as e:
        print_status(f"Crawl error: {e}", "warning")
    finally:
        if browser_engine:
            browser_engine.stop()


def _run_scanners_parallel(scanner_classes, config, context):
    """Run scanners in parallel using ThreadPoolExecutor."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []

    def run_one(scanner_cls):
        scanner = scanner_cls(config, context)
        return scanner.run()

    with ThreadPoolExecutor(max_workers=min(len(scanner_classes), 6)) as pool:
        futures = {pool.submit(run_one, cls): cls for cls in scanner_classes}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print_status(f"Scanner failed: {e}", "error")
    return results


def _run_scanners_sequential(scanner_classes, config, context):
    """Run scanners one at a time."""
    results = []
    for scanner_cls in scanner_classes:
        scanner = scanner_cls(config, context)
        result = scanner.run()
        results.append(result)
    return results


def _run_swarm(args):
    """Execute 600-agent swarm mode."""
    from secprobe.swarm.executor import SwarmExecutor, ExecutorConfig
    from secprobe.swarm.registry import SwarmRegistry
    from secprobe.swarm.safety.governor import SafetyGovernor, ScopeConfig, BudgetConfig
    from secprobe.swarm.comm.event_bus import EventBus
    from secprobe.swarm.memory.working import WorkingMemory

    target = normalize_url(args.target)
    mode = args.mode.upper()

    # ── Mode-aware banner ────────────────────────────────────────
    mode_colors = {
        "RECON": Colors.CYAN,
        "AUDIT": Colors.YELLOW,
        "REDTEAM": Colors.RED,
    }
    mode_color = mode_colors.get(mode, Colors.RESET)
    print(f"\n  {mode_color}{Colors.BOLD}[ SWARM MODE: {mode} ]{Colors.RESET}")
    print(f"  {Colors.GRAY}Target:     {target}{Colors.RESET}")
    print(f"  {Colors.GRAY}Max agents: {args.max_agents}{Colors.RESET}")
    print(f"  {Colors.GRAY}Rate limit: {args.swarm_rate_limit} req/s{Colors.RESET}")
    print(f"  {Colors.GRAY}Consensus:  {args.consensus} agents{Colors.RESET}")
    if args.divisions:
        print(f"  {Colors.GRAY}Divisions:  {args.divisions}{Colors.RESET}")
    if args.federated:
        print(f"  {Colors.GRAY}Federated:  enabled{Colors.RESET}")
    print()

    # ── Build components ─────────────────────────────────────────
    executor_config = ExecutorConfig(
        max_agents=args.max_agents,
        max_requests=args.max_swarm_requests,
        rate_limit=args.swarm_rate_limit,
        consensus=args.consensus,
        federated=args.federated,
    )

    scope_config = ScopeConfig(target_domain=args.target)
    budget_config = BudgetConfig(
        max_requests=args.max_swarm_requests,
        rate_limit=args.swarm_rate_limit,
    )
    governor = SafetyGovernor(scope=scope_config, budget=budget_config)

    event_bus = EventBus()
    working_memory = WorkingMemory()

    # ── Load agent registry ──────────────────────────────────────
    print_section("Loading Swarm Registry")
    registry = SwarmRegistry.load_all()
    total_agents = registry.agent_count
    division_count = registry.division_count
    print_status(f"Registry loaded: {total_agents} agents across {division_count} divisions", "success")

    if args.divisions:
        print_status(f"Deploying divisions: {args.divisions}", "info")

    # ── Wire progress events ─────────────────────────────────────
    _scan_start = datetime.now()

    def _on_agent_deployed(event):
        print_status(
            f"Agent deployed: {event.agent_id} (division {event.division})",
            "progress",
        )

    def _on_finding(event):
        sev = event.finding.severity if hasattr(event, 'finding') else "INFO"
        color = {"CRITICAL": Colors.RED, "HIGH": Colors.RED,
                 "MEDIUM": Colors.YELLOW, "LOW": Colors.GREEN}.get(sev, Colors.GRAY)
        title = event.finding.title if hasattr(event, 'finding') else str(event)
        print(f"    {color}[{sev}]{Colors.RESET} {title}")

    def _on_progress(event):
        print_status(
            f"[{event.agents_deployed}/{total_agents}] "
            f"Findings: {event.findings_count} | "
            f"Requests: {event.requests_made}/{args.max_swarm_requests}",
            "progress",
        )

    event_bus.on("agent_deployed", _on_agent_deployed)
    event_bus.on("finding_discovered", _on_finding)
    event_bus.on("progress", _on_progress)

    # ── Create and run executor ──────────────────────────────────
    print_section(f"Executing Swarm — {mode}")
    executor = SwarmExecutor(
        config=executor_config,
        registry=registry,
        governor=governor,
        event_bus=event_bus,
        working_memory=working_memory,
    )

    divisions = args.divisions
    results = asyncio.run(executor.execute(target, args.mode, divisions))

    # ── Results ──────────────────────────────────────────────────
    _scan_duration = (datetime.now() - _scan_start).total_seconds()

    print_section("Swarm Results")
    all_findings = results.findings if hasattr(results, 'findings') else []

    total = len(all_findings)
    by_sev = {}
    for f in all_findings:
        sev = f.severity if hasattr(f, 'severity') else "INFO"
        by_sev[sev] = by_sev.get(sev, 0) + 1

    print_status(f"Total findings: {total}", "info")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        if count:
            color = {"CRITICAL": Colors.RED, "HIGH": Colors.RED, "MEDIUM": Colors.YELLOW,
                     "LOW": Colors.GREEN, "INFO": Colors.GRAY}.get(sev, Colors.RESET)
            print(f"    {color}{sev}: {count}{Colors.RESET}")

    print_status(f"Duration: {_scan_duration:.1f}s", "info")
    print_status(f"Agents deployed: {results.agents_deployed if hasattr(results, 'agents_deployed') else 'N/A'}", "info")
    print_status(f"Requests made: {results.requests_made if hasattr(results, 'requests_made') else 'N/A'}", "info")

    # ── Generate report using existing infrastructure ────────────
    if args.output != "console" or args.file:
        try:
            reporter = ReportGenerator(
                results.scan_results if hasattr(results, 'scan_results') else [],
                args.target,
                scan_duration=_scan_duration,
            )
            output_file = args.file
            if not output_file and args.output != "console":
                ext_map = {"json": "json", "html": "html", "sarif": "sarif.json", "junit": "xml"}
                ext = ext_map.get(args.output, "json")
                output_file = f"reports/secprobe_swarm_{args.target.replace('/', '_')}_{datetime.now():%Y%m%d_%H%M%S}.{ext}"
            reporter.generate(args.output, output_file)
        except Exception as e:
            print_status(f"Report generation error: {e}", "warning")

    if args.sarif:
        try:
            reporter = ReportGenerator(
                results.scan_results if hasattr(results, 'scan_results') else [],
                args.target,
                scan_duration=_scan_duration,
            )
            reporter.generate("sarif", args.sarif)
        except Exception as e:
            print_status(f"SARIF report error: {e}", "warning")

    if args.junit:
        try:
            reporter = ReportGenerator(
                results.scan_results if hasattr(results, 'scan_results') else [],
                args.target,
                scan_duration=_scan_duration,
            )
            reporter.generate("junit", args.junit)
        except Exception as e:
            print_status(f"JUnit report error: {e}", "warning")

    print_status("Swarm scan complete.", "success")

    # ── Exit code based on --fail-on threshold ───────────────────
    if args.fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold_idx = severity_order.index(args.fail_on)
        fail_severities = [s.upper() for s in severity_order[:threshold_idx + 1]]
        has_failing = any(
            (f.severity if hasattr(f, 'severity') else "") in fail_severities
            for f in all_findings
        )
        if has_failing:
            print_status(f"FAIL: Findings >= {args.fail_on.upper()} detected (exit 1)", "error")
            sys.exit(1)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    print_banner()

    if not is_valid_target(args.target):
        print_status(f"Invalid target: {args.target}", "error")
        print_status("Provide a valid hostname, IP address, or URL.", "info")
        sys.exit(1)

    # ── Swarm mode execution path ────────────────────────────────────
    if args.swarm:
        _run_swarm(args)
        return

    config = ScanConfig(
        target=args.target,
        scan_types=args.scans,
        ports=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        output_format=args.output,
        output_file=args.file,
        verbose=args.verbose,
        follow_redirects=not args.no_redirect,
        rate_limit=args.rate_limit,
        wordlist=args.wordlist,
        proxy=args.proxy,
        auth=args.auth,
        crawl=args.crawl,
        crawl_depth=args.crawl_depth,
        crawl_max_pages=args.crawl_max_pages,
        waf_evasion=args.waf_evasion,
        template_tags=args.template_tags,
        compliance=args.compliance,
        attack_chains=not args.no_attack_chains,
        dedup=not args.no_dedup,
    )
    if args.user_agent:
        config.user_agent = args.user_agent

    if args.output != "console" and not args.file:
        ext_map = {"json": "json", "html": "html", "sarif": "sarif.json", "junit": "xml"}
        ext = ext_map.get(args.output, "json")
        config.output_file = f"reports/secprobe_{args.target.replace('/', '_')}_{datetime.now():%Y%m%d_%H%M%S}.{ext}"

    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    # ── Build fully-wired scan context ───────────────────────────────
    print_section("Initializing Pipeline")
    context = _build_scan_context(config, stealth=args.stealth,
                                  impersonate=args.impersonate)
    if args.stealth:
        print_status("StealthClient: browser TLS impersonation active", "success")
    else:
        print_status("HTTPClient ready (pooling, retry, rate limiting)", "success")
    if config.proxy:
        print_status(f"Proxy: {config.proxy}", "info")
    if config.auth:
        print_status(f"Auth: {config.auth.split(':')[0]}:****", "info")

    # ── Plugin loading ───────────────────────────────────────────
    plugin_manager = None
    if args.plugin:
        try:
            from secprobe.core.plugins import PluginManager
            plugin_manager = PluginManager()
            for plugin_path in args.plugin:
                loaded = plugin_manager.load_file(plugin_path)
                if loaded:
                    print_status(f"Plugin loaded: {loaded.metadata.name} v{loaded.metadata.version}", "success")
                else:
                    print_status(f"Failed to load plugin: {plugin_path}", "warning")
            plugin_manager.initialize_all()
        except Exception as e:
            print_status(f"Plugin system error: {e}", "warning")

    # ── Intercepting proxy ───────────────────────────────────────
    intercept_proxy = None
    if args.proxy_listen:
        try:
            from secprobe.core.proxy import InterceptingProxy, ProxyConfig
            host, port = args.proxy_listen.rsplit(":", 1)
            proxy_config = ProxyConfig(host=host, port=int(port))
            intercept_proxy = InterceptingProxy(proxy_config)
            intercept_proxy.start()
            print_status(f"Intercepting proxy listening on {args.proxy_listen}", "success")
        except Exception as e:
            print_status(f"Proxy server error: {e}", "warning")

    # ── OOB Callback Server ──────────────────────────────────────
    oob_server = None
    if args.oob:
        try:
            from secprobe.core.oob_server import CallbackServer
            oob_server = CallbackServer(
                http_port=args.oob_port,
                callback_host=args.oob_host,
            )
            oob_server.start()
            context.oob_server = oob_server
            print_status(
                f"OOB callback server on port {args.oob_port} "
                f"(host: {oob_server.callback_host})",
                "success",
            )
        except Exception as e:
            print_status(f"OOB server error: {e}", "warning")

    # ── Scan State (resume) ──────────────────────────────────────
    scan_state = None
    if args.resume:
        try:
            from secprobe.core.state import ScanState
            scan_state = ScanState(config.target)
            resumed = scan_state.resume_session()
            if resumed:
                pending = scan_state.get_pending_scans()
                print_status(f"Resumed session {resumed} — {len(pending)} scans pending", "success")
            else:
                print_status("No interrupted session found — starting fresh", "info")
                scan_state.start_session(config.target)
        except Exception as e:
            print_status(f"Scan state error: {e}", "warning")

    if config.waf_evasion:
        _run_waf_detection(context, config)

    if config.crawl:
        _run_crawl(context, config, use_browser=args.browser)

    # ── Select scanners ──────────────────────────────────────────────
    if "all" in config.scan_types:
        scanner_classes = list(SCANNER_REGISTRY.values())
    else:
        scanner_classes = [SCANNER_REGISTRY[s] for s in config.scan_types if s in SCANNER_REGISTRY]

    # ── Scan Intelligence — Technology Profiling & Scanner Ordering ──
    tech_profile = None
    if not args.no_intelligence if hasattr(args, 'no_intelligence') else True:
        try:
            from secprobe.core.scan_intelligence import (
                TechProfile, ScanPlanner, ScanScorecard,
            )
            target_url = normalize_url(config.target)
            resp = context.http_client.get(target_url)
            cookies = [
                f"{k}={v}" for k, v in resp.cookies.items()
            ] if hasattr(resp, 'cookies') else []
            tech_profile = TechProfile.from_response(
                headers=dict(resp.headers) if hasattr(resp, 'headers') else {},
                body=resp.text if hasattr(resp, 'text') else "",
                cookies=cookies,
            )

            # Report what we found
            tech_parts = []
            if tech_profile.server.value != "Unknown":
                tech_parts.append(tech_profile.server.value)
            if tech_profile.language.value != "Unknown":
                tech_parts.append(tech_profile.language.value)
            if tech_profile.framework.value != "Unknown":
                tech_parts.append(tech_profile.framework.value)
            if tech_profile.js_frameworks:
                tech_parts.append("+".join(tech_profile.js_frameworks))
            if tech_profile.waf_detected:
                tech_parts.append(f"WAF:{tech_profile.waf_name}")

            if tech_parts:
                print_status(
                    f"Target fingerprint: {' / '.join(tech_parts)} "
                    f"(confidence: {tech_profile.confidence:.0%})",
                    "success",
                )

            # Reorder scanners based on technology
            if len(scanner_classes) > 3:
                name_to_cls = {}
                for cls in scanner_classes:
                    for name, reg_cls in SCANNER_REGISTRY.items():
                        if reg_cls is cls:
                            name_to_cls[name] = cls
                            break

                plan = ScanPlanner.plan(
                    tech_profile,
                    list(name_to_cls.keys()),
                )
                reordered = [
                    name_to_cls[name]
                    for name in plan.ordered_scanners
                    if name in name_to_cls
                ]
                if reordered:
                    scanner_classes = reordered

                if plan.skipped_scanners:
                    for sname, reason in plan.skipped_scanners:
                        print_status(f"Skipping {sname}: {reason}", "info")

        except Exception as e:
            print_status(f"Intelligence profiling: {e}", "info")

    # ── Safe Mode / Scan Policy ──────────────────────────────────
    safe_mode_instance = None
    if args.safe_mode:
        try:
            from secprobe.core.safe_mode import SafeMode, PolicyPreset
            preset_map = {
                "stealth": PolicyPreset.STEALTH,
                "safe": PolicyPreset.SAFE,
                "normal": PolicyPreset.NORMAL,
                "aggressive": PolicyPreset.AGGRESSIVE,
            }
            preset = preset_map[args.safe_mode]
            target_url = normalize_url(config.target)
            safe_mode_instance = SafeMode.from_preset(preset, target_url)

            # Apply budget overrides from CLI
            if args.max_requests > 0:
                safe_mode_instance.budget = __import__(
                    "secprobe.core.safe_mode", fromlist=["RequestBudget"]
                ).RequestBudget(
                    max_requests=args.max_requests,
                    max_duration=args.max_duration,
                )
            elif args.max_duration > 0:
                safe_mode_instance.budget = __import__(
                    "secprobe.core.safe_mode", fromlist=["RequestBudget"]
                ).RequestBudget(
                    max_requests=safe_mode_instance.policy.max_requests_total,
                    max_duration=args.max_duration,
                )

            print_status(
                f"Safe Mode: {args.safe_mode.upper()} "
                f"(rate: {safe_mode_instance.policy.max_requests_per_second} req/s, "
                f"destructive: {'yes' if safe_mode_instance.policy.allow_destructive else 'no'})",
                "success",
            )
        except Exception as e:
            print_status(f"Safe mode setup error: {e}", "warning")

    print_section("Scan Configuration")
    print_status(f"Target: {config.target}", "info")
    print_status(f"Scanners: {len(scanner_classes)} modules selected", "info")
    _scan_start = datetime.now()
    print_status(f"Started: {_scan_start:%Y-%m-%d %H:%M:%S}", "info")

    # ── Run scanners ─────────────────────────────────────────────────
    # Use ScanSession for orchestration when safe_mode is active
    scan_session = None
    if safe_mode_instance:
        try:
            from secprobe.core.scan_session import ScanSession, EventType

            scan_session = ScanSession(config, context=context, safe_mode=safe_mode_instance)

            # Wire up live progress events
            def _on_finding(event):
                if event.finding:
                    sev = event.finding.severity
                    color = {"CRITICAL": Colors.RED, "HIGH": Colors.RED,
                             "MEDIUM": Colors.YELLOW, "LOW": Colors.GREEN}.get(sev, Colors.GRAY)
                    print(f"    {color}[{sev}]{Colors.RESET} {event.finding.title}")

            def _on_scanner_done(event):
                pct = scan_session.progress.percent_complete
                print_status(
                    f"[{pct:.0f}%] {event.scanner}: {event.message}",
                    "progress",
                )

            scan_session.events.on(EventType.FINDING_DISCOVERED, _on_finding)
            scan_session.events.on(EventType.SCANNER_COMPLETED, _on_scanner_done)
            scan_session.events.on(EventType.SCANNER_FAILED, _on_scanner_done)

            # Resolve names from classes
            scanner_name_list = []
            for cls in scanner_classes:
                for name, reg_cls in SCANNER_REGISTRY.items():
                    if reg_cls is cls:
                        scanner_name_list.append(name)
                        break

            results = scan_session.run(
                scanner_names=scanner_name_list,
                scanner_registry={name: SCANNER_REGISTRY[name] for name in scanner_name_list},
            )

            # Print session summary
            session_summary = scan_session.summary()
            budget_summary = safe_mode_instance.budget.summary()
            print_status(
                f"Session: {session_summary['scanners']['completed']} completed, "
                f"{session_summary['scanners']['failed']} failed, "
                f"{session_summary['scanners']['skipped']} skipped | "
                f"Budget: {budget_summary['requests_made']}/{budget_summary.get('max_requests', '∞')} requests",
                "info",
            )

            risk_score, grade = scan_session.risk_score()
            print_status(f"Risk Score: {risk_score}/100 (Grade: {grade})", "info")

        except Exception as e:
            print_status(f"ScanSession error, falling back: {e}", "warning")
            scan_session = None

    if scan_session is None:
        # Fallback: direct scanner execution (original behavior)
        if args.parallel and len(scanner_classes) > 1:
            print_status("Running scanners in parallel...", "progress")
            results = _run_scanners_parallel(scanner_classes, config, context)
        else:
            results = _run_scanners_sequential(scanner_classes, config, context)

    # ── Run vulnerability templates ──────────────────────────────────
    if args.templates:
        try:
            from secprobe.templates.engine import TemplateEngine
            from secprobe.models import ScanResult

            print_section("Vulnerability Templates")
            engine = TemplateEngine()
            print_status(f"Loaded {len(engine.templates)} templates", "info")

            if config.template_tags:
                engine.templates = engine.filter_templates(tags=config.template_tags)
                print_status(f"Filtered to {len(engine.templates)} templates (tags: {config.template_tags})", "info")

            target_url = normalize_url(config.target)
            template_results = engine.execute_all(target_url, http_client=context.http_client)

            if template_results:
                template_scan = ScanResult(scanner_name="Template Scanner", target=config.target)
                for tr in template_results:
                    finding = tr.to_finding()
                    if finding:
                        template_scan.findings.append(finding)
                        print_status(f"[{tr.template.severity.upper()}] {tr.template.name}", "warning")
                results.append(template_scan)
                print_status(f"{len(template_results)} template matches found", "success")
            else:
                print_status("No template matches", "info")
        except Exception as e:
            print_status(f"Template engine error: {e}", "warning")

    # ── Collect all findings ─────────────────────────────────────────
    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    # ── Finding deduplication ────────────────────────────────────────
    if config.dedup and len(all_findings) > 1:
        try:
            from secprobe.analysis.dedup import FindingDeduplicator
            print_section("Deduplication")
            deduper = FindingDeduplicator()
            groups = deduper.deduplicate(all_findings)
            original_count = len(all_findings)
            deduped_findings = [g.primary for g in groups]
            removed = original_count - len(deduped_findings)
            if removed > 0:
                print_status(f"Deduplicated: {original_count} -> {len(deduped_findings)} findings ({removed} duplicates removed)", "info")
                all_findings = deduped_findings
        except Exception as e:
            print_status(f"Deduplication error: {e}", "warning")

    # ── Attack chain analysis ────────────────────────────────────────
    chains = []
    if config.attack_chains and len(all_findings) > 1:
        try:
            from secprobe.analysis.attack_chain import AttackChainAnalyzer
            print_section("Attack Chain Analysis")
            analyzer = AttackChainAnalyzer()
            chains = analyzer.analyze(all_findings)
            if chains:
                for chain in chains:
                    sev_color = {
                        "critical": Colors.RED, "high": Colors.RED,
                        "medium": Colors.YELLOW, "low": Colors.GREEN,
                    }.get(chain.severity, Colors.GRAY)
                    print(f"  {sev_color}* {chain.name}{Colors.RESET}")
                    print(f"     Risk Score: {chain.risk_score}/100  |  Severity: {chain.severity}")
                    print(f"     Impact: {chain.impact}")
                    if chain.mitre_attack:
                        print(f"     MITRE: {', '.join(chain.mitre_attack)}")
                    print()
                print_status(f"{len(chains)} attack chains identified", "success")
            else:
                print_status("No attack chains identified", "info")
        except Exception as e:
            print_status(f"Attack chain analysis error: {e}", "warning")

    # ── Compliance mapping ───────────────────────────────────────────
    compliance_data = None
    if config.compliance:
        try:
            from secprobe.analysis.compliance import ComplianceMapper
            print_section("Compliance Mapping")
            mapper = ComplianceMapper()
            compliance_data = mapper.map_all(all_findings)

            for framework, report in compliance_data.items():
                print(f"\n  {Colors.BOLD}{framework}:{Colors.RESET}")
                print(f"    Score: {report.compliance_score:.0f}%")
                for control in report.controls:
                    status_icon = {"pass": "v", "fail": "x", "partial": "~", "not-tested": "-"}.get(control.status, "?")
                    status_color = {"pass": Colors.GREEN, "fail": Colors.RED, "partial": Colors.YELLOW}.get(control.status, Colors.GRAY)
                    print(f"    {status_color}{status_icon} {control.control_id}: {control.name}{Colors.RESET}")
        except Exception as e:
            print_status(f"Compliance mapping error: {e}", "warning")

    # ── Generate report ──────────────────────────────────────────────
    _scan_duration = (datetime.now() - _scan_start).total_seconds()
    reporter = ReportGenerator(
        results, config.target,
        tech_profile=tech_profile,
        scan_duration=_scan_duration,
    )
    reporter.generate(config.output_format, config.output_file)

    if config.output_format != "console":
        reporter.generate("console")

    # ── Side reports (SARIF/JUnit alongside primary output) ──────
    if args.sarif:
        reporter.generate("sarif", args.sarif)
    if args.junit:
        reporter.generate("junit", args.junit)

    # ── Final summary ────────────────────────────────────────────────
    print_section("Summary")
    total = len(all_findings)
    by_sev = {}
    for f in all_findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print_status(f"Total findings: {total}", "info")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        if count:
            color = {"CRITICAL": Colors.RED, "HIGH": Colors.RED, "MEDIUM": Colors.YELLOW,
                     "LOW": Colors.GREEN, "INFO": Colors.GRAY}.get(sev, Colors.RESET)
            print(f"    {color}{sev}: {count}{Colors.RESET}")

    if chains:
        print_status(f"Attack chains: {len(chains)}", "warning")
    if compliance_data:
        for fw, rpt in compliance_data.items():
            print_status(f"{fw} compliance: {rpt.compliance_score:.0f}%", "info")

    context.http_client.close()

    # ── OOB callback collection ──────────────────────────────────
    if oob_server and oob_server.is_running:
        print_section("OOB Callback Results")
        callbacks = oob_server.wait_for_callbacks(timeout=15)
        if callbacks:
            from secprobe.models import ScanResult, Finding
            from secprobe.config import Severity
            oob_results = ScanResult(scanner_name="OOB Detector", target=config.target)
            for cb in callbacks:
                oob_results.add_finding(Finding(
                    title=f"Blind {cb.payload_type} Confirmed (OOB {cb.callback_type.upper()})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Out-of-band callback received from {cb.source_ip}.\n"
                        f"Scanner: {cb.scanner}\n"
                        f"Target: {cb.target_url}\n"
                        f"Parameter: {cb.parameter}\n"
                        f"Payload type: {cb.payload_type}"
                    ),
                    evidence=f"Callback: {cb.callback_type} from {cb.source_ip}:{cb.source_port}\nPath: {cb.path}",
                    scanner="OOB Detector",
                    category="Blind Injection",
                    url=cb.target_url,
                    cwe="CWE-74",
                ))
                print_status(
                    f"🔥 BLIND {cb.payload_type.upper()} at {cb.target_url} "
                    f"param={cb.parameter} (via {cb.callback_type})",
                    "warning",
                )
            results.append(oob_results)
            print_status(f"{len(callbacks)} blind vulnerabilities confirmed!", "success")
        else:
            print_status("No OOB callbacks received", "info")
        oob_server.stop()

    # ── Save scan state ──────────────────────────────────────────
    if scan_state:
        scan_state.finish_session()
        summary = scan_state.get_scan_summary()
        print_status(
            f"Scan state saved: {summary['coverage']['completed']} scans completed, "
            f"{summary['coverage']['pending']} pending",
            "info",
        )

    print_status("Scan complete.", "success")

    # ── Stop intercepting proxy ──────────────────────────────────
    if intercept_proxy:
        intercept_proxy.stop()
        stats = intercept_proxy.get_stats()
        print_status(f"Proxy stopped — {stats.get('total_requests', 0)} requests captured", "info")

    # ── Exit code based on --fail-on threshold ───────────────────
    if args.fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold_idx = severity_order.index(args.fail_on)
        fail_severities = [s.upper() for s in severity_order[:threshold_idx + 1]]
        has_failing = any(f.severity in fail_severities for f in all_findings)
        if has_failing:
            print_status(f"FAIL: Findings >= {args.fail_on.upper()} detected (exit 1)", "error")
            sys.exit(1)


if __name__ == "__main__":
    main()
