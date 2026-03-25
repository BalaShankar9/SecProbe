# SecProbe — World-Class Security Platform Design Spec

**Date:** 2026-03-25
**Version:** 1.0
**Status:** Draft
**Author:** Bala Bollineni + Claude Opus 4.6

---

## 1. Vision

SecProbe becomes the world's #1 security testing platform. If a system passes SecProbe's full assessment, it is certifiably safe. If SecProbe can't find a vulnerability, nothing can.

**Endgame:** SecProbe Certification becomes an industry standard — like PCI DSS compliance but automated, continuous, and trustworthy.

---

## 2. Honest Starting Point

### What exists today (67,710 lines, 1,528 tests)
- 48 real scanner modules covering OWASP Top 10 + beyond
- 600 agent definitions organized into 20 divisions
- Swarm framework: registry, executor, consensus, event bus, safety governor
- 5-tier memory hierarchy (working, episodic, semantic, procedural, federated)
- Stealth engine with 5 presets and 8 WAF strategies
- Classic CLI scanner that finds config/header/CORS issues
- API (Railway) + Dashboard (Netlify) + Database (Supabase)

### Critical gaps (what prevents #1 status)
1. Detection rate is low — can't find UNION SQLi in Juice Shop that curl confirms in 1 request
2. Crawler is HTML-only — misses SPA/API endpoints (where most modern vulns live)
3. Scanner-to-endpoint wiring is broken — scanners test root URL params, not discovered endpoints
4. Agents are metadata, not logic — 600 specs exist but don't each contain unique scanning code
5. Swarm mode untested end-to-end — --swarm has never completed a real scan
6. No benchmark tracking — no way to measure detection rate against known-vulnerable apps
7. No browser-based testing — DOM XSS, client-side vulns require a real browser

---

## 3. Architecture — The Complete Platform

```
Layer 5: CERTIFICATION and COMPLIANCE
  Certification Engine | Evidence Generator | Badge System
  Compliance Mapper    | Audit Trail        | Report Templates

Layer 4: PLATFORM and INTEGRATIONS
  SaaS Dashboard | REST API  | Webhooks    | Marketplace
  GitHub Action  | CI/CD     | IDE Plugins | Slack/Teams
  Continuous Mon | Scheduler | Diff Engine | Bug Bounty Triage

Layer 3: INTELLIGENCE and LEARNING
  5-Tier Memory  | Federated Learning | Threat Intel Feed
  Attack Chains  | Pattern Learning   | Payload Evolution
  Benchmark Suite| Detection Metrics  | False Positive Model

Layer 2: AGENT SWARM (600 Agents, 20 Divisions)
  Orchestrator   | Consensus Engine | Safety Governor
  Event Bus      | Blackboard       | Stealth Engine
  Phase Executor | Agent Runtime    | Division Commanders

Layer 1: DETECTION ENGINE (The Core — Everything depends on this)
  Smart Crawler      | Browser Engine   | API Discoverer
  Injection Engine   | Detection Logic  | Response Analyzer
  Payload Mutator    | OOB Server       | Baseline Profiler
  Evidence Collector | CVSS Scorer      | Deduplicator
```

Build order: Layer 1 then Layer 2 then Layer 3 then Layer 4 then Layer 5.

Layer 1 is the foundation. If it doesn't work, nothing above it matters.

---

## 4. Phase 1: Unbeatable Detection Engine

**Goal:** Achieve 80%+ detection rate on OWASP Juice Shop (100+ known vulns), 90%+ on DVWA, and outperform Burp Suite Community on a standard benchmark.

### 4.1 Smart Endpoint Discovery

**Problem:** Current crawler only parses HTML links. Modern apps are SPAs — endpoints are in JavaScript, not HTML.

**Solution: 4-layer discovery**

Layer A: Static HTML Crawling (exists, fixed)
  - Parse a, form, script src, link tags
  - Follow redirects, respect scope

Layer B: JavaScript Analysis (NEW)
  - Parse all script tags and .js files
  - Extract: fetch(), axios, XMLHttpRequest, $.ajax calls
  - Regex patterns for API paths: /api/*, /rest/*, /graphql, /v1/*
  - Extract from Angular/React/Vue router definitions
  - Find hardcoded endpoints in webpack bundles

Layer C: Browser-Based Discovery (NEW)
  - Playwright headless browser
  - Navigate pages, interact with UI elements
  - Intercept all network requests (XHR/fetch)
  - Record every URL the browser contacts
  - Handle SPAs: click buttons, fill forms, scroll

Layer D: API Brute-Force Discovery (NEW)
  - Common API path wordlist (5000+ paths)
  - /api/v1/users, /rest/products, /graphql, etc.
  - Status code analysis: 200/301/401/403 = exists
  - Swagger/OpenAPI auto-discovery: /swagger.json, /openapi.yaml, /api-docs
  - WADL, WSDL discovery for SOAP services

For Juice Shop specifically: Layer B finds /rest/products/search?q= from Angular source code. Layer C intercepts it from browser network requests. Layer D finds /api/Products, /api/Users, /rest/user/login.

### 4.2 Fix the Injection Pipeline

**Problem:** Scanners receive the target URL but don't receive discovered endpoints. The SQLi scanner tests the root URL params instead of discovered API endpoints.

**Solution: AttackSurface to Scanner wiring**

Current broken flow:
  Scanner.scan(target="http://127.0.0.1:3333")
  Scanner finds params from root HTML only, misses API endpoints

Fixed flow:
  crawler.crawl(target) produces AttackSurface with:
    urls: ["/rest/products/search?q=", "/api/Products", "/rest/user/login", ...]
    parameters: {"q": ["/rest/products/search"], "email": ["/rest/user/login"], ...}
    forms: [{action: "/rest/user/login", method: "POST", fields: ["email", "password"]}]
    api_endpoints: ["/api/Products", "/api/Users", "/api/Challenges", ...]
    tech_stack: ["Express", "Angular", "SQLite", "Node.js"]

  Scanner.scan(target, attack_surface=surface)
  Scanner now tests every discovered endpoint with every relevant payload

### 4.3 Injection Detection Improvements

SQLi — what needs to change:

| Detection Type | Current Status | Fix |
|----------------|---------------|-----|
| Error-based | Works but only on root URL params | Wire to discovered endpoints |
| UNION-based | Not detecting Juice Shop | Add: detect controlled data in response (1,2,3,4,5 pattern) |
| Boolean-blind | Works in theory | Add: response length comparison (true vs false queries) |
| Time-blind | Works | Wire to discovered endpoints |
| OOB/DNS | Framework exists | Needs real OOB server integration |
| Second-order | Not implemented | Store payload, trigger on different page |
| JSON body | Exists | Wire to discovered POST endpoints |
| Header injection | Exists | Reduce false positives (most headers aren't injectable) |

XSS — what needs to change:

| Detection Type | Current Status | Fix |
|----------------|---------------|-----|
| Reflected | Basic, tests root URL | Wire to discovered endpoints, check reflection |
| DOM-based | ScriptInfo bug fixed, untested | Playwright: inject payload, check DOM for execution |
| Stored | Not implemented | POST payload to one endpoint, check reflection on another |
| Mutation XSS | Not implemented | Browser-specific parser quirks |
| CSP bypass | Not tested | Check CSP header, try bypass techniques |

Other injection classes needing endpoint wiring:
SSTI, CMDi, LFI, XXE, NoSQL, LDAP, XPath, CRLF, HPP — all exist as scanners but all test root URL only.

### 4.4 Browser-Based Testing

Required for: DOM XSS, client-side prototype pollution, clickjacking verification, CSRF token extraction, SPA authentication flow testing, WebSocket testing, service worker analysis.

Implementation: BrowserTestEngine using Playwright.
  - Launch Chromium with security-relevant flags
  - Intercept all network traffic
  - test_dom_xss: navigate with payload, check dialog/DOM execution
  - test_stored_xss: POST payload, navigate to view page, check execution
  - intercept_api_calls: navigate and capture XHR/fetch requests

### 4.5 Benchmark Suite

Targets:
| App | Known Vulns | Our Target |
|-----|------------|------------|
| OWASP Juice Shop | 100+ challenges | 80+ found |
| DVWA | 14 vuln categories | 12+ categories |
| WebGoat | 30+ lessons | 25+ detected |
| Damn Vulnerable GraphQL | 20+ vulns | 15+ found |

BenchmarkSuite:
  - Start Docker container for each app
  - Run full SecProbe scan
  - Map findings to known challenge/vuln list
  - Calculate detection_rate = found / total
  - Track false_positive_rate = fp / total_findings
  - Generate comparison report

Success criteria for Phase 1:
  - Juice Shop: 80+ of 100+ vulns detected
  - DVWA: 12+ of 14 categories covered
  - False positive rate: less than 5%
  - Scan time: less than 30 minutes for full scan
  - Zero crashes on any target

---

## 5. Phase 2: Agent Swarm — Real Execution

**Goal:** Make the 600 agents actually scan, not just exist as metadata.

### 5.1 Agent Execution Model

Currently: 600 AgentSpec objects with metadata (name, capabilities, payloads, detection_patterns).
What we need: Each agent spec maps to real scanning logic.

Approach: Agent to Scanner Bridge

AgentSpec (metadata) contains:
  - attack_types: ("sqli-union", "sqli-error")
  - target_technologies: ("mysql", "sqlite")
  - payloads: "payloads/sqli.txt"
  - detection_patterns: (regex for SQL syntax, UNION, etc.)

AgentRuntime (execution) does:
  - Load payloads from file
  - For each (endpoint, parameter) from AttackSurface:
    - Check if endpoint tech matches agent's target_technologies
    - Send payload via async HTTP client
    - Match response against detection_patterns
    - If match: create Evidence, create Finding
    - Submit to consensus engine
  - Return findings

Key insight: We don't need 600 unique scanner implementations. We need:
  1. 48 existing scanners (the real detection logic)
  2. 600 agents that are specialized configurations of those scanners
  3. Agent specialization = specific payloads + specific patterns + specific technologies + specific techniques

### 5.2 Swarm Execution Flow (End-to-End)

```
secprobe target.com --swarm --mode audit

Phase 1: RECON (Division 1 — 40 agents)
  DNS enumeration, port scanning, tech fingerprinting,
  browser crawling, JS analysis, API brute-force, WAF detection
  Output: AttackSurface with 50-500 endpoints

Phase 2: PLAN (Division 20 — Meta-Coordination)
  Match tech stack to relevant divisions
  Check semantic memory for known patterns
  Output: Prioritized list of 50-200 agents to deploy

Phase 3: ATTACK (Selected divisions — 50-200 agents)
  Deploy agents in priority order with concurrency control
  Rate limiting via stealth engine
  Governor approves/denies each action based on mode
  Output: Raw findings

Phase 4: VERIFY (Division 19 — Intelligence)
  2 independent verifications per finding
  3-agent consensus for CONFIRMED status
  Baseline comparison, timing analysis
  Output: Verified findings only

Phase 5: REPORT (Division 18 + 19)
  Deduplicate, build attack chains, risk score, compliance mapping
  Generate report (HTML/JSON/SARIF/PDF)
  Store in episodic memory for learning
```

---

## 6. Phase 3: Intelligence and Learning

### 6.1 Semantic Memory — Pattern Learning

After each scan, learn correlations:
  WordPress 6.2 + MySQL 8.0 leads to SQLi probability: 0.73
  WordPress + comments leads to Stored XSS probability: 0.68
  Cloudflare WAF bypass: double-URL-encoding works 45% of time

Next scan recalls:
  "WordPress sites have 73% SQLi rate — prioritize Division 2"
  "Cloudflare detected — use double-URL-encoding payloads first"

### 6.2 Procedural Memory — Attack Replay

Record multi-step attack sequences:
  Step 1: Discover /api/users (recon)
  Step 2: Find IDOR — /api/users/1 returns admin data
  Step 3: Extract admin email from response
  Step 4: Use admin email in password reset
  Step 5: Account takeover confirmed

Store as reusable procedure. Next IDOR auto-triggers steps 3-5.

### 6.3 Federated Intelligence

Anonymized community patterns:
  "Spring Boot 3.2 + Actuator exposed" in 89% of instances
  "Cloudflare WAF v2024.3" bypassed via chunked TE in 67% of cases
  "React 18 + unsafe innerHTML" leads to DOM XSS in 42% of apps

### 6.4 Benchmark Tracking

Every commit runs automated benchmarks:
  Juice Shop: 67/100 vulns (67%)
  DVWA: 11/14 categories (79%)
  FP rate: 3.2%
  CI/CD gate: detection_rate >= 80% OR fail the build

---

## 7. Phase 4: SaaS Platform

### 7.1 Architecture
  Next.js Dashboard: Scan Launch, Results Viewer, History/Trends, Settings/API Keys
  FastAPI Backend: Auth (JWT), Scan Queue, Results Store, Webhooks
  Worker Fleet: SecProbe Engine (600-agent swarm per scan), horizontally scalable
  Data Layer: Supabase (Postgres + Auth), Redis (Queue + Cache), S3/Blob (Reports + Evidence)

### 7.2 Developer Integrations
  GitHub Action: secprobe/scan-action@v1 with SARIF upload
  Pre-commit hook: scan changed endpoints before commit
  IDE Plugin (VS Code): inline vulnerability annotations, right-click scan

### 7.3 Continuous Monitoring
  Schedule: every 6 hours (configurable)
  Compare with previous results, detect new vulns, config drift
  Alert via: webhook, email, Slack, PagerDuty

---

## 8. Phase 5: Certification and Marketplace

### 8.1 SecProbe Certification

Certification Levels:
  Bronze: Pass recon + header + config checks (basic hygiene)
  Silver: Pass all passive + active scanning (no critical/high vulns)
  Gold: Pass full swarm audit (no vulns above LOW severity)
  Platinum: Pass full redteam simulation (no exploitable chains)
  Diamond: Continuous monitoring for 90 days with zero regressions

Each level includes:
  Machine-readable attestation (signed JSON)
  Human-readable report (PDF)
  Embeddable badge (SVG)
  Verifiable on secprobe.io/verify/{cert-id}
  Expiry: 90 days (must re-certify)

### 8.2 Marketplace

Community contributions:
  Custom scanner plugins (Python modules)
  Detection rule packs (YAML templates)
  Agent specializations (new agent specs)
  Payload collections (curated wordlists)
  Compliance templates (custom frameworks)
  Integration adapters (new CI/CD platforms)
Revenue: 70/30 split (creator/platform)

---

## 9. Competitive Positioning

| Feature | Burp Suite | Nessus | ZAP | Nuclei | SecProbe |
|---------|-----------|--------|-----|--------|----------|
| Agents | 0 | 0 | 0 | 0 | 600 |
| Auto-discovery | Manual | Limited | Basic | None | 4-layer |
| Learning | None | None | None | None | 5-tier + federated |
| Stealth | Manual | None | None | None | 5 presets + 8 WAF |
| Consensus | N/A | N/A | N/A | N/A | 3-agent verify |
| Modes | Manual | Scan only | Scan only | Scan only | recon/audit/redteam |
| Continuous | No | Yes ($$$) | No | No | Built-in |
| CI/CD | Plugin | Plugin | Plugin | Yes | Native + Action |
| Certification | No | No | No | No | 5 tiers |
| Open source | No | No | Yes | Yes | Yes (core) |
| Price | $449/yr | $3,990/yr | Free | Free | Free core + SaaS |

---

## 10. Build Sequence — What Gets Built When

### Phase 1A: Endpoint Discovery (Critical Path)
  secprobe/core/js_endpoint_extractor.py    — Parse JS for API calls
  secprobe/core/api_discoverer.py           — Brute-force API paths
  secprobe/core/browser_crawler.py          — Playwright-based crawling
  secprobe/core/attack_surface.py           — Unified AttackSurface model
  secprobe/core/crawler.py                  — Wire new discovery into existing crawler

### Phase 1B: Injection Pipeline Fix (Critical Path)
  secprobe/scanners/base.py                 — Accept AttackSurface input
  secprobe/scanners/sqli_scanner.py         — Test discovered endpoints, fix UNION detection
  secprobe/scanners/xss_scanner.py          — Test discovered endpoints, add DOM XSS
  secprobe/core/scan_session.py             — Pass AttackSurface to scanners
  secprobe/cli.py                           — Wire crawler to session to scanners

### Phase 1C: Browser Testing Engine
  secprobe/core/browser_test_engine.py      — Playwright-based vuln testing
  secprobe/scanners/dom_xss_live.py         — Real browser DOM XSS testing
  secprobe/scanners/csrf_live.py            — Browser-based CSRF verification

### Phase 1D: Benchmark Suite
  secprobe/benchmark/__init__.py
  secprobe/benchmark/runner.py              — Benchmark orchestrator
  secprobe/benchmark/juice_shop.py          — Juice Shop challenge mapper
  secprobe/benchmark/dvwa.py                — DVWA category mapper
  secprobe/benchmark/report.py              — Detection rate reporting

### Phase 2: Swarm Execution
  secprobe/swarm/executor.py                — Wire agents to real scanning
  secprobe/swarm/orchestrator.py            — End-to-end swarm pipeline
  secprobe/swarm/agent.py                   — Agent to Scanner bridge

### Phase 3: Intelligence
  secprobe/swarm/memory/semantic.py         — Real pattern learning
  secprobe/swarm/memory/procedural.py       — Attack sequence recording
  secprobe/swarm/memory/federated.py        — Supabase sync

### Phase 4: SaaS Platform
  platform/                                 — Next.js dashboard
  platform/api/                             — Enhanced FastAPI backend
  platform/workers/                         — Scan worker fleet

### Phase 5: Certification
  secprobe/certification/levels.py          — Bronze/Silver/Gold/Platinum/Diamond
  secprobe/certification/evidence.py        — Evidence generator
  secprobe/certification/badge.py           — Badge/attestation system

---

## 11. Success Metrics

| Metric | Current | Phase 1 | Phase 2 | Number 1 Target |
|--------|---------|---------|---------|-----------------|
| Juice Shop detection | ~14/100 | 80/100 | 90/100 | 95+/100 |
| DVWA coverage | Untested | 12/14 | 14/14 | 14/14 |
| False positive rate | Unknown | below 5% | below 3% | below 1% |
| Scan time (full) | 4+ hours | below 30 min | below 15 min | below 10 min |
| Endpoint discovery | HTML only | +JS+API | +Browser | All 4 layers |
| Agent execution | Metadata only | 48 real scanners | 200+ active | 600 specialized |
| Learning | None | Episodic | +Semantic+Procedural | +Federated |
| CI/CD | None | GitHub Action | +GitLab+Azure | Universal |
| Users | 1 | Beta testers | 100+ | 10,000+ |

---

## 12. Non-Goals (What We Are NOT Building)

- Network infrastructure scanner (Nessus territory — different market)
- Mobile app binary analysis (different toolchain)
- Physical security testing
- Social engineering automation (ethical concerns)
- Malware analysis / reverse engineering
- DDoS testing (legal liability)

We focus on web application and API security testing — and we become the undisputed number 1 in that domain.

---

## 13. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Detection rate plateaus below 80% | Fatal | Benchmark-driven development, fix gaps iteratively |
| False positives destroy trust | High | 3-agent consensus, baseline comparison |
| Legal liability from aggressive scanning | High | Safety governor, mode enforcement, scope guards |
| Playwright dependency issues | Medium | Fallback to static analysis, graceful degradation |
| Federated memory privacy breach | High | Anonymization layer, opt-in only |
| Competitor copies our approach | Medium | Speed of execution, community moat |
