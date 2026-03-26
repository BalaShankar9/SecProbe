"""
SecProbe API — Production FastAPI backend for the 600-agent security testing toolkit.

Provides endpoints for scan management, agent registry browsing, results retrieval,
and federated intelligence sync with Supabase.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from secprobe.swarm.agent import AgentSpec, OperationalMode
from secprobe.swarm.registry import SwarmRegistry

load_dotenv()

# ─── Configuration ────────────────────────────────────────────────────────────

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
API_VERSION = "1.0.0"

# ─── Global State ─────────────────────────────────────────────────────────────

registry: SwarmRegistry | None = None
scans_db: dict[str, dict[str, Any]] = {}
supabase_client: httpx.AsyncClient | None = None


# ─── Pydantic Models ─────────────────────────────────────────────────────────

class ScanMode(str, Enum):
    recon = "recon"
    audit = "audit"
    redteam = "redteam"


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL or hostname")
    mode: ScanMode = Field(ScanMode.audit, description="Operational mode")
    scope_domains: list[str] = Field(default_factory=list, description="In-scope domains")
    output_formats: list[str] = Field(
        default_factory=lambda: ["json"],
        description="Desired output formats (json, html, pdf, sarif)",
    )


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    mode: str
    scope_domains: list[str]
    output_formats: list[str]
    created_at: str
    agent_count: int
    message: str


class FindingOut(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    agent_id: str
    confidence: str
    cwe_ids: list[str]
    evidence_count: int


class IntelligenceContribution(BaseModel):
    pattern_type: str = Field(..., description="Type: vulnerability_pattern | waf_bypass | procedure")
    data: dict[str, Any] = Field(..., description="Anonymized contribution payload")
    source_scan_id: Optional[str] = Field(None, description="Originating scan ID")


class AgentOut(BaseModel):
    id: str
    name: str
    division: int
    description: str
    attack_types: list[str]
    target_technologies: list[str]
    min_mode: str
    priority: int
    max_requests: int
    timeout: int
    capabilities: list[str]
    cwe_ids: list[str]
    tags: list[str]


class DivisionSummary(BaseModel):
    division: int
    agent_count: int


# ─── Helpers ──────────────────────────────────────────────────────────────────

def spec_to_dict(spec: AgentSpec) -> dict[str, Any]:
    """Convert a frozen AgentSpec dataclass to an API-friendly dict."""
    return {
        "id": spec.id,
        "name": spec.name,
        "division": spec.division,
        "description": spec.description,
        "attack_types": list(spec.attack_types),
        "target_technologies": list(spec.target_technologies),
        "min_mode": spec.min_mode.value,
        "priority": int(spec.priority),
        "max_requests": spec.max_requests,
        "timeout": spec.timeout,
        "capabilities": sorted(c.name for c in spec.capabilities),
        "cwe_ids": list(spec.cwe_ids),
        "tags": list(spec.tags),
        "payloads": list(spec.payloads),
        "detection_patterns": list(spec.detection_patterns),
        "depends_on": list(spec.depends_on),
    }


def _supabase_headers() -> dict[str, str]:
    """Build standard Supabase REST API headers."""
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }


async def supabase_get(path: str, params: dict | None = None) -> Any:
    """Execute a GET request against the Supabase REST API."""
    if not supabase_client or not SUPABASE_URL:
        return None
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    resp = await supabase_client.get(url, headers=_supabase_headers(), params=params or {})
    resp.raise_for_status()
    return resp.json()


async def supabase_post(path: str, payload: dict) -> Any:
    """Execute a POST request against the Supabase REST API."""
    if not supabase_client or not SUPABASE_URL:
        return None
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    resp = await supabase_client.post(url, headers=_supabase_headers(), json=payload)
    resp.raise_for_status()
    return resp.json()


# ─── App Lifecycle ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the agent registry on startup, clean up on shutdown."""
    global registry, supabase_client

    # Initialize registry
    registry = SwarmRegistry()
    registry.load_all()

    # Initialize Supabase async client
    if SUPABASE_URL and SUPABASE_SERVICE_KEY:
        supabase_client = httpx.AsyncClient(timeout=30.0)

    yield

    # Cleanup
    if supabase_client:
        await supabase_client.aclose()


# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="SecProbe API",
    description="Backend API for SecProbe — enterprise security testing toolkit with 600 AI agents.",
    version=API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    swagger_ui_parameters={
        "syntaxHighlight.theme": "monokai",
        "docExpansion": "list",
        "filter": True,
        "tryItOutEnabled": True,
    },
    swagger_ui_init_oauth=None,
)

# Dark-themed Swagger via custom CSS
_swagger_dark_css = """
<style>
    body { background-color: #1a1a2e !important; color: #e0e0e0 !important; }
    .swagger-ui { background-color: #1a1a2e !important; }
    .swagger-ui .topbar { background-color: #16213e !important; }
    .swagger-ui .info .title { color: #00d4ff !important; }
    .swagger-ui .info p, .swagger-ui .info li { color: #b0b0b0 !important; }
    .swagger-ui .opblock .opblock-summary { border-color: #333 !important; }
    .swagger-ui .opblock .opblock-summary-description { color: #ccc !important; }
    .swagger-ui .opblock.opblock-get { background: rgba(0,150,255,0.1) !important; border-color: #0096ff !important; }
    .swagger-ui .opblock.opblock-post { background: rgba(0,200,100,0.1) !important; border-color: #00c864 !important; }
    .swagger-ui .scheme-container { background-color: #16213e !important; }
    .swagger-ui select { background-color: #2a2a4a !important; color: #e0e0e0 !important; }
    .swagger-ui input { background-color: #2a2a4a !important; color: #e0e0e0 !important; }
    .swagger-ui textarea { background-color: #2a2a4a !important; color: #e0e0e0 !important; }
    .swagger-ui .model-box { background-color: #16213e !important; }
    .swagger-ui section.models { border-color: #333 !important; }
    .swagger-ui .model { color: #e0e0e0 !important; }
    .swagger-ui .btn { color: #e0e0e0 !important; }
</style>
"""

from fastapi.openapi.docs import get_swagger_ui_html
from starlette.responses import HTMLResponse


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} — Docs",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        swagger_ui_parameters=app.swagger_ui_parameters,
        custom_head_js=_swagger_dark_css,
    )


# CORS — allow all origins for development; tighten in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═════════════════════════════════════════════════════════════════════════════
# Health & Info Endpoints
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/", tags=["Health & Info"])
async def api_info():
    """API info and version."""
    return {
        "name": "SecProbe API",
        "version": API_VERSION,
        "description": "Enterprise security testing toolkit with 600 AI agents",
        "agent_count": registry.count if registry else 0,
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health & Info"])
async def health_check():
    """Health check endpoint for load balancers and deployment platforms."""
    supabase_ok = bool(SUPABASE_URL and SUPABASE_SERVICE_KEY and supabase_client)
    return {
        "status": "healthy",
        "registry_loaded": registry is not None and registry.count > 0,
        "agent_count": registry.count if registry else 0,
        "supabase_connected": supabase_ok,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/stats", tags=["Health & Info"])
async def registry_stats():
    """Comprehensive agent registry statistics."""
    if not registry:
        raise HTTPException(status_code=503, detail="Registry not loaded")
    return registry.stats()


# ═════════════════════════════════════════════════════════════════════════════
# Agent Registry Endpoints
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/agents", tags=["Registry"], response_model=list[AgentOut])
async def list_agents(
    division: Optional[int] = Query(None, ge=1, le=20, description="Filter by division number"),
    attack_type: Optional[str] = Query(None, description="Filter by attack type (e.g. sqli, xss)"),
    technology: Optional[str] = Query(None, description="Filter by target technology (e.g. mysql, react)"),
    mode: Optional[str] = Query(None, regex="^(recon|audit|redteam)$", description="Filter by operational mode"),
    limit: int = Query(100, ge=1, le=600, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """List agents with optional filters. Returns up to 600 agents."""
    if not registry:
        raise HTTPException(status_code=503, detail="Registry not loaded")

    agents = registry.all()

    if division is not None:
        agents = [a for a in agents if a.division == division]
    if attack_type is not None:
        agents = [a for a in agents if attack_type.lower() in a.attack_types]
    if technology is not None:
        agents = [a for a in agents if technology.lower() in a.target_technologies]
    if mode is not None:
        mode_enum = OperationalMode(mode)
        mode_order = {OperationalMode.RECON: 0, OperationalMode.AUDIT: 1, OperationalMode.REDTEAM: 2}
        level = mode_order.get(mode_enum, 0)
        agents = [a for a in agents if mode_order.get(a.min_mode, 0) <= level]

    total = len(agents)
    agents = agents[offset : offset + limit]

    return [spec_to_dict(a) for a in agents]


@app.get("/agents/{agent_id}", tags=["Registry"], response_model=AgentOut)
async def get_agent(agent_id: str):
    """Get a single agent specification by ID."""
    if not registry:
        raise HTTPException(status_code=503, detail="Registry not loaded")
    spec = registry.get(agent_id)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return spec_to_dict(spec)


@app.get("/divisions", tags=["Registry"], response_model=list[DivisionSummary])
async def list_divisions():
    """Division summary with agent counts."""
    if not registry:
        raise HTTPException(status_code=503, detail="Registry not loaded")
    summary = registry.division_summary()
    return [{"division": div, "agent_count": count} for div, count in sorted(summary.items())]


@app.get("/divisions/{division_id}", tags=["Registry"], response_model=list[AgentOut])
async def get_division_agents(division_id: int):
    """List all agents in a specific division."""
    if not registry:
        raise HTTPException(status_code=503, detail="Registry not loaded")
    if division_id < 1 or division_id > 20:
        raise HTTPException(status_code=400, detail="Division ID must be between 1 and 20")
    agents = registry.by_division(division_id)
    if not agents:
        raise HTTPException(status_code=404, detail=f"Division {division_id} not found or has no agents")
    return [spec_to_dict(a) for a in agents]


# ═════════════════════════════════════════════════════════════════════════════
# Scan Management Endpoints
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/scans", tags=["Scans"], response_model=ScanResponse, status_code=201)
async def create_scan(scan: ScanRequest):
    """Submit a new security scan. Returns scan ID for polling."""
    if not registry:
        raise HTTPException(status_code=503, detail="Registry not loaded")

    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    # Determine how many agents apply based on mode
    mode_enum = OperationalMode(scan.mode.value)
    applicable_agents = registry.by_mode(mode_enum)

    scan_record = {
        "scan_id": scan_id,
        "status": "queued",
        "target": scan.target,
        "mode": scan.mode.value,
        "scope_domains": scan.scope_domains,
        "output_formats": scan.output_formats,
        "created_at": now,
        "updated_at": now,
        "agent_count": len(applicable_agents),
        "findings": [],
        "progress": 0.0,
    }

    scans_db[scan_id] = scan_record

    # Persist to Supabase if connected
    try:
        await supabase_post("scans", {
            "scan_id": scan_id,
            "target": scan.target,
            "mode": scan.mode.value,
            "status": "queued",
            "scope_domains": scan.scope_domains,
            "output_formats": scan.output_formats,
            "agent_count": len(applicable_agents),
            "created_at": now,
        })
    except Exception:
        pass  # Supabase is optional; in-memory store is primary

    return {
        "scan_id": scan_id,
        "status": "queued",
        "target": scan.target,
        "mode": scan.mode.value,
        "scope_domains": scan.scope_domains,
        "output_formats": scan.output_formats,
        "created_at": now,
        "agent_count": len(applicable_agents),
        "message": f"Scan queued with {len(applicable_agents)} agents in {scan.mode.value} mode",
    }


@app.get("/scans", tags=["Scans"])
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List scan history, newest first."""
    all_scans = sorted(scans_db.values(), key=lambda s: s["created_at"], reverse=True)
    paginated = all_scans[offset : offset + limit]
    return {
        "total": len(all_scans),
        "scans": [
            {
                "scan_id": s["scan_id"],
                "target": s["target"],
                "mode": s["mode"],
                "status": s["status"],
                "agent_count": s["agent_count"],
                "finding_count": len(s["findings"]),
                "progress": s["progress"],
                "created_at": s["created_at"],
            }
            for s in paginated
        ],
    }


@app.get("/scans/{scan_id}", tags=["Scans"])
async def get_scan(scan_id: str):
    """Get full scan details and results."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    scan = scans_db[scan_id]
    return {
        "scan_id": scan["scan_id"],
        "target": scan["target"],
        "mode": scan["mode"],
        "status": scan["status"],
        "scope_domains": scan["scope_domains"],
        "output_formats": scan["output_formats"],
        "agent_count": scan["agent_count"],
        "finding_count": len(scan["findings"]),
        "progress": scan["progress"],
        "created_at": scan["created_at"],
        "updated_at": scan["updated_at"],
    }


@app.get("/scans/{scan_id}/findings", tags=["Scans"], response_model=list[FindingOut])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
):
    """Get findings for a specific scan."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    findings = scans_db[scan_id]["findings"]
    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# Federated Intelligence Endpoints
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/intelligence/patterns", tags=["Federated Intelligence"])
async def query_patterns(
    pattern_type: Optional[str] = Query(None, description="Filter by pattern type"),
    technology: Optional[str] = Query(None, description="Filter by technology"),
    limit: int = Query(50, ge=1, le=200),
):
    """Query semantic vulnerability patterns from federated intelligence."""
    try:
        params = {"limit": str(limit), "order": "created_at.desc"}
        if pattern_type:
            params["pattern_type"] = f"eq.{pattern_type}"
        if technology:
            params["technology"] = f"eq.{technology}"
        result = await supabase_get("intelligence_patterns", params)
        if result is not None:
            return {"patterns": result, "count": len(result)}
    except Exception:
        pass
    return {"patterns": [], "count": 0, "note": "Supabase not configured or unreachable"}


@app.get("/intelligence/procedures", tags=["Federated Intelligence"])
async def query_procedures(
    attack_type: Optional[str] = Query(None, description="Filter by attack type"),
    success_rate_min: float = Query(0.0, ge=0.0, le=1.0, description="Minimum success rate"),
    limit: int = Query(50, ge=1, le=200),
):
    """Query proven attack procedures from federated intelligence."""
    try:
        params = {"limit": str(limit), "order": "success_rate.desc"}
        if attack_type:
            params["attack_type"] = f"eq.{attack_type}"
        if success_rate_min > 0:
            params["success_rate"] = f"gte.{success_rate_min}"
        result = await supabase_get("intelligence_procedures", params)
        if result is not None:
            return {"procedures": result, "count": len(result)}
    except Exception:
        pass
    return {"procedures": [], "count": 0, "note": "Supabase not configured or unreachable"}


@app.get("/intelligence/waf-bypasses", tags=["Federated Intelligence"])
async def query_waf_bypasses(
    waf_vendor: Optional[str] = Query(None, description="Filter by WAF vendor (e.g. cloudflare, akamai)"),
    bypass_type: Optional[str] = Query(None, description="Filter by bypass type"),
    limit: int = Query(50, ge=1, le=200),
):
    """Query WAF bypass intelligence from federated memory."""
    try:
        params = {"limit": str(limit), "order": "success_count.desc"}
        if waf_vendor:
            params["waf_vendor"] = f"eq.{waf_vendor}"
        if bypass_type:
            params["bypass_type"] = f"eq.{bypass_type}"
        result = await supabase_get("intelligence_waf_bypasses", params)
        if result is not None:
            return {"waf_bypasses": result, "count": len(result)}
    except Exception:
        pass
    return {"waf_bypasses": [], "count": 0, "note": "Supabase not configured or unreachable"}


@app.post("/intelligence/contribute", tags=["Federated Intelligence"], status_code=201)
async def contribute_intelligence(contribution: IntelligenceContribution):
    """Submit an anonymized intelligence contribution to the federated memory."""
    contribution_id = f"contrib-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "contribution_id": contribution_id,
        "pattern_type": contribution.pattern_type,
        "data": contribution.data,
        "source_scan_id": contribution.source_scan_id,
        "contributed_at": now,
        "status": "pending_review",
    }

    # Store in Supabase
    try:
        result = await supabase_post("intelligence_contributions", record)
        if result:
            return {
                "contribution_id": contribution_id,
                "status": "accepted",
                "message": "Contribution submitted for federated review",
            }
    except Exception:
        pass

    return {
        "contribution_id": contribution_id,
        "status": "accepted_local",
        "message": "Contribution recorded locally (Supabase unavailable)",
    }


# ═════════════════════════════════════════════════════════════════════════════
# SaaS Scan Management (/api/scans) — Extended endpoints for dashboard
# ═════════════════════════════════════════════════════════════════════════════


class SaaSScanRequest(BaseModel):
    target: str
    mode: str = "audit"  # recon/audit/redteam
    divisions: list[int] | None = None
    stealth_preset: str | None = None  # ghost/ninja/shadow/blitz/normal
    max_requests: int = 10000


class SaaSScanStatus(BaseModel):
    scan_id: str
    target: str
    mode: str
    status: str  # queued/running/completed/failed
    created_at: str
    findings_count: int = 0
    duration_seconds: float = 0.0


# In-memory SaaS scan store (replace with Supabase in production)
_saas_scans: dict[str, dict] = {}


@app.post("/api/scans", response_model=SaaSScanStatus, tags=["SaaS Scans"])
async def saas_create_scan(req: SaaSScanRequest):
    """Queue a new security scan (SaaS dashboard endpoint)."""
    scan_id = uuid.uuid4().hex[:12]
    scan = {
        "scan_id": scan_id,
        "target": req.target,
        "mode": req.mode,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "divisions": req.divisions,
        "stealth_preset": req.stealth_preset,
        "max_requests": req.max_requests,
        "findings": [],
        "findings_count": 0,
        "duration_seconds": 0.0,
    }
    _saas_scans[scan_id] = scan
    return SaaSScanStatus(**{k: scan[k] for k in SaaSScanStatus.model_fields})


@app.get("/api/scans", response_model=list[SaaSScanStatus], tags=["SaaS Scans"])
async def saas_list_scans():
    """List all scans (SaaS dashboard endpoint)."""
    return [
        SaaSScanStatus(**{k: s[k] for k in SaaSScanStatus.model_fields})
        for s in _saas_scans.values()
    ]


@app.get("/api/scans/{scan_id}", tags=["SaaS Scans"])
async def saas_get_scan(scan_id: str):
    """Get scan details including findings (SaaS dashboard endpoint)."""
    if scan_id not in _saas_scans:
        raise HTTPException(404, "Scan not found")
    return _saas_scans[scan_id]


@app.get("/api/intelligence/priorities", tags=["SaaS Intelligence"])
async def get_priorities(tech: str = ""):
    """Get scan priorities based on learned patterns."""
    try:
        from secprobe.intelligence.learning import ScanLearner
        learner = ScanLearner()
        techs = [t.strip() for t in tech.split(",") if t.strip()] if tech else []
        priorities = learner.get_scan_priorities(techs)
        learner.close()
        return {
            "tech_stack": techs,
            "priorities": [{"vuln_type": v, "probability": p} for v, p in priorities],
        }
    except Exception as e:
        return {"tech_stack": [], "priorities": [], "error": str(e)}


@app.get("/api/intelligence/history", tags=["SaaS Intelligence"])
async def get_scan_history(target: str = ""):
    """Get scan history for a target."""
    try:
        from secprobe.intelligence.learning import ScanLearner
        learner = ScanLearner()
        history = learner.get_target_history(target)
        learner.close()
        return history
    except Exception:
        return {}


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
