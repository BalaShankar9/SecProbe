-- SecProbe Federated Memory Schema
-- 5-tier memory system: L3 (semantic), L4 (procedural), L5 (federated)
-- L1 (working) and L2 (episodic) are in-process/local — not stored here

-- ═══════════════════════════════════════════════════════════════════════
-- L3: Semantic Patterns — Learned cross-scan intelligence
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS semantic_patterns (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    conditions JSONB NOT NULL DEFAULT '{}',
    predictions JSONB NOT NULL DEFAULT '{}',
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence_count INTEGER NOT NULL DEFAULT 1,
    false_positive_rate REAL NOT NULL DEFAULT 0.0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_semantic_category ON semantic_patterns(category);
CREATE INDEX idx_semantic_confidence ON semantic_patterns(confidence DESC);
CREATE INDEX idx_semantic_conditions ON semantic_patterns USING GIN(conditions);
CREATE INDEX idx_semantic_tags ON semantic_patterns USING GIN(tags);

-- ═══════════════════════════════════════════════════════════════════════
-- L4: Procedural Memory — Proven attack sequences
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS procedures (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    steps JSONB NOT NULL DEFAULT '[]',
    applicability JSONB NOT NULL DEFAULT '{}',
    success_count INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    avg_duration REAL NOT NULL DEFAULT 0.0,
    first_recorded TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used TIMESTAMPTZ,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_procedures_category ON procedures(category);
CREATE INDEX idx_procedures_applicability ON procedures USING GIN(applicability);
CREATE INDEX idx_procedures_success ON procedures((success_count::REAL / GREATEST(attempt_count, 1)) DESC);

-- ═══════════════════════════════════════════════════════════════════════
-- L5: Federated Intelligence — Anonymized community data
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS federated_insights (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    conditions JSONB NOT NULL DEFAULT '{}',
    insight TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    contributors INTEGER NOT NULL DEFAULT 1,
    success_rate REAL NOT NULL DEFAULT 0.0,
    sample_size INTEGER NOT NULL DEFAULT 1,
    payload_hash TEXT DEFAULT '',
    first_reported TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_federated_category ON federated_insights(category);
CREATE INDEX idx_federated_confidence ON federated_insights(confidence DESC);
CREATE INDEX idx_federated_conditions ON federated_insights USING GIN(conditions);

-- Contributions from users (anonymized — no target URLs or org data)
CREATE TABLE IF NOT EXISTS federated_contributions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technology TEXT NOT NULL DEFAULT '',
    technology_version TEXT DEFAULT '',
    vulnerability_type TEXT NOT NULL DEFAULT '',
    waf_detected TEXT DEFAULT '',
    payload_hash TEXT DEFAULT '',
    success BOOLEAN NOT NULL DEFAULT FALSE,
    evasion_technique TEXT DEFAULT '',
    contributed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_contributions_tech ON federated_contributions(technology);
CREATE INDEX idx_contributions_vuln ON federated_contributions(vulnerability_type);
CREATE INDEX idx_contributions_waf ON federated_contributions(waf_detected);
CREATE INDEX idx_contributions_success ON federated_contributions(success);

-- ═══════════════════════════════════════════════════════════════════════
-- Scan History — Track scans for diff reports and trending
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    target_hash TEXT NOT NULL,  -- SHA256 of target URL (privacy)
    mode TEXT NOT NULL CHECK (mode IN ('recon', 'audit', 'redteam')),
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    findings_summary JSONB NOT NULL DEFAULT '{}',
    agents_deployed INTEGER NOT NULL DEFAULT 0,
    divisions_activated INTEGER[] DEFAULT '{}',
    total_requests INTEGER NOT NULL DEFAULT 0,
    tech_profile JSONB NOT NULL DEFAULT '{}',
    risk_score REAL DEFAULT 0.0,
    grade TEXT DEFAULT '',
    consensus_stats JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_target ON scan_sessions(target_hash);
CREATE INDEX idx_scans_time ON scan_sessions(start_time DESC);
CREATE INDEX idx_scans_grade ON scan_sessions(grade);

-- ═══════════════════════════════════════════════════════════════════════
-- Agent Performance — Track agent effectiveness for self-improvement
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS agent_performance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    division INTEGER NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    confirmed_count INTEGER NOT NULL DEFAULT 0,
    false_positive_count INTEGER NOT NULL DEFAULT 0,
    requests_made INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_perf_agent ON agent_performance(agent_id);
CREATE INDEX idx_agent_perf_scan ON agent_performance(scan_id);
CREATE INDEX idx_agent_perf_division ON agent_performance(division);

-- ═══════════════════════════════════════════════════════════════════════
-- WAF Bypass Intelligence — Community WAF bypass knowledge
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS waf_bypass_intel (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    waf_name TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    evasion_technique TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sample_count INTEGER NOT NULL DEFAULT 1,
    last_success TIMESTAMPTZ
);

CREATE INDEX idx_waf_bypass_waf ON waf_bypass_intel(waf_name);
CREATE INDEX idx_waf_bypass_technique ON waf_bypass_intel(evasion_technique);
CREATE INDEX idx_waf_bypass_success ON waf_bypass_intel(success);

-- ═══════════════════════════════════════════════════════════════════════
-- RLS Policies — Security first
-- ═══════════════════════════════════════════════════════════════════════

ALTER TABLE semantic_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE procedures ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_insights ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_contributions ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_performance ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_bypass_intel ENABLE ROW LEVEL SECURITY;

-- Service role has full access (used by SecProbe backend)
CREATE POLICY "Service role full access" ON semantic_patterns FOR ALL USING (true);
CREATE POLICY "Service role full access" ON procedures FOR ALL USING (true);
CREATE POLICY "Service role full access" ON federated_insights FOR ALL USING (true);
CREATE POLICY "Service role full access" ON federated_contributions FOR ALL USING (true);
CREATE POLICY "Service role full access" ON scan_sessions FOR ALL USING (true);
CREATE POLICY "Service role full access" ON agent_performance FOR ALL USING (true);
CREATE POLICY "Service role full access" ON waf_bypass_intel FOR ALL USING (true);

-- Anon can read federated insights (community intelligence is public)
CREATE POLICY "Anon read federated" ON federated_insights FOR SELECT USING (true);
CREATE POLICY "Anon read waf bypass" ON waf_bypass_intel FOR SELECT USING (true);
