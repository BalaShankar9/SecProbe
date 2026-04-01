const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ||
  "https://feisty-reflection-production.up.railway.app";

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export interface ScanRequest {
  target: string;
  mode: "recon" | "audit" | "redteam";
  stealth_preset: string;
  max_requests: number;
  divisions: string[];
}

export interface ScanResult {
  id: string;
  target: string;
  status: "running" | "complete" | "failed";
  mode: string;
  started_at: string;
  completed_at?: string;
  findings: Finding[];
  summary?: ScanSummary;
}

export interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence?: string;
  recommendation?: string;
  cwe?: string;
  agent?: string;
  division?: string;
}

export interface ScanSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  duration_seconds: number;
}

export const DIVISIONS = [
  "Reconnaissance",
  "Injection",
  "Authentication",
  "Authorization",
  "XSS",
  "CSRF",
  "SSRF",
  "File Upload",
  "API Security",
  "Business Logic",
  "Cryptography",
  "Session Management",
  "Information Disclosure",
  "Configuration",
  "Infrastructure",
  "Mobile Security",
  "Cloud Security",
  "Supply Chain",
  "Rate Limiting",
  "Compliance",
] as const;

export const STEALTH_PRESETS = [
  { value: "none", label: "None - Full speed" },
  { value: "low", label: "Low - Light evasion" },
  { value: "medium", label: "Medium - Moderate evasion" },
  { value: "high", label: "High - Heavy evasion" },
  { value: "paranoid", label: "Paranoid - Maximum stealth" },
] as const;

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "#ef4444";
    case "high":
      return "#f97316";
    case "medium":
      return "#f59e0b";
    case "low":
      return "#3b82f6";
    case "info":
      return "#6b7280";
    default:
      return "#6b7280";
  }
}

export function severityBadgeClass(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "high":
      return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "medium":
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "low":
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case "info":
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}
