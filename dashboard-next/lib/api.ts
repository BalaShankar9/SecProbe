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
      return "#ff1744";
    case "high":
      return "#ff9100";
    case "medium":
      return "#ffea00";
    case "low":
      return "#00e5ff";
    case "info":
      return "#69f0ae";
    default:
      return "#69f0ae";
  }
}

export function severityBadgeClass(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-[#ff1744]/20 text-[#ff1744] border-[#ff1744]/30";
    case "high":
      return "bg-[#ff9100]/20 text-[#ff9100] border-[#ff9100]/30";
    case "medium":
      return "bg-[#ffea00]/20 text-[#ffea00] border-[#ffea00]/30";
    case "low":
      return "bg-[#00e5ff]/20 text-[#00e5ff] border-[#00e5ff]/30";
    case "info":
      return "bg-[#69f0ae]/20 text-[#69f0ae] border-[#69f0ae]/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}
