"use client";

import Link from "next/link";
import {
  Shield,
  Crosshair,
  FileText,
  Users,
  Building2,
  AlertTriangle,
  ArrowRight,
  Clock,
  Activity,
  Zap,
} from "lucide-react";
import SeverityPieChart from "@/components/SeverityPieChart";
import AnimatedCounter from "@/components/AnimatedCounter";

const stats = [
  {
    label: "Total Scans",
    value: 1247,
    change: "+12%",
    icon: Crosshair,
    color: "#6366f1",
    glowClass: "shadow-glow-accent",
  },
  {
    label: "Findings",
    value: 8392,
    change: "+5%",
    icon: AlertTriangle,
    color: "#ff9100",
    glowClass: "",
  },
  {
    label: "Active Agents",
    value: 600,
    change: "Online",
    icon: Users,
    color: "#69f0ae",
    glowClass: "",
  },
  {
    label: "Divisions",
    value: 20,
    change: "All active",
    icon: Building2,
    color: "#00e5ff",
    glowClass: "",
  },
];

const recentScans = [
  {
    id: "scan-001",
    target: "https://app.example.com",
    mode: "Audit",
    status: "complete",
    findings: 23,
    time: "2 hours ago",
  },
  {
    id: "scan-002",
    target: "https://api.staging.io",
    mode: "Red Team",
    status: "running",
    findings: 8,
    time: "Running...",
  },
  {
    id: "scan-003",
    target: "https://portal.corp.net",
    mode: "Recon",
    status: "complete",
    findings: 45,
    time: "5 hours ago",
  },
  {
    id: "scan-004",
    target: "https://store.example.com",
    mode: "Audit",
    status: "failed",
    findings: 0,
    time: "1 day ago",
  },
  {
    id: "scan-005",
    target: "https://internal.dev.local",
    mode: "Red Team",
    status: "complete",
    findings: 67,
    time: "1 day ago",
  },
];

const severityBreakdown = [
  { label: "Critical", count: 12, color: "#ff1744", percent: 8 },
  { label: "High", count: 47, color: "#ff9100", percent: 22 },
  { label: "Medium", count: 89, color: "#ffea00", percent: 35 },
  { label: "Low", count: 134, color: "#00e5ff", percent: 25 },
  { label: "Info", count: 56, color: "#69f0ae", percent: 10 },
];

function statusBadge(status: string) {
  switch (status) {
    case "complete":
      return "bg-[#69f0ae]/10 text-[#69f0ae] border border-[#69f0ae]/20";
    case "running":
      return "bg-[#00e5ff]/10 text-[#00e5ff] border border-[#00e5ff]/20";
    case "failed":
      return "bg-[#ff1744]/10 text-[#ff1744] border border-[#ff1744]/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border border-zinc-500/20";
  }
}

function ThreatGauge() {
  const level = 62; // percent
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-zinc-500 font-mono uppercase tracking-wider">Threat Level</span>
        <span className="text-sm font-mono font-bold text-[#ff9100]">{level}%</span>
      </div>
      <div className="relative h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all duration-1000"
          style={{
            width: `${level}%`,
            background: `linear-gradient(90deg, #69f0ae, #ffea00, #ff9100, #ff1744)`,
            boxShadow: "0 0 10px rgba(255, 145, 0, 0.4)",
          }}
        />
      </div>
      <div className="flex justify-between text-[9px] text-zinc-600 font-mono">
        <span>LOW</span>
        <span>MODERATE</span>
        <span>HIGH</span>
        <span>CRITICAL</span>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Command Center
          </h1>
          <p className="text-sm text-zinc-600 mt-1 font-mono">
            Security operations overview
          </p>
        </div>
        <div className="flex gap-3">
          <Link href="/scan" className="btn-primary flex items-center gap-2">
            <Crosshair className="h-4 w-4" />
            New Scan
          </Link>
          <Link href="#" className="btn-secondary flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Reports
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, i) => (
          <div
            key={stat.label}
            className="card group relative overflow-hidden"
            style={{ animationDelay: `${i * 100}ms` }}
          >
            {/* Top accent line */}
            <div className="absolute top-0 left-0 right-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${stat.color}40, transparent)` }} />
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[10px] text-zinc-600 uppercase tracking-wider font-mono">{stat.label}</p>
                <p className="text-3xl font-bold text-white mt-2 font-mono">
                  <AnimatedCounter value={stat.value} />
                </p>
                <p className="text-xs mt-1.5 font-mono" style={{ color: stat.color }}>
                  {stat.change}
                </p>
              </div>
              <div
                className="p-2.5 rounded-lg transition-all duration-300 group-hover:scale-110"
                style={{ background: `${stat.color}10` }}
              >
                <stat.icon
                  className="h-5 w-5 transition-all duration-300"
                  style={{ color: stat.color, filter: `drop-shadow(0 0 4px ${stat.color}40)` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Threat Level + Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main content area */}
        <div className="lg:col-span-2 space-y-6">
          {/* Threat Gauge */}
          <div className="card">
            <ThreatGauge />
          </div>

          {/* Severity Bars */}
          <div className="card">
            <h2 className="text-sm font-semibold text-white mb-4 uppercase tracking-wider">
              Severity Breakdown
            </h2>
            <div className="space-y-3">
              {severityBreakdown.map((item) => (
                <div key={item.label} className="group">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-zinc-500">{item.label}</span>
                    <span className="text-xs font-mono font-medium" style={{ color: item.color }}>
                      {item.count}
                    </span>
                  </div>
                  <div className="relative h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.03)" }}>
                    <div
                      className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
                      style={{
                        width: `${item.percent}%`,
                        backgroundColor: item.color,
                        boxShadow: `0 0 8px ${item.color}30`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Pie Chart */}
        <div className="card">
          <h2 className="text-sm font-semibold text-white mb-4 uppercase tracking-wider">
            Distribution
          </h2>
          <SeverityPieChart />
        </div>
      </div>

      {/* Live Agent Status + Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans */}
        <div className="lg:col-span-2 card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
              Recent Scans
            </h2>
            <Link
              href="#"
              className="text-[11px] text-accent hover:text-accent-hover flex items-center gap-1 font-mono transition-colors"
            >
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/5">
                  <th className="text-left py-3 px-2 text-[10px] text-zinc-600 font-mono uppercase tracking-wider font-medium">
                    Target
                  </th>
                  <th className="text-left py-3 px-2 text-[10px] text-zinc-600 font-mono uppercase tracking-wider font-medium">
                    Mode
                  </th>
                  <th className="text-left py-3 px-2 text-[10px] text-zinc-600 font-mono uppercase tracking-wider font-medium">
                    Status
                  </th>
                  <th className="text-right py-3 px-2 text-[10px] text-zinc-600 font-mono uppercase tracking-wider font-medium">
                    Findings
                  </th>
                  <th className="text-right py-3 px-2 text-[10px] text-zinc-600 font-mono uppercase tracking-wider font-medium hidden sm:table-cell">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-white/[0.03] row-glow"
                  >
                    <td className="py-3 px-2">
                      <Link
                        href={`/scan/${scan.id}`}
                        className="text-zinc-300 hover:text-neon-cyan transition-colors font-mono text-xs"
                      >
                        {scan.target}
                      </Link>
                    </td>
                    <td className="py-3 px-2 text-zinc-500 text-xs font-mono">{scan.mode}</td>
                    <td className="py-3 px-2">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-medium ${statusBadge(scan.status)}`}
                      >
                        {scan.status === "running" && (
                          <span className="h-1.5 w-1.5 rounded-full bg-[#00e5ff] mr-1.5 animate-pulse" />
                        )}
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3 px-2 text-right text-zinc-400 font-mono text-xs">
                      {scan.findings}
                    </td>
                    <td className="py-3 px-2 text-right text-zinc-600 text-[11px] hidden sm:table-cell">
                      <span className="flex items-center justify-end gap-1 font-mono">
                        <Clock className="h-3 w-3" />
                        {scan.time}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Agent Status */}
        <div className="card space-y-4">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
            Live Agent Status
          </h2>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: "rgba(105, 240, 174, 0.05)", border: "1px solid rgba(105, 240, 174, 0.1)" }}>
              <div className="flex items-center gap-2">
                <span className="status-online" />
                <span className="text-xs text-zinc-400 font-mono">Active</span>
              </div>
              <span className="text-lg font-bold font-mono text-[#69f0ae]">
                <AnimatedCounter value={584} />
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: "rgba(0, 229, 255, 0.05)", border: "1px solid rgba(0, 229, 255, 0.1)" }}>
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[#00e5ff]" style={{ boxShadow: "0 0 6px rgba(0, 229, 255, 0.5)" }} />
                <span className="text-xs text-zinc-400 font-mono">Idle</span>
              </div>
              <span className="text-lg font-bold font-mono text-[#00e5ff]">
                <AnimatedCounter value={16} />
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg" style={{ background: "rgba(255, 23, 68, 0.05)", border: "1px solid rgba(255, 23, 68, 0.1)" }}>
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[#ff1744] opacity-50" />
                <span className="text-xs text-zinc-400 font-mono">Offline</span>
              </div>
              <span className="text-lg font-bold font-mono text-zinc-500">
                <AnimatedCounter value={0} />
              </span>
            </div>
          </div>

          <div className="pt-2 border-t border-white/5">
            <div className="flex items-center gap-2 text-[10px] text-zinc-600 font-mono">
              <Activity className="h-3 w-3 text-neon-green" />
              <span>Avg response: 1.2ms</span>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-zinc-600 font-mono mt-1.5">
              <Zap className="h-3 w-3 text-neon-cyan" />
              <span>20 divisions operational</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <Link
          href="/scan"
          className="card group cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div
              className="p-3 rounded-lg transition-all duration-300 group-hover:scale-110"
              style={{ background: "rgba(99, 102, 241, 0.1)" }}
            >
              <Crosshair className="h-6 w-6 text-accent transition-all duration-300" style={{ filter: "drop-shadow(0 0 4px rgba(99, 102, 241, 0.3))" }} />
            </div>
            <div>
              <h3 className="font-medium text-zinc-200 group-hover:text-white transition-colors text-sm">
                Launch New Scan
              </h3>
              <p className="text-[11px] text-zinc-600 mt-0.5 font-mono">
                Configure and start assessment
              </p>
            </div>
            <ArrowRight className="h-4 w-4 text-zinc-700 group-hover:text-accent group-hover:translate-x-1 transition-all duration-300 ml-auto" />
          </div>
        </Link>
        <Link
          href="/agents"
          className="card group cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div
              className="p-3 rounded-lg transition-all duration-300 group-hover:scale-110"
              style={{ background: "rgba(105, 240, 174, 0.1)" }}
            >
              <Users className="h-6 w-6 text-[#69f0ae] transition-all duration-300" style={{ filter: "drop-shadow(0 0 4px rgba(105, 240, 174, 0.3))" }} />
            </div>
            <div>
              <h3 className="font-medium text-zinc-200 group-hover:text-white transition-colors text-sm">
                Agent Explorer
              </h3>
              <p className="text-[11px] text-zinc-600 mt-0.5 font-mono">
                Browse 600 agents, 20 divisions
              </p>
            </div>
            <ArrowRight className="h-4 w-4 text-zinc-700 group-hover:text-[#69f0ae] group-hover:translate-x-1 transition-all duration-300 ml-auto" />
          </div>
        </Link>
        <Link
          href="#"
          className="card group cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div
              className="p-3 rounded-lg transition-all duration-300 group-hover:scale-110"
              style={{ background: "rgba(0, 229, 255, 0.1)" }}
            >
              <Shield className="h-6 w-6 text-neon-cyan transition-all duration-300" style={{ filter: "drop-shadow(0 0 4px rgba(0, 229, 255, 0.3))" }} />
            </div>
            <div>
              <h3 className="font-medium text-zinc-200 group-hover:text-white transition-colors text-sm">
                Compliance Reports
              </h3>
              <p className="text-[11px] text-zinc-600 mt-0.5 font-mono">
                OWASP, PCI-DSS, SOC2 status
              </p>
            </div>
            <ArrowRight className="h-4 w-4 text-zinc-700 group-hover:text-neon-cyan group-hover:translate-x-1 transition-all duration-300 ml-auto" />
          </div>
        </Link>
      </div>
    </div>
  );
}
