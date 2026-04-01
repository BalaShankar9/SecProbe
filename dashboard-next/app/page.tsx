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
} from "lucide-react";
import SeverityPieChart from "@/components/SeverityPieChart";

const stats = [
  {
    label: "Total Scans",
    value: "1,247",
    change: "+12%",
    icon: Crosshair,
    color: "text-accent",
  },
  {
    label: "Findings",
    value: "8,392",
    change: "+5%",
    icon: AlertTriangle,
    color: "text-yellow-400",
  },
  {
    label: "Active Agents",
    value: "600",
    change: "Online",
    icon: Users,
    color: "text-green-400",
  },
  {
    label: "Divisions",
    value: "20",
    change: "All active",
    icon: Building2,
    color: "text-blue-400",
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

function statusBadge(status: string) {
  switch (status) {
    case "complete":
      return "bg-green-500/20 text-green-400 border border-green-500/30";
    case "running":
      return "bg-blue-500/20 text-blue-400 border border-blue-500/30";
    case "failed":
      return "bg-red-500/20 text-red-400 border border-red-500/30";
    default:
      return "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30";
  }
}

export default function DashboardPage() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Dashboard</h1>
          <p className="text-sm text-zinc-500 mt-1">
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
            View Reports
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div key={stat.label} className="card flex items-start justify-between">
            <div>
              <p className="text-sm text-zinc-500">{stat.label}</p>
              <p className="text-2xl font-bold text-zinc-100 mt-1">
                {stat.value}
              </p>
              <p className="text-xs text-zinc-500 mt-1">{stat.change}</p>
            </div>
            <div className="p-2 rounded-lg bg-zinc-800">
              <stat.icon className={`h-5 w-5 ${stat.color}`} />
            </div>
          </div>
        ))}
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans */}
        <div className="lg:col-span-2 card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-zinc-100">
              Recent Scans
            </h2>
            <Link
              href="#"
              className="text-xs text-accent hover:text-accent-hover flex items-center gap-1"
            >
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-700">
                  <th className="text-left py-3 px-2 text-zinc-500 font-medium">
                    Target
                  </th>
                  <th className="text-left py-3 px-2 text-zinc-500 font-medium">
                    Mode
                  </th>
                  <th className="text-left py-3 px-2 text-zinc-500 font-medium">
                    Status
                  </th>
                  <th className="text-right py-3 px-2 text-zinc-500 font-medium">
                    Findings
                  </th>
                  <th className="text-right py-3 px-2 text-zinc-500 font-medium hidden sm:table-cell">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-zinc-800 hover:bg-zinc-800/40 transition-colors"
                  >
                    <td className="py-3 px-2">
                      <Link
                        href={`/scan/${scan.id}`}
                        className="text-zinc-200 hover:text-accent transition-colors font-mono text-xs"
                      >
                        {scan.target}
                      </Link>
                    </td>
                    <td className="py-3 px-2 text-zinc-400">{scan.mode}</td>
                    <td className="py-3 px-2">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusBadge(scan.status)}`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3 px-2 text-right text-zinc-300 font-mono">
                      {scan.findings}
                    </td>
                    <td className="py-3 px-2 text-right text-zinc-500 text-xs hidden sm:table-cell">
                      <span className="flex items-center justify-end gap-1">
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

        {/* Severity Breakdown */}
        <div className="card">
          <h2 className="text-lg font-semibold text-zinc-100 mb-4">
            Severity Breakdown
          </h2>
          <SeverityPieChart />
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <Link
          href="/scan"
          className="card hover:bg-card-hover transition-colors group cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-accent/10">
              <Crosshair className="h-6 w-6 text-accent" />
            </div>
            <div>
              <h3 className="font-medium text-zinc-100 group-hover:text-accent transition-colors">
                Launch New Scan
              </h3>
              <p className="text-xs text-zinc-500 mt-0.5">
                Configure and start a security assessment
              </p>
            </div>
          </div>
        </Link>
        <Link
          href="/agents"
          className="card hover:bg-card-hover transition-colors group cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-green-500/10">
              <Users className="h-6 w-6 text-green-400" />
            </div>
            <div>
              <h3 className="font-medium text-zinc-100 group-hover:text-green-400 transition-colors">
                Agent Explorer
              </h3>
              <p className="text-xs text-zinc-500 mt-0.5">
                Browse 600 agents across 20 divisions
              </p>
            </div>
          </div>
        </Link>
        <Link
          href="#"
          className="card hover:bg-card-hover transition-colors group cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-blue-500/10">
              <Shield className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <h3 className="font-medium text-zinc-100 group-hover:text-blue-400 transition-colors">
                Compliance Reports
              </h3>
              <p className="text-xs text-zinc-500 mt-0.5">
                OWASP, PCI-DSS, SOC2 compliance status
              </p>
            </div>
          </div>
        </Link>
      </div>
    </div>
  );
}
