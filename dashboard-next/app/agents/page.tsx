"use client";

import { useState, useMemo } from "react";
import {
  Users,
  ChevronDown,
  ChevronRight,
  Search,
  Filter,
  Activity,
} from "lucide-react";

interface Agent {
  name: string;
  type: string;
  mode: string;
  description: string;
}

interface Division {
  name: string;
  description: string;
  agentCount: number;
  color: string;
  agents: Agent[];
}

const divisions: Division[] = [
  {
    name: "Reconnaissance",
    description: "Passive and active information gathering",
    agentCount: 30,
    color: "#3b82f6",
    agents: [
      { name: "SubEnum-Alpha", type: "Subdomain Enumeration", mode: "recon", description: "DNS-based subdomain discovery" },
      { name: "PortScan-Beta", type: "Port Scanning", mode: "recon", description: "TCP/UDP port enumeration" },
      { name: "TechDetect-Gamma", type: "Technology Fingerprinting", mode: "recon", description: "Identifies web technologies and frameworks" },
      { name: "DirBust-Delta", type: "Directory Brute Force", mode: "recon", description: "Hidden path and file discovery" },
      { name: "OSINT-Epsilon", type: "Open Source Intelligence", mode: "recon", description: "Public information aggregation" },
    ],
  },
  {
    name: "Injection",
    description: "SQL, NoSQL, LDAP, command injection testing",
    agentCount: 45,
    color: "#ef4444",
    agents: [
      { name: "SQLi-Hunter-Alpha", type: "SQL Injection", mode: "audit", description: "Union-based, blind, and time-based SQLi" },
      { name: "NoSQLi-Probe", type: "NoSQL Injection", mode: "audit", description: "MongoDB and CouchDB injection testing" },
      { name: "CMDi-Scanner", type: "Command Injection", mode: "redteam", description: "OS command injection detection" },
      { name: "LDAPi-Checker", type: "LDAP Injection", mode: "audit", description: "LDAP query manipulation testing" },
      { name: "XPathi-Probe", type: "XPath Injection", mode: "audit", description: "XML path injection detection" },
    ],
  },
  {
    name: "Authentication",
    description: "Login, session, and credential testing",
    agentCount: 35,
    color: "#f59e0b",
    agents: [
      { name: "BruteForce-Alpha", type: "Credential Stuffing", mode: "redteam", description: "Distributed credential testing" },
      { name: "PassPolicy-Beta", type: "Password Policy", mode: "audit", description: "Password strength and policy analysis" },
      { name: "MFA-Bypass-Gamma", type: "MFA Testing", mode: "redteam", description: "Multi-factor authentication bypass" },
      { name: "OAuth-Scanner", type: "OAuth Testing", mode: "audit", description: "OAuth flow vulnerability detection" },
      { name: "JWT-Analyzer", type: "JWT Testing", mode: "audit", description: "JWT forgery and misconfiguration checks" },
    ],
  },
  {
    name: "Authorization",
    description: "Access control and privilege escalation",
    agentCount: 30,
    color: "#f97316",
    agents: [
      { name: "IDOR-Hunter", type: "IDOR Testing", mode: "audit", description: "Insecure direct object reference detection" },
      { name: "PrivEsc-Scanner", type: "Privilege Escalation", mode: "redteam", description: "Vertical and horizontal privilege escalation" },
      { name: "RBAC-Checker", type: "Role Testing", mode: "audit", description: "Role-based access control verification" },
      { name: "PathTraversal-Probe", type: "Path Traversal", mode: "audit", description: "Directory traversal vulnerability testing" },
    ],
  },
  {
    name: "XSS",
    description: "Cross-site scripting detection",
    agentCount: 40,
    color: "#a855f7",
    agents: [
      { name: "XSS-Probe-Beta", type: "Reflected XSS", mode: "audit", description: "Reflected cross-site scripting detection" },
      { name: "StoredXSS-Hunter", type: "Stored XSS", mode: "audit", description: "Persistent XSS payload injection" },
      { name: "DOM-XSS-Scanner", type: "DOM XSS", mode: "audit", description: "DOM-based XSS source-sink analysis" },
      { name: "XSS-Filter-Bypass", type: "WAF Bypass", mode: "redteam", description: "XSS filter and WAF evasion" },
    ],
  },
  {
    name: "CSRF",
    description: "Cross-site request forgery testing",
    agentCount: 20,
    color: "#ec4899",
    agents: [
      { name: "CSRF-Token-Checker", type: "Token Analysis", mode: "audit", description: "CSRF token validation testing" },
      { name: "SameSite-Scanner", type: "Cookie Analysis", mode: "audit", description: "SameSite cookie attribute verification" },
      { name: "CSRF-PoC-Gen", type: "PoC Generation", mode: "redteam", description: "Generates proof-of-concept CSRF attacks" },
    ],
  },
  {
    name: "SSRF",
    description: "Server-side request forgery detection",
    agentCount: 25,
    color: "#14b8a6",
    agents: [
      { name: "SSRF-Blind-Hunter", type: "Blind SSRF", mode: "audit", description: "Out-of-band SSRF detection" },
      { name: "SSRF-Cloud-Meta", type: "Cloud Metadata", mode: "redteam", description: "Cloud metadata endpoint access testing" },
      { name: "SSRF-Protocol", type: "Protocol Smuggling", mode: "redteam", description: "Protocol handler abuse detection" },
    ],
  },
  {
    name: "File Upload",
    description: "File upload vulnerability testing",
    agentCount: 20,
    color: "#84cc16",
    agents: [
      { name: "Upload-Bypass", type: "Extension Bypass", mode: "audit", description: "File extension filter bypass testing" },
      { name: "MalFile-Gen", type: "Malicious Files", mode: "redteam", description: "Polyglot and embedded payload testing" },
      { name: "Upload-Size-Bomb", type: "DoS Testing", mode: "redteam", description: "File size limit and resource exhaustion" },
    ],
  },
  {
    name: "API Security",
    description: "REST, GraphQL, gRPC API testing",
    agentCount: 40,
    color: "#06b6d4",
    agents: [
      { name: "API-Fuzz-Alpha", type: "API Fuzzing", mode: "audit", description: "Automated API endpoint fuzzing" },
      { name: "GraphQL-Scanner", type: "GraphQL Testing", mode: "audit", description: "Introspection and query abuse detection" },
      { name: "REST-Audit", type: "REST Analysis", mode: "audit", description: "REST API security best practices audit" },
      { name: "API-Rate-Checker", type: "Rate Limiting", mode: "audit", description: "API rate limit detection and bypass" },
    ],
  },
  {
    name: "Business Logic",
    description: "Application logic flaw detection",
    agentCount: 30,
    color: "#8b5cf6",
    agents: [
      { name: "Logic-Flow-Analyzer", type: "Flow Analysis", mode: "audit", description: "Business process flow analysis" },
      { name: "Race-Condition-Hunter", type: "Race Conditions", mode: "redteam", description: "TOCTOU and race condition detection" },
      { name: "Price-Tamper-Scanner", type: "Price Manipulation", mode: "audit", description: "E-commerce price tampering detection" },
    ],
  },
  {
    name: "Cryptography",
    description: "Encryption and hashing analysis",
    agentCount: 25,
    color: "#0ea5e9",
    agents: [
      { name: "Crypto-Auditor", type: "Cipher Analysis", mode: "audit", description: "Weak cipher and protocol detection" },
      { name: "TLS-Scanner", type: "TLS Testing", mode: "audit", description: "TLS configuration audit" },
      { name: "Hash-Cracker", type: "Hash Analysis", mode: "redteam", description: "Password hash identification and testing" },
    ],
  },
  {
    name: "Session Management",
    description: "Session security testing",
    agentCount: 25,
    color: "#f43f5e",
    agents: [
      { name: "Session-Auditor", type: "Session Analysis", mode: "audit", description: "Session token strength and lifecycle" },
      { name: "Fixation-Scanner", type: "Session Fixation", mode: "audit", description: "Session fixation vulnerability detection" },
      { name: "Cookie-Checker", type: "Cookie Analysis", mode: "audit", description: "Cookie security attribute verification" },
    ],
  },
  {
    name: "Information Disclosure",
    description: "Sensitive data exposure detection",
    agentCount: 30,
    color: "#d946ef",
    agents: [
      { name: "InfoDisc-Scanner", type: "Header Analysis", mode: "recon", description: "Server header information leakage" },
      { name: "Error-Harvester", type: "Error Analysis", mode: "audit", description: "Verbose error message detection" },
      { name: "Source-Map-Scanner", type: "Source Maps", mode: "recon", description: "Exposed source map detection" },
      { name: "Git-Exposed", type: "Git Exposure", mode: "recon", description: ".git directory exposure detection" },
    ],
  },
  {
    name: "Configuration",
    description: "Server and application misconfiguration",
    agentCount: 30,
    color: "#eab308",
    agents: [
      { name: "Config-Auditor", type: "Security Headers", mode: "audit", description: "HTTP security header analysis" },
      { name: "CORS-Scanner", type: "CORS Testing", mode: "audit", description: "Cross-origin policy misconfiguration" },
      { name: "Default-Cred-Checker", type: "Default Credentials", mode: "audit", description: "Default password detection" },
    ],
  },
  {
    name: "Infrastructure",
    description: "Network and infrastructure security",
    agentCount: 35,
    color: "#64748b",
    agents: [
      { name: "DNS-Auditor", type: "DNS Testing", mode: "recon", description: "DNS misconfiguration and zone transfer" },
      { name: "Cloud-Enum", type: "Cloud Discovery", mode: "recon", description: "Cloud resource enumeration" },
      { name: "Container-Scanner", type: "Container Security", mode: "audit", description: "Docker and Kubernetes security" },
    ],
  },
  {
    name: "Mobile Security",
    description: "Mobile API and backend testing",
    agentCount: 25,
    color: "#22d3ee",
    agents: [
      { name: "Mobile-API-Scanner", type: "Mobile API", mode: "audit", description: "Mobile backend API security testing" },
      { name: "Cert-Pin-Checker", type: "Certificate Pinning", mode: "audit", description: "Certificate pinning bypass testing" },
      { name: "Deep-Link-Scanner", type: "Deep Links", mode: "audit", description: "Deep link and intent redirection testing" },
    ],
  },
  {
    name: "Cloud Security",
    description: "Cloud-specific vulnerability testing",
    agentCount: 30,
    color: "#2dd4bf",
    agents: [
      { name: "S3-Bucket-Scanner", type: "S3 Security", mode: "recon", description: "S3 bucket misconfiguration detection" },
      { name: "IAM-Auditor", type: "IAM Testing", mode: "audit", description: "Cloud IAM policy analysis" },
      { name: "Lambda-Scanner", type: "Serverless Testing", mode: "audit", description: "Serverless function security audit" },
    ],
  },
  {
    name: "Supply Chain",
    description: "Dependency and supply chain analysis",
    agentCount: 20,
    color: "#fb923c",
    agents: [
      { name: "Dep-Scanner", type: "Dependency Audit", mode: "audit", description: "Known vulnerability detection in dependencies" },
      { name: "SCA-Analyzer", type: "SCA", mode: "audit", description: "Software composition analysis" },
      { name: "Typosquat-Checker", type: "Typosquatting", mode: "recon", description: "Package typosquatting detection" },
    ],
  },
  {
    name: "Rate Limiting",
    description: "Rate limit and DoS resilience testing",
    agentCount: 20,
    color: "#fbbf24",
    agents: [
      { name: "RateLimit-Scanner", type: "Rate Limit Testing", mode: "audit", description: "Rate limit detection and bypass" },
      { name: "Slowloris-Probe", type: "Slow DoS", mode: "redteam", description: "Slow HTTP attack simulation" },
      { name: "ReDoS-Scanner", type: "ReDoS", mode: "audit", description: "Regular expression DoS detection" },
    ],
  },
  {
    name: "Compliance",
    description: "Regulatory compliance verification",
    agentCount: 25,
    color: "#a3e635",
    agents: [
      { name: "OWASP-Checker", type: "OWASP Top 10", mode: "audit", description: "OWASP Top 10 compliance verification" },
      { name: "PCI-Scanner", type: "PCI-DSS", mode: "audit", description: "PCI DSS requirement validation" },
      { name: "GDPR-Auditor", type: "GDPR", mode: "audit", description: "GDPR data protection compliance" },
      { name: "SOC2-Checker", type: "SOC 2", mode: "audit", description: "SOC 2 control verification" },
    ],
  },
];

const attackTypes = [
  "All Types",
  "SQL Injection",
  "XSS",
  "SSRF",
  "Fuzzing",
  "Credential Testing",
  "Port Scanning",
  "API Testing",
];
const modeFilters = ["All Modes", "recon", "audit", "redteam"];

const modeColors: Record<string, { bg: string; text: string; border: string }> = {
  recon: { bg: "rgba(0, 229, 255, 0.1)", text: "#00e5ff", border: "rgba(0, 229, 255, 0.2)" },
  audit: { bg: "rgba(255, 234, 0, 0.1)", text: "#ffea00", border: "rgba(255, 234, 0, 0.2)" },
  redteam: { bg: "rgba(255, 23, 68, 0.1)", text: "#ff1744", border: "rgba(255, 23, 68, 0.2)" },
};

export default function AgentsPage() {
  const [expandedDivision, setExpandedDivision] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("All Types");
  const [modeFilter, setModeFilter] = useState("All Modes");

  const filteredDivisions = useMemo(() => {
    return divisions
      .map((div) => {
        const filteredAgents = div.agents.filter((agent) => {
          const matchesSearch =
            !searchQuery ||
            agent.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            agent.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
            div.name.toLowerCase().includes(searchQuery.toLowerCase());
          const matchesType =
            typeFilter === "All Types" ||
            agent.type.toLowerCase().includes(typeFilter.toLowerCase());
          const matchesMode =
            modeFilter === "All Modes" || agent.mode === modeFilter;
          return matchesSearch && matchesType && matchesMode;
        });
        return { ...div, agents: filteredAgents };
      })
      .filter(
        (div) =>
          div.agents.length > 0 ||
          (!searchQuery && typeFilter === "All Types" && modeFilter === "All Modes")
      );
  }, [searchQuery, typeFilter, modeFilter]);

  const totalAgents = divisions.reduce((sum, d) => sum + d.agentCount, 0);

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Agent Explorer</h1>
        <p className="text-sm text-zinc-600 mt-1 font-mono">
          {totalAgents} specialized agents across {divisions.length} divisions
        </p>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-600 group-focus-within:text-neon-cyan transition-colors duration-300" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search agents or divisions..."
              className="input pl-10"
            />
          </div>
          <div className="flex gap-3">
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600 pointer-events-none" />
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="input pl-9 w-auto"
              >
                {attackTypes.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <select
              value={modeFilter}
              onChange={(e) => setModeFilter(e.target.value)}
              className="input w-auto"
            >
              {modeFilters.map((m) => (
                <option key={m} value={m}>
                  {m === "All Modes" ? m : m.charAt(0).toUpperCase() + m.slice(1)}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Active filter chips */}
        {(typeFilter !== "All Types" || modeFilter !== "All Modes" || searchQuery) && (
          <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-white/5">
            {searchQuery && (
              <span
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono cursor-pointer transition-all duration-200"
                style={{ background: "rgba(99, 102, 241, 0.1)", border: "1px solid rgba(99, 102, 241, 0.2)", color: "#a5b4fc" }}
                onClick={() => setSearchQuery("")}
              >
                &quot;{searchQuery}&quot; x
              </span>
            )}
            {typeFilter !== "All Types" && (
              <span
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono cursor-pointer transition-all duration-200"
                style={{ background: "rgba(0, 229, 255, 0.1)", border: "1px solid rgba(0, 229, 255, 0.2)", color: "#00e5ff" }}
                onClick={() => setTypeFilter("All Types")}
              >
                {typeFilter} x
              </span>
            )}
            {modeFilter !== "All Modes" && (
              <span
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono cursor-pointer transition-all duration-200"
                style={{
                  background: modeColors[modeFilter]?.bg || "rgba(255,255,255,0.05)",
                  border: `1px solid ${modeColors[modeFilter]?.border || "rgba(255,255,255,0.1)"}`,
                  color: modeColors[modeFilter]?.text || "#a1a1aa",
                }}
                onClick={() => setModeFilter("All Modes")}
              >
                {modeFilter} x
              </span>
            )}
          </div>
        )}
      </div>

      {/* Division Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filteredDivisions.map((division) => {
          const isExpanded = expandedDivision === division.name;
          return (
            <div
              key={division.name}
              className={`card cursor-pointer transition-all duration-300 ${
                isExpanded
                  ? "sm:col-span-2 lg:col-span-3 xl:col-span-4"
                  : ""
              }`}
              style={{
                borderColor: isExpanded ? `${division.color}30` : undefined,
                boxShadow: isExpanded ? `0 0 30px ${division.color}10` : undefined,
              }}
              onClick={() =>
                setExpandedDivision(isExpanded ? null : division.name)
              }
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className="p-2.5 rounded-lg transition-all duration-300"
                    style={{ backgroundColor: `${division.color}12` }}
                  >
                    <Users
                      className="h-5 w-5 transition-all duration-300"
                      style={{
                        color: division.color,
                        filter: `drop-shadow(0 0 4px ${division.color}40)`,
                      }}
                    />
                  </div>
                  <div>
                    <h3 className="font-semibold text-white text-sm">
                      {division.name}
                    </h3>
                    <p className="text-[11px] text-zinc-600 mt-0.5 font-mono">
                      {division.description}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className="text-xs font-mono font-bold px-2 py-0.5 rounded-full"
                    style={{
                      backgroundColor: `${division.color}15`,
                      color: division.color,
                    }}
                  >
                    {division.agentCount}
                  </span>
                  {isExpanded ? (
                    <ChevronDown className="h-4 w-4 text-zinc-600" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-zinc-700" />
                  )}
                </div>
              </div>

              {isExpanded && (
                <div
                  className="mt-4 pt-4 border-t"
                  style={{ borderColor: `${division.color}15` }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {division.agents.map((agent) => {
                      const mc = modeColors[agent.mode];
                      return (
                        <div
                          key={agent.name}
                          className="p-3.5 rounded-lg transition-all duration-200 hover:scale-[1.01]"
                          style={{
                            background: "rgba(255,255,255,0.02)",
                            border: "1px solid rgba(255,255,255,0.05)",
                          }}
                          onMouseEnter={(e) => {
                            (e.currentTarget as HTMLElement).style.borderColor = `${division.color}30`;
                          }}
                          onMouseLeave={(e) => {
                            (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.05)";
                          }}
                        >
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="text-xs font-medium text-zinc-300 font-mono">
                              {agent.name}
                            </span>
                            <span
                              className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                              style={{
                                background: mc?.bg || "rgba(255,255,255,0.05)",
                                color: mc?.text || "#a1a1aa",
                                border: `1px solid ${mc?.border || "rgba(255,255,255,0.1)"}`,
                              }}
                            >
                              {agent.mode}
                            </span>
                          </div>
                          <p className="text-[11px] text-zinc-600 font-mono">{agent.type}</p>
                          <p className="text-[11px] text-zinc-600 mt-1 flex items-center gap-1">
                            <Activity className="h-2.5 w-2.5 text-[#69f0ae]" />
                            {agent.description}
                          </p>
                        </div>
                      );
                    })}
                    {division.agentCount > division.agents.length && (
                      <div
                        className="p-3.5 rounded-lg flex items-center justify-center"
                        style={{
                          border: `1px dashed ${division.color}20`,
                          background: `${division.color}05`,
                        }}
                      >
                        <span className="text-[11px] font-mono" style={{ color: `${division.color}80` }}>
                          +{division.agentCount - division.agents.length} more agents
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
