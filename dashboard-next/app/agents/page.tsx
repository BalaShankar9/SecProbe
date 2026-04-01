"use client";

import { useState, useMemo } from "react";
import {
  Users,
  ChevronDown,
  ChevronRight,
  Search,
  Filter,
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
        <h1 className="text-2xl font-bold text-zinc-100">Agent Explorer</h1>
        <p className="text-sm text-zinc-500 mt-1">
          {totalAgents} specialized agents across {divisions.length} divisions
        </p>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
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
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
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
      </div>

      {/* Division Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filteredDivisions.map((division) => {
          const isExpanded = expandedDivision === division.name;
          return (
            <div
              key={division.name}
              className={`card transition-all cursor-pointer ${
                isExpanded
                  ? "sm:col-span-2 lg:col-span-3 xl:col-span-4"
                  : "hover:bg-card-hover"
              }`}
              onClick={() =>
                setExpandedDivision(isExpanded ? null : division.name)
              }
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className="p-2.5 rounded-lg"
                    style={{ backgroundColor: `${division.color}15` }}
                  >
                    <Users
                      className="h-5 w-5"
                      style={{ color: division.color }}
                    />
                  </div>
                  <div>
                    <h3 className="font-semibold text-zinc-100">
                      {division.name}
                    </h3>
                    <p className="text-xs text-zinc-500 mt-0.5">
                      {division.description}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-zinc-400">
                    {division.agentCount}
                  </span>
                  {isExpanded ? (
                    <ChevronDown className="h-4 w-4 text-zinc-500" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-zinc-500" />
                  )}
                </div>
              </div>

              {isExpanded && (
                <div
                  className="mt-4 pt-4 border-t border-zinc-700"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {division.agents.map((agent) => (
                      <div
                        key={agent.name}
                        className="p-3 rounded-lg bg-zinc-800/50 border border-zinc-700 hover:border-zinc-600 transition-colors"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-zinc-200 font-mono">
                            {agent.name}
                          </span>
                          <span
                            className={`text-xs px-1.5 py-0.5 rounded ${
                              agent.mode === "recon"
                                ? "bg-blue-500/20 text-blue-400"
                                : agent.mode === "audit"
                                  ? "bg-yellow-500/20 text-yellow-400"
                                  : "bg-red-500/20 text-red-400"
                            }`}
                          >
                            {agent.mode}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-500">{agent.type}</p>
                        <p className="text-xs text-zinc-500 mt-1">
                          {agent.description}
                        </p>
                      </div>
                    ))}
                    {division.agentCount > division.agents.length && (
                      <div className="p-3 rounded-lg border border-dashed border-zinc-700 flex items-center justify-center">
                        <span className="text-xs text-zinc-500">
                          +{division.agentCount - division.agents.length} more
                          agents
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
