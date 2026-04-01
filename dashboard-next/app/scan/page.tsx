"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Crosshair, Globe, Shield, Zap, Sliders, Check } from "lucide-react";
import { DIVISIONS, STEALTH_PRESETS } from "@/lib/api";

export default function ScanLauncherPage() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<"recon" | "audit" | "redteam">("audit");
  const [stealthPreset, setStealthPreset] = useState("medium");
  const [maxRequests, setMaxRequests] = useState(1000);
  const [selectedDivisions, setSelectedDivisions] = useState<string[]>([
    ...DIVISIONS,
  ]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function toggleDivision(division: string) {
    setSelectedDivisions((prev) =>
      prev.includes(division)
        ? prev.filter((d) => d !== division)
        : [...prev, division]
    );
  }

  function selectAllDivisions() {
    setSelectedDivisions([...DIVISIONS]);
  }

  function clearAllDivisions() {
    setSelectedDivisions([]);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!target.trim()) {
      setError("Target URL is required");
      return;
    }

    if (selectedDivisions.length === 0) {
      setError("Select at least one division");
      return;
    }

    setIsLoading(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          mode,
          stealth_preset: stealthPreset,
          max_requests: maxRequests,
          divisions: selectedDivisions,
        }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.error || `Request failed: ${res.status}`);
      }

      const data = await res.json();
      router.push(`/scan/${data.scan_id || data.id || "latest"}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setIsLoading(false);
    }
  }

  const modes = [
    {
      value: "recon" as const,
      label: "Reconnaissance",
      desc: "Passive information gathering",
      icon: Globe,
      color: "#00e5ff",
      activeBorder: "rgba(0, 229, 255, 0.5)",
      activeBg: "rgba(0, 229, 255, 0.08)",
    },
    {
      value: "audit" as const,
      label: "Security Audit",
      desc: "Active vulnerability scanning",
      icon: Shield,
      color: "#ffea00",
      activeBorder: "rgba(255, 234, 0, 0.5)",
      activeBg: "rgba(255, 234, 0, 0.08)",
    },
    {
      value: "redteam" as const,
      label: "Red Team",
      desc: "Full adversary simulation",
      icon: Zap,
      color: "#ff1744",
      activeBorder: "rgba(255, 23, 68, 0.5)",
      activeBg: "rgba(255, 23, 68, 0.08)",
    },
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">
          Launch Scan
        </h1>
        <p className="text-sm text-zinc-600 mt-1 font-mono">
          Configure and deploy a security assessment
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target URL */}
        <div className="card">
          <label htmlFor="target" className="label">
            Target URL
          </label>
          <div className="relative group">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-600 group-focus-within:text-neon-cyan transition-colors duration-300" />
            <input
              id="target"
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="input pl-10"
              required
            />
          </div>
        </div>

        {/* Scan Mode */}
        <div className="card">
          <p className="label">Scan Mode</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {modes.map((m) => {
              const isActive = mode === m.value;
              return (
                <button
                  key={m.value}
                  type="button"
                  onClick={() => setMode(m.value)}
                  className="flex flex-col items-center gap-2.5 p-5 rounded-lg transition-all duration-300 relative overflow-hidden"
                  style={{
                    background: isActive ? m.activeBg : "rgba(255,255,255,0.02)",
                    border: `1px solid ${isActive ? m.activeBorder : "rgba(255,255,255,0.06)"}`,
                    boxShadow: isActive ? `0 0 20px ${m.color}15` : "none",
                  }}
                >
                  {isActive && (
                    <div
                      className="absolute top-0 left-0 right-0 h-px"
                      style={{ background: `linear-gradient(90deg, transparent, ${m.color}, transparent)` }}
                    />
                  )}
                  <m.icon
                    className="h-6 w-6 transition-all duration-300"
                    style={{
                      color: isActive ? m.color : "#52525b",
                      filter: isActive ? `drop-shadow(0 0 8px ${m.color}50)` : "none",
                    }}
                  />
                  <span
                    className="text-sm font-medium transition-colors duration-300"
                    style={{ color: isActive ? "#ffffff" : "#71717a" }}
                  >
                    {m.label}
                  </span>
                  <span className="text-[11px] text-zinc-600 text-center font-mono">
                    {m.desc}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Stealth & Rate Limit */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          <div className="card">
            <label htmlFor="stealth" className="label">
              <span className="flex items-center gap-2">
                <Sliders className="h-3.5 w-3.5" />
                Stealth Preset
              </span>
            </label>
            <select
              id="stealth"
              value={stealthPreset}
              onChange={(e) => setStealthPreset(e.target.value)}
              className="input"
            >
              {STEALTH_PRESETS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          <div className="card">
            <label htmlFor="maxRequests" className="label">
              Max Requests: <span className="text-neon-cyan">{maxRequests.toLocaleString()}</span>
            </label>
            <input
              id="maxRequests"
              type="range"
              min={100}
              max={10000}
              step={100}
              value={maxRequests}
              onChange={(e) => setMaxRequests(Number(e.target.value))}
              className="w-full h-1.5 rounded-lg appearance-none cursor-pointer mt-3"
              style={{
                background: `linear-gradient(to right, #6366f1 ${((maxRequests - 100) / 9900) * 100}%, rgba(255,255,255,0.05) ${((maxRequests - 100) / 9900) * 100}%)`,
              }}
            />
            <div className="flex justify-between text-[10px] text-zinc-700 mt-2 font-mono">
              <span>100</span>
              <span>10,000</span>
            </div>
          </div>
        </div>

        {/* Divisions */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <p className="label mb-0">
              Divisions <span className="text-neon-cyan">{selectedDivisions.length}</span>
              <span className="text-zinc-700"> / {DIVISIONS.length}</span>
            </p>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={selectAllDivisions}
                className="text-[11px] text-accent hover:text-accent-hover font-mono transition-colors"
              >
                Select all
              </button>
              <span className="text-zinc-800">|</span>
              <button
                type="button"
                onClick={clearAllDivisions}
                className="text-[11px] text-zinc-600 hover:text-zinc-400 font-mono transition-colors"
              >
                Clear
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {DIVISIONS.map((division) => {
              const isSelected = selectedDivisions.includes(division);
              return (
                <label
                  key={division}
                  className="flex items-center gap-2 px-3 py-2.5 rounded-lg cursor-pointer transition-all duration-200 text-sm"
                  style={{
                    background: isSelected ? "rgba(99, 102, 241, 0.08)" : "rgba(255,255,255,0.01)",
                    border: `1px solid ${isSelected ? "rgba(99, 102, 241, 0.3)" : "rgba(255,255,255,0.05)"}`,
                  }}
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggleDivision(division)}
                    className="sr-only"
                  />
                  <span
                    className="h-3.5 w-3.5 rounded flex items-center justify-center flex-shrink-0 transition-all duration-200"
                    style={{
                      background: isSelected ? "#6366f1" : "transparent",
                      border: `1.5px solid ${isSelected ? "#6366f1" : "rgba(255,255,255,0.1)"}`,
                      boxShadow: isSelected ? "0 0 8px rgba(99, 102, 241, 0.4)" : "none",
                    }}
                  >
                    {isSelected && <Check className="h-2.5 w-2.5 text-white" />}
                  </span>
                  <span
                    className="truncate font-mono text-xs transition-colors duration-200"
                    style={{ color: isSelected ? "#e4e4e7" : "#52525b" }}
                  >
                    {division}
                  </span>
                </label>
              );
            })}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div
            className="rounded-lg px-4 py-3 text-sm font-mono"
            style={{
              background: "rgba(255, 23, 68, 0.08)",
              border: "1px solid rgba(255, 23, 68, 0.2)",
              color: "#ff1744",
            }}
          >
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={isLoading}
          className="w-full flex items-center justify-center gap-2.5 py-3.5 text-base font-medium rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 text-white relative overflow-hidden"
          style={{
            background: "linear-gradient(135deg, #6366f1, #8b5cf6, #6366f1)",
            backgroundSize: "200% 200%",
            animation: "gradient-shift 3s ease infinite",
            boxShadow: isLoading ? "none" : "0 0 25px rgba(99, 102, 241, 0.3), 0 0 50px rgba(99, 102, 241, 0.1)",
          }}
        >
          {isLoading ? (
            <>
              <span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span className="font-mono">Initializing Scan...</span>
            </>
          ) : (
            <>
              <Crosshair className="h-5 w-5" />
              <span>Start Scan</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
}
