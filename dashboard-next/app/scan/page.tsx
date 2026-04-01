"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Crosshair, Globe, Shield, Zap, Sliders } from "lucide-react";
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
      router.push(`/scan/${data.id || "latest"}`);
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
      color: "text-blue-400 border-blue-500/30 bg-blue-500/10",
      active: "border-blue-500 bg-blue-500/20",
    },
    {
      value: "audit" as const,
      label: "Security Audit",
      desc: "Active vulnerability scanning",
      icon: Shield,
      color: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10",
      active: "border-yellow-500 bg-yellow-500/20",
    },
    {
      value: "redteam" as const,
      label: "Red Team",
      desc: "Full adversary simulation",
      icon: Zap,
      color: "text-red-400 border-red-500/30 bg-red-500/10",
      active: "border-red-500 bg-red-500/20",
    },
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Launch Scan</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Configure and deploy a security assessment
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target URL */}
        <div className="card">
          <label htmlFor="target" className="label">
            Target URL
          </label>
          <div className="relative">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
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
            {modes.map((m) => (
              <button
                key={m.value}
                type="button"
                onClick={() => setMode(m.value)}
                className={`flex flex-col items-center gap-2 p-4 rounded-lg border transition-all ${
                  mode === m.value
                    ? m.active
                    : "border-zinc-700 bg-zinc-800/50 hover:border-zinc-600"
                }`}
              >
                <m.icon
                  className={`h-6 w-6 ${mode === m.value ? m.color.split(" ")[0] : "text-zinc-500"}`}
                />
                <span
                  className={`text-sm font-medium ${mode === m.value ? "text-zinc-100" : "text-zinc-400"}`}
                >
                  {m.label}
                </span>
                <span className="text-xs text-zinc-500 text-center">
                  {m.desc}
                </span>
              </button>
            ))}
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
              Max Requests: {maxRequests.toLocaleString()}
            </label>
            <input
              id="maxRequests"
              type="range"
              min={100}
              max={10000}
              step={100}
              value={maxRequests}
              onChange={(e) => setMaxRequests(Number(e.target.value))}
              className="w-full h-2 bg-zinc-700 rounded-lg appearance-none cursor-pointer accent-accent mt-2"
            />
            <div className="flex justify-between text-xs text-zinc-500 mt-1">
              <span>100</span>
              <span>10,000</span>
            </div>
          </div>
        </div>

        {/* Divisions */}
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <p className="label mb-0">
              Divisions ({selectedDivisions.length} / {DIVISIONS.length})
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={selectAllDivisions}
                className="text-xs text-accent hover:text-accent-hover"
              >
                Select all
              </button>
              <span className="text-zinc-600">|</span>
              <button
                type="button"
                onClick={clearAllDivisions}
                className="text-xs text-zinc-500 hover:text-zinc-300"
              >
                Clear
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {DIVISIONS.map((division) => (
              <label
                key={division}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-all text-sm ${
                  selectedDivisions.includes(division)
                    ? "border-accent/50 bg-accent/10 text-zinc-200"
                    : "border-zinc-700 bg-zinc-800/30 text-zinc-500 hover:border-zinc-600"
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedDivisions.includes(division)}
                  onChange={() => toggleDivision(division)}
                  className="sr-only"
                />
                <span
                  className={`h-3 w-3 rounded border flex items-center justify-center flex-shrink-0 ${
                    selectedDivisions.includes(division)
                      ? "bg-accent border-accent"
                      : "border-zinc-600"
                  }`}
                >
                  {selectedDivisions.includes(division) && (
                    <svg
                      className="h-2 w-2 text-white"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={3}
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  )}
                </span>
                <span className="truncate">{division}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={isLoading}
          className="btn-primary w-full flex items-center justify-center gap-2 py-3 text-base disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? (
            <>
              <span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Starting Scan...
            </>
          ) : (
            <>
              <Crosshair className="h-5 w-5" />
              Start Scan
            </>
          )}
        </button>
      </form>
    </div>
  );
}
