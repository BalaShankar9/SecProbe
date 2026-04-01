"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

interface SeverityData {
  name: string;
  value: number;
  color: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ff1744",
  High: "#ff9100",
  Medium: "#ffea00",
  Low: "#00e5ff",
  Info: "#69f0ae",
};

interface Props {
  data?: SeverityData[];
}

const defaultData: SeverityData[] = [
  { name: "Critical", value: 3, color: SEVERITY_COLORS.Critical },
  { name: "High", value: 12, color: SEVERITY_COLORS.High },
  { name: "Medium", value: 28, color: SEVERITY_COLORS.Medium },
  { name: "Low", value: 45, color: SEVERITY_COLORS.Low },
  { name: "Info", value: 18, color: SEVERITY_COLORS.Info },
];

export default function SeverityPieChart({ data = defaultData }: Props) {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <defs>
            {data.map((entry, index) => (
              <filter key={`glow-${index}`} id={`glow-${index}`}>
                <feGaussianBlur stdDeviation="2" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            ))}
          </defs>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={90}
            paddingAngle={4}
            dataKey="value"
            stroke="none"
            animationBegin={0}
            animationDuration={1200}
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.color}
                style={{ filter: `drop-shadow(0 0 6px ${entry.color}40)` }}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "rgba(12, 12, 24, 0.95)",
              border: "1px solid rgba(99, 102, 241, 0.2)",
              borderRadius: "8px",
              color: "#e4e4e7",
              fontSize: "12px",
              fontFamily: "monospace",
              backdropFilter: "blur(10px)",
              boxShadow: "0 0 20px rgba(0, 0, 0, 0.5)",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-wrap justify-center gap-4 -mt-2">
        {data.map((entry) => (
          <div key={entry.name} className="flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full"
              style={{
                backgroundColor: entry.color,
                boxShadow: `0 0 6px ${entry.color}60`,
              }}
            />
            <span className="text-[11px] text-zinc-500 font-mono">
              {entry.name} ({entry.value})
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
