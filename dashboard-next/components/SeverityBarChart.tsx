"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
  Cell,
} from "recharts";

interface SeverityCount {
  name: string;
  count: number;
  color: string;
}

interface Props {
  data: SeverityCount[];
}

export default function SeverityBarChart({ data }: Props) {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} barCategoryGap="20%">
          <XAxis
            dataKey="name"
            tick={{ fill: "#71717a", fontSize: 11, fontFamily: "monospace" }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: "#52525b", fontSize: 11, fontFamily: "monospace" }}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
          />
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
            cursor={{ fill: "rgba(99, 102, 241, 0.05)" }}
          />
          <Bar
            dataKey="count"
            radius={[4, 4, 0, 0]}
            animationBegin={0}
            animationDuration={1200}
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.color}
                style={{ filter: `drop-shadow(0 0 8px ${entry.color}50)` }}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
