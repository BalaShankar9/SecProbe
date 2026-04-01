import type { Config } from "tailwindcss";
import plugin from "tailwindcss/plugin";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0a0a0f",
        foreground: "#e4e4e7",
        card: "rgba(15, 15, 25, 0.8)",
        "card-hover": "rgba(25, 25, 40, 0.9)",
        border: "rgba(100, 100, 180, 0.15)",
        accent: "#6366f1",
        "accent-hover": "#818cf8",
        success: "#22c55e",
        warning: "#f59e0b",
        danger: "#ef4444",
        info: "#3b82f6",
        neon: {
          cyan: "#00e5ff",
          purple: "#bf5af2",
          red: "#ff1744",
          orange: "#ff9100",
          yellow: "#ffea00",
          green: "#69f0ae",
          blue: "#448aff",
        },
        severity: {
          critical: "#ff1744",
          high: "#ff9100",
          medium: "#ffea00",
          low: "#00e5ff",
          info: "#69f0ae",
        },
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "monospace"],
      },
      boxShadow: {
        "glow-cyan": "0 0 15px rgba(0, 229, 255, 0.35), 0 0 40px rgba(0, 229, 255, 0.1)",
        "glow-cyan-sm": "0 0 8px rgba(0, 229, 255, 0.25)",
        "glow-purple": "0 0 15px rgba(191, 90, 242, 0.35), 0 0 40px rgba(191, 90, 242, 0.1)",
        "glow-purple-sm": "0 0 8px rgba(191, 90, 242, 0.25)",
        "glow-red": "0 0 15px rgba(255, 23, 68, 0.35), 0 0 40px rgba(255, 23, 68, 0.1)",
        "glow-red-sm": "0 0 8px rgba(255, 23, 68, 0.25)",
        "glow-accent": "0 0 15px rgba(99, 102, 241, 0.35), 0 0 40px rgba(99, 102, 241, 0.1)",
        "glow-green": "0 0 10px rgba(105, 240, 174, 0.3)",
        "card-glow": "0 0 1px rgba(100, 100, 180, 0.3), 0 0 20px rgba(99, 102, 241, 0.07), inset 0 0 20px rgba(0, 0, 0, 0.3)",
      },
      keyframes: {
        "pulse-glow": {
          "0%, 100%": { opacity: "1", boxShadow: "0 0 8px rgba(0, 229, 255, 0.4)" },
          "50%": { opacity: "0.7", boxShadow: "0 0 20px rgba(0, 229, 255, 0.6)" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        "gradient-shift": {
          "0%": { backgroundPosition: "0% 50%" },
          "50%": { backgroundPosition: "100% 50%" },
          "100%": { backgroundPosition: "0% 50%" },
        },
        "border-glow": {
          "0%, 100%": { borderColor: "rgba(99, 102, 241, 0.3)" },
          "50%": { borderColor: "rgba(0, 229, 255, 0.6)" },
        },
        "float": {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-4px)" },
        },
        "shimmer": {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        "fade-in": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
        "scan-line": "scan-line 4s linear infinite",
        "gradient-shift": "gradient-shift 8s ease infinite",
        "border-glow": "border-glow 3s ease-in-out infinite",
        "float": "float 3s ease-in-out infinite",
        "shimmer": "shimmer 3s ease-in-out infinite",
        "fade-in": "fade-in 0.5s ease-out forwards",
      },
      backdropBlur: {
        xs: "2px",
      },
    },
  },
  plugins: [
    plugin(function ({ addUtilities }) {
      addUtilities({
        ".text-glow-cyan": {
          textShadow: "0 0 10px rgba(0, 229, 255, 0.5), 0 0 30px rgba(0, 229, 255, 0.2)",
        },
        ".text-glow-purple": {
          textShadow: "0 0 10px rgba(191, 90, 242, 0.5), 0 0 30px rgba(191, 90, 242, 0.2)",
        },
        ".text-glow-red": {
          textShadow: "0 0 10px rgba(255, 23, 68, 0.5), 0 0 30px rgba(255, 23, 68, 0.2)",
        },
        ".text-glow-green": {
          textShadow: "0 0 10px rgba(105, 240, 174, 0.5), 0 0 30px rgba(105, 240, 174, 0.2)",
        },
      });
    }),
  ],
};

export default config;
