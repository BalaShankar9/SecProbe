import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import {
  Shield,
  LayoutDashboard,
  Crosshair,
  Users,
  Settings,
  Activity,
  Wifi,
} from "lucide-react";
import "./globals.css";

const sansFont = Inter({
  variable: "--font-geist-sans",
  subsets: ["latin"],
  display: "swap",
});

const monoFont = JetBrains_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "SecProbe Dashboard",
  description:
    "Enterprise security scanning platform with 600 AI agents across 20 divisions",
};

const navItems = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scan", label: "New Scan", icon: Crosshair },
  { href: "/agents", label: "Agents", icon: Users },
];

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${sansFont.variable} ${monoFont.variable} font-sans antialiased`}
      >
        <div className="flex h-screen overflow-hidden">
          {/* Sidebar */}
          <aside className="hidden md:flex w-64 flex-col relative" style={{ background: "rgba(6, 6, 16, 0.95)" }}>
            {/* Animated gradient left edge */}
            <div
              className="absolute left-0 top-0 bottom-0 w-[2px]"
              style={{
                background: "linear-gradient(180deg, #00e5ff, #6366f1, #bf5af2, #6366f1, #00e5ff)",
                backgroundSize: "100% 200%",
                animation: "gradient-shift 4s ease infinite",
              }}
            />
            {/* Inner border */}
            <div className="absolute right-0 top-0 bottom-0 w-px bg-white/5" />

            {/* Logo Section */}
            <div className="flex items-center gap-3 px-6 py-5 border-b border-white/5 scan-line-container">
              <div className="relative">
                <Shield className="h-8 w-8 text-neon-cyan" style={{ filter: "drop-shadow(0 0 8px rgba(0, 229, 255, 0.5))" }} />
                <div className="absolute inset-0 animate-ping opacity-20">
                  <Shield className="h-8 w-8 text-neon-cyan" />
                </div>
              </div>
              <div>
                <h1 className="text-lg font-bold text-white tracking-wide">
                  Sec<span className="text-neon-cyan text-glow-cyan">Probe</span>
                </h1>
                <p className="text-[10px] text-zinc-600 uppercase tracking-[0.2em] font-mono">
                  Security Platform
                </p>
              </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-3 py-4 space-y-1">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="group flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-zinc-500 hover:text-white transition-all duration-300 relative hover:bg-white/[0.03]"
                >
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-0 group-hover:h-6 rounded-r bg-neon-cyan transition-all duration-300" style={{ boxShadow: "0 0 8px rgba(0, 229, 255, 0.5)" }} />
                  <item.icon className="h-4 w-4 group-hover:text-neon-cyan transition-colors duration-300" />
                  <span className="group-hover:translate-x-0.5 transition-transform duration-300">
                    {item.label}
                  </span>
                </Link>
              ))}
            </nav>

            {/* Footer */}
            <div className="px-3 py-4 border-t border-white/5 space-y-3">
              <Link
                href="#"
                className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-zinc-600 hover:text-zinc-400 hover:bg-white/[0.03] transition-all duration-300"
              >
                <Settings className="h-4 w-4" />
                Settings
              </Link>

              {/* System Status */}
              <div className="px-3 py-3 rounded-lg border border-white/5" style={{ background: "rgba(10, 10, 20, 0.6)" }}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="status-online" />
                  <span className="text-[10px] text-neon-green uppercase tracking-[0.15em] font-mono font-medium">
                    System Online
                  </span>
                </div>
                <div className="flex items-center justify-between text-[10px] text-zinc-600 font-mono">
                  <div className="flex items-center gap-1.5">
                    <Activity className="h-3 w-3" />
                    <span>600 agents</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Wifi className="h-3 w-3 text-neon-green" />
                    <span className="text-zinc-500">Connected</span>
                  </div>
                </div>
              </div>

              {/* Version */}
              <div className="px-3 flex items-center justify-between">
                <span className="text-[9px] text-zinc-700 font-mono">v1.0.0</span>
                <span className="text-[9px] text-zinc-700 font-mono flex items-center gap-1">
                  <span className="h-1 w-1 rounded-full bg-neon-green" />
                  Railway
                </span>
              </div>
            </div>
          </aside>

          {/* Mobile header */}
          <div className="flex flex-col flex-1 overflow-hidden">
            <header className="md:hidden flex items-center justify-between px-4 py-3 border-b border-white/5" style={{ background: "rgba(6, 6, 16, 0.95)" }}>
              <div className="flex items-center gap-2">
                <Shield className="h-6 w-6 text-neon-cyan" style={{ filter: "drop-shadow(0 0 6px rgba(0, 229, 255, 0.4))" }} />
                <span className="font-bold text-white">
                  Sec<span className="text-neon-cyan">Probe</span>
                </span>
              </div>
              <nav className="flex items-center gap-1">
                {navItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="p-2 rounded-lg text-zinc-500 hover:text-neon-cyan hover:bg-white/5 transition-all duration-300"
                  >
                    <item.icon className="h-5 w-5" />
                  </Link>
                ))}
              </nav>
            </header>

            {/* Main content */}
            <main className="flex-1 overflow-y-auto p-4 md:p-8">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
