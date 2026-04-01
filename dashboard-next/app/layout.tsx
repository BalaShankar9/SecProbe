import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import {
  Shield,
  LayoutDashboard,
  Crosshair,
  Users,
  Settings,
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
          <aside className="hidden md:flex w-64 flex-col bg-zinc-950 border-r border-zinc-800">
            <div className="flex items-center gap-3 px-6 py-5 border-b border-zinc-800">
              <Shield className="h-8 w-8 text-accent" />
              <div>
                <h1 className="text-lg font-bold text-zinc-100">SecProbe</h1>
                <p className="text-xs text-zinc-500">Security Platform</p>
              </div>
            </div>
            <nav className="flex-1 px-3 py-4 space-y-1">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60 transition-colors"
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </Link>
              ))}
            </nav>
            <div className="px-3 py-4 border-t border-zinc-800">
              <Link
                href="#"
                className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/60 transition-colors"
              >
                <Settings className="h-4 w-4" />
                Settings
              </Link>
              <div className="mt-3 px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800">
                <p className="text-xs text-zinc-500">Platform Status</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                  <span className="text-xs text-zinc-400">
                    600 agents online
                  </span>
                </div>
              </div>
            </div>
          </aside>

          {/* Mobile header */}
          <div className="flex flex-col flex-1 overflow-hidden">
            <header className="md:hidden flex items-center justify-between px-4 py-3 bg-zinc-950 border-b border-zinc-800">
              <div className="flex items-center gap-2">
                <Shield className="h-6 w-6 text-accent" />
                <span className="font-bold text-zinc-100">SecProbe</span>
              </div>
              <nav className="flex items-center gap-1">
                {navItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="p-2 rounded-lg text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800"
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
