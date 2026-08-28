import { NavLink, Outlet } from "react-router-dom";
import { BarChart3, FlaskConical, GitBranch, Network, ScrollText, Settings, ShieldHalf, TerminalSquare, Wrench } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

const NAV = [
  { to: "/", label: "Upload & Scan", icon: ShieldHalf, end: true },
  { to: "/projects", label: "Projects", icon: BarChart3 },
  { to: "/tools", label: "Security Tools", icon: Wrench },
];

export default function Layout() {
  const { data: ai } = useQuery({ queryKey: ["groq"], queryFn: api.groqStatus, refetchInterval: 30_000 });

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-base-700/70 bg-base-900/70">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-glow">
            <ShieldHalf className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="text-sm font-bold tracking-wide text-white">SentinelForge</div>
            <div className="text-[10px] font-medium text-slate-500">AI Security Platform</div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${
                  isActive ? "bg-accent-500/15 text-accent-300" : "text-slate-400 hover:bg-base-800 hover:text-slate-200"
                }`
              }
            >
              <item.icon className="h-4 w-4" /> {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1 border-t border-base-700/70 px-3 py-3">
          <NavLink to="/settings" className={({ isActive }) => `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm ${isActive ? "bg-accent-500/15 text-accent-300" : "text-slate-400 hover:bg-base-800 hover:text-slate-200"}`}>
            <Settings className="h-4 w-4" /> AI Configuration
          </NavLink>
          <div className="px-3 py-1.5 text-[11px]">
            {ai?.configured ? (
              <span className="flex items-center gap-1.5 text-green-400">
                <span className="h-2 w-2 rounded-full bg-green-400" /> Groq · {ai.model}
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-amber-400">
                <span className="pulse-dot h-2 w-2 rounded-full bg-amber-400" /> AI not configured — deterministic mode
              </span>
            )}
          </div>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}

export { Network, GitBranch, ScrollText, TerminalSquare, FlaskConical };
