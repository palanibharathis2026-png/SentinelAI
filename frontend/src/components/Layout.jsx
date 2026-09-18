import { NavLink } from "react-router-dom";
import { Activity, BrainCircuit, Cable, FlaskConical, Globe2, Home, KeyRound, LayoutDashboard, LogOut, Mail, Radio, ShieldCheck, UserCog, Users } from "lucide-react";
import { api } from "../api.js";
import { setAuth } from "../auth.js";
import { usePolling } from "../hooks/usePolling.js";
import AlertToasts from "./AlertToasts.jsx";

const NAV = [
  { to: "/", label: "Overview", icon: Home, end: true },
  { to: "/soc", label: "SOC Dashboard", icon: LayoutDashboard },
  { to: "/map", label: "Threat Map", icon: Globe2 },
  { to: "/lab", label: "Risk Lab", icon: FlaskConical },
  { to: "/employees", label: "Employees", icon: Users },
  { to: "/access", label: "Access Control", icon: KeyRound },
  { to: "/mail", label: "Mail Outbox", icon: Mail },
  { to: "/security", label: "Security Center", icon: ShieldCheck },
  { to: "/integrations", label: "Integrations", icon: Cable },
  { to: "/model", label: "Model & Accuracy", icon: BrainCircuit },
];

export default function Layout({ user, children }) {
  const { data: health } = usePolling(api.health, 10000);
  const { data: live, refresh } = usePolling(api.live, 10000);

  async function toggleLive() {
    await api.setLive(!live?.enabled);
    refresh();
  }

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-white/10 bg-slate-950/70 p-4 backdrop-blur md:flex">
        <div className="mb-8 flex items-center gap-2 px-2">
          <div className="rounded-xl bg-gradient-to-br from-cyan-400 via-indigo-500 to-fuchsia-500 p-1.5 shadow-lg shadow-indigo-500/30">
            <ShieldCheck className="h-6 w-6 text-white" />
          </div>
          <div>
            <div className="gradient-text text-lg font-bold tracking-tight">SentinelAI</div>
            <div className="text-xs text-slate-500">Behavioral Security</div>
          </div>
        </div>
        <nav className="flex flex-col gap-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                  isActive ? "bg-gradient-to-r from-cyan-500/20 to-fuchsia-500/10 text-cyan-200 ring-1 ring-cyan-400/20" : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                }`
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto space-y-2 rounded-lg border border-white/10 p-3 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Activity className={`h-3.5 w-3.5 ${health ? "text-emerald-400" : "text-red-400"}`} />
            API {health ? "online" : "offline"}
          </div>
          {health?.mode === "cert" && (
            <div className="rounded-md bg-emerald-500/15 px-2 py-1 text-emerald-200" title="SENTINEL_MODE=cert in .env">
              Real data: CMU CERT r4.2 (200 employees)
            </div>
          )}
          <div className="flex items-center gap-2">
            <UserCog className="h-3.5 w-3.5 text-fuchsia-300" /> Signed in as <span className="font-semibold text-slate-200">{user}</span>
          </div>
          <div>
            AI analyst:{" "}
            <span className="text-slate-200">{health?.ai_analyst === "claude" ? "Claude" : "Built-in template"}</span>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-white/10 px-6 py-3">
          <nav className="flex gap-3 overflow-x-auto text-sm md:hidden">
            {NAV.map(({ to, label, end }) => (
              <NavLink key={to} to={to} end={end} className={({ isActive }) => (isActive ? "text-cyan-300" : "text-slate-400")}>
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="hidden text-sm text-slate-400 md:block">Security Operations Center</div>
          <div className="flex shrink-0 gap-2">
          <AlertToasts />
          <button onClick={() => setAuth(null)} className="btn-ghost text-xs" title="Sign out">
            <LogOut className="h-4 w-4" /> Sign out
          </button>
          <button onClick={toggleLive} className="btn-ghost text-xs" title="Background company activity">
            <Radio className={`h-4 w-4 ${live?.enabled ? "animate-pulse text-emerald-400" : "text-slate-500"}`} />
            Live traffic {live?.enabled ? "ON" : "OFF"}
          </button>
          </div>
        </header>
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
