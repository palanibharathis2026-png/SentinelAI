import { NavLink } from "react-router-dom";
import { Activity, BrainCircuit, LayoutDashboard, Radio, ShieldCheck, Users } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";

const NAV = [
  { to: "/", label: "SOC Dashboard", icon: LayoutDashboard, end: true },
  { to: "/employees", label: "Employees", icon: Users },
  { to: "/model", label: "Model & Accuracy", icon: BrainCircuit },
];

export default function Layout({ children }) {
  const { data: health } = usePolling(api.health, 10000);
  const { data: live, refresh } = usePolling(api.live, 10000);

  async function toggleLive() {
    await api.setLive(!live?.enabled);
    refresh();
  }

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-950 p-4 md:flex">
        <div className="mb-8 flex items-center gap-2 px-2">
          <ShieldCheck className="h-7 w-7 text-cyan-400" />
          <div>
            <div className="text-lg font-bold tracking-tight">SentinelAI</div>
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
                  isActive ? "bg-cyan-500/15 text-cyan-300" : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                }`
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto space-y-2 rounded-lg border border-slate-800 p-3 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Activity className={`h-3.5 w-3.5 ${health ? "text-emerald-400" : "text-red-400"}`} />
            API {health ? "online" : "offline"}
          </div>
          <div>
            AI analyst:{" "}
            <span className="text-slate-200">{health?.ai_analyst === "claude" ? "Claude" : "Built-in template"}</span>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-slate-800 px-6 py-3">
          <nav className="flex gap-4 text-sm md:hidden">
            {NAV.map(({ to, label, end }) => (
              <NavLink key={to} to={to} end={end} className={({ isActive }) => (isActive ? "text-cyan-300" : "text-slate-400")}>
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="hidden text-sm text-slate-400 md:block">Security Operations Center</div>
          <button onClick={toggleLive} className="btn-ghost text-xs" title="Background company activity">
            <Radio className={`h-4 w-4 ${live?.enabled ? "animate-pulse text-emerald-400" : "text-slate-500"}`} />
            Live traffic {live?.enabled ? "ON" : "OFF"}
          </button>
        </header>
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
