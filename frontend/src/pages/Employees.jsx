import { Link } from "react-router-dom";
import { Lock, Unlock } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import AddEmployee from "../components/AddEmployee.jsx";
import TierBadge from "../components/TierBadge.jsx";
import { fmtDateTime, riskHex } from "../utils/format.js";

export default function Employees() {
  const { data: users, refresh } = usePolling(api.users, 5000);

  async function toggle(u) {
    if (u.status === "blocked") await api.unblock(u.id);
    else await api.block(u.id);
    refresh();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Employees</h1>
          <p className="text-sm text-slate-400">
            Each employee has a Digital Behavioral Twin learned from their past sessions. New joiners start from their team&apos;s habits.
          </p>
        </div>
        <AddEmployee onDone={refresh} />
      </div>
      <div className="card overflow-x-auto p-0">
        <table className="w-full text-sm">
          <thead className="border-b border-slate-800 text-xs tracking-wider text-slate-400 uppercase">
            <tr>
              <th className="px-4 py-3 text-left">Employee</th>
              <th className="px-4 py-3 text-left">Department</th>
              <th className="px-4 py-3 text-left">Last session</th>
              <th className="px-4 py-3 text-left">Peak risk 24h</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {(users || []).map((u) => (
              <tr key={u.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-3">
                  <Link to={`/employees/${u.id}`} className="font-medium hover:text-cyan-300">{u.name}</Link>
                  <div className="text-xs text-slate-500">{u.id} · {u.role}</div>
                </td>
                <td className="px-4 py-3 text-slate-300">{u.department}</td>
                <td className="px-4 py-3">
                  <TierBadge tier={u.last_tier} risk={u.last_risk} />
                  <div className="mt-1 text-xs text-slate-500">{fmtDateTime(u.last_seen)}</div>
                </td>
                <td className="px-4 py-3 font-mono" style={{ color: riskHex(u.peak_risk_24h) }}>{u.peak_risk_24h}</td>
                <td className="px-4 py-3">
                  {u.status === "blocked" ? (
                    <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-300" title={u.status_reason}>BLOCKED</span>
                  ) : (
                    <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-xs font-semibold text-emerald-300">ACTIVE</span>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  <button onClick={() => toggle(u)} className={u.status === "blocked" ? "btn-ghost" : "btn-danger"}>
                    {u.status === "blocked" ? <Unlock className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
                    {u.status === "blocked" ? "Unblock" : "Block"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
