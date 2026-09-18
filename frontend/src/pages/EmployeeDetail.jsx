import { Link, useParams } from "react-router-dom";
import { Fingerprint, Lock, Unlock, UserMinus, UsersRound } from "lucide-react";
import { Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import TierBadge from "../components/TierBadge.jsx";
import { TIER_STYLES, fmtDateTime } from "../utils/format.js";

function TwinRow({ label, value }) {
  return (
    <div className="flex justify-between gap-4 border-b border-slate-800 py-2 text-sm last:border-0">
      <span className="text-slate-400">{label}</span>
      <span className="text-right font-mono text-slate-100">{value}</span>
    </div>
  );
}

export default function EmployeeDetail() {
  const { id } = useParams();
  const { data, error, refresh } = usePolling(() => api.user(id), 5000, [id]);

  if (error) return <div className="card text-red-300">{error}</div>;
  if (!data) return <div className="text-slate-500">Loading...</div>;

  const { employee: emp, twin, events } = data;
  const history = [...events].reverse().map((e) => ({ ...e, t: fmtDateTime(e.timestamp) }));

  async function toggle() {
    if (emp.status === "blocked") await api.unblock(emp.id);
    else await api.block(emp.id);
    refresh();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">{emp.name}</h1>
          <p className="text-sm text-slate-400">{emp.id} · {emp.role} · {emp.department} · {emp.home_city}</p>
          {emp.status === "blocked" && <p className="mt-2 text-sm text-red-300">🔒 {emp.status_reason}</p>}
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={toggle} className={emp.status === "blocked" ? "btn-ghost" : "btn-danger"}>
            {emp.status === "blocked" ? <Unlock className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
            {emp.status === "blocked" ? "Unblock account" : "Block account"}
          </button>
          {data.username && (
            <button className="btn-ghost" title="Remove their login and lock the account; history is kept"
              onClick={async () => {
                if (window.confirm(`Offboard ${emp.name}? Their login is deleted and the account locked.`)) {
                  await api.offboard(emp.id);
                  refresh();
                }
              }}>
              <UserMinus className="h-4 w-4" /> Offboard
            </button>
          )}
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="card">
          <div className="card-title">
            <Fingerprint className="h-4 w-4 text-cyan-400" /> Digital behavioral twin
          </div>
          <TwinRow label="Usual login window" value={twin.usual_hours} />
          <TwinRow label="Home location" value={twin.home_city} />
          <TwinRow label="Known locations" value={twin.known_cities.join(", ")} />
          <TwinRow label="Primary device" value={twin.primary_device} />
          <TwinRow label="Known devices" value={twin.known_devices.length} />
          <TwinRow label="Avg files / session" value={`~${Math.round(twin.avg_files)}`} />
          <TwinRow label="Avg data / session" value={`~${Math.round(twin.avg_mb)} MB`} />
          <TwinRow label="Avg API requests" value={`~${Math.round(twin.avg_api)}`} />
          <TwinRow label="Avg sensitive access" value={`~${twin.avg_sensitive.toFixed(1)}`} />
          <TwinRow label="Weekend activity" value={`${Math.round(twin.weekend_rate * 100)}% of sessions`} />
          <TwinRow label="Learned from" value={twin.baseline === "peer group"
            ? `${twin.sessions} own sessions + the ${twin.peer_group} team` : `${twin.sessions} sessions`} />
          {data.peers?.peers > 0 && (
            <div className="mt-4">
              <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold tracking-wider text-slate-400 uppercase">
                <UsersRound className="h-3.5 w-3.5" /> Compared with {data.peers.department} ({data.peers.peers} peers)
              </div>
              {data.peers.rows.map((r) => (
                <div key={r.metric} className="flex items-center justify-between border-t border-white/5 py-1 text-xs">
                  <span className="text-slate-400">{r.metric}</span>
                  <span className="font-mono">
                    {r.you} <span className="text-slate-500">vs {r.peers ?? "-"}</span>
                    {r.percentile != null && (
                      <span className={`ml-2 ${r.percentile >= 90 ? "text-amber-300" : "text-slate-500"}`}>
                        {r.percentile >= 90 ? "top of team" : `above ${r.percentile}%`}
                      </span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card lg:col-span-2">
          <div className="card-title">Risk per session</div>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="t" stroke="#64748b" fontSize={10} minTickGap={40} />
              <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} ticks={[0, 30, 60, 80, 100]} />
              <ReferenceLine y={80} stroke={TIER_STYLES.BLOCK.hex} strokeDasharray="4 4" strokeOpacity={0.5} />
              <ReferenceLine y={60} stroke={TIER_STYLES.MFA.hex} strokeDasharray="4 4" strokeOpacity={0.5} />
              <Tooltip
                contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: "#94a3b8" }}
              />
              <Line type="monotone" dataKey="risk" stroke="#22d3ee" strokeWidth={2} dot={{ r: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card overflow-x-auto p-0">
        <table className="w-full text-sm">
          <thead className="border-b border-slate-800 text-xs tracking-wider text-slate-400 uppercase">
            <tr>
              <th className="px-4 py-3 text-left">Time</th>
              <th className="px-4 py-3 text-left">Location</th>
              <th className="px-4 py-3 text-left">Device</th>
              <th className="px-4 py-3 text-right">Files</th>
              <th className="px-4 py-3 text-right">API</th>
              <th className="px-4 py-3 text-left">Verdict</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {events.map((e) => (
              <tr key={e.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2">
                  <Link to={`/incidents/${e.id}`} className="hover:text-cyan-300">{fmtDateTime(e.timestamp)}</Link>
                </td>
                <td className="px-4 py-2 text-slate-300">{e.city}, {e.country}</td>
                <td className="px-4 py-2 text-slate-400">{e.device}</td>
                <td className="px-4 py-2 text-right font-mono">{e.files_downloaded}</td>
                <td className="px-4 py-2 text-right font-mono">{e.api_calls}</td>
                <td className="px-4 py-2"><TierBadge tier={e.tier} risk={e.risk} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
