import { useState } from "react";
import { Link } from "react-router-dom";
import { Globe2, MapPin, Plane } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import ThreatMap from "../components/ThreatMap.jsx";
import TierBadge from "../components/TierBadge.jsx";
import { fmtDateTime } from "../utils/format.js";

const RANGES = [
  { hours: 24, label: "24 h" },
  { hours: 24 * 7, label: "7 days" },
  { hours: 24 * 30, label: "30 days" },
];

export default function ThreatMapPage() {
  const [hours, setHours] = useState(24 * 7);
  const { data } = usePolling(() => api.map(hours), 5000, [hours]);
  const arcs = [...(data?.arcs || [])].reverse();

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="gradient-text text-3xl font-bold">Global Threat Map</h1>
          <p className="text-sm text-slate-400">
            Dots are login locations. Arcs fly from the employee&apos;s home city to where a suspicious login came from.
          </p>
        </div>
        <div className="flex gap-1 rounded-lg border border-white/10 p-1">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              onClick={() => setHours(r.hours)}
              className={`rounded-md px-3 py-1 text-sm ${hours === r.hours ? "bg-indigo-500/30 text-indigo-100" : "text-slate-400 hover:text-slate-200"}`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="card glow-border border">
        <ThreatMap data={data} />
        <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-400">
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-cyan-400" /> Normal logins</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-rose-400" /> Location with alerts</span>
          <span className="flex items-center gap-1.5"><span className="h-0.5 w-5 bg-gradient-to-r from-cyan-400 to-rose-500" /> Attack path (click to investigate)</span>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card">
          <div className="card-title"><Plane className="h-4 w-4 text-rose-400" /> Attack paths</div>
          {arcs.length === 0 && <div className="text-sm text-slate-400">No cross-location alerts in this period. Launch an attack from the SOC page.</div>}
          <ul className="max-h-96 space-y-2 overflow-y-auto pr-1">
            {arcs.map((a) => (
              <li key={a.id}>
                <Link to={`/incidents/${a.id}`} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 px-3 py-2 text-sm hover:border-rose-400/50 hover:bg-rose-500/5">
                  <div className="min-w-0">
                    <div className="font-medium">{a.name}</div>
                    <div className="truncate text-xs text-slate-400">
                      {a.from.city} → {a.to.city} · {a.threat} · {fmtDateTime(a.timestamp)}
                    </div>
                  </div>
                  <TierBadge tier={a.tier} risk={a.risk} />
                </Link>
              </li>
            ))}
          </ul>
        </div>
        <div className="card">
          <div className="card-title"><Globe2 className="h-4 w-4 text-cyan-400" /> Login locations</div>
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-slate-400 uppercase">
              <tr><th className="pb-2">City</th><th className="pb-2">Sessions</th><th className="pb-2">Alerts</th></tr>
            </thead>
            <tbody>
              {(data?.cities || []).map((c) => (
                <tr key={c.city} className="border-t border-white/5">
                  <td className="py-1.5">
                    <MapPin className={`mr-1 inline h-3.5 w-3.5 ${c.country === "India" ? "text-cyan-400" : "text-rose-400"}`} />
                    {c.city}, <span className="text-slate-400">{c.country}</span>
                  </td>
                  <td className="py-1.5 font-mono">{c.sessions}</td>
                  <td className={`py-1.5 font-mono ${c.alerts ? "text-rose-300" : "text-slate-500"}`}>{c.alerts}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
