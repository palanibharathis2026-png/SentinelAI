import { Link } from "react-router-dom";
import { MapPin } from "lucide-react";
import TierBadge from "./TierBadge.jsx";
import { fmtDateTime } from "../utils/format.js";

export default function AlertFeed({ alerts }) {
  if (!alerts) return <div className="text-sm text-slate-500">Loading alerts...</div>;
  if (!alerts.length) return <div className="text-sm text-slate-500">No open alerts. All sessions look normal.</div>;

  return (
    <ul className="divide-y divide-slate-800">
      {alerts.map((a) => (
        <li key={a.id}>
          <Link to={`/incidents/${a.id}`} className="-mx-2 flex items-start gap-3 rounded-lg px-2 py-3 hover:bg-slate-800/50">
            <TierBadge tier={a.tier} risk={a.risk} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-medium">{a.name}</span>
                <span className="shrink-0 text-xs text-slate-500">{fmtDateTime(a.timestamp)}</span>
              </div>
              <div className="truncate text-sm text-slate-300">{a.threat || "Anomalous session"}</div>
              <div className="mt-0.5 flex items-center gap-1 text-xs text-slate-500">
                <MapPin className="h-3 w-3" /> {a.city}, {a.country} · {a.device}
                {a.simulated_scenario && <span className="ml-2 rounded bg-fuchsia-500/15 px-1.5 text-fuchsia-300">simulated</span>}
              </div>
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}
