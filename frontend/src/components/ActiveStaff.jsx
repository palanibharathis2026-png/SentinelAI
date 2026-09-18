import { Link } from "react-router-dom";
import { Laptop, MapPin, UsersRound } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import TierBadge from "./TierBadge.jsx";
import { fmtTime } from "../utils/format.js";

// Staff who are signed in to the employee portal right now (real logins, not simulated).
export default function ActiveStaff() {
  const { data } = usePolling(api.activeStaff, 3000);
  const { data: health } = usePolling(api.health, 0);
  const staff = data || [];
  const portal = health?.lan_ip ? `http://${health.lan_ip}:${window.location.port || 80}` : window.location.origin;

  return (
    <div className="card border-emerald-400/30">
      <div className="card-title">
        <UsersRound className="h-4 w-4 text-emerald-400" /> Staff online now
        <span className="ml-auto flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300 normal-case">
          <span className={`h-2 w-2 rounded-full bg-emerald-400 ${staff.length ? "animate-pulse" : "opacity-40"}`} /> {staff.length} active
        </span>
      </div>
      {staff.length === 0 ? (
        <div className="text-sm text-slate-400">
          No one is signed in to the staff portal. Ask a guest to open{" "}
          <span className="font-mono text-cyan-300">{portal}</span> and choose <b>Staff portal</b>.
        </div>
      ) : (
        <ul className="space-y-2">
          {staff.map((s) => (
            <li key={s.user_id}>
              <Link to={`/incidents/${s.event_id}`} className="block rounded-xl border border-white/10 bg-slate-950/40 p-3 hover:border-emerald-400/50">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
                  </span>
                  <span className="font-medium">{s.name}</span>
                  <span className="ml-auto"><TierBadge tier={s.tier} risk={s.risk} /></span>
                </div>
                <div className="mt-1 text-xs text-slate-400">
                  {s.role} · since {fmtTime(s.login_at)}
                  {s.account_status === "blocked" && <span className="ml-2 text-red-300">account locked</span>}
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 text-xs text-slate-500">
                  <span className="flex items-center gap-1"><MapPin className="h-3 w-3" /> {s.city}</span>
                  <span className="flex items-center gap-1"><Laptop className="h-3 w-3" /> {s.device}</span>
                  <span>{s.files_downloaded} files</span>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
