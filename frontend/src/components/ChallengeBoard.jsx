import { Link } from "react-router-dom";
import { Trophy } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import TierBadge from "./TierBadge.jsx";
import { fmtTime } from "../utils/format.js";

// "Can you steal data without getting caught?" results from guests who used the staff portal.
export default function ChallengeBoard() {
  const { data } = usePolling(api.challenge, 5000);
  const attempts = data?.attempts ?? 0;
  const caught = data?.caught ?? 0;

  return (
    <div className="card border-fuchsia-400/30">
      <div className="card-title">
        <Trophy className="h-4 w-4 text-fuchsia-300" /> Beat-SentinelAI challenge
      </div>
      <div className="flex items-end gap-4">
        <div>
          <div className="text-4xl font-extrabold text-white">
            {caught}<span className="text-xl text-slate-400">/{attempts}</span>
          </div>
          <div className="text-xs text-slate-400">guest attempts caught (24 h)</div>
        </div>
        <div className="mb-1 h-2 flex-1 overflow-hidden rounded-full bg-slate-800">
          <div className="h-2 rounded-full bg-gradient-to-r from-fuchsia-500 to-rose-500" style={{ width: `${attempts ? (caught / attempts) * 100 : 0}%` }} />
        </div>
      </div>
      {attempts === 0 ? (
        <p className="mt-3 text-sm text-slate-400">No guest has tried yet. Hand someone a staff login and challenge them to take data without getting caught.</p>
      ) : (
        <ul className="mt-3 space-y-1.5">
          {(data?.recent || []).map((a) => (
            <li key={a.event_id}>
              <Link to={`/incidents/${a.event_id}`} className="flex items-center justify-between gap-2 rounded-lg px-2 py-1 text-sm hover:bg-white/5">
                <span className="truncate">
                  {a.caught ? "🚨" : "🥷"} {a.name} <span className="text-xs text-slate-500">· {a.files} files · {fmtTime(a.timestamp)}</span>
                </span>
                <TierBadge tier={a.tier} risk={a.risk} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
