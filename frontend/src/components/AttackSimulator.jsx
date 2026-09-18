import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Crosshair, Loader2 } from "lucide-react";
import { api } from "../api.js";
import TierBadge from "./TierBadge.jsx";

export default function AttackSimulator({ onLaunched }) {
  const [scenarios, setScenarios] = useState([]);
  const [users, setUsers] = useState([]);
  const [target, setTarget] = useState("");
  const [running, setRunning] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.scenarios().then(setScenarios).catch((e) => setError(e.message));
    api.users().then(setUsers).catch(() => {});
  }, []);

  async function launch(id) {
    setRunning(id);
    setError(null);
    try {
      const events = await api.simulate(id, target);
      setResult(events[events.length - 1]);
      onLaunched?.();
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="card">
      <div className="card-title">
        <Crosshair className="h-4 w-4 text-fuchsia-400" /> Attack simulator
      </div>
      <label className="mb-3 block text-xs text-slate-400">
        Target employee
        <select
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
        >
          <option value="">Random employee</option>
          {users.map((u) => (
            <option key={u.id} value={u.id}>
              {u.name} ({u.role})
            </option>
          ))}
        </select>
      </label>
      <div className="grid gap-2">
        {scenarios.map((s) => (
          <button
            key={s.id}
            onClick={() => launch(s.id)}
            disabled={running !== null}
            title={s.description}
            className="flex items-center justify-between rounded-lg border border-slate-700 px-3 py-2 text-left text-sm hover:border-fuchsia-500/60 hover:bg-fuchsia-500/10 disabled:opacity-50"
          >
            <span>{s.label}</span>
            {running === s.id && <Loader2 className="h-4 w-4 animate-spin" />}
          </button>
        ))}
      </div>
      {error && <div className="mt-3 text-sm text-red-400">{error}</div>}
      {result && (
        <Link
          to={`/incidents/${result.id}`}
          className="mt-4 block rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm hover:border-cyan-500/60"
        >
          <div className="flex items-center justify-between">
            <span className="font-medium">{result.name}</span>
            <TierBadge tier={result.tier} risk={result.risk} />
          </div>
          <div className="mt-1 text-slate-400">{result.threat || "No threat detected"}</div>
          <div className="mt-1 text-xs text-cyan-400">Open incident →</div>
        </Link>
      )}
    </div>
  );
}
