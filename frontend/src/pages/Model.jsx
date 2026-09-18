import { useState } from "react";
import { BrainCircuit, Loader2, RotateCcw, Target } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { TIER_STYLES, pct } from "../utils/format.js";

const DETECTORS = [
  { key: "ml_only", label: "ML only", note: "Isolation Forest + robust distance" },
  { key: "rules_only", label: "Rules only", note: "Security signals with thresholds" },
  { key: "hybrid", label: "SentinelAI hybrid", note: "Both, fused as independent evidence" },
];

const PIPELINE = [
  "User activity",
  "Login / API / file / device logs",
  "Feature extraction vs digital twin",
  "ML anomaly detection",
  "Risk engine",
  "Allow / Monitor / MFA / Block",
  "AI security analyst",
  "SOC dashboard",
];

export default function Model() {
  const { data: m, refresh } = usePolling(api.model, 0);
  const [resetting, setResetting] = useState(false);

  async function reset() {
    if (!window.confirm("Reload the demo dataset? All simulated attacks and live sessions will be cleared.")) return;
    setResetting(true);
    try {
      await api.reset();
      await refresh();
    } finally {
      setResetting(false);
    }
  }

  if (!m) return <div className="text-slate-500">Loading...</div>;
  const h = m.hybrid;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Model &amp; accuracy</h1>
          <p className="text-sm text-slate-400">
            Trained on {m.trained_on} normal sessions. Evaluated on the {m.test_sessions} most recent sessions, which contain{" "}
            {m.test_attacks} planted attacks the model never saw. An alert means risk ≥ {m.alert_threshold}.
          </p>
        </div>
        <button onClick={reset} className="btn-ghost" disabled={resetting}>
          {resetting ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />} Reset demo data
        </button>
      </div>

      <div className="card overflow-x-auto">
        <div className="card-title">
          <Target className="h-4 w-4 text-cyan-400" /> Why hybrid? Detector comparison on unseen data
        </div>
        <table className="w-full text-sm">
          <thead className="text-xs tracking-wider text-slate-400 uppercase">
            <tr>
              <th className="py-2 text-left">Detector</th>
              <th className="py-2 text-right">Recall</th>
              <th className="py-2 text-right">Precision</th>
              <th className="py-2 text-right">F1</th>
              <th className="py-2 text-right">False alarm rate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {DETECTORS.map((d) => {
              const r = m[d.key];
              const best = d.key === "hybrid";
              return (
                <tr key={d.key} className={best ? "text-cyan-200" : ""}>
                  <td className="py-3">
                    <div className="font-medium">{d.label}</div>
                    <div className="text-xs text-slate-500">{d.note}</div>
                  </td>
                  <td className="py-3 text-right font-mono">{pct(r.recall)}</td>
                  <td className="py-3 text-right font-mono">{pct(r.precision)}</td>
                  <td className="py-3 text-right font-mono">{r.f1.toFixed(2)}</td>
                  <td className="py-3 text-right font-mono">{pct(r.false_positive_rate)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="mt-3 text-xs text-slate-500">
          Recall = share of real attacks caught. Precision = share of alerts that were real attacks. Rules miss attacks
          that stay under every threshold; ML alone can miss attacks that look normal on average. Fusing both catches more.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card">
          <div className="card-title">Detection by attack type (hybrid)</div>
          <ul className="space-y-3">
            {Object.entries(m.per_scenario).map(([id, s]) => (
              <li key={id}>
                <div className="flex justify-between text-sm">
                  <span>{s.label}</span>
                  <span className="font-mono text-slate-300">{s.caught}/{s.total}</span>
                </div>
                <div className="mt-1 h-2 rounded-full bg-slate-800">
                  <div
                    className="h-2 rounded-full bg-cyan-400"
                    style={{ width: `${s.total ? (s.caught / s.total) * 100 : 0}%` }}
                  />
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <div className="card-title">Confusion matrix (hybrid)</div>
          <div className="grid grid-cols-[auto_1fr_1fr] gap-2 text-center text-sm">
            <div />
            <div className="text-xs text-slate-400">Flagged</div>
            <div className="text-xs text-slate-400">Not flagged</div>
            <div className="self-center text-right text-xs text-slate-400">Attack</div>
            <div className="rounded-lg bg-emerald-500/15 p-4 font-mono text-2xl text-emerald-300">{h.tp}</div>
            <div className="rounded-lg bg-red-500/15 p-4 font-mono text-2xl text-red-300">{h.fn}</div>
            <div className="self-center text-right text-xs text-slate-400">Normal</div>
            <div className="rounded-lg bg-orange-500/15 p-4 font-mono text-2xl text-orange-300">{h.fp}</div>
            <div className="rounded-lg bg-slate-800 p-4 font-mono text-2xl text-slate-300">{h.tn}</div>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card">
          <div className="card-title">
            <BrainCircuit className="h-4 w-4 text-cyan-400" /> Pipeline
          </div>
          <ol className="space-y-2">
            {PIPELINE.map((step, i) => (
              <li key={step} className="flex items-center gap-3 text-sm">
                <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-500/15 text-xs text-cyan-300">{i + 1}</span>
                {step}
              </li>
            ))}
          </ol>
        </div>
        <div className="card">
          <div className="card-title">Risk tiers &amp; features</div>
          <div className="mb-4 space-y-2">
            {m.tiers.map((t) => (
              <div key={t.tier} className="flex items-center justify-between text-sm">
                <span className="font-semibold" style={{ color: TIER_STYLES[t.tier].hex }}>{t.tier}</span>
                <span className="text-slate-400">risk ≥ {t.min}</span>
                <span className="text-slate-300">{t.action}</span>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {m.features.map((f) => (
              <span key={f} className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300">{f}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
