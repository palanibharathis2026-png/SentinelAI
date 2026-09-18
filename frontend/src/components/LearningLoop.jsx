import { useState } from "react";
import { CheckCircle2, GraduationCap, Loader2, RefreshCcw, ShieldX } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { fmtDateTime, pct } from "../utils/format.js";

const STEPS = [
  ["Analyst labels", "Marks a wrong alert as “False positive” on its incident page"],
  ["Twin learns", "That person’s digital twin absorbs the session at once"],
  ["Drift", "Safe, finished sessions from the last 30 days keep twins up to date"],
  ["Challenger", "A new model is trained with the labels (each counts ×5)"],
  ["Safety gate", "Goes live only if it misses no more held-out attacks"],
];

// Self-learning loop: analyst feedback -> twins -> champion / challenger retraining.
export default function LearningLoop({ onModelChange }) {
  const { data: l, refresh } = usePolling(api.learning, 10000);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  if (!l) return null;

  async function retrain() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.retrain();
      setResult(r);
      await refresh();
      if (r.accepted) onModelChange?.();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card glow-border border">
      <div className="card-title">
        <GraduationCap className="h-4 w-4 text-emerald-300" /> Self-learning loop
        <span className="ml-auto rounded bg-emerald-500/15 px-2 py-0.5 text-xs font-normal tracking-normal text-emerald-300 normal-case">
          live model v{l.version}
        </span>
      </div>

      <ol className="mb-4 grid gap-2 sm:grid-cols-5">
        {STEPS.map(([title, text], i) => (
          <li key={title} className="rounded-lg border border-white/10 bg-slate-950/40 p-2.5 text-xs">
            <div className="mb-1 flex items-center gap-1.5 font-semibold text-slate-200">
              <span className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-300">{i + 1}</span>
              {title}
            </div>
            <div className="text-slate-400">{text}</div>
          </li>
        ))}
      </ol>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-2 text-sm">
          <Row label="False alarms labelled" value={l.labels.false_positive} />
          <Row label="Attacks confirmed (resolved)" value={l.labels.confirmed_attack} />
          <Row label="Open alerts awaiting review" value={l.labels.open_alerts} />
          <Row label="Precision judged by analysts" value={l.analyst_precision == null ? "-" : pct(l.analyst_precision)} />
          <Row label="Labels inside the live model" value={l.feedback_used} />
          <button onClick={retrain} disabled={busy} className="btn-primary mt-2 w-full justify-center">
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCcw className="h-4 w-4" />} Retrain with feedback
          </button>
          {error && <div className="text-xs text-red-300">{error}</div>}
        </div>

        <div className="lg:col-span-2 space-y-3">
          {result && (
            <div className={`rounded-lg border p-3 text-sm ${result.accepted ? "border-emerald-500/40 bg-emerald-500/10" : "border-amber-500/40 bg-amber-500/10"}`}>
              <div className="flex items-center gap-1.5 font-semibold">
                {result.accepted ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <ShieldX className="h-4 w-4 text-amber-300" />}
                {result.accepted ? `Accepted: model v${result.version} is live` : "Not deployed"}
              </div>
              <div className="mt-1 text-slate-300">{result.reason}</div>
              {result.challenger && (
                <div className="mt-2 grid grid-cols-3 gap-2 font-mono text-xs">
                  <Compare label="Recall" a={pct(result.champion.recall)} b={pct(result.challenger.recall)} />
                  <Compare label="False alarms" a={result.champion.fp} b={result.challenger.fp} />
                  <Compare label="ML risk of labelled alarms" a={result.labelled_ml_risk.before} b={result.labelled_ml_risk.after} />
                </div>
              )}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-slate-500 uppercase">
                <tr>
                  <th className="pb-1">Version</th>
                  <th className="pb-1">When</th>
                  <th className="pb-1 text-right">Labels</th>
                  <th className="pb-1 text-right">Recall</th>
                  <th className="pb-1 text-right">False alarms</th>
                </tr>
              </thead>
              <tbody>
                {l.versions.map((v, i) => (
                  <tr key={i} className={`border-t border-white/5 ${v.accepted ? "" : "text-slate-500 line-through decoration-slate-600"}`} title={v.note}>
                    <td className="py-1 font-mono">{v.version}</td>
                    <td className="py-1 text-slate-400">{fmtDateTime(v.at)}</td>
                    <td className="py-1 text-right font-mono">{v.feedback_labels}</td>
                    <td className="py-1 text-right font-mono">{pct(v.recall)}</td>
                    <td className="py-1 text-right font-mono">{v.fp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {l.twins.length > 0 && (
            <div className="text-xs text-slate-400">
              Twins updated since training:{" "}
              {l.twins.map((t) => `${t.name} (${t.feedback} labelled, ${t.recent} recent)`).join(" · ")}
            </div>
          )}
          <div className="text-xs text-slate-500">
            Never learned: alerts nobody reviewed, blocked accounts, and confirmed attacks, so an attacker cannot
            teach SentinelAI that an attack is normal. Accuracy is always measured on the same held-out attacks.
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="flex justify-between rounded-lg bg-slate-950/40 px-3 py-1.5">
      <span className="text-slate-400">{label}</span>
      <span className="font-mono text-slate-100">{value}</span>
    </div>
  );
}

function Compare({ label, a, b }) {
  return (
    <div className="rounded bg-slate-950/50 p-2">
      <div className="font-sans text-slate-400">{label}</div>
      <div>{a} → <span className="text-slate-100">{b}</span></div>
    </div>
  );
}
