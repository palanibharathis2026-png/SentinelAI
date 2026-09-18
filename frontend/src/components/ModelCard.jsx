import { useState } from "react";
import { Download, FileCode2, Layers } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { fmtDateTime } from "../utils/format.js";

// The trained model as files: what it is, what it learned per feature, and downloads.
export default function ModelCard() {
  const { data: card } = usePolling(api.modelCard, 0);
  const [error, setError] = useState(null);
  if (!card?.name) return null;

  async function download(name) {
    setError(null);
    try {
      await api.downloadModel(name);
    } catch (e) {
      setError(e.message);
    }
  }

  const td = card.training_data;
  const maxShare = Math.max(...card.features.map((f) => f.split_share), 0.01);

  return (
    <div className="card glow-border border">
      <div className="card-title">
        <FileCode2 className="h-4 w-4 text-fuchsia-300" /> Trained model
        <span className="ml-auto text-xs font-normal tracking-normal text-slate-500 normal-case">trained {fmtDateTime(card.trained_at)}</span>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-3 text-sm">
          <div>
            <div className="font-semibold text-slate-100">{card.name}</div>
            <div className="text-slate-400">{card.type}</div>
          </div>
          {card.algorithms.map((a) => (
            <div key={a.name} className="rounded-lg border border-white/10 bg-slate-950/50 p-2.5">
              <div className="flex items-center gap-1.5 font-medium text-cyan-200"><Layers className="h-3.5 w-3.5" /> {a.name}</div>
              <div className="text-xs text-slate-400">{a.role}</div>
              <div className="mt-1 font-mono text-[11px] text-slate-500">
                {Object.entries(a.params).map(([k, v]) => `${k}=${v}`).join(" · ")}
              </div>
            </div>
          ))}
          <div className="rounded-lg border border-white/10 bg-slate-950/50 p-2.5 text-xs text-slate-400">
            <div className="font-medium text-slate-200">Training data</div>
            {td.employees} employees · {td.sessions_total} sessions · trained on {td.training_sessions} normal sessions
            (days {td.training_days}) · tested on held-out days {td.test_days}
            <div className="mt-1 truncate font-mono text-[10px] text-slate-600" title={td.sha256}>sha256 {td.sha256?.slice(0, 24)}…</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => download("model")} className="btn-primary text-xs">
              <Download className="h-3.5 w-3.5" /> sentinel_model.npz
            </button>
            <button onClick={() => download("card")} className="btn-ghost text-xs">
              <Download className="h-3.5 w-3.5" /> model_card.json
            </button>
          </div>
          {error && <div className="text-xs text-red-300">{error}</div>}
        </div>

        <div className="lg:col-span-2">
          <div className="mb-2 text-xs text-slate-400">
            What the model learned for each of the {card.features.length} features: the typical (median) normal value, how
            much normal sessions vary, and how often the Isolation Forest splits on it.
          </div>
          <table className="w-full text-xs">
            <thead className="text-left text-slate-500">
              <tr>
                <th className="pb-1.5 font-medium">Feature</th>
                <th className="pb-1.5 font-medium">Normal median</th>
                <th className="pb-1.5 font-medium">Normal spread</th>
                <th className="w-1/3 pb-1.5 font-medium">Forest split share</th>
              </tr>
            </thead>
            <tbody>
              {card.features.map((f) => (
                <tr key={f.name} className="border-t border-white/5" title={f.description}>
                  <td className="py-1 pr-2 font-mono text-slate-300">{f.name}</td>
                  <td className="py-1 font-mono text-slate-400">{f.normal_median}</td>
                  <td className="py-1 font-mono text-slate-400">{f.normal_spread}</td>
                  <td className="py-1">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 flex-1 rounded-full bg-slate-800">
                        <div className="h-1.5 rounded-full bg-gradient-to-r from-cyan-400 to-fuchsia-500" style={{ width: `${(f.split_share / maxShare) * 100}%` }} />
                      </div>
                      <span className="w-10 text-right font-mono text-slate-400">{(f.split_share * 100).toFixed(1)}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-2 text-[11px] text-slate-500">
            Features with 0% (like new country) never varied in normal training data, so the forest cannot split on them;
            they are covered by the Robust Distance model and the explainable rules.
          </div>
        </div>
      </div>
    </div>
  );
}
