import { useState } from "react";
import { BrainCircuit, Loader2, RotateCcw } from "lucide-react";
import { api } from "../api.js";
import Evaluation from "../components/Evaluation.jsx";
import LearningLoop from "../components/LearningLoop.jsx";
import ModelCard from "../components/ModelCard.jsx";
import { usePolling } from "../hooks/usePolling.js";
import { TIER_STYLES } from "../utils/format.js";


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
          <h1 className="gradient-text text-3xl font-bold">Model &amp; accuracy</h1>
          <p className="text-sm text-slate-400">
            Accuracy is measured on real, labelled insider-threat data (Carnegie Mellon CERT r4.2), not on our own demo data.
          </p>
        </div>
        <button onClick={reset} className="btn-ghost" disabled={resetting}>
          {resetting ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />} Reset demo data
        </button>
      </div>

      <ModelCard key={m.trained_on + h.fp + h.recall} />

      <LearningLoop onModelChange={refresh} />

      <Evaluation />

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
