import { useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Database, FlaskConical, LineChart as LineIcon } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { fmtDateTime, pct } from "../utils/format.js";

const SERIES = [
  { key: "hybrid", label: "SentinelAI hybrid", color: "#22d3ee" },
  { key: "ml_only", label: "ML only", color: "#e879f9" },
  { key: "rules_only", label: "Rules only", color: "#fbbf24" },
];

const pm = (s, digits = 1) => `${(s.mean * 100).toFixed(digits)}% ± ${(s.std * 100).toFixed(digits)}`;

// ROC / precision-recall curves, cross-validation over many datasets, and results on real labelled data.
export default function Evaluation({ curves }) {
  const { data: ev } = usePolling(api.evaluation, 0);
  const [kind, setKind] = useState("roc");
  const cv = ev?.cross_validation;
  const external = Object.entries(ev?.external || {});

  return (
    <div className="space-y-6">
      {curves && (
        <div className="card">
          <div className="card-title">
            <LineIcon className="h-4 w-4 text-cyan-400" /> {kind === "roc" ? "ROC curve" : "Precision-recall curve"} (held-out test)
            <div className="ml-auto flex gap-1 text-xs font-normal tracking-normal normal-case">
              {[["roc", "ROC"], ["pr", "Precision-recall"]].map(([k, label]) => (
                <button key={k} onClick={() => setKind(k)}
                  className={`rounded px-2 py-0.5 ${kind === k ? "bg-cyan-500/20 text-cyan-200" : "text-slate-400 hover:text-slate-200"}`}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <Curves curves={curves} kind={kind} />
          <p className="mt-2 text-xs text-slate-500">
            Every alert threshold from 0 to 100, not just the one we use (60). {kind === "roc"
              ? "Top-left is perfect: all attacks caught with no false alarms. AUC = area under the curve (1.0 = perfect, 0.5 = guessing)."
              : "Top-right is perfect: every attack caught and every alert real. AP = average precision."}
          </p>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card">
          <div className="card-title"><FlaskConical className="h-4 w-4 text-fuchsia-300" /> Cross-validation</div>
          {cv ? (
            <>
              <p className="mb-3 text-xs text-slate-400">{cv.method}. Mean ± spread over {cv.runs.length} runs.</p>
              <table className="w-full text-sm">
                <thead className="text-left text-xs text-slate-500 uppercase">
                  <tr><th className="pb-1">Detector</th><th className="pb-1 text-right">Recall</th><th className="pb-1 text-right">Precision</th><th className="pb-1 text-right">AUC</th></tr>
                </thead>
                <tbody>
                  {SERIES.map((s) => (
                    <tr key={s.key} className="border-t border-white/5">
                      <td className="py-1.5" style={{ color: s.color }}>{s.label}</td>
                      <td className="py-1.5 text-right font-mono">{pm(cv.summary[s.key].recall)}</td>
                      <td className="py-1.5 text-right font-mono">{pm(cv.summary[s.key].precision)}</td>
                      <td className="py-1.5 text-right font-mono">{cv.summary[s.key].auc.mean.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="mt-3 flex flex-wrap gap-1">
                {cv.runs.map((r) => (
                  <span key={r.seed} title={`seed ${r.seed}: ${r.test_attacks} attacks, ${r.hybrid.fp} false alarms`}
                    className={`rounded px-1.5 py-0.5 font-mono text-xs ${r.hybrid.recall === 1 ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-300"}`}>
                    {pct(r.hybrid.recall)}
                  </span>
                ))}
              </div>
              <div className="mt-2 text-xs text-slate-500">Hybrid recall per dataset · run {fmtDateTime(cv.evaluated_at)}</div>
            </>
          ) : (
            <p className="text-sm text-slate-400">Run <code className="text-cyan-300">python backend/evaluate.py</code> to test on 8 fresh datasets.</p>
          )}
        </div>

        <div className="card">
          <div className="card-title"><Database className="h-4 w-4 text-emerald-300" /> Real labelled data</div>
          {external.length ? external.map(([name, r]) => (
            <div key={name} className="space-y-2">
              <div className="text-sm">
                <span className="font-semibold text-slate-100">{name}</span>{" "}
                <span className="text-slate-400">· {r.sessions.toLocaleString()} sessions · {r.test_sessions.toLocaleString()} tested ·{" "}
                  {r.test_attacks} insider days in the test period</span>
              </div>
              <table className="w-full text-sm">
                <thead className="text-left text-xs text-slate-500 uppercase">
                  <tr><th className="pb-1">Detector</th><th className="pb-1 text-right">Recall</th><th className="pb-1 text-right">Precision</th><th className="pb-1 text-right">False alarms</th><th className="pb-1 text-right">AUC</th></tr>
                </thead>
                <tbody>
                  {SERIES.map((s) => (
                    <tr key={s.key} className="border-t border-white/5">
                      <td className="py-1.5" style={{ color: s.color }}>{s.label}</td>
                      <td className="py-1.5 text-right font-mono">{pct(r[s.key].recall)}</td>
                      <td className="py-1.5 text-right font-mono">{pct(r[s.key].precision)}</td>
                      <td className="py-1.5 text-right font-mono">{r[s.key].fp}</td>
                      <td className="py-1.5 text-right font-mono">{r[s.key].auc.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {r.hybrid.recall_at_false_alarm_rate && (
                <div className="grid grid-cols-3 gap-2 text-center text-xs">
                  <Stat label="Insiders caught at least once" value={`${r.per_attacker.caught_at_5pct_alerts} / ${r.per_attacker.attackers}`}
                    note="when 5% of normal days are flagged" />
                  <Stat label="Insider days caught" value={pct(r.hybrid.recall_at_false_alarm_rate["0.05"].recall)}
                    note={`5% alert budget · ${pct(r.hybrid.recall_at_false_alarm_rate["0.1"].recall)} at 10%`} />
                  <Stat label="Ranking quality (AUC)" value={r.hybrid.auc.toFixed(3)} note={`rules alone ${r.rules_only.auc.toFixed(3)}`} />
                </div>
              )}
              {r.curves && <Curves curves={r.curves} kind="roc" height={180} />}
              <p className="text-xs text-slate-500">
                Carnegie Mellon CERT Insider Threat dataset r4.2 (© 2011 ExactData, LLC): 200 employees incl. 70 labelled
                insiders, one session per employee-day. It has no locations, failed logins or API logs, so this tests
                after-hours work, new PCs, USB use and data leaving by email. Our alert threshold (60) was calibrated on the
                demo company, so on CERT a real deployment would set the threshold by alert budget instead.
                Evaluated {fmtDateTime(r.evaluated_at)}.
              </p>
            </div>
          )) : (
            <p className="text-sm text-slate-400">
              Convert the CMU CERT r4.2 dataset with <code className="text-cyan-300">backend/cert_to_sentinel.py</code>, then run{" "}
              <code className="text-cyan-300">evaluate.py --data</code>.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, note }) {
  return (
    <div className="rounded-lg bg-slate-950/50 p-2">
      <div className="font-mono text-lg text-emerald-300">{value}</div>
      <div className="text-slate-300">{label}</div>
      <div className="text-slate-500">{note}</div>
    </div>
  );
}

function Curves({ curves, kind, height = 260 }) {
  const xKey = kind === "roc" ? "False alarm rate" : "Recall";
  const yKey = kind === "roc" ? "Attacks caught (recall)" : "Precision";
  return (
    <div style={{ height }}>
      <ResponsiveContainer>
        <LineChart margin={{ top: 5, right: 10, bottom: 15, left: 0 }}>
          <CartesianGrid stroke="#1e293b" />
          <XAxis type="number" dataKey="x" domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} stroke="#64748b" fontSize={11}
            label={{ value: xKey, position: "insideBottom", offset: -8, fill: "#94a3b8", fontSize: 11 }} />
          <YAxis type="number" dataKey="y" domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} stroke="#64748b" fontSize={11} width={42} />
          <Tooltip formatter={(v) => `${(v * 100).toFixed(1)}%`} labelFormatter={(v) => `${xKey} ${(v * 100).toFixed(1)}%`}
            contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }} />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          {SERIES.map((s) => curves[s.key] && (
            <Line key={s.key} name={`${s.label} (${kind === "roc" ? "AUC" : "AP"} ${(kind === "roc" ? curves[s.key].auc : curves[s.key].average_precision).toFixed(3)})`}
              data={curves[s.key][kind].map(([x, y]) => ({ x, y }))} dataKey="y" stroke={s.color} dot={false} strokeWidth={2}
              type={kind === "roc" ? "linear" : "stepAfter"} isAnimationActive={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
