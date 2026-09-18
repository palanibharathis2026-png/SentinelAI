import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Bot, CheckCircle2, Download, Fingerprint, KeyRound, Loader2, Lock, RefreshCw, Server, ShieldAlert, ThumbsDown, Unlock, XCircle } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import RiskGauge from "../components/RiskGauge.jsx";
import TierBadge from "../components/TierBadge.jsx";
import TwinComparison from "../components/TwinComparison.jsx";
import { fmtDateTime } from "../utils/format.js";

const SEVERITY = {
  critical: "border-red-500/40 bg-red-500/10 text-red-200",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-200",
  medium: "border-yellow-500/30 bg-yellow-500/5 text-yellow-100",
};

export default function Incident() {
  const { id } = useParams();
  const { data, error, refresh } = usePolling(() => api.event(id), 0, [id]);
  const [explaining, setExplaining] = useState(false);
  const [explainError, setExplainError] = useState(null);

  if (error) return <div className="card text-red-300">{error}</div>;
  if (!data) return <div className="text-slate-500">Loading...</div>;

  const { event: ev, employee: emp, comparison } = data;

  async function explain(refreshText = false) {
    setExplaining(true);
    setExplainError(null);
    try {
      await api.explain(ev.id, refreshText);
      await refresh();
    } catch (e) {
      setExplainError(e.message);
    } finally {
      setExplaining(false);
    }
  }

  async function setStatus(status) {
    await api.setEventStatus(ev.id, status);
    refresh();
  }

  async function toggleBlock() {
    if (emp.status === "blocked") await api.unblock(emp.id);
    else await api.block(emp.id, `Blocked from incident #${ev.id}: ${ev.threat || "suspicious session"}`);
    refresh();
  }

  const tampering = ["disable_audit_logs", "disable_mfa", "delete_backups"];
  const newResources = ev.resources.filter((r) => !data.twin.familiar_resources?.includes(r));

  return (
    <div className="space-y-6">
      <div className="print-only">
        <div className="text-xl font-bold">SentinelAI incident report #{ev.id}</div>
        <div className="text-sm">Generated {new Date().toLocaleString()} · Team INNOVEX</div>
        <hr className="my-3" />
      </div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="text-xs tracking-wider text-slate-500 uppercase">Incident #{ev.id}</div>
          <h1 className="gradient-text text-3xl font-bold">{ev.threat || "Session review"}</h1>
          <p className="text-sm text-slate-400">
            <Link to={`/employees/${emp.id}`} className="text-cyan-300 hover:underline">{emp.name}</Link> · {emp.role} ·{" "}
            {fmtDateTime(ev.timestamp)} · {ev.city}, {ev.country} · IP {ev.ip}
          </p>
          {ev.simulated_scenario && (
            <span className="mt-2 inline-block rounded bg-fuchsia-500/15 px-2 py-0.5 text-xs text-fuchsia-300">
              Simulated attack: {ev.simulated_scenario}
            </span>
          )}
        </div>
        <div className="no-print flex flex-wrap gap-2">
          <button onClick={() => window.print()} className="btn-primary" title="Save as PDF from the print dialog">
            <Download className="h-4 w-4" /> Download report
          </button>
          <button onClick={() => setStatus("resolved")} className="btn-ghost" disabled={ev.status === "resolved"}>
            <CheckCircle2 className="h-4 w-4" /> Resolve
          </button>
          <button onClick={() => setStatus("false_positive")} className="btn-ghost" disabled={ev.status === "false_positive"}>
            <ThumbsDown className="h-4 w-4" /> False positive
          </button>
          <button onClick={toggleBlock} className={emp.status === "blocked" ? "btn-ghost" : "btn-danger"}>
            {emp.status === "blocked" ? <Unlock className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
            {emp.status === "blocked" ? "Unblock user" : "Block user"}
          </button>
        </div>
      </div>

      {ev.risk >= 30 && (
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-2xl border border-white/10 bg-gradient-to-r from-emerald-500/10 via-slate-900/40 to-rose-500/15 px-5 py-3">
          <KeyRound className="h-5 w-5 text-slate-300" />
          <span className="flex items-center gap-1.5 text-emerald-300"><CheckCircle2 className="h-4 w-4" /> Password correct</span>
          <span className="flex items-center gap-1.5 text-emerald-300"><CheckCircle2 className="h-4 w-4" /> Login succeeded</span>
          <span className="flex items-center gap-1.5 font-semibold text-rose-300"><XCircle className="h-4 w-4" /> Behaviour does not match {emp.name.split(" ")[0]}&apos;s twin</span>
          <span className="text-xs text-slate-400">A normal login system would have let this session in.</span>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="card flex flex-col items-center text-center">
          <RiskGauge risk={ev.risk} />
          <div className="mt-2"><TierBadge tier={ev.tier} /></div>
          <div className="mt-3 text-lg font-semibold">{ev.action}</div>
          <div className="mt-4 grid w-full grid-cols-2 gap-2 text-sm">
            <div className="rounded-lg bg-slate-800/60 p-2">
              <div className="text-xs text-slate-400">ML anomaly</div>
              <div className="font-mono text-lg">{Math.round(ev.ml_score)}</div>
            </div>
            <div className="rounded-lg bg-slate-800/60 p-2">
              <div className="text-xs text-slate-400">Signal evidence</div>
              <div className="font-mono text-lg">{Math.round(ev.rule_score)}</div>
            </div>
          </div>
          <div className="mt-3 text-xs text-slate-500">
            Case status: <span className="text-slate-300">{ev.status.replace("_", " ")}</span> · account{" "}
            <span className={emp.status === "blocked" ? "text-red-300" : "text-emerald-300"}>{emp.status}</span>
          </div>
        </div>

        <div className="card lg:col-span-2">
          <div className="card-title">
            <Bot className="h-4 w-4 text-cyan-400" /> AI security analyst
            {data.explanation && (
              <button onClick={() => explain(true)} className="ml-auto text-slate-500 hover:text-slate-300" title="Regenerate">
                <RefreshCw className={`h-4 w-4 ${explaining ? "animate-spin" : ""}`} />
              </button>
            )}
          </div>
          {data.explanation ? (
            <>
              <p className="leading-relaxed text-slate-200">{data.explanation}</p>
              <div className="mt-3 text-xs text-slate-500">
                Written by {data.explanation_source === "claude" ? "Claude" : "the built-in template analyst"}
              </div>
            </>
          ) : (
            <button onClick={() => explain(false)} className="btn-primary no-print" disabled={explaining}>
              {explaining ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bot className="h-4 w-4" />}
              Explain this session
            </button>
          )}
          {explainError && <div className="mt-2 text-sm text-red-400">{explainError}</div>}

          <div className="card-title mt-6">
            <ShieldAlert className="h-4 w-4 text-orange-400" /> Why it was flagged
          </div>
          {ev.reasons.length === 0 ? (
            <div className="text-sm text-slate-400">No rule signals fired. The session is consistent with the digital twin.</div>
          ) : (
            <ul className="space-y-2">
              {ev.reasons.map((r) => (
                <li key={r.signal} className={`rounded-lg border px-3 py-2 text-sm ${SEVERITY[r.severity]}`}>
                  <div className="flex justify-between font-semibold">
                    <span>{r.signal}</span>
                    <span className="font-mono">+{r.points}</span>
                  </div>
                  <div className="opacity-90">{r.detail}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {(ev.resources.length > 0 || ev.actions.length > 0) && (
        <div className="card">
          <div className="card-title"><Server className="h-4 w-4 text-violet-400" /> What the session touched</div>
          <div className="flex flex-wrap gap-2">
            {ev.resources.map((r) => (
              <span key={r} className={`rounded-full border px-3 py-1 text-xs ${newResources.includes(r) ? "border-orange-400/50 bg-orange-500/15 text-orange-200" : "border-white/10 text-slate-300"}`}>
                {r}{newResources.includes(r) && " · first time"}
              </span>
            ))}
            {ev.actions.map((a) => (
              <span key={a} className={`rounded-full border px-3 py-1 font-mono text-xs ${tampering.includes(a) ? "border-rose-400/60 bg-rose-500/20 text-rose-200" : "border-indigo-400/40 bg-indigo-500/15 text-indigo-200"}`}>
                ⚙ {a}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-title">
          <Fingerprint className="h-4 w-4 text-cyan-400" /> Digital twin vs this session
        </div>
        <TwinComparison rows={comparison} />
      </div>
    </div>
  );
}
