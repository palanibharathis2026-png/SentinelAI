import { useEffect, useMemo, useState } from "react";
import { Bot, FlaskConical, Fingerprint, Loader2, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "../api.js";
import RiskGauge from "../components/RiskGauge.jsx";
import TierBadge from "../components/TierBadge.jsx";
import TwinComparison from "../components/TwinComparison.jsx";

const SEVERITY = {
  critical: "border-red-500/40 bg-red-500/10 text-red-200",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-200",
  medium: "border-yellow-500/30 bg-yellow-500/5 text-yellow-100",
};

// Each preset changes a normal day into a known attack pattern.
const PRESETS = [
  { id: "normal", label: "Normal day", emoji: "🙂", make: (p) => ({}) },
  {
    id: "ato", label: "Stolen password", emoji: "🕵️",
    make: (p) => ({ hour: 3, city: "Moscow", device: "new", files: p.files * 40, sensitive: 30, minutes_since_last: 600, actions: ["bulk_export", "disable_audit_logs"] }),
  },
  {
    id: "insider", label: "Insider leak", emoji: "📦",
    make: (p) => ({ hour: 19, files: p.files * 25, sensitive: 25, actions: ["bulk_export"] }),
  },
  {
    id: "travel", label: "Impossible travel", emoji: "✈️",
    make: (p) => ({ city: "Sao Paulo", device: "new", minutes_since_last: 30, actions: ["disable_mfa"] }),
  },
  {
    id: "bot", label: "Rogue AI agent", emoji: "🤖",
    make: (p) => ({ city: "Ashburn", device: "bot", api_calls: Math.max(p.api, 50) * 80, actions: ["create_api_token", "bulk_export"] }),
  },
  {
    id: "stealth", label: "Stealth leak", emoji: "🥷",
    make: (p) => ({ hour: p.hours[1], city: p.home_city === "Pune" ? "Mumbai" : "Pune", device: "second", files: Math.round(p.files * 3.2), api_calls: Math.round(p.api * 4), sensitive: 3, failed_attempts: 2 }),
  },
];

function baseFor(p) {
  const [start, end] = p.hours;
  const hour = start < end ? Math.floor((start + end) / 2) : 23;
  return {
    user_id: p.id, hour, weekend: false, city: p.home_city, device: "usual", files: p.files, api_calls: p.api,
    sensitive: 0, failed_attempts: 0, minutes_since_last: 240, resources: p.resources.slice(0, 1), actions: [],
  };
}

function Slider({ label, value, min, max, step = 1, onChange, suffix = "" }) {
  return (
    <label className="block text-sm">
      <div className="flex justify-between text-slate-300">
        <span>{label}</span>
        <span className="font-mono text-indigo-200">{value.toLocaleString()}{suffix}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full" />
    </label>
  );
}

function Chips({ options, selected, onToggle, danger = [] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => {
        const on = selected.includes(o);
        const bad = danger.includes(o);
        return (
          <button
            key={o}
            onClick={() => onToggle(o)}
            className={`rounded-full border px-2.5 py-0.5 text-xs transition ${
              on ? (bad ? "border-rose-400 bg-rose-500/25 text-rose-100" : "border-indigo-400 bg-indigo-500/25 text-indigo-100")
                : "border-white/10 text-slate-400 hover:border-white/30"
            }`}
          >
            {o}
          </button>
        );
      })}
    </div>
  );
}

export default function RiskLab() {
  const [opts, setOpts] = useState(null);
  const [form, setForm] = useState(null);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.labOptions().then((o) => {
      setOpts(o);
      setForm(baseFor(o.employees[0]));
    }).catch((e) => setError(e.message));
  }, []);

  const profile = useMemo(() => opts?.employees.find((e) => e.id === form?.user_id), [opts, form?.user_id]);

  // Re-score shortly after every change.
  useEffect(() => {
    if (!form) return undefined;
    const t = setTimeout(async () => {
      setBusy(true);
      try {
        setResult(await api.labScore(form));
        setError(null);
      } catch (e) {
        setError(e.message);
      } finally {
        setBusy(false);
      }
    }, 250);
    return () => clearTimeout(t);
  }, [form]);

  if (!form || !opts) return <div className="text-slate-500">{error || "Loading Risk Lab..."}</div>;

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));
  const toggle = (key) => (v) => set({ [key]: form[key].includes(v) ? form[key].filter((x) => x !== v) : [...form[key], v] });
  const tampering = ["disable_audit_logs", "disable_mfa", "delete_backups"];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="gradient-text flex items-center gap-2 text-3xl font-bold">Risk Lab</h1>
        <p className="text-sm text-slate-400">
          Play attacker: change one thing at a time and watch the ML model and the security signals react live. Nothing is saved.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        {PRESETS.map((pr) => (
          <button key={pr.id} onClick={() => setForm({ ...baseFor(profile), ...pr.make(profile) })} className="btn-ghost">
            <span>{pr.emoji}</span> {pr.label}
          </button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="card space-y-4 lg:col-span-2">
          <div className="card-title mb-0"><FlaskConical className="h-4 w-4 text-violet-400" /> Build a session</div>
          <label className="block text-sm text-slate-300">
            Employee
            <select
              value={form.user_id}
              onChange={(e) => setForm(baseFor(opts.employees.find((x) => x.id === e.target.value)))}
              className="mt-1 w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-2 text-sm"
            >
              {opts.employees.map((e) => <option key={e.id} value={e.id}>{e.name} ({e.role}, {e.home_city})</option>)}
            </select>
          </label>
          <div className="grid grid-cols-2 gap-3">
            <label className="block text-sm text-slate-300">
              Login city
              <select value={form.city} onChange={(e) => set({ city: e.target.value })} className="mt-1 w-full rounded-lg border border-white/10 bg-slate-950 px-2 py-2 text-sm">
                {opts.cities.map((c) => <option key={c.city} value={c.city}>{c.city} ({c.country})</option>)}
              </select>
            </label>
            <label className="block text-sm text-slate-300">
              Device
              <select value={form.device} onChange={(e) => set({ device: e.target.value })} className="mt-1 w-full rounded-lg border border-white/10 bg-slate-950 px-2 py-2 text-sm">
                {opts.devices.map((d) => <option key={d.id} value={d.id}>{d.label}</option>)}
              </select>
            </label>
          </div>
          <Slider label="Login hour" value={form.hour} min={0} max={23} onChange={(v) => set({ hour: v })} suffix=":00" />
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={form.weekend} onChange={(e) => set({ weekend: e.target.checked })} /> Weekend
          </label>
          <Slider label="Minutes since last login" value={form.minutes_since_last} min={5} max={1440} step={5} onChange={(v) => set({ minutes_since_last: v })} />
          <Slider label={`Files downloaded (usual ~${profile.files})`} value={form.files} min={0} max={Math.max(800, profile.files * 60)} onChange={(v) => set({ files: v })} />
          <Slider label={`API calls (usual ~${profile.api})`} value={form.api_calls} min={0} max={Math.max(10000, profile.api * 100)} step={10} onChange={(v) => set({ api_calls: v })} />
          <Slider label="Sensitive records opened" value={form.sensitive} min={0} max={100} onChange={(v) => set({ sensitive: v })} />
          <Slider label="Failed logins first" value={form.failed_attempts} min={0} max={30} onChange={(v) => set({ failed_attempts: v })} />
          <div>
            <div className="mb-1 text-sm text-slate-300">Systems opened <span className="text-xs text-slate-500">(usual: {profile.resources.join(", ") || "none"})</span></div>
            <Chips options={opts.resources} selected={form.resources} onToggle={toggle("resources")} />
          </div>
          <div>
            <div className="mb-1 text-sm text-slate-300">Admin actions <span className="text-xs text-slate-500">(usual: {profile.actions.join(", ") || "none"})</span></div>
            <Chips options={opts.actions} selected={form.actions} onToggle={toggle("actions")} danger={tampering} />
          </div>
        </div>

        <div className="space-y-6 lg:col-span-3">
          <div className="card glow-border border">
            <div className="grid items-center gap-6 sm:grid-cols-2">
              <div className="flex flex-col items-center">
                {result && <RiskGauge risk={result.risk} />}
                {result && <div className="mt-2"><TierBadge tier={result.tier} /></div>}
                <div className="mt-2 text-lg font-semibold">{result?.action}</div>
                {busy && <Loader2 className="mt-1 h-4 w-4 animate-spin text-slate-500" />}
              </div>
              <div className="space-y-3">
                <div className="rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/10 p-3 ring-1 ring-cyan-400/30">
                  <div className="flex items-center gap-1.5 text-xs text-cyan-200"><Sparkles className="h-3.5 w-3.5" /> ML anomaly (Isolation Forest + robust distance)</div>
                  <div className="font-mono text-2xl">{Math.round(result?.ml_score ?? 0)}</div>
                </div>
                <div className="rounded-xl bg-gradient-to-br from-fuchsia-500/20 to-violet-600/10 p-3 ring-1 ring-fuchsia-400/30">
                  <div className="flex items-center gap-1.5 text-xs text-fuchsia-200"><ShieldAlert className="h-3.5 w-3.5" /> Security signals (explainable rules)</div>
                  <div className="font-mono text-2xl">{result?.rule_score ?? 0}</div>
                </div>
                <div className="rounded-xl border border-white/10 bg-slate-950/60 p-3 font-mono text-xs text-slate-300">
                  risk = 1 − (1 − ML) × (1 − signals)
                  <div className="mt-1 text-indigo-200">= {result?.formula} = {result?.risk}</div>
                </div>
              </div>
            </div>
            {result?.threat && (
              <div className="mt-4 flex items-center gap-2 rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
                <Bot className="h-4 w-4" /> Likely threat: <b>{result.threat}</b>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title"><ShieldAlert className="h-4 w-4 text-orange-400" /> Why</div>
            {!result?.reasons?.length ? (
              <div className="text-sm text-slate-400">No security signals. This looks like the employee&apos;s normal behaviour.</div>
            ) : (
              <ul className="space-y-2">
                {result.reasons.map((r) => (
                  <li key={r.signal} className={`rounded-lg border px-3 py-2 text-sm ${SEVERITY[r.severity]}`}>
                    <div className="flex justify-between font-semibold"><span>{r.signal}</span><span className="font-mono">+{r.points}</span></div>
                    <div className="opacity-90">{r.detail}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="card">
            <div className="card-title"><Fingerprint className="h-4 w-4 text-cyan-400" /> Digital twin vs this session</div>
            {result && <TwinComparison rows={result.comparison} />}
          </div>
        </div>
      </div>
      {error && <div className="text-sm text-red-400">{error}</div>}
    </div>
  );
}
