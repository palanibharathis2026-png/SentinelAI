import { Link } from "react-router-dom";
import {
  ArrowRight, Bot, BrainCircuit, Fingerprint, FlaskConical, Globe2, KeyRound, Plane, ScanEye,
  ShieldCheck, ShieldHalf, Siren, UserX, Zap,
} from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import ThreatMap from "../components/ThreatMap.jsx";
import { pct } from "../utils/format.js";

const STEPS = [
  { icon: Fingerprint, title: "Learn", text: "Builds a Digital Behavioral Twin of every employee: hours, devices, cities, data habits, systems and admin actions.", color: "from-cyan-500 to-blue-600" },
  { icon: ScanEye, title: "Compare", text: "Every new session is turned into 13 behaviour features that measure drift from the twin.", color: "from-indigo-500 to-violet-600" },
  { icon: BrainCircuit, title: "Score", text: "An ML ensemble (Isolation Forest + robust distance) and explainable security signals are fused into one risk score.", color: "from-violet-500 to-fuchsia-600" },
  { icon: Zap, title: "Respond", text: "Allow, monitor, challenge with MFA or block automatically, and an AI analyst explains why in plain English.", color: "from-fuchsia-500 to-rose-600" },
];

const THREATS = [
  { icon: KeyRound, title: "Account takeover", text: "Stolen password used from abroad at night on a new laptop.", color: "text-rose-300 bg-rose-500/15" },
  { icon: UserX, title: "Insider data theft", text: "A trusted employee suddenly downloads 30x their normal data.", color: "text-orange-300 bg-orange-500/15" },
  { icon: Siren, title: "Credential stuffing", text: "Dozens of failed logins from a datacenter, then a bot gets in.", color: "text-amber-300 bg-amber-500/15" },
  { icon: Plane, title: "Impossible travel", text: "Chennai at 10:00, São Paulo at 10:30. Nobody flies that fast.", color: "text-sky-300 bg-sky-500/15" },
  { icon: Bot, title: "Rogue AI agent", text: "A script with a stolen token hammers APIs at machine speed.", color: "text-violet-300 bg-violet-500/15" },
  { icon: ShieldHalf, title: "Stealth leak + tampering", text: "Every signal kept just under the limit, or audit logs switched off. Only ML sees it.", color: "text-fuchsia-300 bg-fuchsia-500/15" },
];

export default function Landing() {
  const { data: model } = usePolling(api.model, 0);
  const { data: map } = usePolling(() => api.map(24 * 7), 8000);
  const h = model?.hybrid;

  return (
    <div className="space-y-14 pb-10">
      <section className="grid items-center gap-10 pt-4 lg:grid-cols-2">
        <div>
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-fuchsia-400/30 bg-fuchsia-500/10 px-3 py-1 text-xs text-fuchsia-200">
            <ShieldCheck className="h-3.5 w-3.5" /> Code Cortex 3.0 · Security track · Team INNOVEX
          </div>
          <h1 className="text-4xl leading-tight font-extrabold sm:text-5xl">
            The password was correct.
            <br />
            <span className="gradient-text">The behavior was not.</span>
          </h1>
          <p className="mt-5 max-w-xl text-lg text-slate-300">
            SentinelAI catches hackers who log in with <b>real</b> stolen passwords, and insiders who already have access,
            by learning how each employee normally behaves and flagging the moment they don&apos;t.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link to="/soc" className="btn-primary px-5 py-3 text-base">
              Open SOC dashboard <ArrowRight className="h-4 w-4" />
            </Link>
            <Link to="/lab" className="btn-ghost px-5 py-3 text-base">
              <FlaskConical className="h-4 w-4" /> Try the Risk Lab
            </Link>
          </div>
        </div>
        <div className="card glow-border border">
          <div className="card-title"><Globe2 className="h-4 w-4 text-cyan-400" /> Live threat map</div>
          <ThreatMap data={map} compact />
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: "Attacks caught", value: h ? pct(h.recall) : "-", sub: `${h?.tp ?? "-"} of ${model?.test_attacks ?? "-"} in the test set`, c: "from-emerald-500/25 ring-emerald-400/30" },
          { label: "Alert precision", value: h ? pct(h.precision) : "-", sub: `${h?.fp ?? "-"} false alarms`, c: "from-cyan-500/25 ring-cyan-400/30" },
          { label: "Rules alone", value: model ? pct(model.rules_only.recall) : "-", sub: "miss the stealth attacks", c: "from-orange-500/25 ring-orange-400/30" },
          { label: "Threat types", value: "6", sub: "simulated end-to-end", c: "from-fuchsia-500/25 ring-fuchsia-400/30" },
        ].map((s) => (
          <div key={s.label} className={`rounded-2xl bg-gradient-to-br to-transparent p-5 ring-1 ${s.c}`}>
            <div className="text-xs tracking-wider text-slate-300 uppercase">{s.label}</div>
            <div className="mt-1 text-4xl font-extrabold text-white">{s.value}</div>
            <div className="text-xs text-slate-400">{s.sub}</div>
          </div>
        ))}
      </section>

      <section>
        <h2 className="mb-5 text-2xl font-bold">How it works</h2>
        <div className="grid gap-4 md:grid-cols-4">
          {STEPS.map((s, i) => (
            <div key={s.title} className="card relative">
              <div className={`mb-3 inline-flex rounded-xl bg-gradient-to-br p-2.5 text-white shadow-lg ${s.color}`}>
                <s.icon className="h-5 w-5" />
              </div>
              <div className="text-xs text-slate-500">Step {i + 1}</div>
              <div className="text-lg font-semibold">{s.title}</div>
              <p className="mt-1 text-sm text-slate-400">{s.text}</p>
            </div>
          ))}
        </div>
        <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/60 p-4 text-center font-mono text-sm text-slate-300">
          risk = 1 − (1 − <span className="text-cyan-300">ML anomaly</span>) × (1 − <span className="text-fuchsia-300">security signals</span>)
          <span className="ml-3 text-slate-500">→ ALLOW &lt;30 · MONITOR · MFA ≥60 · BLOCK ≥80</span>
        </div>
      </section>

      <section>
        <h2 className="mb-5 text-2xl font-bold">Threats it catches</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {THREATS.map((t) => (
            <div key={t.title} className="card flex gap-4">
              <div className={`h-fit rounded-xl p-2.5 ${t.color}`}><t.icon className="h-5 w-5" /></div>
              <div>
                <div className="font-semibold">{t.title}</div>
                <p className="text-sm text-slate-400">{t.text}</p>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
