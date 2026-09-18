import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle, Briefcase, CheckCircle2, Clock, Database, FileDown, Laptop, Loader2, Lock, LogOut, MapPin,
  PackageOpen, ShieldCheck, ShieldOff,
} from "lucide-react";
import { api } from "../api.js";
import { setAuth } from "../auth.js";
import { fmtTime } from "../utils/format.js";

const CHECK = {
  verified: { icon: CheckCircle2, text: "Session verified: your activity matches your usual behaviour.", cls: "border-emerald-400/40 bg-emerald-500/10 text-emerald-200" },
  mfa: { icon: AlertTriangle, text: "Security asked for extra verification (MFA) because this session looks unusual.", cls: "border-amber-400/40 bg-amber-500/10 text-amber-200" },
  locked: { icon: Lock, text: "Account locked by the security team.", cls: "border-red-500/50 bg-red-500/15 text-red-200" },
};

export default function StaffPortal() {
  const [me, setMe] = useState(null);
  const [busy, setBusy] = useState(null);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const heartbeat = useCallback(async () => {
    try {
      setMe(await api.staffHeartbeat());
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    heartbeat();
    const id = setInterval(heartbeat, 10000);
    return () => clearInterval(id);
  }, [heartbeat]);

  async function logout() {
    try {
      await api.staffLogout();
    } catch {
      /* already signed out */
    }
    setAuth(null);
  }

  async function act(kind, system, label) {
    setBusy(system || kind);
    setError(null);
    try {
      setMe(await api.staffActivity(kind, system));
      setMessage(label);
    } catch (e) {
      setError(e.message);
      heartbeat();
    } finally {
      setBusy(null);
    }
  }

  if (!me) return <div className="flex min-h-screen items-center justify-center text-slate-400">{error || "Opening workspace..."}</div>;

  const { employee: emp, session, security_check: check } = me;
  const locked = check === "locked" || emp.status === "blocked";

  if (locked) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="card max-w-md border-red-500/50 text-center">
          <div className="mx-auto mb-4 w-fit rounded-full bg-red-500/20 p-4">
            <ShieldOff className="h-10 w-10 text-red-400" />
          </div>
          <h1 className="text-2xl font-bold text-red-200">Account locked</h1>
          <p className="mt-2 text-slate-300">
            SentinelAI noticed that this session does not behave like {emp.name.split(" ")[0]} and locked the account.
            The security team has been alerted.
          </p>
          <button onClick={logout} className="btn-ghost mx-auto mt-6">
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </div>
      </div>
    );
  }

  const status = CHECK[check] || CHECK.verified;
  const others = me.all_systems.filter((s) => !me.usual_systems.includes(s));

  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b border-white/10 px-4 py-3 sm:px-8">
        <div className="flex items-center gap-2">
          <div className="rounded-lg bg-gradient-to-br from-indigo-500 to-fuchsia-500 p-1.5">
            <Briefcase className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="font-bold">Company Workspace</div>
            <div className="text-xs text-slate-400">protected by SentinelAI</div>
          </div>
        </div>
        <button onClick={logout} className="btn-ghost text-sm">
          <LogOut className="h-4 w-4" /> Sign out
        </button>
      </header>

      <main className="mx-auto max-w-4xl space-y-6 p-4 sm:p-8">
        <div>
          <h1 className="text-3xl font-bold">
            Hi, <span className="gradient-text">{emp.name.split(" ")[0]}</span> 👋
          </h1>
          <p className="text-slate-400">{emp.role} · {emp.department}</p>
        </div>

        <div className={`flex items-center gap-3 rounded-2xl border px-4 py-3 ${status.cls}`}>
          <status.icon className="h-5 w-5 shrink-0" />
          <span className="text-sm">{status.text}</span>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          {[
            [Clock, "Signed in", fmtTime(session.login_at)],
            [MapPin, "Location", `${session.city}, ${session.country}`],
            [Laptop, "Device", session.device],
          ].map(([Icon, label, value]) => (
            <div key={label} className="card flex items-center gap-3 p-4">
              <Icon className="h-5 w-5 text-cyan-300" />
              <div className="min-w-0">
                <div className="text-xs text-slate-400">{label}</div>
                <div className="truncate text-sm font-medium">{value}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="card-title"><ShieldCheck className="h-4 w-4 text-emerald-400" /> Your everyday work</div>
          <div className="grid gap-3 sm:grid-cols-2">
            <button onClick={() => act("work", null, "Downloaded today's work files")} disabled={!!busy} className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-4 text-left hover:bg-emerald-500/20 disabled:opacity-50">
              <FileDown className="mb-2 h-5 w-5 text-emerald-300" />
              <div className="font-semibold">Download today&apos;s files</div>
              <div className="text-xs text-slate-400">Normal work. Should stay green.</div>
            </button>
            {me.usual_systems.map((s) => (
              <button key={s} onClick={() => act("open", s, `Opened ${s}`)} disabled={!!busy} className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 p-4 text-left hover:bg-cyan-500/20 disabled:opacity-50">
                <Database className="mb-2 h-5 w-5 text-cyan-300" />
                <div className="font-semibold">Open {s}</div>
                <div className="text-xs text-slate-400">A system you use every day</div>
              </button>
            ))}
          </div>
        </div>

        <div className="card border-rose-500/30">
          <div className="card-title"><AlertTriangle className="h-4 w-4 text-rose-400" /> Try something suspicious (demo)</div>
          <div className="mb-3 flex flex-wrap gap-2">
            {others.map((s) => (
              <button key={s} onClick={() => act("open", s, `Opened ${s}`)} disabled={!!busy} className="rounded-full border border-orange-400/40 bg-orange-500/10 px-3 py-1 text-xs text-orange-200 hover:bg-orange-500/20 disabled:opacity-50">
                {busy === s ? "..." : `Open ${s}`}
              </button>
            ))}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <button onClick={() => act("export", null, "Exported company data")} disabled={!!busy} className="rounded-xl border border-rose-400/40 bg-rose-500/10 p-4 text-left hover:bg-rose-500/20 disabled:opacity-50">
              <PackageOpen className="mb-2 h-5 w-5 text-rose-300" />
              <div className="font-semibold">Export ALL company data</div>
              <div className="text-xs text-slate-400">30x your normal downloads</div>
            </button>
            <button onClick={() => act("disable_audit_logs", null, "Turned off audit logs")} disabled={!!busy} className="rounded-xl border border-rose-400/40 bg-rose-500/10 p-4 text-left hover:bg-rose-500/20 disabled:opacity-50">
              <ShieldOff className="mb-2 h-5 w-5 text-rose-300" />
              <div className="font-semibold">Turn off audit logs</div>
              <div className="text-xs text-slate-400">What attackers do to hide</div>
            </button>
          </div>
        </div>

        {busy && <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Working...</div>}
        {message && !busy && <div className="text-sm text-slate-300">✓ {message}. Files downloaded this session: {session.files_downloaded}</div>}
        {error && <div className="text-sm text-red-300">{error}</div>}
      </main>
    </div>
  );
}
