import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle, Briefcase, CheckCircle2, Clock, Database, FileDown, FileSpreadsheet, FolderOpen, Info, KeyRound,
  Laptop, Loader2, Lock, LogOut, Mail, MapPin, PackageOpen, ShieldCheck, ShieldOff, Trophy, X,
} from "lucide-react";
import { api } from "../api.js";
import { setAuth } from "../auth.js";
import { fmtTime } from "../utils/format.js";

const CHECK = {
  verified: { icon: CheckCircle2, text: "Session verified: your activity matches your usual behaviour.", cls: "border-emerald-400/40 bg-emerald-500/10 text-emerald-200" },
  mfa: { icon: AlertTriangle, text: "Security flagged this session as unusual and is watching it closely.", cls: "border-amber-400/40 bg-amber-500/10 text-amber-200" },
};

// Awareness note shown before opening something new or something outside your permissions.
function Notice({ notice, onClose, onOpen, onRequest }) {
  if (!notice) return null;
  const denied = notice.type === "denied";
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className={`card w-full max-w-md ${denied ? "border-red-500/50" : "border-amber-400/50"}`}>
        <div className="flex items-start gap-3">
          <div className={`rounded-full p-2 ${denied ? "bg-red-500/20" : "bg-amber-500/20"}`}>
            {denied ? <Lock className="h-6 w-6 text-red-300" /> : <Info className="h-6 w-6 text-amber-300" />}
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-bold">{denied ? "You don't have access" : "First time opening this"}</h3>
            <p className="mt-1 text-sm text-slate-300">
              {denied ? (
                <>
                  Your role has no permission for <b>{notice.system}</b>. Opening it anyway will <b>lock your account</b> until the
                  security admin unlocks it, and the admin will be emailed.
                </>
              ) : (
                <>
                  You have never opened <b>{notice.system}</b> before. You are allowed to, but SentinelAI will record it and send
                  you and the admin a security notice.
                </>
              )}
            </p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X className="h-5 w-5" /></button>
        </div>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <button onClick={onClose} className="btn-ghost">Cancel</button>
          {denied && (
            <button onClick={onRequest} className="btn-primary" disabled={notice.pending}>
              <KeyRound className="h-4 w-4" /> {notice.pending ? "Request pending" : "Request access"}
            </button>
          )}
          <button onClick={onOpen} className={denied ? "btn-danger" : "btn-primary"}>
            {denied ? "Open anyway" : "Continue"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function StaffPortal() {
  const [me, setMe] = useState(null);
  const [busy, setBusy] = useState(null);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [newEmail, setNewEmail] = useState("");
  const [editEmail, setEditEmail] = useState(false);

  const heartbeat = useCallback(async () => {
    try {
      setMe(await api.staffHeartbeat());
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    heartbeat();
    const id = setInterval(heartbeat, 8000);
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

  async function run(label, fn, done) {
    setBusy(label);
    setError(null);
    try {
      const res = await fn();
      setMe(res);
      setMessage(typeof done === "function" ? done(res) : done);
    } catch (e) {
      setError(e.message);
      heartbeat();
    } finally {
      setBusy(null);
    }
  }

  const act = (kind, system, label) =>
    run(system || kind, () => api.staffActivity(kind, system), (res) =>
      res.first_time ? `${label}. Security notice sent to your email (first-time access).` : label);

  function openSystem(system) {
    if (!me.permissions.includes(system)) {
      setNotice({ type: "denied", system, pending: me.pending_requests.includes(system) });
    } else if (!me.familiar.includes(system)) {
      setNotice({ type: "new", system });
    } else {
      act("open", system, `Opened ${system}`);
    }
  }

  if (!me) return <div className="flex min-h-screen items-center justify-center text-slate-400">{error || "Opening workspace..."}</div>;

  const { employee: emp, session, security_check: check } = me;

  if (check === "locked") {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="card max-w-md border-red-500/50 text-center">
          <div className="mx-auto mb-4 w-fit rounded-full bg-red-500/20 p-4">
            <ShieldOff className="h-10 w-10 text-red-400" />
          </div>
          <h1 className="text-2xl font-bold text-red-200">Account temporarily locked</h1>
          <p className="mt-2 text-slate-300">{emp.status_reason || "SentinelAI noticed unusual behaviour and locked the account."}</p>
          <p className="mt-2 text-sm text-slate-400">
            The security admin has been emailed. This page unlocks by itself as soon as they unlock your account.
          </p>
          <div className="mt-4 flex items-center justify-center gap-2 text-xs text-slate-500">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Waiting for the admin…
          </div>
          <button onClick={logout} className="btn-ghost mx-auto mt-6">
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </div>
      </div>
    );
  }

  const status = CHECK[check] || CHECK.verified;

  return (
    <div className="min-h-screen">
      <Notice
        notice={notice}
        onClose={() => setNotice(null)}
        onOpen={() => {
          const n = notice;
          setNotice(null);
          act("open", n.system, `Opened ${n.system}`);
        }}
        onRequest={() => {
          const n = notice;
          setNotice(null);
          run("request", () => api.staffRequestAccess(n.system), `Access to ${n.system} requested. The admin has been emailed.`);
        }}
      />

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

        <div className="grid gap-3 sm:grid-cols-4">
          {[
            [Clock, "Signed in", fmtTime(session.login_at)],
            [MapPin, "Location", `${session.city}, ${session.country}`],
            [Laptop, "Device", session.device],
            [Mail, "Email", me.email],
          ].map(([Icon, label, value]) => (
            <div key={label} className="card flex items-center gap-3 p-4">
              <Icon className="h-5 w-5 shrink-0 text-cyan-300" />
              <div className="min-w-0">
                <div className="text-xs text-slate-400">{label}</div>
                <div className="truncate text-sm font-medium" title={value}>{value}</div>
              </div>
            </div>
          ))}
        </div>

        {(message || error || busy) && (
          <div className={`rounded-lg px-3 py-2 text-sm ${error ? "bg-red-500/10 text-red-200" : "bg-white/5 text-slate-200"}`}>
            {busy ? <span className="flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Working...</span> : error || `✓ ${message}`}
          </div>
        )}

        <div className="card">
          <div className="card-title"><Database className="h-4 w-4 text-cyan-300" /> Company systems</div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {me.all_systems.map((s) => {
              const allowed = me.permissions.includes(s);
              const familiar = me.familiar.includes(s);
              const pending = me.pending_requests.includes(s);
              return (
                <button
                  key={s}
                  onClick={() => openSystem(s)}
                  disabled={!!busy}
                  className={`flex items-center gap-3 rounded-xl border p-3 text-left transition disabled:opacity-50 ${
                    allowed ? "border-cyan-400/30 bg-cyan-500/10 hover:bg-cyan-500/20" : "border-white/10 bg-slate-950/40 hover:border-red-400/40"
                  }`}
                >
                  {allowed ? <Database className="h-5 w-5 shrink-0 text-cyan-300" /> : <Lock className="h-5 w-5 shrink-0 text-slate-500" />}
                  <div className="min-w-0">
                    <div className={`truncate font-medium ${allowed ? "" : "text-slate-400"}`}>{s}</div>
                    <div className="text-xs text-slate-500">
                      {!allowed ? (pending ? "Access requested" : "No access") : familiar ? "You use this" : "Allowed · never opened"}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="card">
          <div className="card-title"><ShieldCheck className="h-4 w-4 text-emerald-400" /> Everyday work</div>
          <div className="grid gap-3 sm:grid-cols-3">
            <button onClick={() => act("work", null, "Downloaded today's work files")} disabled={!!busy} className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-4 text-left hover:bg-emerald-500/20 disabled:opacity-50">
              <FileDown className="mb-2 h-5 w-5 text-emerald-300" />
              <div className="font-semibold">Download today&apos;s files</div>
              <div className="text-xs text-slate-400">Normal work. Should stay green.</div>
            </button>
            <div className="rounded-xl border border-white/10 bg-slate-950/40 p-4 sm:col-span-2">
              <div className="flex items-center gap-2 font-semibold"><Mail className="h-4 w-4 text-cyan-300" /> My email</div>
              {editEmail ? (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    setEditEmail(false);
                    run("email", () => api.staffChangeEmail(newEmail), `Email changed to ${newEmail}`);
                  }}
                  className="mt-2 flex gap-2"
                >
                  <input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} placeholder="new@example.com" className="min-w-0 flex-1 rounded-lg border border-white/10 bg-slate-950 px-3 py-1.5 text-sm" />
                  <button className="btn-primary text-xs" disabled={!newEmail}>Save</button>
                </form>
              ) : (
                <div className="mt-1 flex items-center justify-between gap-2 text-sm text-slate-400">
                  <span className="truncate">Codes and security notices go to {me.email}</span>
                  <button onClick={() => setEditEmail(true)} className="shrink-0 text-cyan-300 hover:underline">Change</button>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-title"><FolderOpen className="h-4 w-4 text-amber-300" /> Shared drive</div>
          <div className="grid gap-2 sm:grid-cols-3">
            {me.shared_files.map((f) => (
              <button key={f} onClick={() => act("open", f, `Opened ${f}`)} disabled={!!busy} className="flex items-center gap-2 rounded-lg border border-white/10 bg-slate-950/50 px-3 py-2.5 text-left text-sm hover:border-amber-300/50 disabled:opacity-50">
                <FileSpreadsheet className="h-4 w-4 shrink-0 text-amber-300" />
                <span className="truncate">{f}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-fuchsia-400/30 bg-gradient-to-r from-fuchsia-500/10 to-indigo-500/10 p-4 text-sm">
          <div className="flex items-center gap-2 font-semibold text-fuchsia-200"><Trophy className="h-4 w-4" /> Challenge: can you beat SentinelAI?</div>
          <p className="mt-1 text-slate-300">
            Try to take as much data as you can without getting caught. Files taken so far: <b>{session.files_downloaded}</b>
          </p>
        </div>

        <div className="card border-rose-500/30">
          <div className="card-title"><AlertTriangle className="h-4 w-4 text-rose-400" /> Try something suspicious (demo)</div>
          <div className="grid gap-3 sm:grid-cols-3">
            <button onClick={() => act("extra", null, "Downloaded an extra batch")} disabled={!!busy} className="rounded-xl border border-orange-400/40 bg-orange-500/10 p-4 text-left hover:bg-orange-500/20 disabled:opacity-50">
              <FileDown className="mb-2 h-5 w-5 text-orange-300" />
              <div className="font-semibold">Download an extra batch</div>
              <div className="text-xs text-slate-400">3x your normal files</div>
            </button>
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
      </main>
    </div>
  );
}
