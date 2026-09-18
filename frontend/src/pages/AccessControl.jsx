import { useEffect, useState } from "react";
import { Check, KeyRound, Loader2, Lock, Mail, Send, ShieldCheck, Unlock, X } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { fmtDateTime } from "../utils/format.js";

function EmailField({ value, placeholder, onSave }) {
  const [text, setText] = useState(value || "");
  const [saving, setSaving] = useState(false);
  useEffect(() => setText(value || ""), [value]);
  const changed = text.trim() !== (value || "");
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        setSaving(true);
        try {
          await onSave(text.trim());
        } finally {
          setSaving(false);
        }
      }}
      className="flex gap-1.5"
    >
      <input
        type="email"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={placeholder}
        className="min-w-0 flex-1 rounded-md border border-white/10 bg-slate-950 px-2 py-1 text-xs"
      />
      {changed && (
        <button className="rounded-md bg-cyan-500/20 px-2 text-xs text-cyan-200 hover:bg-cyan-500/30" disabled={saving}>
          {saving ? "..." : "Save"}
        </button>
      )}
    </form>
  );
}

export default function AccessControl() {
  const { data, error, refresh } = usePolling(api.access, 4000);
  const [busy, setBusy] = useState(null);
  const [note, setNote] = useState(null);
  const [emailCheck, setEmailCheck] = useState(null);

  async function run(key, fn, message) {
    setBusy(key);
    setNote(null);
    try {
      await fn();
      if (message) setNote(message);
      await refresh();
    } catch (e) {
      setNote(e.message);
    } finally {
      setBusy(null);
    }
  }

  if (!data) return <div className="text-slate-500">{error || "Loading access control..."}</div>;

  function toggle(person, system) {
    const perms = person.permissions.includes(system)
      ? person.permissions.filter((p) => p !== system)
      : [...person.permissions, system];
    run(`${person.user_id}-${system}`, () => api.updateAccess(person.user_id, { permissions: perms }));
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="gradient-text text-3xl font-bold">Access Control</h1>
        <p className="text-sm text-slate-400">
          Decide which systems each person may open. Opening a system without permission locks the account until you unlock it here.
        </p>
      </div>

      {note && <div className="rounded-lg bg-white/5 px-3 py-2 text-sm text-slate-200">{note}</div>}

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card border-amber-400/30">
          <div className="card-title"><KeyRound className="h-4 w-4 text-amber-300" /> Access requests</div>
          {data.requests.length === 0 ? (
            <div className="text-sm text-slate-400">No pending requests.</div>
          ) : (
            <ul className="space-y-2">
              {data.requests.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/10 px-3 py-2 text-sm">
                  <div>
                    <b>{r.name}</b> wants <span className="text-amber-200">{r.resource}</span>
                    <div className="text-xs text-slate-500">{fmtDateTime(r.created_at)}</div>
                  </div>
                  <div className="flex gap-1.5">
                    <button onClick={() => run(`r${r.id}`, () => api.decideRequest(r.id, true), `Approved ${r.resource} for ${r.name}`)} disabled={!!busy} className="flex items-center gap-1 rounded-md bg-emerald-500/20 px-2 py-1 text-xs text-emerald-200 hover:bg-emerald-500/30">
                      <Check className="h-3.5 w-3.5" /> Approve
                    </button>
                    <button onClick={() => run(`r${r.id}`, () => api.decideRequest(r.id, false), `Denied ${r.resource} for ${r.name}`)} disabled={!!busy} className="flex items-center gap-1 rounded-md bg-red-500/20 px-2 py-1 text-xs text-red-200 hover:bg-red-500/30">
                      <X className="h-3.5 w-3.5" /> Deny
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card">
          <div className="card-title"><Mail className="h-4 w-4 text-cyan-300" /> Security alerts by email</div>
          <div className="space-y-3 text-sm">
            <label className="block text-slate-300">
              Admin email (receives login, denial, request and attack alerts)
              <div className="mt-1">
                <EmailField value={data.admin_email.endsWith(".demo") ? "" : data.admin_email} placeholder={data.admin_email}
                  onSave={(v) => run("admin-email", async () => {
                    const r = await api.setAdminEmail(v);
                    setEmailCheck(r.verify_required ? { to: r.pending, code: "" } : null);
                  }, "Admin email updated")} />
              </div>
            </label>
            {emailCheck && (
              <form className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-3 text-xs"
                onSubmit={(e) => {
                  e.preventDefault();
                  run("admin-email", async () => { await api.verifyAdminEmail(emailCheck.code); setEmailCheck(null); },
                    "New admin email confirmed. Sign-in codes and alerts go there now.");
                }}>
                <div className="mb-2 text-slate-200">We sent a code to <b>{emailCheck.to}</b>. Enter it to confirm the new address
                  (the old one keeps working until then).</div>
                <div className="flex gap-2">
                  <input value={emailCheck.code} maxLength={6} inputMode="numeric" placeholder="000000"
                    onChange={(e) => setEmailCheck({ ...emailCheck, code: e.target.value.replace(/\D/g, "") })}
                    className="w-28 rounded-md border border-white/10 bg-slate-950 px-2 py-1 text-center font-mono tracking-widest" />
                  <button className="rounded-md bg-cyan-500/20 px-3 text-cyan-200 hover:bg-cyan-500/30" disabled={emailCheck.code.length !== 6}>
                    Confirm
                  </button>
                  <button type="button" className="text-slate-400 hover:text-slate-200" onClick={() => setEmailCheck(null)}>Cancel</button>
                </div>
              </form>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded-full px-2 py-0.5 text-xs ${data.smtp_configured ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-200"}`}>
                {data.smtp_configured ? "Email sending: ON (SMTP)" : "Email sending: demo mode (Mail Outbox only)"}
              </span>
              <span className="rounded-full bg-indigo-500/15 px-2 py-0.5 text-xs text-indigo-200">
                Staff OTP: {data.otp_required ? "required" : "off"}
              </span>
              <button onClick={() => run("test", async () => {
                const r = await api.testMail();
                setNote(`Test email ${r.delivery === "demo" ? "saved to the Mail Outbox" : "sent"} to ${r.to}`);
              })} disabled={!!busy} className="btn-ghost text-xs">
                <Send className="h-3.5 w-3.5" /> Send test email
              </button>
            </div>
            {!data.smtp_configured && (
              <p className="text-xs text-slate-500">
                To send real emails, add SMTP_HOST, SMTP_USER and SMTP_PASSWORD (e.g. a Gmail app password) to the .env file and restart.
              </p>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title"><ShieldCheck className="h-4 w-4 text-emerald-400" /> Staff permissions</div>
        <div className="space-y-3">
          {data.staff.map((p) => (
            <div key={p.user_id} className={`rounded-xl border p-3 ${p.status === "blocked" ? "border-red-500/40 bg-red-500/5" : "border-white/10"}`}>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                <div className="min-w-44">
                  <div className="flex items-center gap-2 font-semibold">
                    {p.online && <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" title="Online now" />}
                    {p.name}
                  </div>
                  <div className="text-xs text-slate-400">{p.role} · ID <span className="font-mono">{p.username}</span></div>
                </div>
                <div className="w-64">
                  <EmailField value={p.email} placeholder={p.email_shown}
                    onSave={(v) => run(`${p.user_id}-email`, () => api.updateAccess(p.user_id, { email: v }), `Email for ${p.name} saved`)} />
                </div>
                <div className="ml-auto">
                  {p.status === "blocked" ? (
                    <button onClick={() => run(`${p.user_id}-unlock`, () => api.unlockStaff(p.user_id), `${p.name} unlocked`)} disabled={!!busy} className="flex items-center gap-1 rounded-md bg-emerald-500/20 px-2.5 py-1 text-xs text-emerald-200 hover:bg-emerald-500/30">
                      {busy === `${p.user_id}-unlock` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unlock className="h-3.5 w-3.5" />} Unlock
                    </button>
                  ) : (
                    <span className="text-xs text-emerald-300">Active</span>
                  )}
                </div>
              </div>
              {p.status === "blocked" && (
                <div className="mt-2 flex items-center gap-1.5 text-xs text-red-200"><Lock className="h-3.5 w-3.5" /> {p.status_reason}</div>
              )}
              <div className="mt-2 flex flex-wrap gap-1.5">
                {data.systems.map((s) => {
                  const on = p.permissions.includes(s);
                  return (
                    <button
                      key={s}
                      onClick={() => toggle(p, s)}
                      disabled={!!busy}
                      title={on ? "Click to remove access" : "Click to grant access"}
                      className={`rounded-full border px-2.5 py-0.5 text-xs transition ${
                        on ? "border-emerald-400/50 bg-emerald-500/20 text-emerald-100" : "border-white/10 text-slate-500 hover:border-white/30"
                      }`}
                    >
                      {on ? "✓ " : ""}{s}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
