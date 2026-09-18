import { CheckCircle2, History, ShieldCheck, XCircle } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { fmtDateTime } from "../utils/format.js";

const CONTROL_LABELS = [
  ["admin_2fa", "Admin 2-step login (password + authenticator app)"],
  ["admin_2fa_enrolled", "Admin authenticator app linked"],
  ["admin_session_hours", "Admin session expires after (hours)"],
  ["admin_lockout", "Admin brute-force protection"],
  ["staff_otp", "Staff 2-step login (password + email code)"],
  ["staff_lockout", "Staff brute-force protection"],
  ["password_storage", "Password storage"],
  ["email_delivery", "Security email delivery"],
];

const ACTION_STYLE = (action) =>
  /failed|block|denied/.test(action) ? "text-red-300" : /unlock|approved|enrolled|login/.test(action) ? "text-emerald-300" : "text-slate-300";

export default function SecurityCenter() {
  const { data } = usePolling(api.security, 5000);
  if (!data) return <div className="text-slate-500">Loading security center...</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="gradient-text text-3xl font-bold">Security Center</h1>
        <p className="text-sm text-slate-400">How SentinelAI protects itself, and a record of every sign-in and admin decision.</p>
      </div>

      <div className="card">
        <div className="card-title"><ShieldCheck className="h-4 w-4 text-emerald-400" /> Controls in force</div>
        <div className="grid gap-2 sm:grid-cols-2">
          {CONTROL_LABELS.map(([key, label]) => {
            const value = data.controls[key];
            const ok = value !== false;
            return (
              <div key={key} className="flex items-start gap-2.5 rounded-lg border border-white/10 bg-slate-950/40 p-3 text-sm">
                {ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />}
                <div>
                  <div className="text-slate-200">{label}</div>
                  <div className="text-xs text-slate-400">{value === true ? "On" : value === false ? "Off" : String(value)}</div>
                </div>
              </div>
            );
          })}
        </div>
        <div className="mt-3 text-xs text-slate-500">
          Also: signed session tokens (HMAC-SHA256), every API call requires login, staff can only reach their own portal,
          security headers on every response, decoy files, and automatic account locking on risky behaviour.
        </div>
      </div>

      <div className="card">
        <div className="card-title"><History className="h-4 w-4 text-cyan-300" /> Audit log</div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="pb-2">Time</th>
                <th className="pb-2">Who</th>
                <th className="pb-2">Action</th>
                <th className="pb-2">Target</th>
                <th className="pb-2">Details</th>
                <th className="pb-2">IP</th>
              </tr>
            </thead>
            <tbody>
              {data.audit.map((a) => (
                <tr key={a.id} className="border-t border-white/5 align-top">
                  <td className="py-1.5 pr-3 whitespace-nowrap text-slate-400">{fmtDateTime(a.at)}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs">{a.actor}</td>
                  <td className={`py-1.5 pr-3 font-mono text-xs ${ACTION_STYLE(a.action)}`}>{a.action}</td>
                  <td className="py-1.5 pr-3 text-slate-300">{a.target || "-"}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{a.detail || ""}</td>
                  <td className="py-1.5 font-mono text-xs text-slate-500">{a.ip || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.audit.length === 0 && <div className="text-sm text-slate-400">No entries yet.</div>}
        </div>
      </div>
    </div>
  );
}
