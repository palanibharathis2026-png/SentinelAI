import { useState } from "react";
import { Inbox, Mail } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { fmtDateTime } from "../utils/format.js";

const KIND = {
  otp: "bg-cyan-500/15 text-cyan-200",
  login: "bg-emerald-500/15 text-emerald-200",
  first_access: "bg-amber-500/15 text-amber-200",
  denied: "bg-red-500/15 text-red-200",
  alert: "bg-rose-500/15 text-rose-200",
  request: "bg-indigo-500/15 text-indigo-200",
  unlock: "bg-emerald-500/15 text-emerald-200",
  test: "bg-slate-500/15 text-slate-200",
};

const DELIVERY = {
  sent: "text-emerald-300",
  sending: "text-cyan-300",
  demo: "text-amber-300",
  failed: "text-red-300",
};

export default function MailOutbox() {
  const { data } = usePolling(() => api.mail(80), 4000);
  const [open, setOpen] = useState(null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="gradient-text text-3xl font-bold">Mail Outbox</h1>
        <p className="text-sm text-slate-400">
          Every email SentinelAI sends: sign-in codes, login alerts, awareness notes, access decisions and attack alerts.
          In demo mode (no SMTP set up) this page is the inbox.
        </p>
      </div>
      <div className="card">
        <div className="card-title"><Inbox className="h-4 w-4 text-cyan-300" /> Messages</div>
        {!data?.length ? (
          <div className="text-sm text-slate-400">No emails yet. They appear here when staff sign in or trigger alerts.</div>
        ) : (
          <ul className="divide-y divide-white/5">
            {data.map((m) => (
              <li key={m.id}>
                <button onClick={() => setOpen(open === m.id ? null : m.id)} className="w-full py-2.5 text-left">
                  <div className="flex items-center gap-2">
                    <Mail className="h-4 w-4 shrink-0 text-slate-500" />
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${KIND[m.kind] || KIND.test}`}>{m.kind.replace("_", " ")}</span>
                    <span className="truncate font-medium">{m.subject}</span>
                    <span className="ml-auto shrink-0 text-xs text-slate-500">{fmtDateTime(m.created_at)}</span>
                  </div>
                  <div className="mt-0.5 pl-6 text-xs text-slate-400">
                    to {m.to} · <span className={DELIVERY[m.delivery] || ""}>{m.delivery === "demo" ? "demo (not sent)" : m.delivery}</span>
                    {m.error && <span className="text-red-300"> · {m.error}</span>}
                  </div>
                </button>
                {open === m.id && (
                  <pre className="mb-3 ml-6 rounded-lg bg-slate-950/70 p-3 text-sm whitespace-pre-wrap text-slate-200">{m.body}</pre>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
