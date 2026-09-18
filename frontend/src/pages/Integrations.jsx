import { useState } from "react";
import { Cable, Download, FileUp, KeyRound, Loader2, Plug, Send, Server, Trash2 } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import { fmtDateTime } from "../utils/format.js";

const FIELD_LABELS = {
  webhook_url: "Webhook URL", url: "URL", secret: "Signing secret (optional)", account_sid: "Twilio account SID",
  auth_token: "Twilio auth token", from_number: "From number", to_number: "Send to (e.g. +9198…)", host: "Syslog host", port: "Port (514)",
};
const STATUS = { sent: "text-emerald-300", received: "text-emerald-300", failed: "text-red-300", rejected: "text-red-300", skipped: "text-slate-400" };

// Connect SentinelAI to company systems: logs in, alerts out, SIEM export.
export default function Integrations() {
  const { data, refresh } = usePolling(api.integrations, 5000);
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(null);
  const [newKey, setNewKey] = useState(null);
  const [source, setSource] = useState("okta");
  const [result, setResult] = useState(null);

  if (!data) return <div className="text-slate-500">Loading integrations...</div>;

  async function run(label, fn) {
    setBusy(label);
    setMsg(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setMsg({ error: true, text: e.message });
    } finally {
      setBusy(null);
    }
  }

  const ingestJson = (payload) => run("ingest", async () => setResult(await api.ingest(source, payload)));

  async function uploadFile(file) {
    if (!file) return;
    try {
      ingestJson(JSON.parse(await file.text()));
    } catch {
      setMsg({ error: true, text: "That file is not valid JSON." });
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="gradient-text text-3xl font-bold">Integrations</h1>
        <p className="text-sm text-slate-400">
          Read sign-in logs from company systems, push alerts to where the security team already works, and export to a SIEM.
        </p>
      </div>
      {msg && <div className={`card text-sm ${msg.error ? "text-red-300" : "text-emerald-300"}`}>{msg.text}</div>}

      <div className="card">
        <div className="card-title"><FileUp className="h-4 w-4 text-cyan-300" /> Log ingestion (in)</div>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <select value={source} onChange={(e) => { setSource(e.target.value); setResult(null); }}
                className="rounded-lg border border-white/10 bg-slate-950 px-2 py-1.5">
                {Object.entries(data.sources).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
              </select>
              <button className="btn-primary" disabled={busy === "ingest"}
                onClick={() => run("ingest", async () => setResult(await api.ingest(source, await api.ingestSample(source))))}>
                {busy === "ingest" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plug className="h-4 w-4" />} Import sample log
              </button>
              <label className="btn-ghost cursor-pointer">
                <FileUp className="h-4 w-4" /> Upload JSON export
                <input type="file" accept=".json,application/json" className="hidden" onChange={(e) => uploadFile(e.target.files[0])} />
              </label>
            </div>
            <p className="text-xs text-slate-400">
              The sample is written in the provider&apos;s real export format: two normal sign-ins, then an attacker from Lagos
              who fails five passwords and gets in on the sixth. Each sign-in becomes a session scored against that person&apos;s twin.
            </p>
            {result && (
              <div className="rounded-lg border border-white/10 bg-slate-950/50 p-3 text-xs">
                <div className="text-slate-200">{result.source}: {result.received} records → {result.sessions} sessions,{" "}
                  {result.failed_logins} failed sign-ins{result.unknown_users.length ? `, unknown: ${result.unknown_users.join(", ")}` : ""}</div>
                {result.alerts.map((a) => (
                  <a key={a.id} href={`/incidents/${a.id}`} className="mt-1 block text-rose-300 hover:underline">
                    {a.tier} · {a.user_id} · risk {a.risk} · {a.threat}
                  </a>
                ))}
                {!result.alerts.length && <div className="mt-1 text-emerald-300">No alerts: everything matched the twins.</div>}
              </div>
            )}
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex items-center gap-2 text-slate-200"><KeyRound className="h-4 w-4 text-amber-300" /> API keys for automated feeds</div>
            <pre className="overflow-x-auto rounded-lg bg-slate-950 p-2 text-xs text-slate-300">{`curl -X POST ${window.location.origin}/api/ingest/okta \\
  -H "X-API-Key: sk_sentinel_…" -H "Content-Type: application/json" \\
  -d @okta_system_log.json`}</pre>
            {newKey && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-2 text-xs">
                Copy this key now, it is shown only once: <span className="font-mono break-all text-amber-100 select-all">{newKey}</span>
              </div>
            )}
            <ul className="space-y-1">
              {data.keys.map((k) => (
                <li key={k.id} className="flex items-center justify-between rounded bg-slate-950/40 px-2 py-1 text-xs">
                  <span><span className="text-slate-200">{k.label}</span> · …{k.last4} · {fmtDateTime(k.created)}</span>
                  <button className="text-slate-500 hover:text-red-300" title="Revoke" onClick={() => run("key", () => api.revokeIngestKey(k.id))}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </li>
              ))}
            </ul>
            <button className="btn-ghost" onClick={() => run("key", async () => setNewKey((await api.createIngestKey("feed")).key))}>
              <KeyRound className="h-4 w-4" /> Create API key
            </button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">
          <Cable className="h-4 w-4 text-fuchsia-300" /> Alert channels (out)
          <span className="ml-auto flex items-center gap-2 text-xs font-normal tracking-normal normal-case">
            Send alerts from
            <select value={data.min_tier} onChange={(e) => run("tier", () => api.updateIntegration({ min_tier: e.target.value }))}
              className="rounded border border-white/10 bg-slate-950 px-1.5 py-0.5">
              <option value="MFA">MFA and BLOCK</option>
              <option value="BLOCK">BLOCK only</option>
            </select>
          </span>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {data.channels.map((c) => <Channel key={c.id} c={c} busy={busy} run={run} setMsg={setMsg} />)}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
          No accounts handy? <button className="btn-ghost" onClick={() => run("demo", () => api.useDemoReceiver())}>
            Use the built-in test receiver
          </button> It points the webhook at SentinelAI itself and checks the signature, like a SOAR tool would.
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card">
          <div className="card-title"><Server className="h-4 w-4 text-emerald-300" /> SIEM export</div>
          <p className="mb-3 text-sm text-slate-400">Alerts from the last 7 days for Splunk, Microsoft Sentinel, QRadar or Elastic.</p>
          <div className="flex flex-wrap gap-2">
            {[["cef", "CEF (ArcSight / QRadar)"], ["jsonl", "JSON lines (Splunk / Elastic)"], ["csv", "CSV"]].map(([f, label]) => (
              <button key={f} className="btn-ghost" onClick={() => run("export", () => api.exportEvents(f))}>
                <Download className="h-4 w-4" /> {label}
              </button>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="card-title"><Send className="h-4 w-4 text-cyan-300" /> Delivery log</div>
          <div className="max-h-64 space-y-1 overflow-y-auto text-xs">
            {data.log.map((l) => (
              <div key={l.id} className="flex gap-2 border-t border-white/5 pt-1">
                <span className="w-28 shrink-0 text-slate-500">{fmtDateTime(l.at)}</span>
                <span className="w-16 shrink-0 text-slate-300">{l.channel}</span>
                <span className={`w-16 shrink-0 ${STATUS[l.status] || ""}`}>{l.status}</span>
                <span className="text-slate-400">{l.event_id ? `#${l.event_id} ` : ""}{l.detail}</span>
              </div>
            ))}
            {!data.log.length && <div className="text-slate-400">Nothing sent yet.</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

function Channel({ c, busy, run, setMsg }) {
  const [fields, setFields] = useState(c.fields);
  const dirty = Object.keys(fields).some((k) => fields[k] !== c.fields[k]);
  return (
    <div className={`rounded-xl border p-3 text-sm ${c.enabled ? "border-emerald-500/40 bg-emerald-500/5" : "border-white/10 bg-slate-950/40"}`}>
      <div className="mb-2 flex items-center justify-between">
        <span className="font-semibold text-slate-100">{c.label}</span>
        <label className="flex items-center gap-1.5 text-xs text-slate-400">
          <input type="checkbox" checked={c.enabled} onChange={(e) => run(c.id, () => api.updateIntegration({ channel: c.id, enabled: e.target.checked }))} />
          {c.enabled ? "On" : "Off"}
        </label>
      </div>
      <div className="space-y-1.5">
        {Object.keys(c.fields).map((f) => (
          <input key={f} value={fields[f]} placeholder={FIELD_LABELS[f] || f} onChange={(e) => setFields({ ...fields, [f]: e.target.value })}
            className="w-full rounded border border-white/10 bg-slate-950 px-2 py-1 text-xs" />
        ))}
      </div>
      <div className="mt-2 flex gap-2">
        <button className="btn-ghost text-xs" disabled={!dirty} onClick={() => run(c.id, () => api.updateIntegration({ channel: c.id, fields }))}>Save</button>
        <button className="btn-ghost text-xs" disabled={!c.configured || busy === `test-${c.id}`}
          onClick={() => run(`test-${c.id}`, async () => {
            const r = (await api.testIntegration(c.id)).results[0];
            setMsg({ error: r.status !== "sent", text: `${c.label}: ${r.status} (${r.detail})` });
          })}>
          <Send className="h-3.5 w-3.5" /> Test
        </button>
      </div>
    </div>
  );
}
