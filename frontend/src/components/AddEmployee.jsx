import { useState } from "react";
import { Loader2, UserPlus, X } from "lucide-react";
import { api } from "../api.js";

// Onboard a new employee with a staff portal login. Their twin starts from their department's habits.
export default function AddEmployee({ onDone }) {
  const [open, setOpen] = useState(false);
  const [opts, setOpts] = useState(null);
  const [form, setForm] = useState({ name: "", department: "", role: "", home_city: "Chennai", username: "", email: "", permissions: [] });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [created, setCreated] = useState(null);

  async function start() {
    setOpen(true);
    setCreated(null);
    setError(null);
    const o = await api.onboardingOptions();
    setOpts(o);
    const dept = o.departments[0] || "";
    setForm((f) => ({ ...f, department: dept, permissions: o.suggested[dept] || [] }));
  }

  const set = (key, value) => setForm((f) => ({ ...f, [key]: value }));

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.onboard({ ...form, email: form.email || null });
      setCreated(res);
      onDone?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return <button className="btn-primary" onClick={start}><UserPlus className="h-4 w-4" /> Add employee</button>;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setOpen(false)}>
      <div className="card max-h-[90vh] w-full max-w-lg overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="card-title">
          <UserPlus className="h-4 w-4 text-cyan-300" /> Onboard an employee
          <button className="ml-auto text-slate-500 hover:text-slate-200" onClick={() => setOpen(false)}><X className="h-4 w-4" /></button>
        </div>
        {created ? (
          <div className="space-y-3 text-sm">
            <p className="text-emerald-300">Created {created.user_id}. They can sign in to the staff portal now.</p>
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3">
              Username <span className="font-mono text-slate-100">{created.username}</span>
              {created.password && <> · first password <span className="font-mono text-amber-100 select-all">{created.password}</span>
                <div className="mt-1 text-xs text-slate-400">Shown once. Only a salted hash is stored.</div></>}
            </div>
            <p className="text-slate-400">
              With no history yet, their digital twin is based on the <b>{created.twin.peer_group}</b> team: usual hours{" "}
              {created.twin.usual_hours}, ~{Math.round(created.twin.avg_files)} files per session. It switches to their own
              habits after 10 normal sessions.
            </p>
            <button className="btn-ghost" onClick={() => setOpen(false)}>Done</button>
          </div>
        ) : !opts ? (
          <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
        ) : (
          <form onSubmit={submit} className="space-y-2 text-sm">
            <Field label="Full name"><input required value={form.name} onChange={(e) => set("name", e.target.value)} className="input" /></Field>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Department">
                <input required list="departments" value={form.department} className="input"
                  onChange={(e) => { set("department", e.target.value); if (opts.suggested[e.target.value]) set("permissions", opts.suggested[e.target.value]); }} />
                <datalist id="departments">{opts.departments.map((d) => <option key={d} value={d} />)}</datalist>
              </Field>
              <Field label="Role"><input required value={form.role} onChange={(e) => set("role", e.target.value)} className="input" /></Field>
              <Field label="Home city">
                <select value={form.home_city} onChange={(e) => set("home_city", e.target.value)} className="input">
                  {opts.cities.map((c) => <option key={c}>{c}</option>)}
                </select>
              </Field>
              <Field label="Username"><input required value={form.username} onChange={(e) => set("username", e.target.value.toLowerCase())} className="input font-mono" /></Field>
            </div>
            <Field label="Work email (for sign-in codes, optional)">
              <input type="email" value={form.email} onChange={(e) => set("email", e.target.value)} className="input" />
            </Field>
            <Field label="Systems they may open">
              <div className="flex flex-wrap gap-1.5">
                {opts.systems.map((s) => {
                  const on = form.permissions.includes(s);
                  return (
                    <button type="button" key={s} onClick={() => set("permissions", on ? form.permissions.filter((x) => x !== s) : [...form.permissions, s])}
                      className={`rounded px-2 py-0.5 text-xs ${on ? "bg-cyan-500/20 text-cyan-200" : "bg-slate-800 text-slate-400"}`}>
                      {s}
                    </button>
                  );
                })}
              </div>
            </Field>
            {error && <div className="text-red-300">{error}</div>}
            <button className="btn-primary" disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />} Create account
            </button>
            <p className="text-xs text-slate-500">A strong first password is generated for you.</p>
          </form>
        )}
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="mb-0.5 block text-xs text-slate-400">{label}</span>
      {children}
    </label>
  );
}
