import { useState } from "react";
import { Briefcase, Eye, EyeOff, Fingerprint, Loader2, LogIn, MapPin, ShieldCheck, UserCog } from "lucide-react";
import { api } from "../api.js";
import { setAuth } from "../auth.js";

// Demo only: lets a guest pretend to log in from somewhere else and watch SentinelAI react.
const DEMO_CITIES = ["Mumbai", "Delhi", "Kolkata", "Singapore", "Frankfurt", "Moscow", "Ashburn", "Lagos", "Sao Paulo"];

export default function Login() {
  const [mode, setMode] = useState("admin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [city, setCity] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [flash] = useState(() => {
    try {
      const msg = sessionStorage.getItem("sentinel-flash");
      sessionStorage.removeItem("sentinel-flash");
      return msg;
    } catch {
      return null;
    }
  });

  function switchMode(m) {
    setMode(m);
    setError(null);
    setUsername("");
    setPassword("");
  }

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = mode === "admin" ? await api.login(username, password) : await api.staffLogin(username, password, city);
      setAuth({ token: res.token, role: res.role, name: res.name });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const staff = mode === "staff";

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <section className="relative hidden flex-col justify-between overflow-hidden p-12 lg:flex">
        <div className="absolute -top-32 -left-32 h-96 w-96 rounded-full bg-cyan-500/20 blur-3xl" />
        <div className="absolute right-0 bottom-0 h-96 w-96 rounded-full bg-fuchsia-500/20 blur-3xl" />
        <div className="relative flex items-center gap-3">
          <div className="rounded-xl bg-gradient-to-br from-cyan-400 via-indigo-500 to-fuchsia-500 p-2 shadow-lg shadow-indigo-500/30">
            <ShieldCheck className="h-7 w-7 text-white" />
          </div>
          <div>
            <div className="gradient-text text-2xl font-bold">SentinelAI</div>
            <div className="text-sm text-slate-400">Behavioral Security</div>
          </div>
        </div>
        <div className="relative">
          <h1 className="text-5xl leading-tight font-extrabold">
            The password was correct.
            <br />
            <span className="gradient-text">The behavior was not.</span>
          </h1>
          <p className="mt-5 max-w-lg text-lg text-slate-300">
            Every login is compared with the employee&apos;s Digital Behavioral Twin. Stolen passwords stop being enough.
          </p>
          <div className="mt-8 grid max-w-lg grid-cols-3 gap-3 text-center text-sm">
            {[
              ["🧬", "Digital twin"],
              ["🤖", "ML + rules"],
              ["🚨", "Auto-block"],
            ].map(([emoji, label]) => (
              <div key={label} className="rounded-xl border border-white/10 bg-white/5 p-3">
                <div className="text-2xl">{emoji}</div>
                <div className="mt-1 text-slate-300">{label}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="relative text-xs text-slate-500">Code Cortex 3.0 · Security track · Team INNOVEX</div>
      </section>

      <section className="flex items-center justify-center p-4 sm:p-10">
        <div className="w-full max-w-md">
          <div className="mb-6 flex items-center gap-3 lg:hidden">
            <ShieldCheck className="h-8 w-8 text-cyan-300" />
            <div className="gradient-text text-2xl font-bold">SentinelAI</div>
          </div>

          <div className="card glow-border border p-7">
            <div className="mb-6 grid grid-cols-2 gap-1 rounded-xl bg-slate-950/70 p-1">
              {[
                ["admin", UserCog, "SOC Admin"],
                ["staff", Briefcase, "Staff portal"],
              ].map(([m, Icon, label]) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => switchMode(m)}
                  className={`flex items-center justify-center gap-2 rounded-lg py-2 text-sm font-medium transition ${
                    mode === m ? "bg-gradient-to-r from-cyan-500/30 to-fuchsia-500/30 text-white" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Icon className="h-4 w-4" /> {label}
                </button>
              ))}
            </div>

            <h2 className="text-2xl font-bold">{staff ? "Employee sign in" : "Security team sign in"}</h2>
            <p className="mt-1 text-sm text-slate-400">
              {staff
                ? "Sign in to the company workspace. Your session is checked against your behavioural twin."
                : "Owner / admin access to the SentinelAI Security Operations Center."}
            </p>

            {flash && (
              <div className="mt-4 rounded-lg border border-amber-400/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">{flash}</div>
            )}

            <form onSubmit={submit} className="mt-6 space-y-4">
              <label className="block text-sm text-slate-300">
                {staff ? "Staff ID" : "Username"}
                <input
                  autoFocus
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  placeholder={staff ? "e.g. rahul" : "Admin username"}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-2.5 outline-none focus:border-cyan-400"
                />
              </label>
              <label className="block text-sm text-slate-300">
                Password
                <div className="relative mt-1">
                  <input
                    type={show ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    placeholder="••••"
                    className="w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-2.5 pr-10 outline-none focus:border-cyan-400"
                  />
                  <button type="button" onClick={() => setShow(!show)} className="absolute top-2.5 right-3 text-slate-500 hover:text-slate-200">
                    {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </label>

              {staff && (
                <label className="block text-sm text-slate-300">
                  <span className="flex items-center gap-1.5">
                    <MapPin className="h-3.5 w-3.5 text-fuchsia-300" /> Login location <span className="text-xs text-slate-500">(demo)</span>
                  </span>
                  <select
                    value={city}
                    onChange={(e) => setCity(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-2.5"
                  >
                    <option value="">My usual office</option>
                    {DEMO_CITIES.map((c) => (
                      <option key={c} value={c}>Pretend I am in {c}</option>
                    ))}
                  </select>
                </label>
              )}

              {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}

              <button type="submit" disabled={busy || !username || !password} className="btn-primary w-full justify-center py-3 text-base">
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : staff ? <Fingerprint className="h-4 w-4" /> : <LogIn className="h-4 w-4" />}
                {staff ? "Sign in to workspace" : "Sign in to SOC"}
              </button>
            </form>
          </div>
          <p className="mt-4 text-center text-xs text-slate-500">
            {staff ? "Wrong passwords are counted: too many look like a brute-force attack." : "Only the owner / security admin can open the dashboard."}
          </p>
        </div>
      </section>
    </div>
  );
}
