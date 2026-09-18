import { useState } from "react";
import QRCode from "qrcode";
import {
  ArrowLeft, Briefcase, Eye, EyeOff, Fingerprint, Inbox, KeyRound, Loader2, LogIn, Mail, MapPin, ShieldCheck, Smartphone,
  UserCog,
} from "lucide-react";
import { api } from "../api.js";
import { setAuth } from "../auth.js";

// The device's own location (GPS / mobile network / Wi-Fi). Browsers only allow this on https or localhost.
function deviceLocation() {
  return new Promise((resolve) => {
    if (!("geolocation" in navigator) || !window.isSecureContext) return resolve(null);
    navigator.geolocation.getCurrentPosition(
      (pos) => resolve({ lat: pos.coords.latitude, lon: pos.coords.longitude }),
      () => resolve(null),
      { enableHighAccuracy: true, timeout: 8000, maximumAge: 60000 },
    );
  });
}

export default function Login() {
  const [mode, setMode] = useState("admin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otherEmail, setOtherEmail] = useState(false);
  const [email, setEmail] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [otp, setOtp] = useState(null); // pending email verification (staff)
  const [adminMfa, setAdminMfa] = useState(null); // pending authenticator code (admin)
  const [qr, setQr] = useState(null);
  const [code, setCode] = useState("");
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
    setOtp(null);
    setAdminMfa(null);
  }

  function finish(res) {
    setAuth({ token: res.token, role: res.role, name: res.name });
  }

  async function submit(e) {
    e.preventDefault();
    setError(null);
    try {
      if (mode === "admin") {
        setBusy("Checking password...");
        const res = await api.login(username, password);
        if (res.mfa_required) {
          setAdminMfa(res);
          setCode("");
          setQr(res.otpauth_uri ? await QRCode.toDataURL(res.otpauth_uri, { margin: 1, width: 200 }) : null);
        } else {
          finish(res);
        }
        return;
      }
      setBusy("Getting your location...");
      const where = await deviceLocation();
      setBusy("Checking password...");
      const res = await api.staffLogin(username, password, { ...(where || {}), email: otherEmail && email ? email : null });
      if (res.otp_required) {
        setOtp(res);
        setCode("");
      } else {
        finish(res);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  async function verify(e) {
    e.preventDefault();
    setError(null);
    setBusy("Verifying code...");
    try {
      finish(adminMfa ? await api.adminSecondFactor(adminMfa.challenge_id, code) : await api.staffOtp(otp.challenge_id, code));
    } catch (err) {
      setError(err.message);
      if (/expired|Too many/.test(err.message)) {
        setOtp(null);
        setAdminMfa(null);
      }
    } finally {
      setBusy(null);
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
              ["📧", "Email OTP"],
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
            {adminMfa ? (
              <>
                <button type="button" onClick={() => setAdminMfa(null)} className="mb-4 flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
                  <ArrowLeft className="h-4 w-4" /> Back
                </button>
                <div className="mb-3 w-fit rounded-xl bg-gradient-to-br from-fuchsia-500 to-indigo-600 p-2.5">
                  <Smartphone className="h-6 w-6 text-white" />
                </div>
                {adminMfa.enrolled ? (
                  <>
                    <h2 className="text-2xl font-bold">Admin verification</h2>
                    <p className="mt-1 text-sm text-slate-400">
                      Enter the 6-digit code from your authenticator app (Google or Microsoft Authenticator). It changes every 30 seconds.
                    </p>
                  </>
                ) : (
                  <>
                    <h2 className="text-2xl font-bold">Set up admin verification</h2>
                    <p className="mt-1 text-sm text-slate-400">
                      One-time setup. Open <b>Google Authenticator</b> or <b>Microsoft Authenticator</b> on your phone, tap <b>+</b>, and
                      scan this code. From now on the admin needs the password <i>and</i> the phone.
                    </p>
                    <div className="mt-4 flex flex-col items-center gap-2 rounded-xl bg-white p-3">
                      {qr && <img src={qr} alt="Authenticator QR code" className="h-44 w-44" />}
                    </div>
                    <div className="mt-2 text-center text-xs text-slate-400">
                      Can&apos;t scan? Enter this key: <span className="font-mono break-all text-slate-200 select-all">{adminMfa.secret}</span>
                    </div>
                  </>
                )}
                <form onSubmit={verify} className="mt-5 space-y-4">
                  <input
                    autoFocus
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                    placeholder="000000"
                    className="w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-3 text-center font-mono text-3xl tracking-[0.5em] outline-none focus:border-fuchsia-400"
                  />
                  {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
                  <button type="submit" disabled={!!busy || code.length !== 6} className="btn-primary w-full justify-center py-3 text-base">
                    {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                    {busy || (adminMfa.enrolled ? "Verify and open SOC" : "Link app and open SOC")}
                  </button>
                </form>
              </>
            ) : otp ? (
              <>
                <button type="button" onClick={() => setOtp(null)} className="mb-4 flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
                  <ArrowLeft className="h-4 w-4" /> Back
                </button>
                <div className="mb-3 w-fit rounded-xl bg-gradient-to-br from-cyan-500 to-indigo-600 p-2.5">
                  <Mail className="h-6 w-6 text-white" />
                </div>
                <h2 className="text-2xl font-bold">Check your email</h2>
                <p className="mt-1 text-sm text-slate-400">
                  We sent a 6-digit sign-in code to <span className="font-medium text-slate-200">{otp.sent_to}</span>. It expires in 5 minutes.
                </p>
                {otp.demo_code && (
                  <div className="mt-4 rounded-xl border border-amber-400/40 bg-amber-500/10 p-3 text-sm">
                    <div className="flex items-center gap-1.5 font-semibold text-amber-200">
                      <Inbox className="h-4 w-4" /> Demo inbox
                    </div>
                    <div className="mt-1 text-slate-300">
                      Email sending is not set up for this address, so the message is shown here. Your code is{" "}
                      <span className="font-mono text-lg font-bold tracking-widest text-white">{otp.demo_code}</span>
                    </div>
                  </div>
                )}
                <form onSubmit={verify} className="mt-5 space-y-4">
                  <input
                    autoFocus
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                    placeholder="000000"
                    className="w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-3 text-center font-mono text-3xl tracking-[0.5em] outline-none focus:border-cyan-400"
                  />
                  {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
                  <button type="submit" disabled={!!busy || code.length !== 6} className="btn-primary w-full justify-center py-3 text-base">
                    {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                    {busy || "Verify and sign in"}
                  </button>
                </form>
              </>
            ) : (
              <>
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
                    ? "Password, then a one-time code by email. Your session is checked against your behavioural twin."
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
                    <div className="text-sm">
                      {otherEmail ? (
                        <label className="block text-slate-300">
                          Send my code to
                          <input
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="you@example.com"
                            className="mt-1 w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-2.5 outline-none focus:border-cyan-400"
                          />
                          <span className="mt-1 block text-xs text-slate-500">A new email is checked against your usual address.</span>
                        </label>
                      ) : (
                        <button type="button" onClick={() => setOtherEmail(true)} className="text-cyan-300 hover:underline">
                          Send the code to a different email
                        </button>
                      )}
                      <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-500">
                        <MapPin className="h-3.5 w-3.5" /> Your location is taken from this device (allow it when asked).
                      </div>
                    </div>
                  )}

                  {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}

                  <button type="submit" disabled={!!busy || !username || !password} className="btn-primary w-full justify-center py-3 text-base">
                    {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : staff ? <Fingerprint className="h-4 w-4" /> : <LogIn className="h-4 w-4" />}
                    {busy || (staff ? "Continue" : "Sign in to SOC")}
                  </button>
                </form>
              </>
            )}
          </div>
          <p className="mt-4 text-center text-xs text-slate-500">
            {staff ? "5 wrong passwords in a row lock the account until the admin unlocks it." : "Admin sign-in needs the password and a code from the admin's phone."}
          </p>
        </div>
      </section>
    </div>
  );
}
