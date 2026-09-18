import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { BellRing, LogIn, Siren, Volume2, VolumeX, X } from "lucide-react";
import { api } from "../api.js";
import { riskHex } from "../utils/format.js";

function readMuted() {
  try {
    return localStorage.getItem("sentinel-muted") === "1";
  } catch {
    return false;
  }
}

// Short two-tone alarm made with the Web Audio API (no sound files needed).
function playAlarm(tier) {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const notes = tier === "BLOCK" ? [880, 660, 880, 660] : [740, 988];
    notes.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "square";
      osc.frequency.value = freq;
      const t = ctx.currentTime + i * 0.16;
      gain.gain.setValueAtTime(0.06, t);
      gain.gain.exponentialRampToValueAtTime(0.001, t + 0.15);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.16);
    });
    setTimeout(() => ctx.close(), 1200);
  } catch {
    /* audio not available */
  }
}

// Soft rising chime for a staff login.
function playChime() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [523, 659, 784].forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = freq;
      const t = ctx.currentTime + i * 0.12;
      gain.gain.setValueAtTime(0.08, t);
      gain.gain.exponentialRampToValueAtTime(0.001, t + 0.3);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.3);
    });
    setTimeout(() => ctx.close(), 1200);
  } catch {
    /* audio not available */
  }
}

// Windows / macOS notification, so alerts are seen even when the dashboard tab is in the background.
function desktopNotify(title, body) {
  try {
    if ("Notification" in window && Notification.permission === "granted" && document.hidden) {
      new Notification(title, { body });
    }
  } catch {
    /* notifications unavailable */
  }
}

// Watches for new MFA/BLOCK alerts and new staff-portal logins, and pops a toast (plus a sound) for each.
export default function AlertToasts() {
  const [toasts, setToasts] = useState([]);
  const [muted, setMuted] = useState(readMuted);
  const [notifyState, setNotifyState] = useState(() => ("Notification" in window ? Notification.permission : "unsupported"));
  const seen = useRef(null);
  const seenLogins = useRef(null);
  const mutedRef = useRef(muted);
  mutedRef.current = muted;
  const navigate = useNavigate();

  function push(items) {
    setToasts((t) => [...items, ...t].slice(0, 4));
    items.forEach((item) => setTimeout(() => setToasts((t) => t.filter((x) => x.key !== item.key)), 9000));
  }

  useEffect(() => {
    let stop = false;
    async function pollLogins() {
      try {
        const staff = await api.activeStaff();
        if (stop) return;
        if (seenLogins.current === null) {
          seenLogins.current = new Set(staff.map((s) => s.event_id));
          return;
        }
        const fresh = staff.filter((s) => !seenLogins.current.has(s.event_id));
        fresh.forEach((s) => seenLogins.current.add(s.event_id));
        if (fresh.length) {
          if (!mutedRef.current) playChime();
          fresh.forEach((s) => desktopNotify(`${s.name} logged in`, `${s.city} · ${s.device} · risk ${s.risk}`));
          push(fresh.map((s) => ({ ...s, id: s.event_id, key: `login-${s.event_id}`, kind: "login" })));
        }
      } catch {
        /* API offline */
      }
    }
    async function poll() {
      pollLogins();
      try {
        const alerts = await api.alerts("all");
        if (stop) return;
        if (seen.current === null) {
          seen.current = new Set(alerts.map((a) => a.id)); // ignore alerts that existed before the page opened
          return;
        }
        const fresh = alerts.filter((a) => !seen.current.has(a.id));
        fresh.forEach((a) => seen.current.add(a.id));
        if (fresh.length) {
          if (!mutedRef.current) playAlarm(fresh[0].tier);
          fresh.slice(0, 3).forEach((a) => desktopNotify(`${a.tier === "BLOCK" ? "BLOCKED" : "MFA"}: ${a.name} (risk ${a.risk})`, a.threat || "Anomalous session"));
          push(fresh.slice(0, 3).map((a) => ({ ...a, key: `alert-${a.id}`, kind: "alert" })));
        }
      } catch {
        /* API offline: the layout already shows this */
      }
    }
    poll();
    const id = setInterval(poll, 3000);
    return () => {
      stop = true;
      clearInterval(id);
    };
  }, []);

  function toggleMute() {
    setMuted((m) => {
      try {
        localStorage.setItem("sentinel-muted", m ? "0" : "1");
      } catch {
        /* storage blocked */
      }
      return !m;
    });
  }

  async function enableDesktop() {
    try {
      setNotifyState(await Notification.requestPermission());
    } catch {
      setNotifyState("denied");
    }
  }

  return (
    <>
      {notifyState === "default" && (
        <button onClick={enableDesktop} className="btn-ghost text-xs" title="Show Windows notifications for alerts">
          <BellRing className="h-4 w-4 text-amber-300" /> Desktop alerts
        </button>
      )}
      <button onClick={toggleMute} className="btn-ghost text-xs" title="Alarm sound for new alerts">
        {muted ? <VolumeX className="h-4 w-4 text-slate-500" /> : <Volume2 className="h-4 w-4 text-fuchsia-300" />}
        {muted ? "Muted" : "Sound on"}
      </button>
      <div className="no-print fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((a) => a.kind === "login" ? (
          <div
            key={a.key}
            className="toast-in cursor-pointer rounded-xl border border-emerald-400/60 bg-slate-900/95 p-3 shadow-2xl backdrop-blur"
            style={{ boxShadow: "0 0 24px #34d39955" }}
            onClick={() => navigate(`/incidents/${a.id}`)}
          >
            <div className="flex items-center gap-2">
              <LogIn className="h-4 w-4 text-emerald-300" />
              <span className="text-sm font-semibold text-emerald-300">Staff logged in</span>
              <span className="ml-auto h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
            </div>
            <div className="mt-1 text-sm text-slate-100">{a.name}</div>
            <div className="text-xs text-slate-400">{a.city} · {a.device} · risk {a.risk}</div>
          </div>
        ) : (
          <div
            key={a.key}
            className="toast-in cursor-pointer rounded-xl border bg-slate-900/95 p-3 shadow-2xl backdrop-blur"
            style={{ borderColor: riskHex(a.risk), boxShadow: `0 0 24px ${riskHex(a.risk)}55` }}
            onClick={() => navigate(`/incidents/${a.id}`)}
          >
            <div className="flex items-center gap-2">
              <Siren className="h-4 w-4 animate-pulse" style={{ color: riskHex(a.risk) }} />
              <span className="text-sm font-semibold" style={{ color: riskHex(a.risk) }}>
                {a.tier === "BLOCK" ? "Session blocked" : "MFA challenge"} · risk {a.risk}
              </span>
              <button
                className="ml-auto text-slate-500 hover:text-slate-200"
                onClick={(e) => {
                  e.stopPropagation();
                  setToasts((t) => t.filter((x) => x.key !== a.key));
                }}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-1 text-sm text-slate-100">{a.name}</div>
            <div className="text-xs text-slate-400">
              {a.threat || "Anomalous session"} · {a.city}, {a.country}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
