import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Siren, Volume2, VolumeX, X } from "lucide-react";
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

// Watches for new MFA/BLOCK alerts and pops a toast (plus an alarm) for each one.
export default function AlertToasts() {
  const [toasts, setToasts] = useState([]);
  const [muted, setMuted] = useState(readMuted);
  const seen = useRef(null);
  const mutedRef = useRef(muted);
  mutedRef.current = muted;
  const navigate = useNavigate();

  useEffect(() => {
    let stop = false;
    async function poll() {
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
          setToasts((t) => [...fresh.slice(0, 3), ...t].slice(0, 4));
          fresh.forEach((a) => setTimeout(() => setToasts((t) => t.filter((x) => x.id !== a.id)), 9000));
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

  return (
    <>
      <button onClick={toggleMute} className="btn-ghost text-xs" title="Alarm sound for new alerts">
        {muted ? <VolumeX className="h-4 w-4 text-slate-500" /> : <Volume2 className="h-4 w-4 text-fuchsia-300" />}
        {muted ? "Muted" : "Sound on"}
      </button>
      <div className="no-print fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((a) => (
          <div
            key={a.id}
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
                  setToasts((t) => t.filter((x) => x.id !== a.id));
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
