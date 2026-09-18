import { Link } from "react-router-dom";
import { Activity, Ban, BellRing, Gauge, Globe2, Siren, TrendingUp } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";
import StatCard from "../components/StatCard.jsx";
import RiskTimeline from "../components/RiskTimeline.jsx";
import AlertFeed from "../components/AlertFeed.jsx";
import ActiveStaff from "../components/ActiveStaff.jsx";
import AttackSimulator from "../components/AttackSimulator.jsx";
import ChallengeBoard from "../components/ChallengeBoard.jsx";
import DepartmentHeatmap from "../components/DepartmentHeatmap.jsx";
import ThreatMap from "../components/ThreatMap.jsx";
import { TIER_STYLES, riskHex } from "../utils/format.js";

export default function Dashboard() {
  const stats = usePolling(api.stats, 4000);
  const alerts = usePolling(() => api.alerts("open"), 4000);
  const timeline = usePolling(() => api.timeline(72), 5000);
  const map = usePolling(() => api.map(72), 6000);

  const refreshAll = () => {
    stats.refresh();
    alerts.refresh();
    timeline.refresh();
    map.refresh();
  };

  const s = stats.data;
  const tiers = s?.tiers_24h || {};
  const tierTotal = Object.values(tiers).reduce((a, b) => a + b, 0) || 1;

  if (stats.error && !s) {
    return (
      <div className="card border-red-500/40 text-red-300">
        Cannot reach the SentinelAI API ({stats.error}). Is the backend running on port 8000?
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="gradient-text text-3xl font-bold">Security Operations Center</h1>
        <p className="text-sm text-slate-400">
          Every session is compared with the employee&apos;s Digital Behavioral Twin and scored 0-100.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Activity} label="Sessions (24h)" value={s?.sessions_24h} hint={`${s?.total_sessions ?? "-"} analysed in total`} color="cyan" />
        <StatCard icon={BellRing} label="Open alerts" value={s?.open_alerts} hint="MFA + Block verdicts" color="orange" />
        <StatCard icon={Ban} label="Blocked accounts" value={s?.blocked_users} hint={`of ${s?.employees ?? "-"} employees`} color="red" />
        <StatCard icon={Gauge} label="Avg risk (24h)" value={s?.avg_risk_24h} hint="0 = identical to twin" color="green" />
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-2">
          <div className="card">
            <div className="card-title">
              <TrendingUp className="h-4 w-4 text-cyan-400" /> Session risk, last 72 hours
              <span className="ml-auto text-xs font-normal tracking-normal text-slate-500 normal-case">click a dot to investigate</span>
            </div>
            <RiskTimeline points={timeline.data || []} />
            <div className="mt-4 flex h-2.5 overflow-hidden rounded-full bg-slate-800">
              {Object.entries(TIER_STYLES).map(([tier, style]) => (
                <div key={tier} style={{ width: `${((tiers[tier] || 0) / tierTotal) * 100}%`, background: style.hex }} />
              ))}
            </div>
            <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-400">
              {Object.entries(TIER_STYLES).map(([tier, style]) => (
                <span key={tier} className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: style.hex }} />
                  {style.label}: {tiers[tier] || 0}
                </span>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-title">
              <Globe2 className="h-4 w-4 text-cyan-400" /> Where logins came from (72 h)
              <Link to="/map" className="ml-auto text-xs font-normal tracking-normal text-cyan-300 normal-case hover:underline">full map →</Link>
            </div>
            <ThreatMap data={map.data} compact />
          </div>

          <div className="card">
            <div className="card-title">
              <Siren className="h-4 w-4 text-red-400" /> Open alerts
            </div>
            <AlertFeed alerts={alerts.data} />
          </div>
        </div>

        <div className="space-y-6">
          <ActiveStaff />
          <ChallengeBoard />
          <AttackSimulator onLaunched={refreshAll} />
          <div className="card">
            <div className="card-title">Riskiest employees (24h)</div>
            <ul className="space-y-3">
              {(s?.top_risky_users || []).map((u) => (
                <li key={u.user_id}>
                  <Link to={`/employees/${u.user_id}`} className="block hover:text-cyan-300">
                    <div className="flex justify-between text-sm">
                      <span>{u.name}</span>
                      <span className="font-mono" style={{ color: riskHex(u.max_risk) }}>{u.max_risk}</span>
                    </div>
                    <div className="mt-1 h-1.5 rounded-full bg-slate-800">
                      <div className="h-1.5 rounded-full" style={{ width: `${u.max_risk}%`, background: riskHex(u.max_risk) }} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      <DepartmentHeatmap />
    </div>
  );
}
