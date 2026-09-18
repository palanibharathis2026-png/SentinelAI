import { useNavigate } from "react-router-dom";
import {
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { TIER_STYLES, fmtDateTime } from "../utils/format.js";

function PointTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs shadow-xl">
      <div className="font-semibold text-slate-100">{p.name}</div>
      <div className="text-slate-400">{fmtDateTime(p.timestamp)}</div>
      <div className="mt-1" style={{ color: TIER_STYLES[p.tier].hex }}>
        Risk {p.risk} · {p.tier}
      </div>
      {p.threat && <div className="text-slate-300">{p.threat}</div>}
    </div>
  );
}

export default function RiskTimeline({ points = [], height = 280 }) {
  const navigate = useNavigate();
  const data = points.map((p) => ({ ...p, x: new Date(p.timestamp).getTime(), y: p.risk }));

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ScatterChart margin={{ top: 10, right: 10, bottom: 0, left: -20 }}>
        <CartesianGrid stroke="#1e293b" />
        <XAxis
          dataKey="x"
          type="number"
          domain={["dataMin", "dataMax"]}
          tickFormatter={(t) => fmtDateTime(t)}
          stroke="#64748b"
          fontSize={11}
          tickCount={6}
        />
        <YAxis dataKey="y" domain={[0, 100]} stroke="#64748b" fontSize={11} ticks={[0, 30, 60, 80, 100]} />
        <ReferenceLine y={80} stroke={TIER_STYLES.BLOCK.hex} strokeDasharray="4 4" strokeOpacity={0.5} />
        <ReferenceLine y={60} stroke={TIER_STYLES.MFA.hex} strokeDasharray="4 4" strokeOpacity={0.5} />
        <ReferenceLine y={30} stroke={TIER_STYLES.MONITOR.hex} strokeDasharray="4 4" strokeOpacity={0.4} />
        <Tooltip content={<PointTooltip />} cursor={{ stroke: "#334155" }} />
        <Scatter data={data} onClick={(p) => navigate(`/incidents/${p.id}`)} cursor="pointer">
          {data.map((p) => (
            <Cell key={p.id} fill={TIER_STYLES[p.tier].hex} fillOpacity={p.tier === "ALLOW" ? 0.45 : 0.95} />
          ))}
        </Scatter>
      </ScatterChart>
    </ResponsiveContainer>
  );
}
