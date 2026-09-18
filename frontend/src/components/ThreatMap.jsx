import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { geoEqualEarth, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import { riskHex } from "../utils/format.js";

const WIDTH = 960;
const HEIGHT = 470;
const land = feature(world, world.objects.countries);

// Smooth curve between the two projected points, bowed upwards so arcs never overlap the dots.
function arcPath(projection, from, to) {
  const [x0, y0] = projection([from.lon, from.lat]);
  const [x1, y1] = projection([to.lon, to.lat]);
  const lift = Math.min(120, Math.hypot(x1 - x0, y1 - y0) * 0.3);
  const cx = (x0 + x1) / 2;
  const cy = Math.max(20, Math.min(y0, y1) - lift);
  return `M${x0.toFixed(1)},${y0.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
}

export default function ThreatMap({ data, compact = false }) {
  const navigate = useNavigate();
  const projection = useMemo(() => geoEqualEarth().fitSize([WIDTH, HEIGHT], land), []);
  const path = useMemo(() => geoPath(projection), [projection]);
  const countries = useMemo(() => land.features.map((f, i) => <path key={i} d={path(f)} />), [path]);

  const cities = data?.cities || [];
  const arcs = data?.arcs || [];
  const maxSessions = Math.max(1, ...cities.map((c) => c.sessions));

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" style={compact ? { maxHeight: 320 } : undefined}>
      <defs>
        <linearGradient id="arcGrad" x1="0" x2="1">
          <stop offset="0%" stopColor="#22d3ee" />
          <stop offset="100%" stopColor="#f43f5e" />
        </linearGradient>
        <radialGradient id="ocean" cx="50%" cy="50%" r="70%">
          <stop offset="0%" stopColor="#1e1b4b" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#020617" stopOpacity="0" />
        </radialGradient>
      </defs>
      <rect width={WIDTH} height={HEIGHT} fill="url(#ocean)" />
      <g fill="#1e293b" stroke="#334155" strokeWidth="0.5">{countries}</g>

      {arcs.map((a, i) => (
        <path
          key={a.id}
          d={arcPath(projection, a.from, a.to)}
          fill="none"
          stroke="url(#arcGrad)"
          strokeWidth={a.tier === "BLOCK" ? 2 : 1.4}
          strokeLinecap="round"
          className="arc cursor-pointer"
          style={{ animationDelay: `${(i % 12) * 0.15}s` }}
          onClick={() => navigate(`/incidents/${a.id}`)}
        >
          <title>{`${a.name}: ${a.from.city} → ${a.to.city}\n${a.threat || a.tier} (risk ${a.risk})`}</title>
        </path>
      ))}

      {cities.map((c) => {
        const [x, y] = projection([c.lon, c.lat]);
        const color = c.alerts ? riskHex(c.max_risk) : "#22d3ee";
        const r = 2.5 + 5 * Math.sqrt(c.sessions / maxSessions);
        return (
          <g key={c.city}>
            {c.alerts > 0 && <circle cx={x} cy={y} r={3} fill="none" stroke={color} strokeWidth="1.5" className="pulse-ring" />}
            <circle cx={x} cy={y} r={r} fill={color} fillOpacity={0.85} stroke="#020617" strokeWidth="1">
              <title>{`${c.city}, ${c.country}\n${c.sessions} sessions · ${c.alerts} alerts`}</title>
            </circle>
            {!compact && c.country !== "India" && (
              <text x={x + r + 3} y={y + 3} fontSize="11" fill="#cbd5e1">
                {c.city}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}
