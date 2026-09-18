import { riskHex } from "../utils/format.js";

// Half-circle gauge from 0 to 100.
export default function RiskGauge({ risk = 0, size = 200 }) {
  const r = 80;
  const circumference = Math.PI * r;
  const filled = (Math.min(Math.max(risk, 0), 100) / 100) * circumference;
  const color = riskHex(risk);

  return (
    <svg width={size} height={size * 0.62} viewBox="0 0 200 124">
      <path d="M 20 110 A 80 80 0 0 1 180 110" fill="none" stroke="#1e293b" strokeWidth="16" strokeLinecap="round" />
      <path
        d="M 20 110 A 80 80 0 0 1 180 110"
        fill="none"
        stroke={color}
        strokeWidth="16"
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circumference}`}
      />
      <text x="100" y="98" textAnchor="middle" fontSize="40" fontWeight="700" fill={color}>
        {risk}
      </text>
      <text x="100" y="118" textAnchor="middle" fontSize="11" fill="#94a3b8">
        RISK / 100
      </text>
    </svg>
  );
}
