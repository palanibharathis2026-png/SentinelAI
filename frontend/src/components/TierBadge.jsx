import { TIER_STYLES } from "../utils/format.js";

export default function TierBadge({ tier, risk }) {
  const s = TIER_STYLES[tier] || TIER_STYLES.ALLOW;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold ${s.bg} ${s.border} ${s.text}`}>
      {risk !== undefined && <span className="font-mono">{risk}</span>}
      {s.label}
    </span>
  );
}
