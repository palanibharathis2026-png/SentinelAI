export const TIER_STYLES = {
  ALLOW: { label: "Allow", text: "text-emerald-300", bg: "bg-emerald-500/15", border: "border-emerald-500/40", hex: "#34d399" },
  MONITOR: { label: "Monitor", text: "text-yellow-300", bg: "bg-yellow-500/15", border: "border-yellow-500/40", hex: "#facc15" },
  MFA: { label: "MFA", text: "text-orange-300", bg: "bg-orange-500/15", border: "border-orange-500/40", hex: "#fb923c" },
  BLOCK: { label: "Block", text: "text-red-300", bg: "bg-red-500/15", border: "border-red-500/40", hex: "#f87171" },
};

export function tierForRisk(risk) {
  if (risk >= 80) return "BLOCK";
  if (risk >= 60) return "MFA";
  if (risk >= 30) return "MONITOR";
  return "ALLOW";
}

export const riskHex = (risk) => TIER_STYLES[tierForRisk(risk)].hex;

export function fmtDateTime(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtTime(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export const pct = (x) => `${Math.round((x ?? 0) * 1000) / 10}%`;
