import { Building2 } from "lucide-react";
import { api } from "../api.js";
import { usePolling } from "../hooks/usePolling.js";

const SIGNAL_GROUPS = [
  { label: "Location", signals: ["Impossible travel", "New country", "New city"] },
  { label: "Device / bot", signals: ["Unrecognised device", "Automation client"] },
  { label: "Odd hours", signals: ["Unusual login time", "Slightly unusual time", "Weekend activity"] },
  { label: "Logins", signals: ["Brute-force pattern", "Repeated failed logins"] },
  { label: "Data theft", signals: ["Mass data download", "Abnormal data download", "Elevated downloads", "Sensitive data access"] },
  { label: "New systems", signals: ["First-time sensitive access", "Unfamiliar admin action"] },
  { label: "Tampering", signals: ["Security tampering"] },
  { label: "API abuse", signals: ["Machine-speed API usage", "High API usage"] },
];

function cellColor(n, max) {
  if (!n) return "rgb(30 41 59 / 0.5)";
  const t = Math.min(1, n / max);
  // cyan -> violet -> rose as intensity grows
  const hue = 190 + t * 150;
  return `hsl(${hue} 85% ${55 - t * 10}% / ${0.35 + t * 0.6})`;
}

export default function DepartmentHeatmap() {
  const { data } = usePolling(api.departments, 8000);
  const rows = (data || []).map((d) => ({
    ...d,
    cells: SIGNAL_GROUPS.map((g) => g.signals.reduce((sum, s) => sum + (d.signals[s] || 0), 0)),
  }));
  const max = Math.max(1, ...rows.flatMap((r) => r.cells));

  return (
    <div className="card">
      <div className="card-title">
        <Building2 className="h-4 w-4 text-violet-400" /> Department risk heatmap (7 days)
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-separate border-spacing-1 text-xs">
          <thead>
            <tr className="text-slate-400">
              <th className="text-left font-medium">Department</th>
              {SIGNAL_GROUPS.map((g) => <th key={g.label} className="font-medium">{g.label}</th>)}
              <th className="font-medium">Alerts</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.department}>
                <td className="pr-2 whitespace-nowrap text-slate-200">{r.department}</td>
                {r.cells.map((n, i) => (
                  <td
                    key={i}
                    title={`${r.department} · ${SIGNAL_GROUPS[i].label}: ${n} signals`}
                    className="h-8 min-w-12 rounded-md text-center font-mono text-white"
                    style={{ background: cellColor(n, max) }}
                  >
                    {n || ""}
                  </td>
                ))}
                <td className={`text-center font-mono ${r.alerts ? "text-rose-300" : "text-slate-500"}`}>{r.alerts}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
