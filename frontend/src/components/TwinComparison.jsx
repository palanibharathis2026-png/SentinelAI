import { AlertTriangle, CheckCircle2, Siren } from "lucide-react";

const LEVEL = {
  ok: { icon: CheckCircle2, color: "text-emerald-400", row: "" },
  warn: { icon: AlertTriangle, color: "text-orange-400", row: "bg-orange-500/5" },
  critical: { icon: Siren, color: "text-red-400", row: "bg-red-500/10" },
};

// Side-by-side: the employee's Digital Behavioral Twin vs. this session.
export default function TwinComparison({ rows = [] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <table className="w-full text-sm">
        <thead className="bg-slate-900 text-xs tracking-wider text-slate-400 uppercase">
          <tr>
            <th className="px-3 py-2 text-left">Signal</th>
            <th className="px-3 py-2 text-left">Digital twin (normal)</th>
            <th className="px-3 py-2 text-left">This session</th>
            <th className="w-10 px-3 py-2" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {rows.map((r) => {
            const { icon: Icon, color, row } = LEVEL[r.level] || LEVEL.ok;
            return (
              <tr key={r.label} className={row}>
                <td className="px-3 py-2 text-slate-300">{r.label}</td>
                <td className="px-3 py-2 font-mono text-slate-400">{r.normal}</td>
                <td className={`px-3 py-2 font-mono ${r.level === "ok" ? "text-slate-200" : color}`}>{r.current}</td>
                <td className="px-3 py-2">
                  <Icon className={`h-4 w-4 ${color}`} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
