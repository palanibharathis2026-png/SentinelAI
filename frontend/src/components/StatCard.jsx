export default function StatCard({ icon: Icon, label, value, hint, accent = "text-cyan-400" }) {
  return (
    <div className="card flex items-start gap-4">
      <div className={`rounded-lg bg-slate-800/80 p-2.5 ${accent}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <div className="text-xs tracking-wider text-slate-400 uppercase">{label}</div>
        <div className="mt-1 text-2xl font-bold">{value ?? "-"}</div>
        {hint && <div className="mt-0.5 text-xs text-slate-500">{hint}</div>}
      </div>
    </div>
  );
}
