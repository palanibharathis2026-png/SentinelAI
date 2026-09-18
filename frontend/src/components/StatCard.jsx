const COLORS = {
  cyan: "from-cyan-500/25 to-blue-600/10 text-cyan-300 ring-cyan-400/30",
  orange: "from-orange-500/25 to-amber-600/10 text-orange-300 ring-orange-400/30",
  red: "from-rose-500/25 to-red-700/10 text-rose-300 ring-rose-400/30",
  green: "from-emerald-500/25 to-teal-600/10 text-emerald-300 ring-emerald-400/30",
  violet: "from-violet-500/25 to-fuchsia-600/10 text-violet-300 ring-violet-400/30",
};

export default function StatCard({ icon: Icon, label, value, hint, color = "cyan" }) {
  const c = COLORS[color] || COLORS.cyan;
  return (
    <div className={`flex items-start gap-4 rounded-2xl bg-gradient-to-br p-5 ring-1 ${c}`}>
      <div className="rounded-xl bg-slate-950/50 p-2.5">
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <div className="text-xs tracking-wider text-slate-300 uppercase">{label}</div>
        <div className="mt-1 text-3xl font-bold text-white">{value ?? "-"}</div>
        {hint && <div className="mt-0.5 text-xs text-slate-400">{hint}</div>}
      </div>
    </div>
  );
}
