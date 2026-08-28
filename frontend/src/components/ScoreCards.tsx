import { useEffect, useState } from "react";

function Ring({ value, label, color }: { value: number; label: string; color: string }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setDisplay(value), 120);
    return () => clearTimeout(t);
  }, [value]);
  const r = 34;
  const c = 2 * Math.PI * r;
  const offset = c - (Math.max(0, Math.min(100, display)) / 100) * c;
  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative h-24 w-24">
        <svg viewBox="0 0 84 84" className="h-full w-full -rotate-90">
          <circle cx="42" cy="42" r={r} fill="none" stroke="#1a2740" strokeWidth="6" />
          <circle
            cx="42"
            cy="42"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 1s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-2xl font-bold" style={{ color }}>
          {display}
        </div>
      </div>
      <div className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</div>
    </div>
  );
}

export default function ScoreCards({ scores }: { scores: Record<string, number> }) {
  return (
    <div className="flex flex-wrap items-center justify-around gap-4">
      <Ring value={scores.overall ?? 0} label="Overall" color="#38bdf8" />
      <Ring value={scores.security ?? 0} label="Security" color="#f87171" />
      <Ring value={scores.reliability ?? 0} label="Reliability" color="#4ade80" />
      <Ring value={scores.code_health ?? 0} label="Code Health" color="#facc15" />
    </div>
  );
}
