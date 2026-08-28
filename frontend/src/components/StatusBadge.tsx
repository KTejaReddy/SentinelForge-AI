const STYLES: Record<string, string> = {
  COMPLETED: "bg-green-500/15 text-green-400 border-green-500/40",
  DONE: "bg-green-500/15 text-green-400 border-green-500/40",
  verified: "bg-green-500/15 text-green-400 border-green-500/40",
  fixed: "bg-green-500/15 text-green-400 border-green-500/40",
  RUNNING: "bg-sky-500/15 text-sky-400 border-sky-500/40",
  applied: "bg-sky-500/15 text-sky-400 border-sky-500/40",
  open: "bg-red-500/15 text-red-400 border-red-500/40",
  FAILED: "bg-red-500/15 text-red-400 border-red-500/40",
  CANCELLED: "bg-slate-500/15 text-slate-400 border-slate-500/40",
  needs_review: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  SKIPPED: "bg-slate-500/15 text-slate-400 border-slate-500/40",
  UNAVAILABLE: "bg-slate-500/15 text-slate-400 border-slate-500/40",
  PENDING: "bg-slate-500/15 text-slate-400 border-slate-500/40",
};

export default function StatusBadge({ status }: { status: string }) {
  const cls = STYLES[status] || STYLES.PENDING;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${cls}`}>
      {status}
    </span>
  );
}
