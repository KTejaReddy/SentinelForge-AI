import { useEffect, useRef } from "react";
import type { ScanEvent } from "../types";
import { fmtTime } from "../utils/format";

const LEVEL_COLOR: Record<string, string> = {
  error: "text-red-400",
  warn: "text-amber-400",
  info: "text-slate-300",
  ok: "text-green-400",
  success: "text-green-400",
};

export default function LiveFeed({ logs }: { logs: ScanEvent[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs.length]);

  return (
    <div ref={ref} className="terminal-scroll h-72 overflow-y-auto rounded-lg border border-base-700 bg-black/60 p-3 font-mono text-[12px] leading-relaxed">
      {logs.length === 0 && <div className="text-slate-600">Awaiting scan output…</div>}
      {logs.map((e, i) => (
        <div key={i} className={`feed-line whitespace-pre-wrap ${LEVEL_COLOR[e.level || "info"] || "text-slate-300"}`}>
          <span className="text-slate-600">[{fmtTime(e.ts)}] </span>
          {e.message || e.msg || ""}
        </div>
      ))}
    </div>
  );
}
