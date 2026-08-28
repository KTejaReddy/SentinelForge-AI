import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { Bug } from "lucide-react";
import { api } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import { CATEGORY_LABELS } from "../utils/format";

export default function FindingsPage() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const { data: findings, isLoading } = useQuery({ queryKey: ["findings", id], queryFn: () => api.scanFindings(id) });

  const sorted = [...(findings || [])].sort((a, b) => sev(a.severity) - sev(b.severity));
  const counts = (findings || []).reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <div className="mb-5 flex items-center gap-2">
        <Bug className="h-5 w-5 text-accent-400" />
        <h1 className="text-xl font-bold text-white">Findings — Scan #{id}</h1>
      </div>
      <div className="mb-5 flex flex-wrap gap-2">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map((s) => (
          <span key={s} className="rounded-lg border border-base-600 bg-base-800 px-2.5 py-1 text-[11px] text-slate-400">
            {s}: <span className="font-bold text-slate-200">{counts[s] || 0}</span>
          </span>
        ))}
      </div>
      {isLoading && <div className="text-sm text-slate-500">Loading…</div>}
      {!isLoading && sorted.length === 0 && <div className="py-16 text-center text-sm text-slate-600">No findings recorded.</div>}
      <div className="space-y-2">
        {sorted.map((f) => (
          <Link key={f.id} to={`/scan/${id}/findings/${f.id}`} className="card card-pad block transition-colors hover:border-accent-500/50">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={f.severity} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-semibold text-slate-200">{f.title}</div>
                <div className="mt-0.5 truncate text-[11px] text-slate-500">
                  {CATEGORY_LABELS[f.category] || f.category} · {f.affected_file || f.affected_component || "n/a"}
                  {f.line_start ? `:${f.line_start}` : ""} · conf {(f.confidence * 100).toFixed(0)}% · {f.source}
                </div>
              </div>
              <span className="hidden text-[10px] uppercase tracking-wide text-slate-500 sm:inline">{f.provenance}</span>
              <StatusBadge status={f.patch_status === "verified" ? "verified" : f.patch_status === "applied" ? "applied" : f.status === "fixed" ? "fixed" : f.status} />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function sev(s: string): number {
  return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[s] ?? 5;
}
