import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, FolderArchive } from "lucide-react";
import { api } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import { fmtBytes, STATE_LABELS, timeAgo } from "../utils/format";

export default function ProjectsPage() {
  const { data: scans, isLoading } = useQuery({ queryKey: ["scans"], queryFn: api.listScans, refetchInterval: 5000 });

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-6 flex items-center gap-2">
        <Activity className="h-5 w-5 text-accent-400" />
        <h1 className="text-xl font-bold text-white">Scan Activity</h1>
      </div>
      {isLoading && <div className="text-sm text-slate-500">Loading…</div>}
      <div className="space-y-3">
        {scans?.map((scan) => (
          <Link key={scan.id} to={`/scan/${scan.id}`} className="card card-pad block transition-colors hover:border-accent-500/50">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-base-700/60">
                <FolderArchive className="h-4 w-4 text-slate-400" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-slate-200">Scan #{scan.id}</div>
                <div className="text-[11px] text-slate-500">
                  Project #{scan.project_id} · {STATE_LABELS[scan.state] || scan.state} · {fmtBytes(0)} · {timeAgo(scan.created_at)}
                </div>
              </div>
              <div className="w-40">
                <div className="mb-1 flex justify-between text-[10px] text-slate-500">
                  <span>progress</span>
                  <span>{Math.round(scan.progress)}%</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-base-700">
                  <div className="h-full bg-accent-500 transition-all" style={{ width: `${scan.progress}%` }} />
                </div>
              </div>
              <StatusBadge status={scan.state} />
              {scan.scores && scan.scores.overall !== undefined && (
                <span className="rounded-lg border border-base-600 bg-base-800 px-2.5 py-1 font-mono text-sm font-bold text-cyan-300">
                  {scan.scores.overall}
                </span>
              )}
            </div>
          </Link>
        ))}
        {scans && scans.length === 0 && <div className="py-10 text-center text-sm text-slate-600">No scans yet.</div>}
      </div>
    </div>
  );
}
