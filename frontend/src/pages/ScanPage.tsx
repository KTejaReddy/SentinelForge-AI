import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { CheckCircle2, Download, FileSearch, GitBranch, ScrollText, Square } from "lucide-react";
import { api } from "../api/client";
import AgentPanel from "../components/AgentPanel";
import LiveFeed from "../components/LiveFeed";
import ScoreCards from "../components/ScoreCards";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import { useScanEvents } from "../hooks/useScanEvents";
import { STATE_LABELS } from "../utils/format";

const RUNNING_STATES = new Set(["UPLOADED", "VALIDATING", "EXTRACTING", "ANALYZING", "BUILDING", "RUNNING", "DISCOVERING", "STATIC_ANALYSIS", "DEPENDENCY_ANALYSIS", "SECRET_ANALYSIS", "DYNAMIC_TESTING", "BROWSER_TESTING", "FUZZING", "BUG_HUNTING", "CORRELATING", "AI_ANALYSIS", "REPAIRING", "REBUILDING", "VERIFYING", "REPORTING"]);

export default function ScanPage() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const { data: scan, refetch } = useQuery({ queryKey: ["scan", id], queryFn: () => api.getScan(id), refetchInterval: (q) => (q.state.data && RUNNING_STATES.has(q.state.data.state) ? 2500 : false) });
  const live = useScanEvents(id, true);
  const running = scan ? RUNNING_STATES.has(scan.state) : true;

  const stop = () => {
    api.stopScan(id).then(() => setTimeout(refetch, 800));
  };

  const progress = Math.max(live.progress || 0, scan?.progress || 0);
  const state = live.state || scan?.state || "UPLOADED";
  const findings = scan?.findings || [];
  const counts = useQuery({ queryKey: ["scan-findings-count", id], queryFn: () => api.scanFindings(id), refetchInterval: 3000, enabled: running });

  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white">Scan #{id}</h1>
            <StatusBadge status={state} />
          </div>
          <div className="mt-0.5 text-xs text-slate-500">Project #{scan?.project_id} · intensity: {scan?.intensity}</div>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {running ? (
            <button onClick={stop} className="btn-danger">
              <Square className="h-3.5 w-3.5" /> Stop Scan
            </button>
          ) : (
            <>
              <Link to={`/scan/${id}/findings`} className="btn-ghost">
                <FileSearch className="h-4 w-4" /> Findings ({counts.data?.length ?? findings.length})
              </Link>
              <Link to={`/scan/${id}/graph`} className="btn-ghost">
                <GitBranch className="h-4 w-4" /> Attack Graph
              </Link>
              <Link to={`/scan/${id}/report`} className="btn-primary">
                <ScrollText className="h-4 w-4" /> Report
              </Link>
            </>
          )}
        </div>
      </div>

      <div className="card card-pad mb-5">
        <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
          <span className="font-semibold uppercase tracking-wider">{STATE_LABELS[state] || state}</span>
          <span>{Math.round(progress)}%</span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-base-700">
          <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-700" style={{ width: `${Math.max(2, progress)}%` }} />
        </div>
        {scan?.error && <div className="mt-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-400">{scan.error}</div>}
      </div>

      {!running && scan?.scores && Object.keys(scan.scores).length > 0 && (
        <div className="card card-pad mb-5">
          <ScoreCards scores={scan.scores} />
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            {(["original", "patched", "reports"] as const).map((k) => (
              <a key={k} href={api.downloadUrl(id, k)} className="btn-ghost">
                <Download className="h-4 w-4" /> Download {k === "reports" ? "Reports" : k === "patched" ? "Patched ZIP" : "Original ZIP"}
              </a>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-5">
          <div className="card card-pad">
            <h3 className="mb-2 text-sm font-semibold text-slate-300">Live Console</h3>
            <LiveFeed logs={live.logs} />
          </div>
          <div className="card card-pad">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-300">Pipeline Steps</h3>
              {live.connected && running && <span className="flex items-center gap-1.5 text-[11px] text-green-400"><span className="pulse-dot h-1.5 w-1.5 rounded-full bg-green-400" /> live</span>}
            </div>
            <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
              {(scan?.steps || []).map((s) => (
                <div key={s.id} className="flex items-center justify-between rounded-lg border border-base-700/70 bg-base-900/50 px-3 py-1.5">
                  <span className="text-xs text-slate-300">{s.name}</span>
                  <StatusBadge status={s.status} />
                </div>
              ))}
              {scan && scan.steps.length === 0 && <div className="text-xs text-slate-600">Waiting for the pipeline…</div>}
            </div>
          </div>
        </div>
        <div className="space-y-5">
          <AgentPanel agents={live.agents} />
          <div className="card card-pad">
            <h3 className="mb-3 text-sm font-semibold text-slate-300">Findings So Far</h3>
            {findings.length === 0 && live.findingsCount === 0 ? (
              <div className="py-4 text-center text-xs text-slate-600">No findings yet.</div>
            ) : (
              <div className="space-y-1.5">
                {(counts.data || findings).slice(0, 12).map((f) => (
                  <Link key={f.id} to={`/scan/${id}/findings/${f.id}`} className="flex items-center gap-2 rounded-lg border border-base-700/70 bg-base-900/50 px-3 py-2 hover:border-accent-500/40">
                    <SeverityBadge severity={f.severity} />
                    <span className="truncate text-xs text-slate-300">{f.title}</span>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {!running && scan?.state === "COMPLETED" && (
        <div className="mt-5 flex items-center gap-2 rounded-lg border border-green-500/40 bg-green-500/10 px-4 py-3 text-sm text-green-400">
          <CheckCircle2 className="h-4 w-4" /> Scan completed. Explore findings, the attack graph, and the report above.
        </div>
      )}
    </div>
  );
}
