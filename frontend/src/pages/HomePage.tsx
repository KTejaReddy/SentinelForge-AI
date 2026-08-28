import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Bot, FlaskConical, Loader2, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "../api/client";
import UploadDropzone from "../components/UploadDropzone";
import ScanOptionsForm, { DEFAULT_OPTIONS } from "../components/ScanOptionsForm";
import type { Project, ScanOptions } from "../types";
import { fmtBytes, timeAgo } from "../utils/format";

export default function HomePage() {
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);
  const [error, setError] = useState("");

  const { data: projects } = useQuery({ queryKey: ["projects"], queryFn: api.listProjects, refetchInterval: 15_000 });

  const startMutation = useMutation({
    mutationFn: (p: Project) => api.startScan(p.id, options),
    onSuccess: (scan) => navigate(`/scan/${scan.id}`),
    onError: (e) => setError(e instanceof Error ? e.message : "failed to start scan"),
  });

  const { data: demos } = useQuery({ queryKey: ["demos"], queryFn: api.listDemos });
  const [demoName, setDemoName] = useState("vulnerable-app");

  const demoMutation = useMutation({
    mutationFn: (name: string) => api.loadDemo(name),
    onSuccess: (scan) => navigate(`/scan/${scan.id}`),
    onError: (e) => setError(e instanceof Error ? e.message : "failed to load demo"),
  });

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-10 text-center">
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-accent-500/40 bg-accent-500/10 px-4 py-1.5 text-xs font-medium text-accent-300">
          <Bot className="h-3.5 w-3.5" /> Autonomous Red-Team, Bug Hunter & Self-Repairing Application Security Platform
        </div>
        <h1 className="text-4xl font-black tracking-tight text-white">
          Sentinel<span className="text-accent-400">Forge</span> AI
        </h1>
        <p className="mx-auto mt-3 max-w-2xl text-sm text-slate-400">
          Upload a project ZIP. The platform builds it in an isolated sandbox, discovers its attack surface, runs broad
          authorized security & QA testing, uses AI to find root causes, generates patches, rebuilds, retests, and verifies fixes —
          then hands you the report and the patched project.
        </p>
        <div className="mx-auto mt-4 flex max-w-xl items-center justify-center gap-2 rounded-lg border border-base-700 bg-base-900/60 px-4 py-2 text-[11px] text-slate-400">
          <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-green-400" />
          Testing is restricted to applications contained in the uploaded project and their sandboxed runtime.
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <div className="space-y-5 lg:col-span-3">
          <UploadDropzone onUploaded={(id) => api.getProject(id).then(setProject).catch(() => undefined)} />
          {project && (
            <div className="card card-pad">
              <div className="flex flex-wrap items-center gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-slate-200">{project.name}</div>
                  <div className="text-[11px] text-slate-500">
                    {project.filename} · {fmtBytes(project.size_bytes)} · type: {project.project_type}
                  </div>
                </div>
                <div className="ml-auto flex items-center gap-2">
                  <button onClick={() => setProject(null)} className="btn-ghost text-xs">
                    Change
                  </button>
                  <span className="rounded-md border border-green-500/40 bg-green-500/10 px-2 py-1 text-[11px] font-medium text-green-400">Validated ✓</span>
                </div>
              </div>
              {project.detection && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {(Object.entries(project.detection as Record<string, unknown>).find(([k]) => k === "frameworks")?.[1] as string[])?.slice(0, 6).map((f) => (
                    <span key={f} className="rounded-md border border-base-600 bg-base-800 px-2 py-0.5 text-[11px] text-slate-300">
                      {f}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
          <ScanOptionsForm value={options} onChange={setOptions} onStart={() => project && startMutation.mutate(project)} disabled={!project || startMutation.isPending} />
          {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</div>}

          <div className="card card-pad">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-amber-500/30 to-orange-600/30">
                <FlaskConical className="h-5 w-5 text-amber-400" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-slate-200">Try a built-in demo project</div>
                <div className="text-xs text-slate-500">
                  {demos?.find((d) => d.name === demoName)?.description ||
                    "Intentionally vulnerable local apps — pick one and scan it end-to-end."}
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <select
                    value={demoName}
                    onChange={(e) => setDemoName(e.target.value)}
                    className="input w-auto max-w-full py-1.5 text-xs"
                    aria-label="Choose a demo project"
                  >
                    {(demos ?? []).map((d) => (
                      <option key={d.name} value={d.name}>
                        {d.title}
                      </option>
                    ))}
                  </select>
                  <button onClick={() => demoMutation.mutate(demoName)} disabled={demoMutation.isPending} className="btn-primary">
                    {demoMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                    Load Demo
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2">
          <div className="card card-pad">
            <h3 className="mb-3 text-sm font-semibold text-slate-300">Recent Projects</h3>
            {!projects?.length && <div className="py-6 text-center text-xs text-slate-600">No projects yet — upload a ZIP to begin.</div>}
            <div className="space-y-2">
              {projects?.slice(0, 8).map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProject(p)}
                  className="w-full rounded-lg border border-base-700 bg-base-900/50 px-3 py-2.5 text-left hover:border-accent-500/50"
                >
                  <div className="flex items-center justify-between">
                    <span className="truncate text-xs font-medium text-slate-200">{p.name}</span>
                    <span className="shrink-0 text-[10px] text-slate-500">{timeAgo(p.created_at)}</span>
                  </div>
                  <div className="mt-0.5 flex items-center justify-between text-[10px] text-slate-500">
                    <span>{fmtBytes(p.size_bytes)}</span>
                    <span className="uppercase tracking-wide">{p.status}</span>
                  </div>
                </button>
              ))}
            </div>
            <div className="mt-4 border-t border-base-700 pt-3 text-[10px] leading-relaxed text-slate-600">
              Deterministic tools first, AI reasoning second. No fabricated results — every finding originates from a scanner,
              an executed test, or observed application behavior.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
