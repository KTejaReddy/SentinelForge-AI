import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Braces, FileCode2, FlaskConical, Hammer, ShieldCheck, Sparkles } from "lucide-react";
import { api } from "../api/client";
import DiffView from "../components/DiffView";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import { CATEGORY_LABELS } from "../utils/format";

export default function FindingDetailPage() {
  const { scanId, findingId } = useParams();
  const id = Number(findingId);
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["finding-detail", id], queryFn: () => api.getFindingDetail(id), refetchInterval: 5000 });

  const repair = useMutation({ mutationFn: () => api.repairFinding(id), onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["finding-detail", id] }), 2000) });
  const verify = useMutation({ mutationFn: () => api.verifyFinding(id), onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["finding-detail", id] }), 2000) });

  if (isLoading) return <div className="p-10 text-sm text-slate-500">Loading finding…</div>;
  if (!data) return <div className="p-10 text-sm text-slate-500">Finding not found.</div>;

  const f = data.finding;
  const patch = data.patches[data.patches.length - 1];
  const verification = data.verifications[data.verifications.length - 1];
  const files = patch ? Object.entries(patch.files) : [];

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <Link to={`/scan/${scanId}/findings`} className="mb-4 inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to findings
      </Link>

      <div className="mb-5 flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <StatusBadge status={f.patch_status === "verified" ? "verified" : f.patch_status === "applied" ? "applied" : f.status} />
            <span className="rounded-md border border-base-600 bg-base-800 px-2 py-0.5 text-[11px] text-slate-400">{f.provenance}</span>
          </div>
          <h1 className="mt-2 text-2xl font-bold text-white">{f.title}</h1>
          <div className="mt-1 text-xs text-slate-500">
            {CATEGORY_LABELS[f.category] || f.category} · source: {f.source} · confidence {(f.confidence * 100).toFixed(0)}%
          </div>
        </div>
        <div className="flex gap-2">
          <button onClick={() => verify.mutate()} disabled={verify.isPending} className="btn-ghost">
            <ShieldCheck className="h-4 w-4" /> Verify
          </button>
          <button onClick={() => repair.mutate()} disabled={repair.isPending} className="btn-primary">
            <Hammer className="h-4 w-4" /> {repair.isPending ? "Repairing…" : "Repair"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5">
        {f.description && (
          <Section title="Description">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">{f.description}</p>
          </Section>
        )}
        {f.why_it_matters && (
          <Section title="Why it matters">
            <p className="text-sm text-slate-300">{f.why_it_matters}</p>
          </Section>
        )}

        {f.evidence && Object.keys(f.evidence).length > 0 && (
          <Section title="Evidence">
            <pre className="overflow-x-auto rounded-lg border border-base-700 bg-black/50 p-3 font-mono text-[11px] leading-relaxed text-slate-300">
              {JSON.stringify(f.evidence, null, 2).slice(0, 4000)}
            </pre>
          </Section>
        )}

        {f.reproduction && Object.keys(f.reproduction).length > 0 && (
          <Section title="Reproduction">
            <div className="space-y-1 font-mono text-[12px] text-slate-300">
              {Object.entries(f.reproduction).map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <span className="w-24 shrink-0 text-slate-500">{k}</span>
                  <span className="break-all">{typeof v === "string" ? v : JSON.stringify(v)}</span>
                </div>
              ))}
            </div>
          </Section>
        )}

        {f.affected_file && (
          <Section title="Affected file">
            <div className="flex items-center gap-2 font-mono text-[13px] text-cyan-300">
              <FileCode2 className="h-4 w-4" /> {f.affected_file}
              {f.line_start ? <span className="text-slate-500">: lines {f.line_start}–{f.line_end || f.line_start}</span> : null}
            </div>
          </Section>
        )}

        {f.root_cause && (
          <Section title="Root cause">
            <p className="text-sm text-slate-300">{f.root_cause}</p>
          </Section>
        )}

        {f.ai_explanation && (
          <Section title="AI reasoning">
            <div className="rounded-lg border border-accent-500/30 bg-accent-500/5 p-4">
              <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-accent-300">
                <Sparkles className="h-3.5 w-3.5" /> AI Assessment
              </div>
              <pre className="whitespace-pre-wrap font-mono text-[12px] leading-relaxed text-slate-300">{f.ai_explanation}</pre>
            </div>
          </Section>
        )}

        {f.recommended_fix && (
          <Section title="Recommended fix">
            <p className="whitespace-pre-wrap text-sm text-slate-300">{f.recommended_fix}</p>
          </Section>
        )}

        {patch && (
          <Section title={`Patch — ${patch.status}`}>
            <p className="mb-3 text-sm text-slate-300">{patch.explanation}</p>
            <div className="space-y-4">
              {files.map(([rel, content]) => (
                <div key={rel}>
                  <div className="mb-1.5 flex items-center gap-1.5 font-mono text-xs text-slate-400">
                    <Braces className="h-3.5 w-3.5" /> {rel}
                  </div>
                  <DiffView original={content.before || ""} modified={content.after || ""} height={Math.min(420, Math.max(160, content.before.split("\n").length * 18 + 40))} />
                </div>
              ))}
              {patch.diff && (
                <details>
                  <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-200">Full unified diff</summary>
                  <pre className="mt-2 overflow-x-auto rounded-lg border border-base-700 bg-black/50 p-3 font-mono text-[11px] text-slate-300">{patch.diff}</pre>
                </details>
              )}
            </div>
          </Section>
        )}

        {verification && (
          <Section title="Verification">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Verdict label="Security fix" ok={verification.status === "FIXED" || verification.status === "PARTIALLY_FIXED"} text={verification.status} />
              <Verdict label="Build" ok={verification.build_pass} text={verification.build_pass ? "PASS" : "FAIL"} />
              <Verdict label="Regression" ok={verification.regression_pass} text={verification.regression_pass ? "PASS" : "FAIL"} />
              <Verdict label="Original exploit" ok={verification.exploit_blocked} text={verification.exploit_blocked ? "BLOCKED" : "STILL WORKS"} />
            </div>
            {(Boolean(verification.details.reason) || Boolean(verification.details.ai_evidence)) && (
              <pre className="mt-3 whitespace-pre-wrap rounded-lg border border-base-700 bg-black/50 p-3 font-mono text-[11px] text-slate-300">
                {String(verification.details.reason || verification.details.ai_evidence)}
              </pre>
            )}
          </Section>
        )}

        {data.evidence.length > 0 && (
          <Section title="Evidence records">
            {data.evidence.map((e, i) => (
              <details key={i} className="mb-2 rounded-lg border border-base-700 bg-base-900/40 p-3">
                <summary className="cursor-pointer text-xs font-medium text-slate-300">
                  <FlaskConical className="mr-1 inline h-3.5 w-3.5 text-accent-400" />
                  {String(e.tool)} · {String(e.target || e.source_file || "evidence")}
                </summary>
                <pre className="mt-2 overflow-x-auto font-mono text-[11px] text-slate-400">
                  {JSON.stringify({ request: e.request, response: e.response, logs: e.logs, reproduction_steps: e.reproduction_steps }, null, 2).slice(0, 3000)}
                </pre>
              </details>
            ))}
          </Section>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card card-pad">
      <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">{title}</h3>
      {children}
    </div>
  );
}

function Verdict({ label, ok, text }: { label: string; ok: boolean; text: string }) {
  return (
    <div className={`rounded-lg border p-3 text-center ${ok ? "border-green-500/40 bg-green-500/10" : "border-red-500/40 bg-red-500/10"}`}>
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1 text-sm font-bold ${ok ? "text-green-400" : "text-red-400"}`}>{text}</div>
    </div>
  );
}
