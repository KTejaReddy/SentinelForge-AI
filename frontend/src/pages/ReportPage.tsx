import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Check, Download, FileJson, Minus, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import ScoreCards from "../components/ScoreCards";

const SEV_COLORS: Record<string, string> = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#38bdf8", INFO: "#94a3b8" };

export default function ReportPage() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const { data, isLoading } = useQuery({ queryKey: ["report", id], queryFn: () => api.scanReport(id), refetchInterval: 5000 });

  if (isLoading) return <div className="p-10 text-sm text-slate-500">Loading report…</div>;
  if (!data) return <div className="p-10 text-sm text-slate-500">Report not ready — the scan must complete first.</div>;

  const scores = (data.scores as Record<string, unknown>) || {};
  const findings = (data.findings as Array<Record<string, unknown>>) || [];
  const summary = (data.summary as Record<string, unknown>) || {};
  const counts = (summary.counts as Record<string, number>) || {};
  const limitations = (data.limitations as string[]) || [];
  const ai = (summary.ai as Record<string, unknown>) || {};
  const categories = (scores.categories as Record<string, number>) || {};

  const sevData = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => ({ name: s, value: counts[s.toLowerCase()] || 0, color: SEV_COLORS[s] }));
  const catData = Object.entries(categories)
    .map(([name, value]) => ({ name: name.replace(/_/g, " "), value }))
    .sort((a, b) => a.value - b.value);

  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">Scan Report — #{id}</h1>
          <div className="text-xs text-slate-500">status: {String(data.status)}</div>
        </div>
        <div className="ml-auto flex gap-2">
          <a href={api.downloadUrl(id, "reports")} className="btn-ghost">
            <FileJson className="h-4 w-4" /> Reports ZIP
          </a>
          <a href={api.downloadUrl(id, "patched")} className="btn-primary">
            <Download className="h-4 w-4" /> Patched Project ZIP
          </a>
          <a href={api.downloadUrl(id, "original")} className="btn-ghost">
            <Download className="h-4 w-4" /> Original ZIP
          </a>
        </div>
      </div>

      <div className="card card-pad mb-5">
        <ScoreCards scores={scores as unknown as Record<string, number>} />
      </div>

      <div className="mb-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="card card-pad">
          <h3 className="mb-3 text-sm font-semibold text-slate-300">Findings by Severity</h3>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
                {sevData.map((s) => (
                  <Cell key={s.name} fill={s.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#0b1220", border: "1px solid #1a2740", borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-2 grid grid-cols-5 text-center text-[11px]">
            {sevData.map((s) => (
              <div key={s.name}>
                <span className="font-bold" style={{ color: s.color }}>{s.value}</span>
                <span className="block text-slate-500">{s.name}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="card card-pad">
          <h3 className="mb-3 text-sm font-semibold text-slate-300">Category Scores</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={catData} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid stroke="#1a2740" horizontal={false} />
              <XAxis type="number" domain={[0, 100]} stroke="#475569" tick={{ fontSize: 10 }} />
              <YAxis type="category" dataKey="name" width={120} stroke="#475569" tick={{ fontSize: 10 }} />
              <Tooltip contentStyle={{ background: "#0b1220", border: "1px solid #1a2740", borderRadius: 8 }} />
              <Bar dataKey="value" fill="#38bdf8" radius={[0, 4, 4, 0]} barSize={12} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
        {[
          ["Findings", counts.findings_total],
          ["Critical", counts.critical],
          ["High", counts.high],
          ["Medium", counts.medium],
          ["Low", counts.low],
          ["Confirmed", counts.confirmed],
          ["Fixed", counts.fixed],
          ["Verified", counts.verified],
        ].map(([label, value]) => (
          <div key={label as string} className="card px-4 py-3 text-center">
            <div className="text-xl font-bold text-white">{value ?? 0}</div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="card card-pad">
          <h3 className="mb-3 text-sm font-semibold text-slate-300">Tool Coverage</h3>
          <div className="grid grid-cols-2 gap-1.5">
            {KNOWN_TOOLS.map((t) => {
              const executed = (data.tools_executed as string[] | undefined) || [];
              const ran = executed.includes(t.key);
              return (
                <div key={t.key} className="flex items-center justify-between rounded-lg border border-base-700 bg-base-900/50 px-3 py-1.5 text-xs">
                  <span className="text-slate-300">{t.label}</span>
                  {ran ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Minus className="h-3.5 w-3.5 text-slate-600" />}
                </div>
              );
            })}
          </div>
          <div className="mt-3 border-t border-base-700 pt-3 text-[11px] text-slate-500">
            AI calls: {String(ai.calls ?? 0)} · est. cost: ${Number(ai.cost_usd ?? 0).toFixed(4)} · sandbox: {String(data.sandbox_mode)}
          </div>
        </div>
        <div className="card card-pad">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-300">
            <ShieldAlert className="h-4 w-4 text-amber-400" /> Limitations & Coverage Gaps
          </h3>
          {limitations.length === 0 ? (
            <div className="text-sm text-slate-500">No limitations recorded.</div>
          ) : (
            <ul className="space-y-1.5 text-xs text-slate-400">
              {limitations.map((l, i) => (
                <li key={i} className="flex gap-2">
                  <Minus className="mt-0.5 h-3 w-3 shrink-0 text-slate-600" /> {l}
                </li>
              ))}
            </ul>
          )}
          <div className="mt-3 border-t border-base-700 pt-3 text-[11px] leading-relaxed text-slate-500">
            Testing was restricted to the uploaded project and its sandboxed runtime. Tool unavailability is reported honestly — coverage is never invented.
          </div>
        </div>
      </div>
    </div>
  );
}

const KNOWN_TOOLS: Array<{ key: string; label: string }> = [
  { key: "semgrep", label: "Semgrep" },
  { key: "custom_probes", label: "Dynamic Probes" },
  { key: "zap", label: "OWASP ZAP" },
  { key: "nuclei", label: "Nuclei" },
  { key: "trivy", label: "Trivy" },
  { key: "gitleaks", label: "Gitleaks" },
  { key: "secret-scanner", label: "Secret Scanner" },
  { key: "browser", label: "Playwright / Browser" },
  { key: "ffuf", label: "ffuf" },
  { key: "native_tests", label: "Native Tests" },
  { key: "fuzz", label: "Fuzzing" },
];
