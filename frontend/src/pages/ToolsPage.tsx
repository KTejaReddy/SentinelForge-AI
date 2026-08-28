import { useQuery } from "@tanstack/react-query";
import {
  Boxes,
  CheckCircle2,
  Cpu,
  FileSearch,
  Fingerprint,
  Globe,
  Lock,
  Network,
  PackageSearch,
  Radar,
  Search,
  ShieldCheck,
  TerminalSquare,
  Wrench,
  XCircle,
  Zap,
} from "lucide-react";
import { api } from "../api/client";

const TOOL_META: Record<string, { purpose: string; icon: typeof Search }> = {
  Semgrep: { purpose: "SAST — framework-specific rules, injection risks, dangerous APIs, data-flow analysis", icon: FileSearch },
  "OWASP ZAP": { purpose: "Dynamic web/API security testing — passive & active scanning, spidering, endpoint discovery", icon: Zap },
  Nuclei: { purpose: "Template-based vulnerability scanning against the sandboxed target", icon: Radar },
  Trivy: { purpose: "Dependency & filesystem vulnerability scanning (OSV/npm/pip metadata)", icon: PackageSearch },
  "OSV-Scanner": { purpose: "Dependency vulnerability scanning via the OSV database (npm, pip, go, maven, gem…)", icon: PackageSearch },
  "Bandit (Python SAST)": { purpose: "Python static security analysis — unsafe APIs, injection, crypto misuse", icon: FileSearch },
  Gitleaks: { purpose: "Secrets & credential detection (tokens, API keys, private keys)", icon: Lock },
  ffuf: { purpose: "Fast fuzzing / path & parameter discovery (strictly rate-limited, loopback only)", icon: Network },
  "Browser Agent": { purpose: "Headless Chromium — console errors, failed requests, forms, screenshots, workflow walking", icon: Globe },
  "Dynamic Probes (built-in)": { purpose: "Passive header/configuration checks, method abuse, missing auth, IDOR/BOLA probes", icon: Fingerprint },
  "Secrets Scanner (built-in)": { purpose: "Deterministic regex-based secret scanning fallback", icon: Lock },
  "Fuzzing (built-in)": { purpose: "Bounded malformed-JSON / query-parameter fuzzing of writable endpoints", icon: Wrench },
  "Native Test Runner": { purpose: "Executes the project's own test suite for regression evidence", icon: TerminalSquare },
};

function StatusBadge({ ok }: { ok: boolean }) {
  return ok ? (
    <span className="flex items-center gap-1.5 rounded-md border border-green-500/40 bg-green-500/10 px-2 py-0.5 text-[11px] font-semibold text-green-400">
      <CheckCircle2 className="h-3.5 w-3.5" /> AVAILABLE
    </span>
  ) : (
    <span className="flex items-center gap-1.5 rounded-md border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[11px] font-semibold text-red-400">
      <XCircle className="h-3.5 w-3.5" /> UNAVAILABLE
    </span>
  );
}

export default function ToolsPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["healthTools"], queryFn: api.healthTools, refetchInterval: 30_000 });

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Security Toolchain</h1>
        <p className="mt-1 text-sm text-slate-500">
          Live capability matrix — every tool shown here is detected at runtime. Unavailable tools fall back to the built-in
          analyzers (recorded as limitations, never simulated).
        </p>
      </div>

      {isLoading && <div className="text-sm text-slate-500">Loading capability matrix…</div>}
      {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">Failed to load: {String(error)}</div>}

      {data && (
        <>
          {/* Environment summary */}
          <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
            <div className="card card-pad">
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                <Cpu className="h-3.5 w-3.5" /> OS
              </div>
              <div className="mt-1 truncate text-sm font-medium text-slate-200" title={data.runtime.os}>{data.runtime.os}</div>
            </div>
            <div className="card card-pad">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Python</div>
              <div className="mt-1 text-sm font-medium text-slate-200">{data.runtime.python}</div>
            </div>
            <div className="card card-pad">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Node.js</div>
              <div className="mt-1 text-sm font-medium text-slate-200">{data.runtime.node}</div>
            </div>
            <div className="card card-pad">
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                <Boxes className="h-3.5 w-3.5" /> Sandbox
              </div>
              <div className="mt-1 flex items-center gap-2 text-sm font-medium text-slate-200">
                {data.sandbox_mode === "docker" ? (
                  <span className="flex items-center gap-1.5 text-green-400"><CheckCircle2 className="h-4 w-4" /> Docker</span>
                ) : (
                  <span className="flex items-center gap-1.5 text-amber-400"><ShieldCheck className="h-4 w-4" /> Local (process-isolated)</span>
                )}
              </div>
              <div className="mt-1 text-[10px] text-slate-600">{data.docker.detail}</div>
            </div>
          </div>

          {/* Tool cards */}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {data.tools.map((t) => {
              const meta = TOOL_META[t.name] || { purpose: "Security analysis", icon: Search };
              const Icon = meta.icon;
              return (
                <div key={t.name} className="card card-pad">
                  <div className="flex items-start gap-3">
                    <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${t.available ? "bg-green-500/15" : "bg-base-700/60"}`}>
                      <Icon className={`h-4.5 w-4.5 ${t.available ? "text-green-400" : "text-slate-500"}`} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-slate-200">{t.name}</span>
                        <StatusBadge ok={t.available} />
                      </div>
                      <div className="mt-0.5 text-[11px] text-slate-500">{meta.purpose}</div>
                      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px]">
                        <span className="text-slate-400">
                          Version: <span className="font-mono text-slate-300">{t.version || "—"}</span>
                        </span>
                      </div>
                      {!t.available && t.install_hint && (
                        <div className="mt-2 rounded-md border border-base-700 bg-base-900/60 px-2.5 py-1.5 text-[11px] text-slate-500">
                          Setup: <span className="font-mono text-slate-400">{t.install_hint}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Scan limits */}
          <div className="card card-pad mt-6">
            <h3 className="mb-3 text-sm font-semibold text-slate-300">Scan limits & configuration</h3>
            <div className="grid grid-cols-2 gap-3 text-xs md:grid-cols-5">
              <div>
                <div className="text-slate-500">Max upload</div>
                <div className="mt-0.5 font-mono text-slate-300">{data.scan_limits.max_upload_size_mb} MB</div>
              </div>
              <div>
                <div className="text-slate-500">Scan timeout</div>
                <div className="mt-0.5 font-mono text-slate-300">{data.scan_limits.scan_timeout_seconds}s</div>
              </div>
              <div>
                <div className="text-slate-500">Repair iterations</div>
                <div className="mt-0.5 font-mono text-slate-300">{data.scan_limits.max_repair_iterations}</div>
              </div>
              <div>
                <div className="text-slate-500">AI calls / scan</div>
                <div className="mt-0.5 font-mono text-slate-300">{data.scan_limits.max_ai_calls_per_scan}</div>
              </div>
              <div>
                <div className="text-slate-500">Default intensity</div>
                <div className="mt-0.5 font-mono text-slate-300">{data.scan_limits.default_intensity}</div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
