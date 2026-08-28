import { useState } from "react";
import { Scan, ShieldCheck, Sparkles } from "lucide-react";
import type { ScanOptions } from "../types";

export const DEFAULT_OPTIONS: ScanOptions = {
  security_testing: true,
  bug_hunting: true,
  static_analysis: true,
  dependency_analysis: true,
  secrets_detection: true,
  dynamic_testing: true,
  browser_testing: true,
  fuzzing: true,
  automatic_repair: true,
  verification: true,
  intensity: "standard",
};

const TOGGLES: Array<{ key: keyof ScanOptions; label: string; desc: string }> = [
  { key: "security_testing", label: "Security Testing", desc: "Dynamic web/API security tests" },
  { key: "bug_hunting", label: "Bug Hunting", desc: "Reliability & QA analysis" },
  { key: "static_analysis", label: "Static Analysis", desc: "SAST over source" },
  { key: "dependency_analysis", label: "Dependency Analysis", desc: "Known vulnerable packages" },
  { key: "secrets_detection", label: "Secrets Detection", desc: "Keys, tokens, credentials" },
  { key: "dynamic_testing", label: "Dynamic Testing", desc: "Probes against the sandboxed app" },
  { key: "browser_testing", label: "Browser Testing", desc: "Playwright / crawl exploration" },
  { key: "fuzzing", label: "Fuzzing", desc: "Malformed-input testing" },
  { key: "automatic_repair", label: "Automatic Repair", desc: "AI patches + rebuild + retest" },
  { key: "verification", label: "Verification", desc: "Reproduce, regression, verify fixes" },
];

interface Props {
  value: ScanOptions;
  onChange: (o: ScanOptions) => void;
  onStart: () => void;
  disabled?: boolean;
}

export default function ScanOptionsForm({ value, onChange, onStart, disabled }: Props) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card card-pad">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Scan className="h-4 w-4 text-accent-400" /> Scan Configuration
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            Testing is restricted to applications contained in the uploaded project and their sandboxed runtime.
          </p>
        </div>
        <button onClick={() => setExpanded(!expanded)} className="btn-ghost text-xs">
          {expanded ? "Hide options" : "Configure"}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {TOGGLES.map((t) => (
            <label key={t.key} className="flex cursor-pointer items-start gap-3 rounded-lg border border-base-700 bg-base-900/50 px-3 py-2.5 hover:border-base-600">
              <input
                type="checkbox"
                checked={value[t.key] as boolean}
                onChange={(e) => onChange({ ...value, [t.key]: e.target.checked })}
                className="mt-0.5 h-4 w-4 accent-sky-500"
              />
              <span>
                <span className="block text-sm text-slate-200">{t.label}</span>
                <span className="block text-[11px] text-slate-500">{t.desc}</span>
              </span>
            </label>
          ))}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-400">Intensity</span>
        {(["standard", "aggressive", "maximum_safe"] as const).map((i) => (
          <button
            key={i}
            onClick={() => onChange({ ...value, intensity: i })}
            className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
              value.intensity === i
                ? "border-accent-500 bg-accent-500/15 text-accent-300"
                : "border-base-600 text-slate-400 hover:border-base-500"
            }`}
          >
            {i === "standard" ? "Standard" : i === "aggressive" ? "Aggressive" : "Maximum Safe"}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <span className="flex items-center gap-1 text-[11px] text-slate-500">
            <ShieldCheck className="h-3.5 w-3.5 text-green-400" /> Sandbox-isolated
          </span>
          <button onClick={onStart} disabled={disabled} className="btn-primary">
            <Sparkles className="h-4 w-4" /> Start Analysis
          </button>
        </div>
      </div>
    </div>
  );
}
