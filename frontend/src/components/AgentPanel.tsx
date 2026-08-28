import { Check, Loader2, MinusCircle } from "lucide-react";

const AGENTS = [
  "recon_agent",
  "build_agent",
  "security_agent",
  "api_agent",
  "browser_agent",
  "bug_hunter_agent",
  "dependency_agent",
  "secret_agent",
  "fuzz_agent",
  "business_logic_agent",
  "root_cause_agent",
  "repair_agent",
  "verification_agent",
];

const LABELS: Record<string, string> = {
  recon_agent: "Recon Agent",
  build_agent: "Build Agent",
  security_agent: "Red-Team Agent",
  api_agent: "API Agent",
  browser_agent: "Browser Agent",
  bug_hunter_agent: "Bug Hunter",
  dependency_agent: "Dependency Agent",
  secret_agent: "Secrets Agent",
  fuzz_agent: "Fuzz Agent",
  business_logic_agent: "Business Logic Agent",
  root_cause_agent: "Root Cause Agent",
  repair_agent: "Repair Agent",
  verification_agent: "Verification Agent",
};

function AgentRow({ name, status }: { name: string; status?: string }) {
  const s = status || "PENDING";
  return (
    <div className="flex items-center justify-between rounded-lg border border-base-700/70 bg-base-900/50 px-3 py-2">
      <span className="text-xs text-slate-300">{LABELS[name] || name}</span>
      {s === "DONE" && <Check className="h-4 w-4 text-green-400" />}
      {s === "RUNNING" && <Loader2 className="pulse-dot h-4 w-4 animate-spin text-sky-400" />}
      {(s === "FAILED" || s === "SKIPPED") && <MinusCircle className="h-4 w-4 text-amber-400" />}
      {s === "PENDING" && <span className="h-2 w-2 rounded-full bg-base-600" />}
    </div>
  );
}

export default function AgentPanel({ agents }: { agents: Record<string, string> }) {
  return (
    <div className="card card-pad">
      <h3 className="mb-3 text-sm font-semibold text-slate-300">Active Agents</h3>
      <div className="grid grid-cols-1 gap-1.5">
        {AGENTS.map((a) => (
          <AgentRow key={a} name={a} status={agents[a]} />
        ))}
      </div>
    </div>
  );
}
