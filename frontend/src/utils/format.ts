export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function fmtTime(ts?: string | number): string {
  if (ts === undefined || ts === null) return "—";
  const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
  return d.toLocaleTimeString([], { hour12: false });
}

export function timeAgo(ts?: string | number): string {
  if (!ts) return "—";
  const t = typeof ts === "number" ? ts * 1000 : new Date(ts).getTime();
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/40",
  MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  LOW: "bg-sky-500/15 text-sky-400 border-sky-500/40",
  INFO: "bg-slate-500/15 text-slate-400 border-slate-500/40",
};

export const CATEGORY_LABELS: Record<string, string> = {
  authentication: "Authentication",
  authorization: "Authorization",
  injection: "Injection",
  xss: "XSS",
  csrf: "CSRF",
  web_security: "Web Security",
  api_security: "API Security",
  file_security: "File Security",
  secrets: "Secrets",
  dependencies: "Dependencies",
  configuration: "Configuration",
  business_logic: "Business Logic",
  frontend_security: "Frontend Security",
  reliability: "Reliability",
  code_quality: "Code Quality",
};

export const STATE_LABELS: Record<string, string> = {
  UPLOADED: "Uploaded",
  VALIDATING: "Validating",
  EXTRACTING: "Extracting",
  ANALYZING: "Analyzing",
  BUILDING: "Building",
  RUNNING: "Running",
  DISCOVERING: "Discovering",
  STATIC_ANALYSIS: "Static analysis",
  DEPENDENCY_ANALYSIS: "Dependency analysis",
  SECRET_ANALYSIS: "Secrets analysis",
  DYNAMIC_TESTING: "Dynamic testing",
  BROWSER_TESTING: "Browser testing",
  FUZZING: "Fuzzing",
  BUG_HUNTING: "Bug hunting",
  CORRELATING: "Correlating",
  AI_ANALYSIS: "AI analysis",
  REPAIRING: "Repairing",
  REBUILDING: "Rebuilding",
  VERIFYING: "Verifying",
  REPORTING: "Reporting",
  COMPLETED: "Completed",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
};
