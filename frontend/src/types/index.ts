export interface Project {
  id: number;
  name: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  status: string;
  project_type: string;
  detection: Record<string, unknown>;
  created_at?: string;
}

export interface ScanOptions {
  security_testing: boolean;
  bug_hunting: boolean;
  static_analysis: boolean;
  dependency_analysis: boolean;
  secrets_detection: boolean;
  dynamic_testing: boolean;
  browser_testing: boolean;
  fuzzing: boolean;
  automatic_repair: boolean;
  verification: boolean;
  intensity: "standard" | "aggressive" | "maximum_safe";
}

export interface ScanStep {
  id: number;
  name: string;
  status: string;
  order: number;
  detail: string;
  result: Record<string, unknown>;
  started_at?: string;
  finished_at?: string;
}

export interface Finding {
  id: number;
  scan_id: number;
  title: string;
  category: string;
  severity: string;
  confidence: number;
  status: string;
  source: string;
  affected_component: string;
  affected_file: string;
  line_start?: number | null;
  line_end?: number | null;
  description: string;
  why_it_matters: string;
  evidence: Record<string, unknown>;
  reproduction: Record<string, unknown>;
  root_cause: string;
  ai_explanation: string;
  recommended_fix: string;
  patch_status: string;
  provenance: string;
  created_at?: string;
}

export interface Scan {
  id: number;
  project_id: number;
  status: string;
  state: string;
  intensity: string;
  options: Record<string, unknown>;
  progress: number;
  scores: Record<string, number>;
  summary: Record<string, unknown>;
  error?: string | null;
  started_at?: string;
  finished_at?: string;
  created_at?: string;
}

export interface ScanDetail extends Scan {
  steps: ScanStep[];
  findings: Finding[];
}

export interface ScanEvent {
  type: string;
  ts: number;
  message?: string;
  level?: string;
  msg?: string;
  agent?: string;
  status?: string;
  state?: string;
  progress?: number;
  finding?: Finding;
  tool?: string;
}

export interface ToolStatus {
  name: string;
  available: boolean;
  version?: string | null;
  install_hint: string;
}

export interface HealthTools {
  status: string;
  sandbox_mode: string;
  docker: { available: boolean; detail: string };
  runtime: { python: string; node: string; os: string };
  tools: ToolStatus[];
  scan_limits: Record<string, number | string>;
}

export interface DemoInfo {
  name: string;
  title: string;
  description: string;
}

export interface FindingDetail {
  finding: Finding;
  evidence: Record<string, unknown>[];
  patches: Array<{
    id: number;
    scan_id: number;
    finding_id: number | null;
    status: string;
    diff: string;
    files: Record<string, { before: string; after: string }>;
    explanation: string;
    created_at?: string | null;
  }>;
  verifications: Array<{
    id: number;
    status: string;
    build_pass: boolean;
    regression_pass: boolean;
    exploit_blocked: boolean;
    details: Record<string, unknown>;
    created_at?: string | null;
  }>;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: string;
  severity?: string;
  status?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
  kind: string;
}

export interface AiStatus {
  configured: boolean;
  model: string;
  key_hint: string;
  cost: Record<string, unknown>;
}
