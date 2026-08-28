import type {
  AiStatus,
  DemoInfo,
  Finding,
  FindingDetail,
  HealthTools,
  Project,
  Scan,
  ScanDetail,
  ScanOptions,
  ToolStatus,
} from "../types";

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) || "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  base: BASE,

  // projects
  uploadProject: (file: File, onProgress?: (pct: number) => void) =>
    new Promise<Project>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${BASE}/api/projects/upload`);
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(JSON.parse(xhr.responseText));
        } else {
          try {
            reject(new Error(JSON.parse(xhr.responseText).detail || "upload failed"));
          } catch {
            reject(new Error(`upload failed (${xhr.status})`));
          }
        }
      };
      xhr.onerror = () => reject(new Error("network error during upload"));
      const form = new FormData();
      form.append("file", file);
      xhr.send(form);
    }),

  listProjects: () => request<Project[]>("/projects"),
  getProject: (id: number) => request<Project>(`/projects/${id}`),

  // scans
  startScan: (projectId: number, options: ScanOptions) =>
    request<Scan>("/projects/" + projectId + "/scan", { method: "POST", body: JSON.stringify({ project_id: projectId, options }) }),
  listScans: () => request<Scan[]>("/scans"),
  getScan: (id: number) => request<ScanDetail>(`/scans/${id}`),
  stopScan: (id: number) => request<{ ok: boolean }>(`/scans/${id}/stop`, { method: "POST" }),
  scanFindings: (id: number) => request<Finding[]>(`/scans/${id}/findings`),
  scanReport: (id: number) => request<Record<string, unknown>>(`/scans/${id}/report`),
  scanGraph: (id: number) => request<{ graph: Array<Record<string, unknown>> }>(`/scans/${id}/attack-graph`),

  // findings
  getFinding: (id: number) => request<Finding>(`/findings/${id}`),
  getFindingDetail: (id: number) => request<FindingDetail>(`/findings/${id}/detail`),
  repairFinding: (id: number) => request<{ ok: boolean }>(`/findings/${id}/repair`, { method: "POST" }),
  verifyFinding: (id: number) => request<{ ok: boolean }>(`/findings/${id}/verify`, { method: "POST" }),

  // settings / misc
  groqStatus: () => request<AiStatus>("/settings/groq"),
  saveGroq: (body: { api_key?: string; model?: string; max_tokens?: number; temperature?: number }) =>
    request<AiStatus>("/settings/groq", { method: "POST", body: JSON.stringify(body) }),
  testGroq: (body: { api_key?: string; model?: string }) => request<{ ok: boolean; message: string; model: string; latency_ms: number }>("/settings/groq/test", { method: "POST", body: JSON.stringify(body) }),
  tools: () => request<ToolStatus[]>("/tools"),
  healthTools: () => request<HealthTools>("/health/tools"),
  listDemos: () => request<DemoInfo[]>("/demo/list"),
  loadDemo: (name?: string) => request<Scan>("/demo/load", { method: "POST", body: JSON.stringify({ name: name ?? "vulnerable-app" }) }),

  downloadUrl: (scanId: number, kind: "original" | "patched" | "reports") => `${BASE}/api/scans/${scanId}/download/${kind}`,
};
