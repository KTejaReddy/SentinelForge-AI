import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, KeyRound, Loader2, XCircle } from "lucide-react";
import { api } from "../api/client";

export default function SettingsPage() {
  const { data: status } = useQuery({ queryKey: ["groq"], queryFn: api.groqStatus });
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("");
  const [saved, setSaved] = useState(false);

  const save = useMutation({
    mutationFn: () => api.saveGroq({ api_key: apiKey || undefined, model: model || undefined }),
    onSuccess: () => {
      setSaved(true);
      setApiKey("");
      setTimeout(() => setSaved(false), 3000);
    },
  });

  const test = useMutation({
    mutationFn: () => api.testGroq({ api_key: apiKey || undefined, model: model || undefined }),
  });

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <h1 className="mb-1 text-xl font-bold text-white">AI Configuration</h1>
      <p className="mb-6 text-sm text-slate-500">
        The AI layer (Groq) powers root-cause analysis, patch generation, and verification. The key is stored encrypted at rest
        and is never sent to the browser UI as plaintext — the frontend only ever talks to this backend.
      </p>

      <div className="card card-pad space-y-5">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-500/15">
            <KeyRound className="h-5 w-5 text-accent-400" />
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-200">AI Provider</div>
            <div className="text-xs text-slate-500">Groq (OpenAI-compatible chat completions)</div>
          </div>
          <div className="ml-auto">
            {status?.configured ? (
              <span className="flex items-center gap-1.5 text-xs text-green-400"><CheckCircle2 className="h-4 w-4" /> configured</span>
            ) : (
              <span className="flex items-center gap-1.5 text-xs text-amber-400"><XCircle className="h-4 w-4" /> not configured</span>
            )}
          </div>
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-slate-400">GROQ API Key</label>
          <input
            type="password"
            className="input w-full font-mono"
            placeholder={status?.key_hint ? `saved: ${status.key_hint}` : "gsk_…"}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          />
          <p className="mt-1 text-[11px] text-slate-600">Also supported via the GROQ_API_KEY environment variable or a root-level .env file.</p>
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-slate-400">Model</label>
          <input
            type="text"
            className="input w-full font-mono"
            placeholder={status?.model || "llama-3.3-70b-versatile"}
            value={model}
            onChange={(e) => setModel(e.target.value)}
          />
          <p className="mt-1 text-[11px] text-slate-600">Any Groq-hosted model. Defaults to {status?.model || "llama-3.3-70b-versatile"}.</p>
        </div>

        <div className="flex flex-wrap gap-3">
          <button onClick={() => test.mutate()} disabled={test.isPending} className="btn-primary">
            {test.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />} Test Connection
          </button>
          <button onClick={() => save.mutate()} disabled={save.isPending} className="btn-ghost">
            {saved ? "Saved ✓" : "Save Configuration"}
          </button>
        </div>

        {test.data && (
          <div className={`rounded-lg border px-4 py-3 text-sm ${test.data.ok ? "border-green-500/40 bg-green-500/10 text-green-400" : "border-red-500/40 bg-red-500/10 text-red-400"}`}>
            {test.data.message}
          </div>
        )}
        {test.isError && <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">{String(test.error)}</div>}
      </div>

      <div className="card card-pad mt-5 text-xs leading-relaxed text-slate-500">
        <h3 className="mb-2 text-sm font-semibold text-slate-300">Degraded mode</h3>
        Without a Groq key the platform still performs project detection, build testing, static analysis, dependency scanning,
        secrets detection, browser testing, native tests, and deterministic security checks. AI steps show{" "}
        <span className="text-amber-400">Skipped — Groq unavailable</span> and the system never crashes.
      </div>
    </div>
  );
}
