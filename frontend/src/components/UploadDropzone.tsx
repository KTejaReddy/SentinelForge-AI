import { useCallback, useRef, useState } from "react";
import { FileUp, Loader2, UploadCloud } from "lucide-react";
import { api } from "../api/client";

interface Props {
  onUploaded: (projectId: number) => void;
}

export default function UploadDropzone({ onUploaded }: Props) {
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [hash, setHash] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const upload = useCallback(
    async (file: File) => {
      setError("");
      setBusy(true);
      setProgress(0);
      if (!file.name.toLowerCase().endsWith(".zip")) {
        setError("Only .zip files are accepted.");
        setBusy(false);
        return;
      }
      try {
        const buf = await file.arrayBuffer();
        const digest = await crypto.subtle.digest("SHA-256", buf);
        setHash(Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join(""));
        const project = await api.uploadProject(file, setProgress);
        setProgress(100);
        onUploaded(project.id);
      } catch (e) {
        setError(e instanceof Error ? e.message : "upload failed");
      } finally {
        setBusy(false);
      }
    },
    [onUploaded],
  );

  return (
    <div>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const f = e.dataTransfer.files?.[0];
          if (f) upload(f);
        }}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-2xl border-2 border-dashed p-10 text-center transition-colors ${
          dragging ? "border-accent-400 bg-accent-500/10" : "border-base-600 bg-base-900/40 hover:border-accent-500/50"
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".zip"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) upload(f);
          }}
        />
        {busy ? (
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="h-10 w-10 animate-spin text-accent-400" />
            <div className="text-sm text-slate-300">Uploading & validating…</div>
            {progress !== null && (
              <div className="h-2 w-64 overflow-hidden rounded-full bg-base-700">
                <div className="h-full bg-accent-500 transition-all" style={{ width: `${progress}%` }} />
              </div>
            )}
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent-500/15">
              <UploadCloud className="h-8 w-8 text-accent-400" />
            </div>
            <div className="text-lg font-semibold text-slate-200">Drag & drop your project ZIP</div>
            <div className="text-sm text-slate-400">
              or <span className="text-accent-400 underline">browse files</span> — SHA-256 verified, zip-slip & bomb guarded
            </div>
            <div className="flex items-center gap-4 text-[11px] text-slate-500">
              <span className="flex items-center gap-1"><FileUp className="h-3 w-3" /> Max {200} MB</span>
              <span>ZIP validation</span>
              <span>Sandboxed execution</span>
            </div>
          </div>
        )}
      </div>
      {hash && (
        <div className="mt-2 truncate font-mono text-[11px] text-slate-500">
          SHA-256: <span className="text-slate-400">{hash}</span>
        </div>
      )}
      {error && <div className="mt-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</div>}
    </div>
  );
}
