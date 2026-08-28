import { DiffEditor } from "@monaco-editor/react";

interface Props {
  original: string;
  modified: string;
  language?: string;
  height?: number | string;
}

function langFor(file: string): string {
  const ext = (file.split(".").pop() || "").toLowerCase();
  if (["py"].includes(ext)) return "python";
  if (["js", "jsx", "mjs", "cjs"].includes(ext)) return "javascript";
  if (["ts", "tsx"].includes(ext)) return "typescript";
  if (["go"].includes(ext)) return "go";
  if (["java"].includes(ext)) return "java";
  if (["rb"].includes(ext)) return "ruby";
  if (["php"].includes(ext)) return "php";
  if (["html", "vue"].includes(ext)) return "html";
  if (["css"].includes(ext)) return "css";
  if (["json"].includes(ext)) return "json";
  if (["yml", "yaml"].includes(ext)) return "yaml";
  if (["sql"].includes(ext)) return "sql";
  if (["sh"].includes(ext)) return "shell";
  return "plaintext";
}

export default function DiffView({ original, modified, language, height = 320 }: Props) {
  const lang = language || langFor(original && modified ? "x.js" : "x.txt");
  return (
    <div className="overflow-hidden rounded-lg border border-base-700">
      <DiffEditor
        height={height}
        theme="vs-dark"
        language={lang}
        options={{
          readOnly: true,
          fontSize: 12,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          renderSideBySide: true,
          wordWrap: "on",
        }}
        original={original}
        modified={modified}
      />
    </div>
  );
}
