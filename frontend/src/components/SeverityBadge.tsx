import { SEVERITY_COLORS } from "../utils/format";

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_COLORS[severity] || SEVERITY_COLORS.INFO;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-bold tracking-wide ${cls}`}>
      {severity || "INFO"}
    </span>
  );
}
