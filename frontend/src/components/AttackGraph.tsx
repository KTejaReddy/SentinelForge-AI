import { useMemo } from "react";

interface Node {
  id: string;
  label: string;
  kind: string;
  severity?: string;
  status?: string;
}
interface Edge {
  source: string;
  target: string;
  label: string;
  kind: string;
}

const KIND_COLORS: Record<string, { fill: string; stroke: string; text: string }> = {
  root: { fill: "#0e7490", stroke: "#22d3ee", text: "#cffafe" },
  component: { fill: "#1e3a8a", stroke: "#3b82f6", text: "#dbeafe" },
  test: { fill: "#3f3f46", stroke: "#71717a", text: "#e4e4e7" },
  finding: { fill: "#450a0a", stroke: "#ef4444", text: "#fecaca" },
  patch: { fill: "#14532d", stroke: "#22c55e", text: "#dcfce7" },
};

const SEV_STROKE: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#38bdf8",
};

export default function AttackGraph({ graph }: { graph: Array<Record<string, unknown>> }) {
  const { nodes, edges } = useMemo(() => {
    const nodes = graph.filter((g) => g.id && !(g.source && g.target)) as unknown as Node[];
    const edges = graph.filter((g) => g.source && g.target) as unknown as Edge[];
    return { nodes, edges };
  }, [graph]);

  const layout = useMemo(() => {
    const LAYERS = ["root", "component", "test", "finding", "patch"] as const;
    const byLayer: Record<string, Node[]> = { root: [], component: [], test: [], finding: [], patch: [] };
    for (const n of nodes) byLayer[n.kind]?.push(n);
    const positions: Record<string, { x: number; y: number }> = {};
    const W = 980;
    const H = 560;
    const widths = { root: 1, component: 1, test: 1, finding: 1, patch: 1 };
    let index = 0;
    for (const layer of LAYERS) {
      const count = byLayer[layer]?.length || 1;
      widths[layer] = Math.max(1, count);
      index += count;
    }
    const totalNodes = Math.max(1, index);
    const top = 40;
    const bottom = H - 40;
    const yFor: Record<string, number> = { root: top, component: top + (bottom - top) * 0.22, test: top + (bottom - top) * 0.45, finding: top + (bottom - top) * 0.68, patch: bottom };
    for (const layer of LAYERS) {
      const list = byLayer[layer] || [];
      const count = Math.max(1, list.length);
      const gap = Math.min(170, (W - 80) / count);
      const startX = (W - gap * (count - 1)) / 2;
      list.forEach((n, i) => {
        positions[n.id] = { x: count === 1 ? W / 2 : startX + i * gap, y: yFor[layer] };
      });
    }
    // fallback for misplaced nodes
    for (const n of nodes) {
      if (!positions[n.id]) positions[n.id] = { x: W / 2, y: H / 2 };
    }
    return { positions, W, H };
  }, [nodes]);

  return (
    <div className="overflow-auto rounded-xl border border-base-700 bg-base-900/60">
      <svg viewBox={`0 0 ${layout.W} ${layout.H}`} className="min-h-[420px] w-full">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
          </marker>
        </defs>
        {edges.map((e, i) => {
          const a = layout.positions[e.source];
          const b = layout.positions[e.target];
          if (!a || !b) return null;
          const mx = (a.x + b.x) / 2;
          const my = (a.y + b.y) / 2;
          const d = `M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`;
          return (
            <g key={i}>
              <path d={d} fill="none" stroke="#334155" strokeWidth="1.2" markerEnd="url(#arrow)" />
              <text x={mx} y={my - 6} textAnchor="middle" fontSize="9" fill="#64748b" className="select-none">
                {e.label}
              </text>
            </g>
          );
        })}
        {nodes.map((n) => {
          const pos = layout.positions[n.id];
          if (!pos) return null;
          const c = KIND_COLORS[n.kind] || KIND_COLORS.test;
          const stroke = n.kind === "finding" && n.severity ? SEV_STROKE[n.severity] || c.stroke : c.stroke;
          return (
            <g key={n.id} transform={`translate(${pos.x}, ${pos.y})`}>
              <title>{`${n.label}${n.severity ? ` [${n.severity}]` : ""}${n.status ? ` — ${n.status}` : ""}`}</title>
              <rect x={-62} y={-16} width={124} height={32} rx={9} fill={c.fill} stroke={stroke} strokeWidth="1.4" />
              <text textAnchor="middle" dominantBaseline="middle" fontSize="10" fill={c.text} className="select-none pointer-events-none">
                {n.label.length > 18 ? n.label.slice(0, 17) + "…" : n.label}
              </text>
              {n.kind === "finding" && n.severity && (
                <circle cx={52} cy={-11} r={4} fill={SEV_STROKE[n.severity] || "#ef4444"} />
              )}
            </g>
          );
        })}
      </svg>
      <div className="flex flex-wrap gap-4 border-t border-base-700 px-4 py-2 text-[11px] text-slate-400">
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-cyan-500" /> Application</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-blue-500" /> Component / Route</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-zinc-500" /> Test</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-red-500" /> Finding</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-green-600" /> Patch / Fix</span>
      </div>
    </div>
  );
}
