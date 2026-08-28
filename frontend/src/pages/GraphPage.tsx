import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { GitBranch } from "lucide-react";
import { api } from "../api/client";
import AttackGraph from "../components/AttackGraph";

export default function GraphPage() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const { data } = useQuery({ queryKey: ["graph", id], queryFn: () => api.scanGraph(id) });

  const graph = data?.graph || [];

  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-5 flex items-center gap-2">
        <GitBranch className="h-5 w-5 text-accent-400" />
        <h1 className="text-xl font-bold text-white">Attack Graph — Scan #{id}</h1>
      </div>
      {graph.length === 0 ? (
        <div className="py-16 text-center text-sm text-slate-600">
          No attack graph yet — the graph is generated when the scan completes.
        </div>
      ) : (
        <AttackGraph graph={graph} />
      )}
    </div>
  );
}
