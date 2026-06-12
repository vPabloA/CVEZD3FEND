import { Link } from "react-router-dom";
import {
  REASONING_CLASSIFICATION_LABELS,
  classificationClass,
  classificationNeedsReview,
} from "@/lib/colors";
import type { ReasoningEdgeClassification, ReasoningResult } from "@/lib/reasoningTypes";

const ROUTE_BUCKETS = [
  { key: "canonical_chain", label: "Ruta", hint: "selected path" },
  { key: "primary_nodes", label: "Primary", hint: "direct route" },
  { key: "conditional_nodes", label: "Condicional", hint: "preconditioned" },
  { key: "defensive_nodes", label: "D3FEND", hint: "defense" },
  { key: "weak_fit_nodes", label: "Weak-fit", hint: "low confidence" },
] as const;

function nodeType(id: string): string {
  if (/^CVE-/i.test(id)) return "CVE";
  if (/^CWE-/i.test(id)) return "CWE";
  if (/^CAPEC-/i.test(id)) return "CAPEC";
  if (/^T\d/i.test(id)) return "ATT&CK";
  if (/^D3-/i.test(id)) return "D3FEND";
  if (/^MIT-/i.test(id)) return "Mitigation";
  if (/^DET-/i.test(id)) return "Detection";
  return "Context";
}

function countBy<T extends string>(items: T[]): [T, number][] {
  const counts = new Map<T, number>();
  items.forEach((item) => counts.set(item, (counts.get(item) ?? 0) + 1));
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

export default function EntityNavigationPanel({
  result,
  selectedNode,
  onSelectNode,
}: {
  result: ReasoningResult;
  selectedNode: string | null;
  onSelectNode: (nodeId: string) => void;
}) {
  const routeIds = new Set([
    ...result.route.canonical_chain,
    ...result.route.primary_nodes,
    ...result.route.secondary_nodes,
    ...result.route.conditional_nodes,
    ...result.route.defensive_nodes,
    ...result.route.weak_fit_nodes,
  ]);
  result.edges.forEach((edge) => {
    routeIds.add(edge.source);
    routeIds.add(edge.target);
  });
  const nodeTypes = countBy([...routeIds].map(nodeType));
  const classifications = countBy(result.edges.map((edge) => edge.classification));
  const reviewCount = result.edges.filter((edge) => classificationNeedsReview(edge.classification)).length;

  return (
    <aside className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white p-3 shadow-sm xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-auto">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Entities</p>
        <h2 className="mt-1 text-sm font-semibold text-slate-800">Route navigator</h2>
      </div>

      {ROUTE_BUCKETS.map(({ key, label, hint }) => {
        const ids = result.route[key];
        if (ids.length === 0) return null;
        return (
          <section key={key} className="rounded-xl border border-slate-100 bg-slate-50/70 p-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</h3>
              <span className="text-[11px] text-slate-400">{hint}</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {ids.map((id) => {
                const selected = selectedNode === id;
                return (
                  <button
                    key={`${key}-${id}`}
                    type="button"
                    onClick={() => onSelectNode(id)}
                    className={`rounded-full border px-2 py-1 font-mono text-[11px] transition ${
                      selected
                        ? "border-link bg-blue-50 text-link shadow-sm"
                        : "border-slate-200 bg-white text-slate-600 hover:border-link hover:text-link"
                    }`}
                  >
                    {id}
                  </button>
                );
              })}
            </div>
          </section>
        );
      })}

      <section className="rounded-xl border border-slate-100 p-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Node types</h3>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {nodeTypes.map(([type, count]) => (
            <span key={type} className="rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-slate-600">
              {type} <span className="font-mono text-slate-400">{count}</span>
            </span>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-100 p-2">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence filters</h3>
          {reviewCount > 0 && <span className="rounded-full border border-inferred bg-amber-50 px-2 py-0.5 text-[11px] text-inferred">{reviewCount} review</span>}
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {classifications.map(([classification, count]) => (
            <span key={classification} className={`rounded border px-1.5 py-0.5 text-[11px] ${classificationClass(classification as ReasoningEdgeClassification)}`}>
              {REASONING_CLASSIFICATION_LABELS[classification as ReasoningEdgeClassification]} {count}
            </span>
          ))}
        </div>
      </section>

      {selectedNode && (
        <section className="rounded-xl border border-link bg-blue-50 p-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-link">Focused node</h3>
          <p className="mt-1 font-mono text-sm font-semibold text-slate-800">{selectedNode}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Link to={`/node/${encodeURIComponent(selectedNode)}`} className="rounded border border-link bg-white px-2 py-1 text-xs font-medium text-link hover:bg-blue-50">
              Open detail
            </Link>
            <button type="button" onClick={() => onSelectNode("")} className="rounded border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50">
              Clear focus
            </button>
          </div>
        </section>
      )}
    </aside>
  );
}
