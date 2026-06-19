import { Link } from "react-router-dom";
import {
  REASONING_CLASSIFICATION_LABELS,
  classificationClass,
  classificationNeedsReview,
} from "@/lib/colors";
import { nodeKindForId } from "@/components/reasoning/graph/graphAdapter";
import type { GraphNodeKind } from "@/components/reasoning/graph/graphTypes";
import type { ReasoningEdgeClassification, ReasoningResult } from "@/lib/reasoningTypes";

const ROUTE_STAGES: { kind: GraphNodeKind; label: string }[] = [
  { kind: "cve", label: "CVE" },
  { kind: "cwe", label: "CWE" },
  { kind: "capec", label: "CAPEC" },
  { kind: "attack", label: "ATT&CK" },
  { kind: "defend", label: "D3FEND" },
];

const SECONDARY_BUCKETS = [
  { key: "primary_nodes", label: "Primary nodes" },
  { key: "conditional_nodes", label: "Conditional branches" },
  { key: "defensive_nodes", label: "Defensive path" },
  { key: "weak_fit_nodes", label: "Weak-fit relations" },
] as const;

function stageLabel(id: string): string {
  const stage = ROUTE_STAGES.find((item) => item.kind === nodeKindForId(id));
  return stage?.label ?? "Context";
}

function countBy<T extends string>(items: T[]): [T, number][] {
  const counts = new Map<T, number>();
  items.forEach((item) => counts.set(item, (counts.get(item) ?? 0) + 1));
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

/**
 * Left rail of the workbench: a route-spine navigator answering "where am I
 * in the CVE→CWE→CAPEC→ATT&CK→D3FEND route", not a settings panel. Counts
 * and classification context are demoted to a collapsed section.
 */
export default function EntityNavigationPanel({
  result,
  selectedNode,
  onSelectNode,
}: {
  result: ReasoningResult;
  selectedNode: string | null;
  onSelectNode: (nodeId: string) => void;
}) {
  const chain = result.route.canonical_chain;
  const routeIds = new Set([
    ...chain,
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

  const reviewNodeIds = new Set<string>();
  result.edges.forEach((edge) => {
    if (classificationNeedsReview(edge.classification)) {
      reviewNodeIds.add(edge.source);
      reviewNodeIds.add(edge.target);
    }
  });

  const presentStageKinds = new Set([...routeIds].map((id) => nodeKindForId(id)));
  const stagesPresent = ROUTE_STAGES.filter((stage) => presentStageKinds.has(stage.kind));
  const routeComplete = stagesPresent.length === ROUTE_STAGES.length;
  const hasDefensivePath = result.route.defensive_nodes.length > 0 || presentStageKinds.has("defend");
  const nodeTypes = countBy([...routeIds].map(stageLabel));
  const classifications = countBy(result.edges.map((edge) => edge.classification));
  const reviewCount = result.edges.filter((edge) => classificationNeedsReview(edge.classification)).length;

  return (
    <aside className="flex flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-950 p-3 text-slate-300 shadow-xl xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-auto">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">Route spine</p>
        <h2 className="mt-0.5 text-sm font-semibold text-slate-100">Route navigator</h2>
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
          <span
            className={`rounded-full border px-2 py-0.5 font-medium ${
              routeComplete ? "border-ok/60 bg-green-950/40 text-green-300" : "border-amber-500/50 bg-amber-950/40 text-amber-200"
            }`}
          >
            {routeComplete ? "Route complete" : "Partial route"} · {stagesPresent.length}/{ROUTE_STAGES.length}
          </span>
          {hasDefensivePath && (
            <span className="rounded-full border border-defense/60 bg-green-950/40 px-2 py-0.5 font-medium text-green-300">Defense mapped</span>
          )}
          {reviewCount > 0 && (
            <span className="rounded-full border border-amber-500/50 bg-amber-950/40 px-2 py-0.5 font-medium text-amber-200">{reviewCount} review</span>
          )}
        </div>
      </div>

      {chain.length > 0 ? (
        <ol className="relative flex flex-col" aria-label="Canonical route">
          {chain.map((id, index) => {
            const selected = selectedNode === id;
            const needsReview = reviewNodeIds.has(id);
            const defensive = nodeKindForId(id) === "defend";
            return (
              <li key={id} className="relative pl-5">
                {index < chain.length - 1 && <span className="absolute left-[7px] top-5 h-full w-px bg-slate-700" aria-hidden="true" />}
                <span
                  className={`absolute left-1 top-2 h-3 w-3 rounded-full border-2 ${
                    selected ? "border-sky-300 bg-link" : defensive ? "border-defense bg-green-900" : "border-slate-500 bg-slate-900"
                  }`}
                  aria-hidden="true"
                />
                <button
                  type="button"
                  onClick={() => onSelectNode(id)}
                  className={`group flex w-full flex-col items-start rounded-lg px-2 py-1 text-left transition focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                    selected ? "bg-slate-800/90" : "hover:bg-slate-900"
                  }`}
                >
                  <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">{stageLabel(id)}</span>
                  <span className={`flex items-center gap-1.5 font-mono text-xs ${selected ? "text-sky-300" : "text-slate-200 group-hover:text-sky-300"}`}>
                    {id}
                    {needsReview && (
                      <span className="rounded border border-amber-500/50 bg-amber-950/50 px-1 text-[9px] font-semibold uppercase text-amber-300" title="Edges touching this node need human review">
                        review
                      </span>
                    )}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      ) : (
        <p className="rounded-lg border border-slate-800 bg-slate-900/60 px-2 py-2 text-xs text-slate-400">
          No canonical chain was produced. Route context below still reflects the available reasoning edges.
        </p>
      )}

      {SECONDARY_BUCKETS.map(({ key, label }) => {
        const ids = result.route[key].filter((id) => !chain.includes(id));
        if (ids.length === 0) return null;
        return (
          <details key={key} className="group rounded-xl border border-slate-800 bg-slate-900/50" open={key === "defensive_nodes"}>
            <summary className="flex cursor-pointer select-none items-center justify-between gap-2 px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200">
              {label}
              <span className="font-mono text-slate-500">{ids.length}</span>
            </summary>
            <div className="flex flex-wrap gap-1.5 px-2 pb-2">
              {ids.map((id) => {
                const selected = selectedNode === id;
                return (
                  <button
                    key={`${key}-${id}`}
                    type="button"
                    onClick={() => onSelectNode(id)}
                    className={`rounded-full border px-2 py-1 font-mono text-[11px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                      selected
                        ? "border-sky-400 bg-slate-800 text-sky-300"
                        : "border-slate-700 bg-slate-950 text-slate-300 hover:border-sky-400 hover:text-sky-300"
                    }`}
                  >
                    {id}
                  </button>
                );
              })}
            </div>
          </details>
        );
      })}

      <details className="group rounded-xl border border-slate-800 bg-slate-900/50">
        <summary className="cursor-pointer select-none px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200">
          Entity & evidence context
        </summary>
        <div className="flex flex-col gap-2 px-2 pb-2">
          <div className="flex flex-wrap gap-1.5">
            {nodeTypes.map(([type, count]) => (
              <span key={type} className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-[11px] text-slate-400">
                {type} <span className="font-mono text-slate-500">{count}</span>
              </span>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {classifications.map(([classification, count]) => (
              <span key={classification} className={`rounded border px-1.5 py-0.5 text-[11px] ${classificationClass(classification as ReasoningEdgeClassification)}`}>
                {REASONING_CLASSIFICATION_LABELS[classification as ReasoningEdgeClassification]} {count}
              </span>
            ))}
          </div>
        </div>
      </details>

      {selectedNode && (
        <section className="rounded-xl border border-sky-500/40 bg-sky-950/30 p-2">
          <h3 className="text-[11px] font-semibold uppercase tracking-wide text-sky-300">Focused node</h3>
          <p className="mt-1 font-mono text-sm font-semibold text-slate-100">{selectedNode}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Link
              to={`/node/${encodeURIComponent(selectedNode)}`}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs font-medium text-slate-200 hover:border-sky-400 hover:text-sky-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
            >
              Open detail
            </Link>
            <button
              type="button"
              onClick={() => onSelectNode("")}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs font-medium text-slate-400 hover:border-slate-500 hover:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
            >
              Clear focus
            </button>
          </div>
        </section>
      )}
    </aside>
  );
}
