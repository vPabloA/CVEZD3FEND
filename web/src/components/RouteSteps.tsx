import { Link } from "react-router-dom";
import { getNode } from "@/lib/bundle";
import { coverageBgClass, edgeIsAiPromoted, nodeColorClass } from "@/lib/colors";
import type { KnowledgeBundle, Route } from "@/lib/types";
import { AiPromotedBadge, ConfidenceBadge, ProvenanceBadge, TypeBadge } from "./NodeBadge";

/** Step-by-step list with confidence + source per edge, recommended actions, gaps, coverage badge. */
export default function RouteSteps({ bundle, route }: { bundle: KnowledgeBundle; route: Route }) {
  const steps = route.edges.map((edgeId, i) => {
    const edge = bundle.edges.find((e) => e.id === edgeId);
    const from = getNode(bundle, route.nodes[i]);
    const to = getNode(bundle, route.nodes[i + 1]);
    return { edge, from, to };
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`inline-flex items-center rounded border px-2 py-1 text-sm font-medium ${coverageBgClass(
            route.coverage_status
          )}`}
        >
          Coverage: {route.coverage_status}
        </span>
        <ProvenanceBadge canonical={route.canonical} inferred={route.inferred} />
        <ConfidenceBadge confidence={route.confidence} />
      </div>

      <ol className="flex flex-col gap-2">
        {steps.map(({ edge, from, to }, i) => (
          <li key={edge?.id ?? i} className="rounded-md border border-slate-200 bg-white p-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              {from && (
                <Link to={`/node/${encodeURIComponent(from.id)}`} className={`font-mono font-semibold hover:underline ${nodeColorClass(from)}`}>
                  {from.id}
                </Link>
              )}
              {from && <TypeBadge type={from.type} />}
              <span aria-hidden="true" className="text-slate-400">
                →
              </span>
              {to && (
                <Link to={`/node/${encodeURIComponent(to.id)}`} className={`font-mono font-semibold hover:underline ${nodeColorClass(to)}`}>
                  {to.id}
                </Link>
              )}
              {to && <TypeBadge type={to.type} />}
            </div>
            {edge && (
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                <span className="font-mono">{edge.type}</span>
                <ConfidenceBadge confidence={edge.confidence} />
                {edgeIsAiPromoted(edge) && <AiPromotedBadge />}
                {edge.source_url ? (
                  <a href={edge.source_url} target="_blank" rel="noreferrer" className="text-link hover:underline">
                    {edge.source_ref ?? "source"}
                  </a>
                ) : edge.source_ref ? (
                  <span>{edge.source_ref}</span>
                ) : (
                  <span className="italic text-slate-400">no source ref</span>
                )}
              </div>
            )}
          </li>
        ))}
      </ol>

      <RouteRefList bundle={bundle} title="Recommended actions" ids={route.recommended_actions} />
      <RouteRefList bundle={bundle} title="Evidence required" ids={route.evidence_required} />
    </div>
  );
}

function RouteRefList({ bundle, title, ids }: { bundle: KnowledgeBundle; title: string; ids: string[] }) {
  if (ids.length === 0) return null;
  return (
    <div>
      <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      <div className="flex flex-wrap gap-1.5">
        {ids.map((id) => {
          const node = getNode(bundle, id);
          return (
            <Link
              key={id}
              to={`/node/${encodeURIComponent(id)}`}
              className={`rounded border border-slate-300 bg-white px-2 py-1 font-mono text-xs hover:bg-slate-50 ${
                node ? nodeColorClass(node) : "text-slate-500"
              }`}
            >
              {id}
              {node ? ` · ${node.name}` : ""}
            </Link>
          );
        })}
      </div>
    </div>
  );
}
