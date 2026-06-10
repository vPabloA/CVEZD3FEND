import { useState } from "react";
import { Link } from "react-router-dom";
import { getEdgesFor, getNode } from "@/lib/bundle";
import { edgeIsAiPromoted, nodeBorderClass, nodeBorderStyle, nodeColorClass } from "@/lib/colors";
import { windowNodes } from "@/lib/graphWindow";
import type { BundleEdge, KnowledgeBundle, Route } from "@/lib/types";
import { AiPromotedBadge, ProvenanceBadge, TypeBadge } from "./NodeBadge";

/**
 * Bounded graph renderer (UIX_CONTRACT §1/§2): the route's own chain is always
 * fully shown; sibling nodes (other routes for the same CVE) fill the
 * remaining 40-node budget and expand 20 at a time via "Show more".
 */
export default function RouteGraph({
  bundle,
  promotedEdges,
  route,
  siblingRoutes,
}: {
  bundle: KnowledgeBundle;
  promotedEdges: BundleEdge[];
  route: Route;
  siblingRoutes: Route[];
}) {
  const [expandSteps, setExpandSteps] = useState(0);

  const siblingNodeIds = Array.from(new Set(siblingRoutes.flatMap((r) => r.nodes)));
  const { visible, remainingCount } = windowNodes(route.nodes, siblingNodeIds, expandSteps);
  const extraIds = visible.slice(route.nodes.length);

  return (
    <div className="flex flex-col gap-4">
      {/* Core chain */}
      <div className="flex flex-wrap items-center gap-2" role="list" aria-label="Route chain">
        {route.nodes.map((nodeId, i) => {
          const node = getNode(bundle, nodeId);
          if (!node) return null;
          const edge = i > 0 ? bundle.edges.find((e) => e.id === route.edges[i - 1]) : undefined;
          return (
            <div key={nodeId} className="flex items-center gap-2" role="listitem">
              {i > 0 && (
                <div className="flex flex-col items-center text-slate-400" aria-hidden="true">
                  <span className="text-lg leading-none">→</span>
                  {edge && <span className="text-[10px] font-mono">{edge.confidence.toFixed(2)}</span>}
                </div>
              )}
              <Link
                to={`/node/${encodeURIComponent(node.id)}`}
                className={`flex min-w-[120px] flex-col gap-0.5 rounded-md border-2 bg-white px-2 py-1.5 text-center hover:shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${nodeBorderClass(
                  node
                )}`}
                style={{ borderStyle: nodeBorderStyle(node) }}
              >
                <span className={`font-mono text-xs font-semibold ${nodeColorClass(node)}`}>{node.id}</span>
                <span className="truncate text-[11px] text-slate-600">{node.name}</span>
                <TypeBadge type={node.type} />
              </Link>
            </div>
          );
        })}
      </div>

      {/* Sibling nodes from alternative routes for the same CVE */}
      {extraIds.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Alternative paths ({extraIds.length} of {extraIds.length + remainingCount} shown)
          </h3>
          <div className="flex flex-wrap gap-2" role="list" aria-label="Alternative path nodes">
            {extraIds.map((nodeId) => {
              const node = getNode(bundle, nodeId);
              if (!node) return null;
              const { incoming, outgoing } = getEdgesFor(bundle, nodeId, promotedEdges);
              const aiPromoted = [...incoming, ...outgoing].some(edgeIsAiPromoted);
              return (
                <Link
                  key={nodeId}
                  to={`/node/${encodeURIComponent(node.id)}`}
                  role="listitem"
                  className={`flex flex-col gap-0.5 rounded-md border-2 bg-white px-2 py-1.5 text-center hover:shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${nodeBorderClass(
                    node
                  )}`}
                  style={{ borderStyle: nodeBorderStyle(node) }}
                >
                  <span className={`font-mono text-xs font-semibold ${nodeColorClass(node)}`}>{node.id}</span>
                  <span className="max-w-[140px] truncate text-[11px] text-slate-600">{node.name}</span>
                  <div className="flex flex-wrap items-center justify-center gap-1">
                    <ProvenanceBadge canonical={node.canonical} inferred={node.inferred} />
                    {aiPromoted && <AiPromotedBadge />}
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      )}

      {remainingCount > 0 && (
        <button
          type="button"
          onClick={() => setExpandSteps((n) => n + 1)}
          className="self-start rounded border border-slate-300 px-3 py-1.5 text-sm font-medium text-link hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
        >
          Show 20 more ({remainingCount} remaining)
        </button>
      )}
    </div>
  );
}
