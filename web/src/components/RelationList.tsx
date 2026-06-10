import { useState } from "react";
import { Link } from "react-router-dom";
import { getNode } from "@/lib/bundle";
import { edgeColorClass, edgeIsAiPromoted, nodeColorClass } from "@/lib/colors";
import type { BundleEdge, KnowledgeBundle } from "@/lib/types";
import EmptyState from "./EmptyState";
import { AiPromotedBadge, ConfidenceBadge, TypeBadge } from "./NodeBadge";

const PAGE_SIZE = 20;

/** Paginated incoming/outgoing edge list for Node Detail (UIX_CONTRACT §3 "Node Detail"). */
export default function RelationList({
  bundle,
  edges,
  direction,
}: {
  bundle: KnowledgeBundle;
  edges: BundleEdge[];
  direction: "incoming" | "outgoing";
}) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  if (edges.length === 0) {
    return <EmptyState title={`No ${direction} relations`} hint="This node has no edges in this direction." />;
  }

  const visible = edges.slice(0, visibleCount);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex max-h-96 flex-col gap-1.5 overflow-y-auto pr-1">
        {visible.map((edge) => {
          const otherId = direction === "incoming" ? edge.source : edge.target;
          const other = getNode(bundle, otherId);
          return (
            <div
              key={edge.id}
              className="flex flex-wrap items-center gap-2 rounded border border-slate-200 bg-white px-2 py-1.5 text-sm"
            >
              <span className={`font-mono text-xs ${edgeColorClass(edge)}`}>{edge.type}</span>
              <span aria-hidden="true" className="text-slate-300">
                {direction === "incoming" ? "←" : "→"}
              </span>
              {other ? (
                <Link
                  to={`/node/${encodeURIComponent(other.id)}`}
                  className={`font-mono font-medium hover:underline ${nodeColorClass(other)}`}
                >
                  {other.id}
                </Link>
              ) : (
                <span className="font-mono text-slate-400">{otherId}</span>
              )}
              {other && <TypeBadge type={other.type} />}
              <ConfidenceBadge confidence={edge.confidence} />
              {edgeIsAiPromoted(edge) && <AiPromotedBadge />}
            </div>
          );
        })}
      </div>
      <div className="flex items-center justify-between text-xs text-slate-500">
        <span>
          Showing {visible.length} of {edges.length}
        </span>
        {visibleCount < edges.length && (
          <button
            type="button"
            onClick={() => setVisibleCount((n) => n + PAGE_SIZE)}
            className="rounded border border-slate-300 px-2 py-1 font-medium text-link hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Show 20 more
          </button>
        )}
      </div>
    </div>
  );
}
