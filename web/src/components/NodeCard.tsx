import { Link } from "react-router-dom";
import { nodeBorderClass, nodeBorderStyle, nodeColorClass } from "@/lib/colors";
import type { BundleNode } from "@/lib/types";
import { ConfidenceBadge, ProvenanceBadge, TypeBadge } from "./NodeBadge";

/** A clickable summary card for a node — used in search results, relation lists, route steps. */
export default function NodeCard({ node, compact = false }: { node: BundleNode; compact?: boolean }) {
  const borderStyle = nodeBorderStyle(node);
  return (
    <Link
      to={`/node/${encodeURIComponent(node.id)}`}
      className={`block rounded-md border-2 bg-white px-3 py-2 transition hover:shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${nodeBorderClass(
        node
      )}`}
      style={{ borderStyle }}
    >
      <div className="flex items-center justify-between gap-2">
        <span className={`truncate font-mono text-sm font-semibold ${nodeColorClass(node)}`}>{node.id}</span>
        <TypeBadge type={node.type} />
      </div>
      <p className="mt-1 truncate text-sm text-slate-700">{node.name}</p>
      {!compact && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <ProvenanceBadge canonical={node.canonical} inferred={node.inferred} />
          <ConfidenceBadge confidence={node.confidence} />
          {node.type === "cve" && (
            <Link
              to={`/analyze?cve=${encodeURIComponent(node.id)}`}
              onClick={(e) => e.stopPropagation()}
              className="ml-auto rounded border border-link bg-blue-50 px-1.5 py-0.5 text-xs font-medium text-link hover:bg-blue-100"
            >
              Analyze →
            </Link>
          )}
        </div>
      )}
    </Link>
  );
}
