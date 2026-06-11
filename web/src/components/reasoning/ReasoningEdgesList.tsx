import { useState } from "react";
import { Link } from "react-router-dom";
import { classificationBorderStyle, classificationNeedsReview } from "@/lib/colors";
import EdgeClassificationBadge from "./EdgeClassificationBadge";
import type { ReasoningEdge } from "@/lib/reasoningTypes";

const PAGE_SIZE = 40;
const PAGE_STEP = 20;

interface ReasoningEdgesListProps {
  edges: ReasoningEdge[];
  emptyMessage?: string;
  reviewer?: string;
  apiAvailable?: boolean;
  busyEdgeId?: string | null;
  onPromote?: (edgeId: string) => void;
}

/**
 * Bounded, classification-aware edge list — the "reasoning trace" / provenance
 * ledger. Shows at most PAGE_SIZE rows initially with a "Show more" control
 * (UIX_CONTRACT §1). Optionally exposes a per-edge "Promote" action gated on a
 * named reviewer (AI_ASSISTANCE_CONTRACT — humans promote, never automatic).
 */
export default function ReasoningEdgesList({ edges, emptyMessage, reviewer, apiAvailable, busyEdgeId, onPromote }: ReasoningEdgesListProps) {
  const [limit, setLimit] = useState(PAGE_SIZE);

  if (edges.length === 0) {
    return <p className="text-sm italic text-slate-400">{emptyMessage ?? "No edges."}</p>;
  }

  const visible = edges.slice(0, limit);
  const canPromote = Boolean(onPromote && apiAvailable && reviewer?.trim());

  return (
    <div className="flex flex-col gap-2">
      <ul className="flex flex-col gap-1.5">
        {visible.map((edge) => {
          const needsReview = classificationNeedsReview(edge.classification);
          const dashed = classificationBorderStyle(edge.classification) === "dashed";
          return (
            <li
              key={edge.id}
              className={`rounded border bg-white p-2 text-sm ${dashed ? "border-dashed" : "border-solid"} border-slate-200`}
            >
              <div className="flex flex-wrap items-center gap-1.5">
                <Link to={`/node/${encodeURIComponent(edge.source)}`} className="rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 font-mono text-xs hover:bg-slate-100">
                  {edge.source}
                </Link>
                <span className="text-xs text-slate-400" aria-hidden="true">
                  —[{edge.type}]→
                </span>
                <Link to={`/node/${encodeURIComponent(edge.target)}`} className="rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 font-mono text-xs hover:bg-slate-100">
                  {edge.target}
                </Link>
                <EdgeClassificationBadge classification={edge.classification} />
                <span className="rounded border border-slate-300 px-1.5 py-0.5 text-xs font-mono text-slate-500" aria-label={`Confidence ${edge.confidence.toFixed(2)}`}>
                  conf {edge.confidence.toFixed(2)}
                </span>
                {edge.conditional && (
                  <span className="rounded border border-conditional bg-cyan-50 px-1.5 py-0.5 text-xs font-medium text-conditional">conditional</span>
                )}
              </div>

              {edge.note && <p className="mt-1 text-xs text-slate-600">{edge.note}</p>}

              {edge.evidence.length > 0 && (
                <ul className="mt-1 list-inside list-disc text-xs text-slate-500">
                  {edge.evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              )}

              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                {edge.source_refs.map((ref) => (
                  <span key={ref} className="rounded border border-slate-200 bg-slate-50 px-1 py-0.5 font-mono">
                    {ref}
                  </span>
                ))}
                {edge.source_url && (
                  <a href={edge.source_url} target="_blank" rel="noreferrer" className="text-link hover:underline">
                    Source ↗
                  </a>
                )}
              </div>

              {onPromote && needsReview && (
                <div className="mt-1.5 flex items-center gap-2">
                  <button
                    type="button"
                    disabled={!canPromote || busyEdgeId === edge.id}
                    onClick={() => onPromote(edge.id)}
                    className="rounded border border-ok bg-green-50 px-2 py-0.5 text-xs font-medium text-ok hover:bg-green-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-ok disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {busyEdgeId === edge.id ? "Promoting…" : "Promote to canonical"}
                  </button>
                  {!apiAvailable && <span className="text-xs text-slate-400">API offline</span>}
                  {apiAvailable && !reviewer?.trim() && <span className="text-xs text-slate-400">Enter a reviewer name to act</span>}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {limit < edges.length && (
        <button
          type="button"
          onClick={() => setLimit((n) => n + PAGE_STEP)}
          className="self-start rounded border border-slate-300 px-3 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
        >
          Show {Math.min(PAGE_STEP, edges.length - limit)} more ({edges.length - limit} remaining)
        </button>
      )}
    </div>
  );
}
