import { Link } from "react-router-dom";
import { REASONING_CLASSIFICATION_LABELS, classificationClass, classificationNeedsReview } from "@/lib/colors";
import { buildOfficialUrl } from "./officialUrlBuilder";
import type { GraphLinkData, GraphNodeData, GraphSelection } from "./graphTypes";
import type { ReasoningEdge } from "@/lib/reasoningTypes";

function copyText(value: string) {
  void navigator.clipboard?.writeText(value);
}

function chipClass(active = false) {
  return active ? "border-link bg-blue-50 text-link" : "border-slate-200 bg-slate-50 text-slate-600";
}

function relatedEdges(resultEdges: ReasoningEdge[], nodeId: string): ReasoningEdge[] {
  return resultEdges.filter((edge) => edge.source === nodeId || edge.target === nodeId).slice(0, 5);
}

export default function GraphInspector({
  selection,
  nodes,
  links,
  resultEdges,
  onFocusNode,
  onFocusEdge,
  onClearSelection,
}: {
  selection: GraphSelection;
  nodes: GraphNodeData[];
  links: GraphLinkData[];
  resultEdges: ReasoningEdge[];
  onFocusNode: (nodeId: string) => void;
  onFocusEdge: (edgeId: string) => void;
  onClearSelection: () => void;
}) {
  const selectedNode = selection?.kind === "node" ? nodes.find((node) => node.id === selection.id) ?? null : null;
  const selectedLink = selection?.kind === "edge" ? links.find((link) => link.id === selection.id) ?? null : null;

  return (
    <aside className="flex h-full min-h-[18rem] flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950/80 p-4 text-slate-200">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Inspector</p>
          <h3 className="mt-1 text-sm font-semibold text-slate-100">{selectedLink ? "Selected edge" : selectedNode ? "Selected node" : "No selection"}</h3>
        </div>
        {selection && (
          <button
            type="button"
            onClick={onClearSelection}
            className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
          >
            Clear
          </button>
        )}
      </div>

      {!selection && (
        <p className="text-sm leading-relaxed text-slate-400">
          Select a node or edge to inspect its classification, evidence, review status and official source links. The graph remains the
          primary route surface; this panel is the focused detail lens.
        </p>
      )}

      {selectedNode && (
        <div className="flex flex-1 flex-col gap-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-base font-semibold text-slate-100">{selectedNode.id}</span>
              <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${chipClass(true)}`}>{selectedNode.kind}</span>
              <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${chipClass(selectedNode.reviewRequired)}`}>
                {selectedNode.routeRole}
              </span>
              {selectedNode.reviewRequired && <span className="rounded-full border border-amber-400 bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-800">Review</span>}
            </div>
            <p className="mt-2 text-sm leading-relaxed text-slate-300">{selectedNode.description}</p>
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <button
                type="button"
                onClick={() => copyText(selectedNode.id)}
                className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                Copy node id
              </button>
              <button
                type="button"
                onClick={() => onFocusNode(selectedNode.id)}
                className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                Focus neighborhood
              </button>
              <Link
                to={`/node/${encodeURIComponent(selectedNode.id)}`}
                className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                Open detail
              </Link>
              {(selectedNode.officialUrl ?? buildOfficialUrl(selectedNode.id)) && (
                <a
                  href={selectedNode.officialUrl ?? buildOfficialUrl(selectedNode.id) ?? undefined}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                >
                  Official source ↗
                </a>
              )}
            </div>
          </div>

          <div className="grid gap-2 text-xs text-slate-300">
            <div className="flex flex-wrap gap-1.5">
              {selectedNode.tags.map((tag) => (
                <span key={tag} className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-400">
                  {tag}
                </span>
              ))}
            </div>
            {selectedNode.sourceRefs.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {selectedNode.sourceRefs.map((ref) => (
                  <span key={ref} className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-slate-400">
                    {ref}
                  </span>
                ))}
              </div>
            )}
            {selectedNode.evidence.length > 0 && (
              <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
                <h4 className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Evidence</h4>
                <ul className="mt-2 flex flex-col gap-1.5 text-sm text-slate-300">
                  {selectedNode.evidence.map((item) => (
                    <li key={item} className="rounded border border-slate-800 bg-slate-950/80 px-2 py-1">
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
              <h4 className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Related edges</h4>
              <div className="mt-2 flex flex-col gap-1.5">
                {relatedEdges(resultEdges, selectedNode.id).map((edge) => (
                  <button
                    key={edge.id}
                    type="button"
                    onClick={() => onFocusEdge(edge.id)}
                    className="rounded-lg border border-slate-800 bg-slate-950 px-2 py-1.5 text-left hover:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-slate-100">
                        {edge.source} → {edge.target}
                      </span>
                      <span className={`rounded-full border px-1.5 py-0.5 text-[10px] ${classificationClass(edge.classification)}`}>
                        {REASONING_CLASSIFICATION_LABELS[edge.classification]}
                      </span>
                    </div>
                    {edge.note && <p className="mt-1 text-[11px] text-slate-400">{edge.note}</p>}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {selectedLink && (
        <div className="flex flex-1 flex-col gap-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-base font-semibold text-slate-100">{selectedLink.source} → {selectedLink.target}</span>
              <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${classificationClass(selectedLink.classification)}`}>
                {REASONING_CLASSIFICATION_LABELS[selectedLink.classification]}
              </span>
              {classificationNeedsReview(selectedLink.classification) && (
                <span className="rounded-full border border-amber-400 bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-800">Review</span>
              )}
            </div>
            <p className="mt-2 text-sm leading-relaxed text-slate-300">{selectedLink.label}</p>
            <p className="mt-1 text-xs text-slate-400">Confidence {selectedLink.confidence.toFixed(2)} · {selectedLink.type}</p>
            {selectedLink.note && <p className="mt-2 rounded-lg border border-slate-800 bg-slate-950/80 px-2 py-1.5 text-sm text-slate-300">{selectedLink.note}</p>}
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <button
                type="button"
                onClick={() => copyText(selectedLink.id)}
                className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                Copy edge id
              </button>
              <button
                type="button"
                onClick={() => onFocusNode(selectedLink.source)}
                className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                Focus source
              </button>
              <button
                type="button"
                onClick={() => onFocusNode(selectedLink.target)}
                className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
              >
                Focus target
              </button>
              {selectedLink.sourceUrl && (
                <a
                  href={selectedLink.sourceUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-full border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300 hover:border-link hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                >
                  Source ↗
                </a>
              )}
            </div>
          </div>

          {selectedLink.evidence.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
              <h4 className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Evidence reasoning</h4>
              <ul className="mt-2 flex flex-col gap-1.5 text-sm text-slate-300">
                {selectedLink.evidence.map((item) => (
                  <li key={item} className="rounded border border-slate-800 bg-slate-950/80 px-2 py-1">
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {selectedLink.sourceRefs.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {selectedLink.sourceRefs.map((ref) => (
                <span key={ref} className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-400">
                  {ref}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </aside>
  );
}
