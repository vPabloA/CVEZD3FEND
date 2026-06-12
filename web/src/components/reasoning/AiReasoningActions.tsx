import { useEffect, useMemo, useState } from "react";
import { ApiError, proposeRoute, validateRoute } from "@/lib/api";
import { REASONING_CLASSIFICATION_LABELS, classificationNeedsReview } from "@/lib/colors";
import KeyFacts from "./KeyFacts";
import type { ReasoningEdge } from "@/lib/reasoningTypes";

interface ActionState {
  busy: boolean;
  result: Record<string, unknown> | null;
  error: string | null;
}

const IDLE: ActionState = { busy: false, result: null, error: null };

/**
 * AI propose-route / deterministic validate-route actions
 * (AI_ASSISTANCE_CONTRACT: AI proposes, the graph/contracts validate, humans
 * promote). Results are shown as visible "AI Review Status" facts — never as
 * hidden chain-of-thought.
 */
export default function AiReasoningActions({
  cveId,
  apiAvailable,
  reviewer = "",
  edges = [],
  busyEdgeId = null,
  promoteMessage = null,
  onPromote,
  onReviewerChange,
}: {
  cveId: string;
  apiAvailable: boolean;
  reviewer?: string;
  edges?: ReasoningEdge[];
  busyEdgeId?: string | null;
  promoteMessage?: string | null;
  onPromote?: (edgeId: string) => void;
  onReviewerChange?: (value: string) => void;
}) {
  const [propose, setPropose] = useState<ActionState>(IDLE);
  const [validate, setValidate] = useState<ActionState>(IDLE);
  const reviewEdges = useMemo(() => edges.filter((edge) => classificationNeedsReview(edge.classification)), [edges]);
  const [selectedEdgeId, setSelectedEdgeId] = useState("");

  useEffect(() => {
    setSelectedEdgeId((current) => (reviewEdges.some((edge) => edge.id === current) ? current : reviewEdges[0]?.id ?? ""));
  }, [reviewEdges]);

  const handlePropose = () => {
    setPropose({ busy: true, result: null, error: null });
    proposeRoute(cveId)
      .then((result) => setPropose({ busy: false, result, error: null }))
      .catch((err: ApiError) => setPropose({ busy: false, result: null, error: err.message }));
  };

  const handleValidate = () => {
    setValidate({ busy: true, result: null, error: null });
    validateRoute(cveId)
      .then((result) => setValidate({ busy: false, result, error: null }))
      .catch((err: ApiError) => setValidate({ busy: false, result: null, error: err.message }));
  };

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-700">AI Review</h2>
        <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
          Governed
        </span>
      </div>
      <p className="mt-1 text-xs text-slate-500">
        AI proposes, the engine validates, and a named reviewer promotes only one selected edge at a time.
      </p>

      <div className="mt-3 flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!apiAvailable || propose.busy}
            onClick={handlePropose}
            className="rounded-md border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:cursor-not-allowed disabled:opacity-50"
          >
            {propose.busy ? "Thinking…" : "Propose route"}
          </button>
          <button
            type="button"
            disabled={!apiAvailable || validate.busy}
            onClick={handleValidate}
            className="rounded-md border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:cursor-not-allowed disabled:opacity-50"
          >
            {validate.busy ? "Validating…" : "Validate route"}
          </button>
        </div>

        {(propose.busy || validate.busy) && (
          <p className="rounded border border-blue-100 bg-blue-50 px-2 py-1.5 text-xs text-link">Reasoning review in progress...</p>
        )}

        <div>
          {propose.error && <p className="mt-2 text-xs text-gap">{propose.error}</p>}
          {propose.result && (
            <details className="mt-2 rounded border border-inferred bg-amber-50 p-2">
              <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-wide text-inferred">
                AI proposal (not canonical)
              </summary>
              <div className="mt-2">
                <KeyFacts data={propose.result} />
              </div>
            </details>
          )}
          {validate.error && <p className="mt-2 text-xs text-gap">{validate.error}</p>}
          {validate.result && (
            <details className="mt-2 rounded border border-link bg-blue-50 p-2">
              <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-wide text-link">Route Validation</summary>
              <div className="mt-2">
                <KeyFacts data={validate.result} />
              </div>
            </details>
          )}
        </div>

        {onPromote && (
          <div className="rounded border border-slate-200 bg-slate-50 p-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Governed promotion</p>
            {reviewEdges.length === 0 ? (
              <p className="mt-1 text-xs text-slate-400">No reviewable edges in this route.</p>
            ) : (
              <div className="mt-2 flex flex-col gap-2">
                <label className="flex flex-col gap-1 text-xs">
                  <span className="font-semibold uppercase tracking-wide text-slate-400">Reviewer</span>
                  <input
                    type="text"
                    value={reviewer}
                    onChange={(event) => onReviewerChange?.(event.target.value)}
                    placeholder="your name"
                    className="rounded border border-slate-300 bg-white px-2 py-1 text-xs focus:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                  />
                </label>
                <select
                  value={selectedEdgeId}
                  onChange={(event) => setSelectedEdgeId(event.target.value)}
                  className="rounded border border-slate-300 bg-white px-2 py-1 text-xs focus:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                  aria-label="Edge to promote"
                >
                  {reviewEdges.map((edge) => (
                    <option key={edge.id} value={edge.id}>
                      {edge.source} to {edge.target} - {REASONING_CLASSIFICATION_LABELS[edge.classification]} - conf {edge.confidence.toFixed(2)}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  disabled={!apiAvailable || !reviewer.trim() || !selectedEdgeId || busyEdgeId === selectedEdgeId}
                  onClick={() => selectedEdgeId && onPromote(selectedEdgeId)}
                  className="rounded border border-ok bg-green-50 px-3 py-1.5 text-xs font-semibold text-ok hover:bg-green-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-ok disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {busyEdgeId === selectedEdgeId ? "Promoting..." : "Promote selected edge"}
                </button>
                {!reviewer.trim() && <p className="text-xs text-slate-400">Enter a reviewer name to promote the selected edge.</p>}
                {promoteMessage && <p className="rounded border border-slate-200 bg-white p-2 text-xs text-slate-600">{promoteMessage}</p>}
              </div>
            )}
          </div>
        )}

        {!apiAvailable && <p className="text-xs text-slate-400">API offline — start `CVEzD3FEND api` to use AI actions.</p>}
      </div>
    </section>
  );
}
