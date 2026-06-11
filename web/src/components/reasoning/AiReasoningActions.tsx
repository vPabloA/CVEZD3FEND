import { useState } from "react";
import { ApiError, proposeRoute, validateRoute } from "@/lib/api";
import KeyFacts from "./KeyFacts";

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
export default function AiReasoningActions({ cveId, apiAvailable }: { cveId: string; apiAvailable: boolean }) {
  const [propose, setPropose] = useState<ActionState>(IDLE);
  const [validate, setValidate] = useState<ActionState>(IDLE);

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
    <section className="rounded-md border border-slate-200 bg-white p-4">
      <h2 className="text-sm font-semibold text-slate-700">AI-assisted review</h2>
      <p className="mt-1 text-xs text-slate-500">
        AI proposes a route, the engine validates it deterministically against the bundle and contracts. Nothing here is canonical until a
        human reviewer promotes an edge below.
      </p>

      <div className="mt-3 flex flex-col gap-3">
        <div>
          <button
            type="button"
            disabled={!apiAvailable || propose.busy}
            onClick={handlePropose}
            className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:cursor-not-allowed disabled:opacity-50"
          >
            {propose.busy ? "Requesting AI proposal…" : "Propose route (AI)"}
          </button>
          {propose.error && <p className="mt-2 text-xs text-gap">{propose.error}</p>}
          {propose.result && (
            <div className="mt-2 rounded border border-inferred bg-amber-50 p-2">
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-inferred">AI proposal (not canonical)</p>
              <KeyFacts data={propose.result} />
            </div>
          )}
        </div>

        <div>
          <button
            type="button"
            disabled={!apiAvailable || validate.busy}
            onClick={handleValidate}
            className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:cursor-not-allowed disabled:opacity-50"
          >
            {validate.busy ? "Validating route…" : "Validate route"}
          </button>
          {validate.error && <p className="mt-2 text-xs text-gap">{validate.error}</p>}
          {validate.result && (
            <div className="mt-2 rounded border border-link bg-blue-50 p-2">
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-link">Validation result</p>
              <KeyFacts data={validate.result} />
            </div>
          )}
        </div>

        {!apiAvailable && <p className="text-xs text-slate-400">API offline — start `CVEzD3FEND api` to use AI actions.</p>}
      </div>
    </section>
  );
}
