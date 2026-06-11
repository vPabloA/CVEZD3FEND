import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import ActionListPanel from "@/components/reasoning/ActionListPanel";
import AiReasoningActions from "@/components/reasoning/AiReasoningActions";
import CtemPanel from "@/components/reasoning/CtemPanel";
import CveAnalyzeForm from "@/components/reasoning/CveAnalyzeForm";
import ExportsPanel from "@/components/reasoning/ExportsPanel";
import GraphNavigatorPlaceholder from "@/components/reasoning/GraphNavigatorPlaceholder";
import HumanReviewBanner from "@/components/reasoning/HumanReviewBanner";
import NarrativePanel from "@/components/reasoning/NarrativePanel";
import ProvenancePanel from "@/components/reasoning/ProvenancePanel";
import ReasoningEdgesList from "@/components/reasoning/ReasoningEdgesList";
import RiskSummaryPanel from "@/components/reasoning/RiskSummaryPanel";
import RouteContractPanel from "@/components/reasoning/RouteContractPanel";
import SourceModeBadge from "@/components/reasoning/SourceModeBadge";
import { useApiAvailability, useReasoning } from "@/hooks/useReasoning";
import { ApiError, promoteEdge } from "@/lib/api";
import { useQueryParam } from "@/lib/url";
import type { ReasoningResult } from "@/lib/reasoningTypes";

const REVIEWER_KEY = "cvezd3fend:reviewer";

function ReasoningResultView({
  result,
  cveId,
  reviewer,
  apiAvailable,
  busyEdgeId,
  promoteMessage,
  onPromote,
}: {
  result: ReasoningResult;
  cveId: string;
  reviewer: string;
  apiAvailable: boolean;
  busyEdgeId: string | null;
  promoteMessage: string | null;
  onPromote: (edgeId: string) => void;
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-md border border-slate-200 bg-white p-4">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="font-mono text-lg font-bold text-slate-800">{result.normalized_input || result.input}</h2>
          <span className="rounded border border-slate-300 bg-slate-100 px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide text-slate-600">
            {result.status}
          </span>
          <SourceModeBadge mode={result.source_mode} />
          {result.baseline_provider && (
            <span className="rounded border border-template bg-slate-50 px-1.5 py-0.5 text-xs text-template">via {result.baseline_provider}</span>
          )}
          <Link to={`/node/${encodeURIComponent(result.normalized_input || result.input)}`} className="ml-auto text-xs text-link hover:underline">
            Open in knowledge bundle →
          </Link>
        </div>
        {result.input !== result.normalized_input && (
          <p className="mt-1 text-xs text-slate-400">
            Input <span className="font-mono">{result.input}</span> normalized to <span className="font-mono">{result.normalized_input}</span>
          </p>
        )}
      </div>

      <HumanReviewBanner review={result.human_review} />

      {result.warnings.length > 0 && (
        <div className="rounded-md border border-inferred bg-amber-50 p-3 text-sm text-amber-900">
          <p className="font-medium">Warnings</p>
          <ul className="mt-1 list-inside list-disc">
            {result.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {result.errors.length > 0 && (
        <div role="alert" className="rounded-md border border-gap bg-red-50 p-3 text-sm text-gap">
          <p className="font-medium">Errors</p>
          <ul className="mt-1 list-inside list-disc">
            {result.errors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_20rem]">
        <div className="flex flex-col gap-4">
          <NarrativePanel narrative={result.narrative} />
          <RiskSummaryPanel risk={result.risk} />
          <RouteContractPanel route={result.route} />

          <section className="rounded-md border border-slate-200 bg-white p-4">
            <h2 className="text-sm font-semibold text-slate-700">
              Reasoning trace <span className="font-normal text-slate-400">({result.edges.length} edges)</span>
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              Every edge the engine considered, classified by how it was derived. Edges that aren&apos;t official-explicit may be promoted to
              canonical by a named reviewer.
            </p>
            <div className="mt-3">
              <ReasoningEdgesList
                edges={result.edges}
                emptyMessage="No edges were produced for this CVE."
                reviewer={reviewer}
                apiAvailable={apiAvailable}
                busyEdgeId={busyEdgeId}
                onPromote={onPromote}
              />
            </div>
            {promoteMessage && <p className="mt-2 rounded border border-slate-200 bg-slate-50 p-2 text-xs text-slate-600">{promoteMessage}</p>}
          </section>

          <ProvenancePanel provenance={result.provenance} />

          <ActionListPanel
            title="SOC Action Pack"
            sections={[
              { label: "Validations", items: result.soc_action_pack.validations },
              { label: "Detections", items: result.soc_action_pack.detections },
              { label: "Containment", items: result.soc_action_pack.containment },
              { label: "Owners", items: result.soc_action_pack.owners },
              { label: "Evidence expected", items: result.soc_action_pack.evidence_expected },
            ]}
          />

          <ActionListPanel
            title="Detection engineering"
            sections={[
              { label: "Hypotheses", items: result.detection_engineering.hypotheses },
              { label: "Log sources", items: result.detection_engineering.log_sources },
              { label: "Rule ideas", items: result.detection_engineering.rule_ideas },
              { label: "Gaps", items: result.detection_engineering.gaps },
            ]}
          />

          <ActionListPanel
            title="Threat hunting"
            sections={[
              { label: "Hypotheses", items: result.threat_hunting.hypotheses },
              { label: "Queries", items: result.threat_hunting.queries },
              { label: "Pivot points", items: result.threat_hunting.pivot_points },
            ]}
          />

          <CtemPanel ctem={result.ctem} />

          <ExportsPanel exports={result.exports} cveId={cveId} />
        </div>

        <aside className="flex flex-col gap-4 lg:sticky lg:top-4 lg:self-start">
          <AiReasoningActions cveId={cveId} apiAvailable={apiAvailable} />
          <GraphNavigatorPlaceholder navigatorLayer={result.exports.navigator_layer} cveId={cveId} />
        </aside>
      </div>
    </div>
  );
}

/**
 * The Reasoning Workbench: live CVE analysis entry point. Surfaces the full
 * `/api/reason/{cve_id}` result — risk, narrative, classified route contract,
 * provenance, SOC/Detection/Hunting/CTEM outputs, exports and AI-assisted
 * review actions. All data is fetched live from the API sidecar; nothing is
 * hardcoded (UIX product brief — workbench foundation).
 */
export default function AnalyzePage() {
  const [cve, setCve] = useQueryParam("cve");
  const api = useApiAvailability();
  const reasoning = useReasoning(cve, api.available === true);
  const [reviewer, setReviewer] = useState(() => localStorage.getItem(REVIEWER_KEY) ?? "");
  const [busyEdgeId, setBusyEdgeId] = useState<string | null>(null);
  const [promoteMessage, setPromoteMessage] = useState<string | null>(null);

  useEffect(() => {
    localStorage.setItem(REVIEWER_KEY, reviewer);
  }, [reviewer]);

  const handlePromote = (edgeId: string) => {
    setBusyEdgeId(edgeId);
    setPromoteMessage(null);
    promoteEdge(edgeId, reviewer.trim())
      .then(() => {
        setPromoteMessage(`Promoted ${edgeId} to canonical.`);
        reasoning.reload();
      })
      .catch((err: ApiError) => setPromoteMessage(`Failed to promote ${edgeId}: ${err.message}`))
      .finally(() => setBusyEdgeId(null));
  };

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold text-slate-800">Reasoning workbench</h1>
        <p className="text-sm text-slate-500">
          Run the live enrichment + reasoning engine for a CVE: classified route, risk evidence, provenance, SOC/Detection/Hunting/CTEM
          outputs, exports and AI-assisted review — all derived from the API sidecar, never hardcoded.
        </p>
      </div>

      {api.available === null && <LoadingState label="Checking API sidecar…" />}

      {api.available === false && (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm text-amber-800">
          <p className="font-medium">API sidecar not reachable{api.error ? ` (${api.error})` : ""}.</p>
          <p className="mt-1">The reasoning workbench requires the live API sidecar. From the project root:</p>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-900 p-2 text-xs text-slate-100">
{`CVEzD3FEND api                           # start the sidecar (default http://127.0.0.1:8000)
CVEzD3FEND reason <cve_id>               # CLI equivalent of this page
CVEzD3FEND enrich <cve_id> --mode cached # offline/cached enrichment fallback`}
          </pre>
          <button
            type="button"
            onClick={api.recheck}
            className="mt-3 rounded border border-amber-400 px-3 py-1.5 text-sm font-medium text-amber-800 hover:bg-amber-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500"
          >
            Check again
          </button>
        </div>
      )}

      {api.available && (
        <>
          {api.meta && !api.meta.reasoning_available && (
            <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
              The API sidecar is reachable, but the reasoning plane reports itself unavailable. Enrichment-only data may still work; reasoning
              requests below may fail.
            </div>
          )}

          <div className="rounded-md border border-slate-200 bg-white p-3">
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex-1">
                <CveAnalyzeForm value={cve} busy={reasoning.loading} onSubmit={setCve} />
              </div>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">Reviewer name</span>
                <input
                  type="text"
                  value={reviewer}
                  onChange={(e) => setReviewer(e.target.value)}
                  placeholder="your name"
                  className="rounded border border-slate-300 px-2 py-1 text-sm focus:border-link focus:outline-none focus-visible:ring-2 focus-visible:ring-link"
                />
              </label>
              {cve.trim() && (
                <button
                  type="button"
                  onClick={reasoning.reload}
                  disabled={reasoning.loading}
                  className="rounded border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:opacity-50"
                >
                  {reasoning.loading ? "Refreshing…" : "Refresh"}
                </button>
              )}
            </div>
          </div>

          {!cve.trim() ? (
            <EmptyState title="Enter a CVE ID to begin analysis" hint="Try a CVE id such as CVE-2021-44228, or open a CVE node and choose “Analyze”.">
              <Link to="/" className="mt-2 text-sm text-link hover:underline">
                ← Back to search
              </Link>
            </EmptyState>
          ) : reasoning.loading ? (
            <LoadingState label={`Running reasoning engine for ${cve}…`} />
          ) : reasoning.error ? (
            <ErrorState message={reasoning.error} onRetry={reasoning.reload} />
          ) : reasoning.result ? (
            <ReasoningResultView
              result={reasoning.result}
              cveId={cve.trim()}
              reviewer={reviewer}
              apiAvailable={Boolean(api.available)}
              busyEdgeId={busyEdgeId}
              promoteMessage={promoteMessage}
              onPromote={handlePromote}
            />
          ) : null}
        </>
      )}
    </div>
  );
}
