import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import EmptyState from "@/components/EmptyState";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import AdvancedEvidenceDrawer from "@/components/reasoning/AdvancedEvidenceDrawer";
import AiReasoningActions from "@/components/reasoning/AiReasoningActions";
import CveAnalyzeForm from "@/components/reasoning/CveAnalyzeForm";
import EntityNavigationPanel from "@/components/reasoning/EntityNavigationPanel";
import HumanReviewBanner from "@/components/reasoning/HumanReviewBanner";
import NarrativePanel from "@/components/reasoning/NarrativePanel";
import ReasoningRouteGraph from "@/components/reasoning/ReasoningRouteGraph";
import RiskSummaryPanel from "@/components/reasoning/RiskSummaryPanel";
import SourceModeBadge from "@/components/reasoning/SourceModeBadge";
import { useApiAvailability, useReasoning } from "@/hooks/useReasoning";
import { ApiError, promoteEdge } from "@/lib/api";
import { RISK_LEVEL_LABELS, riskLevelClass, riskLevelFromScore } from "@/lib/colors";
import { useQueryParam } from "@/lib/url";
import type { ReasoningResult } from "@/lib/reasoningTypes";

const REVIEWER_KEY = "cvezd3fend:reviewer";

function num(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

function baseScore(result: ReasoningResult): number | undefined {
  const cvss = result.risk.cvss;
  if (!cvss) return undefined;
  return num(cvss.base_score) ?? num(cvss.baseScore) ?? num(cvss.score);
}

function kevListed(result: ReasoningResult): boolean {
  const kev = result.risk.kev;
  if (!kev) return false;
  if (typeof kev.listed === "boolean") return kev.listed;
  if (typeof kev.in_kev === "boolean") return kev.in_kev;
  return Object.keys(kev).length > 0;
}

function firstItems(items: string[], count = 2): string[] {
  return items.slice(0, count);
}

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
  const [selectedNode, setSelectedNode] = useState<string | null>(result.route.canonical_chain[0] ?? result.normalized_input ?? result.input);
  const cveLabel = result.normalized_input || result.input;
  const riskLevel = riskLevelFromScore(baseScore(result), kevListed(result));
  const routeLabel = result.route.canonical_chain.length > 0 ? result.route.canonical_chain.join(" -> ") : "Partial route";
  const noticeCount = result.warnings.length + result.errors.length;

  useEffect(() => {
    setSelectedNode(result.route.canonical_chain[0] ?? result.normalized_input ?? result.input);
  }, [result]);

  return (
    <div className="flex flex-col gap-4">
      <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="font-mono text-xl font-bold text-slate-900">{cveLabel}</h2>
              <span className="rounded border border-slate-300 bg-slate-100 px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide text-slate-600">
                {result.status}
              </span>
              <SourceModeBadge mode={result.source_mode} />
              <span className={`rounded border px-1.5 py-0.5 text-xs font-semibold ${riskLevelClass(riskLevel)}`}>
                Priority: {RISK_LEVEL_LABELS[riskLevel]}
              </span>
              {result.human_review.required && (
                <span className="rounded border border-inferred bg-amber-50 px-1.5 py-0.5 text-xs font-semibold text-inferred">Requiere revisión</span>
              )}
              {noticeCount > 0 && (
                <span className="rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-amber-800">
                  {noticeCount} data notice(s)
                </span>
              )}
            </div>
            <p className="mt-2 max-w-5xl font-mono text-xs text-slate-500">{routeLabel}</p>
            {result.input !== result.normalized_input && (
              <p className="mt-1 text-xs text-slate-400">
                Input <span className="font-mono">{result.input}</span> normalized to <span className="font-mono">{result.normalized_input}</span>
              </p>
            )}
          </div>
          <Link to={`/node/${encodeURIComponent(cveLabel)}`} className="text-xs font-medium text-link hover:underline">
            Open in knowledge bundle
          </Link>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[17rem_minmax(0,1fr)_24rem]">
        <EntityNavigationPanel
          result={result}
          selectedNode={selectedNode}
          onSelectNode={(nodeId) => setSelectedNode(nodeId || null)}
        />

        <main className="min-w-0">
          <ReasoningRouteGraph result={result} selectedNode={selectedNode} onSelectNode={setSelectedNode} />
        </main>

        <aside className="flex min-w-0 flex-col gap-4 xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-auto">
          <NarrativePanel narrative={result.narrative} />

          <section className="rounded-md border border-slate-200 bg-white p-4">
            <h2 className="text-sm font-semibold text-slate-700">Acción recomendada</h2>
            <p className="mt-2 text-sm leading-relaxed text-slate-700" lang="es">
              {result.narrative.tier1_conclusion_es || "No Tier 1 conclusion was produced for this CVE."}
            </p>
            <div className="mt-3 grid gap-3">
              {firstItems(result.soc_action_pack.validations).length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Validate now</h3>
                  <ul className="mt-1 list-inside list-disc text-sm text-slate-700">
                    {firstItems(result.soc_action_pack.validations).map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
              {firstItems(result.soc_action_pack.containment).length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Containment</h3>
                  <ul className="mt-1 list-inside list-disc text-sm text-slate-700">
                    {firstItems(result.soc_action_pack.containment).map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </section>

          <HumanReviewBanner review={result.human_review} />
          <RiskSummaryPanel risk={result.risk} />
          <AiReasoningActions
            cveId={cveId}
            apiAvailable={apiAvailable}
            reviewer={reviewer}
            edges={result.edges}
            busyEdgeId={busyEdgeId}
            promoteMessage={promoteMessage}
            onPromote={onPromote}
          />
        </aside>
      </div>

      <AdvancedEvidenceDrawer result={result} cveId={cveId} />
    </div>
  );
}

/**
 * The Reasoning Workbench: graph-centered Single Pane of Glass for one CVE.
 * Route, narrative and Tier 1 action are first-class; full provenance,
 * exports and raw details stay available through progressive disclosure.
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
        <h1 className="text-lg font-semibold text-slate-800">Single Pane of Glass</h1>
        <p className="text-sm text-slate-500">
          Route first, graph center, narrative right, entities left, evidence in the drawer. All reasoning data comes from the API sidecar.
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

          <div className="sticky top-0 z-30 rounded-2xl border border-slate-200 bg-white/95 p-3 shadow-sm backdrop-blur">
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
              <div className="flex flex-col gap-1 text-sm">
                <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">State</span>
                <span className="rounded border border-slate-300 bg-slate-50 px-2 py-1 text-xs font-medium text-slate-600">
                  {reasoning.loading ? "Reasoning" : reasoning.result ? reasoning.result.status : "Ready"}
                </span>
              </div>
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
