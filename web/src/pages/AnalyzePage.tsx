import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import AdvancedEvidenceDrawer from "@/components/reasoning/AdvancedEvidenceDrawer";
import AiReasoningActions from "@/components/reasoning/AiReasoningActions";
import CveAnalyzeForm from "@/components/reasoning/CveAnalyzeForm";
import EntityNavigationPanel from "@/components/reasoning/EntityNavigationPanel";
import HumanReviewBanner from "@/components/reasoning/HumanReviewBanner";
import ReasoningSkillsPanel from "@/components/reasoning/ReasoningSkillsPanel";
import Tier1BriefingCard from "@/components/reasoning/Tier1BriefingCard";
import ThreatDefenseGraphNavigator from "@/components/reasoning/graph/ThreatDefenseGraphNavigator";
import RiskSummaryPanel from "@/components/reasoning/RiskSummaryPanel";
import SourceModeBadge from "@/components/reasoning/SourceModeBadge";
import { useApiAvailability, useReasoning } from "@/hooks/useReasoning";
import { ApiError, promoteEdge } from "@/lib/api";
import { RISK_LEVEL_LABELS, riskLevelClass, riskLevelFromScore } from "@/lib/colors";
import { useQueryParam } from "@/lib/url";
import type { ReasoningResult } from "@/lib/reasoningTypes";

const REVIEWER_KEY = "cvezd3fend:reviewer";

const ROUTE_SPINE = ["CVE", "CWE", "CAPEC", "ATT&CK", "D3FEND"];

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

/** Live mission signals shown in the command bar once a CVE is staged. */
function CommandSignals({ result }: { result: ReasoningResult }) {
  const cveLabel = result.normalized_input || result.input;
  const riskLevel = riskLevelFromScore(baseScore(result), kevListed(result));

  return (
    <div className="flex min-w-0 flex-wrap items-center gap-1.5">
      <h2 className="font-mono text-sm font-bold text-slate-100">{cveLabel}</h2>
      <span className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide text-slate-300">
        {result.status}
      </span>
      <SourceModeBadge mode={result.source_mode} />
      <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${riskLevelClass(riskLevel)}`}>
        Priority: {RISK_LEVEL_LABELS[riskLevel]}
      </span>
      {result.human_review.required && (
        <span className="rounded border border-inferred bg-amber-50 px-1.5 py-0.5 text-[11px] font-semibold text-inferred">Requiere revisión</span>
      )}
      {result.input !== result.normalized_input && (
        <span
          className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[11px] text-slate-400"
          title={`Input ${result.input} normalized to ${result.normalized_input}`}
        >
          normalized
        </span>
      )}
      <Link to={`/node/${encodeURIComponent(cveLabel)}`} className="text-[11px] font-medium text-sky-400 hover:text-sky-300 hover:underline">
        Open in knowledge bundle
      </Link>
    </div>
  );
}

function ReasoningResultView({
  result,
  cveId,
  reviewer,
  apiAvailable,
  busyEdgeId,
  promoteMessage,
  onPromote,
  onReviewerChange,
}: {
  result: ReasoningResult;
  cveId: string;
  reviewer: string;
  apiAvailable: boolean;
  busyEdgeId: string | null;
  promoteMessage: string | null;
  onPromote: (edgeId: string) => void;
  onReviewerChange: (value: string) => void;
}) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const riskLevel = riskLevelFromScore(baseScore(result), kevListed(result));

  useEffect(() => {
    setSelectedNode(null);
    setSelectedEdge(null);
  }, [result]);

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[15rem_minmax(0,1fr)_23rem]">
        <EntityNavigationPanel
          result={result}
          selectedNode={selectedNode}
          onSelectNode={(nodeId) => {
            setSelectedNode(nodeId || null);
            setSelectedEdge(null);
          }}
        />

        <main className="min-w-0">
          <ThreatDefenseGraphNavigator
            result={result}
            selection={selectedEdge ? { kind: "edge", id: selectedEdge } : selectedNode ? { kind: "node", id: selectedNode } : null}
            onSelectNode={(nodeId) => {
              setSelectedNode(nodeId);
              setSelectedEdge(null);
            }}
            onSelectEdge={(edgeId) => {
              setSelectedEdge(edgeId || null);
            }}
            onClearSelection={() => {
              setSelectedNode(null);
              setSelectedEdge(null);
            }}
          />
        </main>

        <aside className="flex min-w-0 flex-col gap-4 xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-auto">
          <Tier1BriefingCard
            result={result}
            riskLevel={riskLevel}
            onFocusNode={(nodeId) => {
              setSelectedNode(nodeId);
              setSelectedEdge(null);
            }}
          />
          <ReasoningSkillsPanel result={result} />
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
            onReviewerChange={onReviewerChange}
          />
        </aside>
      </div>

      <AdvancedEvidenceDrawer result={result} cveId={cveId} />
    </div>
  );
}

/** Premium idle state for the graph stage: route spine preview, no fake data. */
function WorkbenchEmptyState() {
  return (
    <section className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-950 px-6 py-16 text-center shadow-xl">
      <div
        className="pointer-events-none absolute inset-0 opacity-20 [background-image:linear-gradient(rgba(148,163,184,0.14)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.14)_1px,transparent_1px)] [background-size:28px_28px]"
        aria-hidden="true"
      />
      <div className="relative flex flex-col items-center gap-4">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500">Graph stage idle</p>
        <p className="text-base font-semibold text-slate-100">Enter a CVE ID to begin analysis</p>
        <p className="max-w-xl text-sm text-slate-400">
          The reasoning engine stages the full threat-defense route — operational priority, mitigation path, evidence signal and the
          recommended Tier 1 action — on this canvas.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-1.5" aria-hidden="true">
          {ROUTE_SPINE.map((stage, index) => (
            <span key={stage} className="flex items-center gap-1.5">
              <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-medium text-slate-400">{stage}</span>
              {index < ROUTE_SPINE.length - 1 && <span className="text-slate-600">→</span>}
            </span>
          ))}
        </div>
        <Link to="/" className="text-sm text-sky-400 hover:text-sky-300 hover:underline">
          ← Back to search
        </Link>
      </div>
    </section>
  );
}

/**
 * The Reasoning Workbench: graph-centered Single Pane of Glass for one CVE.
 * Four deliberate zones — command bar, graph stage, intelligence briefing,
 * evidence dock. Route, conclusion and Tier 1 action are first-class; full
 * provenance, exports and raw details stay behind progressive disclosure.
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
    <div className="mx-auto flex w-full max-w-screen-2xl flex-col gap-4 px-4 py-5 lg:px-6">
      {api.available === null && <LoadingState label="Checking API sidecar…" />}

      {api.available === false && (
        <div className="rounded-2xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-800 shadow-sm">
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
            <div className="rounded-2xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800 shadow-sm">
              The API sidecar is reachable, but the reasoning plane reports itself unavailable. Enrichment-only data may still work; reasoning
              requests below may fail.
            </div>
          )}

          <div className="sticky top-0 z-30 rounded-2xl border border-slate-800 bg-slate-950/95 px-4 py-3 shadow-xl backdrop-blur">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <div className="hidden shrink-0 md:block">
                <p className="text-[10px] font-semibold uppercase tracking-[0.24em] text-slate-500">Threat-Defense Workbench</p>
                <h1 className="text-sm font-semibold text-slate-100">Single Pane of Glass</h1>
              </div>
              <div className="min-w-[14rem] max-w-xl flex-1">
                <CveAnalyzeForm value={cve} busy={reasoning.loading} onSubmit={setCve} />
              </div>
              {cve.trim() && (
                <button
                  type="button"
                  onClick={reasoning.reload}
                  disabled={reasoning.loading}
                  className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-sky-400 hover:text-sky-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-link disabled:opacity-50"
                >
                  {reasoning.loading ? "Refreshing…" : "Refresh"}
                </button>
              )}
              {reasoning.loading ? (
                <span className="animate-pulse rounded-full border border-sky-500/40 bg-sky-950/40 px-2.5 py-1 text-[11px] font-medium text-sky-300">
                  Reasoning…
                </span>
              ) : reasoning.result ? (
                <CommandSignals result={reasoning.result} />
              ) : (
                <span className="rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-400">Ready</span>
              )}
            </div>
          </div>

          {!cve.trim() ? (
            <WorkbenchEmptyState />
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
              onReviewerChange={setReviewer}
            />
          ) : null}
        </>
      )}
    </div>
  );
}
