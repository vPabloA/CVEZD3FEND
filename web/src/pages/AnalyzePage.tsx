import { useCallback, useMemo } from "react";
import ErrorState from "@/components/ErrorState";
import LoadingState from "@/components/LoadingState";
import CveAnalyzeForm from "@/components/reasoning/CveAnalyzeForm";
import BatchCandidateRouteList from "@/components/reasoning/batch/BatchCandidateRouteList";
import BatchConvergencePanel from "@/components/reasoning/batch/BatchConvergencePanel";
import BatchCveFilters from "@/components/reasoning/batch/BatchCveFilters";
import BatchDecisionSummary from "@/components/reasoning/batch/BatchDecisionSummary";
import BatchEvidencePanel from "@/components/reasoning/batch/BatchEvidencePanel";
import BatchNarrativePanel from "@/components/reasoning/batch/BatchNarrativePanel";
import BatchRouteRanking from "@/components/reasoning/batch/BatchRouteRanking";
import ThreatDefenseGraphNavigator from "@/components/reasoning/graph/ThreatDefenseGraphNavigator";
import { buildBatchGraphModel, projectGraphSliceByRoutes } from "@/components/reasoning/graph/graphAdapter";
import { useApiAvailability, useBatchReasoning } from "@/hooks/useReasoning";
import type { BatchAnalysisRequest, RankedRoute } from "@/lib/reasoningTypes";
import { useQueryParam } from "@/lib/url";

function WorkbenchIdle() {
  return (
    <section className="rounded-2xl border border-dashed border-slate-700 bg-slate-950/70 p-10 text-center">
      <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-sky-400">Selected routes are the product</p>
      <h2 className="mt-2 text-xl font-semibold text-slate-100">Analyze several CVEs in one operational context</h2>
      <p className="mx-auto mt-2 max-w-2xl text-sm leading-relaxed text-slate-400">CVEZD3FEND will perform exact Galeax lookup, traverse only catalog-demonstrated edges, score routes deterministically, optionally rerank a validated shortlist, and return a reduced graph with evidence.</p>
      <p className="mt-4 font-mono text-sm text-slate-500">CVE → CWE → CAPEC → ATT&amp;CK → D3FEND</p>
    </section>
  );
}

export default function AnalyzePage() {
  const [deepLinkedCve] = useQueryParam("cve");
  const api = useApiAvailability();
  const workbench = useBatchReasoning(api.available === true);
  const selectedResult = workbench.selectedResult;
  const activeResult = workbench.activeView === "all" && workbench.allResult ? workbench.allResult : selectedResult;

  const allCvesSelected = workbench.filteredCves.length === 0;
  const activeRoutes = useMemo(() => {
    if (!activeResult) return [];
    const routes = workbench.activeView === "all" ? activeResult.candidate_routes : activeResult.selected_routes;
    if (allCvesSelected) return routes;
    return routes.filter((route) => workbench.filteredCves.includes(route.cve_id));
  }, [activeResult, allCvesSelected, workbench.activeView, workbench.filteredCves]);

  const activeSlice = useMemo(() => {
    if (!activeResult) return null;
    const slice = workbench.activeView === "all" ? activeResult.candidate_graph : activeResult.selected_graph;
    if (!slice) return null;
    return allCvesSelected ? slice : projectGraphSliceByRoutes(slice, activeRoutes);
  }, [activeResult, activeRoutes, allCvesSelected, workbench.activeView]);

  const focusedRoute = useMemo<RankedRoute | null>(() => {
    if (!activeResult) return null;
    return activeRoutes.find((route) => route.route_id === workbench.selectedRouteId) ?? activeRoutes[0] ?? null;
  }, [activeResult, activeRoutes, workbench.selectedRouteId]);

  const graphBuilder = useCallback(
    (mode: Parameters<typeof buildBatchGraphModel>[2], selection: Parameters<typeof buildBatchGraphModel>[3]) =>
      buildBatchGraphModel(activeSlice ?? { nodes: [], edges: [] }, activeRoutes, mode, selection, focusedRoute?.route_id),
    [activeRoutes, activeSlice, focusedRoute?.route_id]
  );

  const graphContext = useMemo(() => ({
    eyebrow: "Aggregated Threat-Defense Graph",
    title: workbench.activeView === "all" ? "Complete candidate universe" : "Selected contextual routes",
    badge: workbench.activeView === "all" ? "All candidates" : "Selected Top-K",
    status: activeResult?.status === "partial" ? "Partial result" : "Catalog-backed",
    sourceMode: "Galeax + catalogs",
    reviewRequired: activeResult?.selection_summary.fallback_used ?? false,
    errors: activeResult?.errors ?? [],
    rootId: focusedRoute?.node_ids[0],
    scopeLabel: activeResult
      ? workbench.activeView === "all"
        ? `Complete universe: ${activeResult.available_route_count} routes`
        : `${activeResult.selected_route_count} selected of ${activeResult.available_route_count} available`
      : undefined,
  }), [activeResult, focusedRoute?.node_ids, workbench.activeView]);

  const handleSubmit = (request: BatchAnalysisRequest) => {
    void workbench.submit(request);
  };

  const loadingSelected = workbench.phase === "validating" || workbench.phase === "loading-selected";
  const loadingAll = workbench.phase === "loading-all";
  const attackConvergence = activeResult
    ? workbench.activeView === "all"
      ? activeResult.shared_attack_techniques_all_candidates
      : activeResult.shared_attack_techniques_selected
    : [];
  const defenseConvergence = activeResult
    ? workbench.activeView === "all"
      ? activeResult.shared_defenses_all_candidates
      : activeResult.shared_defenses_selected
    : [];

  return (
    <div className="mx-auto flex w-full max-w-screen-2xl flex-col gap-5 px-4 py-5 lg:px-6">
      {api.available === null && <LoadingState label="Checking API sidecar…" />}
      {api.available === false && (
        <div className="rounded-2xl border border-amber-500/40 bg-amber-950/20 p-4 text-sm text-amber-100" role="alert">
          <p className="font-semibold">API sidecar not reachable{api.error ? `: ${api.error}` : "."}</p>
          <p className="mt-1 text-amber-200">Start it with <code className="rounded bg-slate-950 px-1.5 py-0.5">CVEzD3FEND api</code>. No synthetic result or client-side mapping will be shown.</p>
          <button type="button" onClick={api.recheck} className="mt-3 rounded-lg border border-amber-500/50 px-3 py-2 text-xs font-semibold hover:bg-amber-950/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-300">Check again</button>
        </div>
      )}

      {api.available && (
        <>
          <CveAnalyzeForm initialValue={deepLinkedCve} busy={loadingSelected} onSubmit={handleSubmit} onClear={workbench.reset} />

          {workbench.phase === "idle" && <WorkbenchIdle />}
          {loadingSelected && <div aria-live="polite"><LoadingState label="Running exact lookup, deterministic scoring and Selected route projection…" /></div>}
          {workbench.phase === "error" && workbench.error && <ErrorState message={workbench.error} />}

          {selectedResult && activeResult && (
            <>
              <BatchDecisionSummary
                result={selectedResult}
                activeView={workbench.activeView}
                allAvailable={Boolean(workbench.allResult)}
                loadingAll={loadingAll}
                onViewChange={workbench.setActiveView}
              />

              {workbench.allError && (
                <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-3 text-sm text-rose-100">
                  All candidates could not be loaded: {workbench.allError}. Selected remains available and unchanged.
                </div>
              )}
              {loadingAll && <div aria-live="polite"><LoadingState label="Loading the complete candidate universe…" /></div>}

              <div id="analysis-workbench" className="grid gap-4 xl:grid-cols-[22rem_minmax(0,1fr)]">
                <aside className="flex min-w-0 flex-col gap-3">
                  <BatchCveFilters
                    found={selectedResult.found_cves}
                    represented={selectedResult.selection_summary.represented_cves}
                    selected={workbench.filteredCves}
                    onChange={workbench.setFilteredCves}
                  />
                  <BatchRouteRanking routes={selectedResult.selected_routes.filter((route) => allCvesSelected || workbench.filteredCves.includes(route.cve_id))} selectedRouteId={focusedRoute?.route_id ?? null} onSelect={(routeId) => { workbench.setSelectedRouteId(routeId); workbench.setGraphSelection(null); }} />
                  {workbench.activeView === "all" && (
                    <BatchCandidateRouteList routes={activeRoutes} onFocus={(routeId) => { workbench.setSelectedRouteId(routeId); workbench.setGraphSelection(null); }} />
                  )}
                  <BatchConvergencePanel title={workbench.activeView === "all" ? "ATT&CK convergence — All" : "ATT&CK convergence — Selected"} values={attackConvergence} routes={activeRoutes} kind="attack" />
                  <BatchConvergencePanel title={workbench.activeView === "all" ? "D3FEND reuse — All" : "D3FEND reuse — Selected"} values={defenseConvergence} routes={activeRoutes} kind="defense" />
                </aside>

                <main className="min-w-0">
                  {!activeSlice || activeRoutes.length === 0 ? (
                    <section className="rounded-2xl border border-amber-500/40 bg-amber-950/20 p-8 text-center text-amber-100">
                      <h2 className="text-lg font-semibold">No graphable routes in the active projection</h2>
                      <p className="mt-2 text-sm text-amber-200">Review the CVE filter, missing identifiers, warnings and route gaps. The application does not fabricate graph nodes for missing or invalid CVEs.</p>
                    </section>
                  ) : (
                    <>
                      {workbench.activeView === "all" && activeSlice.nodes.length > 64 && (
                        <div className="mb-3 rounded-xl border border-violet-500/40 bg-violet-950/30 p-3 text-sm text-violet-100">
                          The complete universe contains {activeResult.available_route_count} routes and {activeSlice.nodes.length} nodes. The navigator uses progressive visual disclosure; the route list and backend evidence remain complete.
                        </div>
                      )}
                      <ThreatDefenseGraphNavigator
                        graphBuilder={graphBuilder}
                        context={graphContext}
                        selection={workbench.graphSelection}
                        onSelectNode={(nodeId) => workbench.setGraphSelection({ kind: "node", id: nodeId })}
                        onSelectEdge={(edgeId) => workbench.setGraphSelection(edgeId ? { kind: "edge", id: edgeId } : null)}
                        onClearSelection={() => workbench.setGraphSelection(null)}
                      />
                    </>
                  )}
                </main>
              </div>

              <BatchNarrativePanel narrative={selectedResult.narrative} />
              <BatchEvidencePanel result={activeResult} route={focusedRoute} graph={activeSlice} />
            </>
          )}
        </>
      )}
    </div>
  );
}
