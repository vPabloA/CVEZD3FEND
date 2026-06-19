import { useEffect, useRef, useState } from "react";
import { ApiError, apiHealth, getMeta, reasonCve, reasonCves, type ApiMeta } from "@/lib/api";
import type { BatchAnalysisRequest, BatchReasoningResult, ReasoningResult } from "@/lib/reasoningTypes";
import type { GraphSelection } from "@/components/reasoning/graph/graphTypes";

export interface ApiAvailability {
  /** null while the initial health check is in flight. */
  available: boolean | null;
  error: string | null;
  meta: ApiMeta | null;
  recheck: () => void;
}

/**
 * Checks the CVEzD3FEND API sidecar (`CVEzD3FEND api`) once on mount, and
 * fetches `/api/meta` (enrichment source list, reasoning availability) when
 * it's reachable. Every reasoning-plane view gates on `available` before
 * issuing live requests (UIX_CONTRACT §3 — degraded states must be honest).
 */
export function useApiAvailability(): ApiAvailability {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<ApiMeta | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setAvailable(null);
    setError(null);
    apiHealth()
      .then(() => {
        if (cancelled) return;
        setAvailable(true);
        getMeta()
          .then((m) => !cancelled && setMeta(m))
          .catch(() => undefined);
      })
      .catch((err: ApiError) => {
        if (cancelled) return;
        setAvailable(false);
        setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  return { available, error, meta, recheck: () => setAttempt((n) => n + 1) };
}

export interface ReasoningState {
  result: ReasoningResult | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/**
 * Fetches `/api/reason/{cveId}` — the full classified route contract, risk
 * summary, narrative and SOC/detection/hunting/CTEM outputs for one CVE.
 * Pass an empty `cveId` (or `enabled=false`) to skip the request, e.g. while
 * the API sidecar hasn't been confirmed reachable yet.
 */
export function useReasoning(cveId: string, enabled: boolean): ReasoningState {
  const [result, setResult] = useState<ReasoningResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!enabled || !cveId.trim()) {
      setResult(null);
      setError(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    reasonCve(cveId.trim())
      .then((r) => {
        if (!cancelled) setResult(r);
      })
      .catch((err: ApiError) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [cveId, enabled, attempt]);

  return { result, loading, error, reload: () => setAttempt((n) => n + 1) };
}

// ---------------------------------------------------------------------------
// Contextual multi-CVE workbench state machine
// ---------------------------------------------------------------------------


export type BatchWorkbenchPhase =
  | "idle"
  | "validating"
  | "loading-selected"
  | "selected-ready"
  | "loading-all"
  | "all-ready"
  | "partial"
  | "error";

export type BatchView = "selected" | "all";

export function batchRequestSignature(request: BatchAnalysisRequest): string {
  const normalized = {
    cve_ids: [...new Set(request.cve_ids.map((value) => value.trim().toUpperCase()).filter(Boolean))].sort(),
    technologies: [...new Set(request.context.technologies.map((value) => value.trim()).filter(Boolean))].sort(),
    exposure: [...new Set(request.context.exposure.map((value) => value.trim()).filter(Boolean))].sort(),
    priorities: [...new Set(request.context.priorities.map((value) => value.trim()).filter(Boolean))].sort(),
    audience: request.context.audience,
    top_k: request.top_k,
    use_ai: request.use_ai,
  };
  return JSON.stringify(normalized);
}

export interface BatchReasoningState {
  phase: BatchWorkbenchPhase;
  request: BatchAnalysisRequest | null;
  selectedResult: BatchReasoningResult | null;
  allResult: BatchReasoningResult | null;
  activeView: BatchView;
  filteredCves: string[];
  selectedRouteId: string | null;
  graphSelection: GraphSelection;
  error: string | null;
  allError: string | null;
  submit: (request: BatchAnalysisRequest) => Promise<void>;
  loadAll: () => Promise<void>;
  setActiveView: (view: BatchView) => void;
  setFilteredCves: (cves: string[]) => void;
  setSelectedRouteId: (routeId: string | null) => void;
  setGraphSelection: (selection: GraphSelection) => void;
  reset: () => void;
}

export function useBatchReasoning(enabled: boolean): BatchReasoningState {
  const [phase, setPhase] = useState<BatchWorkbenchPhase>("idle");
  const [requestState, setRequestState] = useState<BatchAnalysisRequest | null>(null);
  const [selectedResult, setSelectedResult] = useState<BatchReasoningResult | null>(null);
  const [allResult, setAllResult] = useState<BatchReasoningResult | null>(null);
  const [activeView, setActiveViewState] = useState<BatchView>("selected");
  const [filteredCves, setFilteredCvesState] = useState<string[]>([]);
  const [selectedRouteId, setSelectedRouteIdState] = useState<string | null>(null);
  const [graphSelection, setGraphSelectionState] = useState<GraphSelection>(null);
  const [error, setError] = useState<string | null>(null);
  const [allError, setAllError] = useState<string | null>(null);
  const selectedController = useRef<AbortController | null>(null);
  const allController = useRef<AbortController | null>(null);
  const allCache = useRef(new Map<string, BatchReasoningResult>());

  useEffect(() => () => {
    selectedController.current?.abort();
    allController.current?.abort();
  }, []);

  const submit = async (request: BatchAnalysisRequest) => {
    selectedController.current?.abort();
    allController.current?.abort();
    const controller = new AbortController();
    selectedController.current = controller;
    const selectedRequest = { ...request, include_all_candidates: false };

    setPhase("validating");
    setRequestState(selectedRequest);
    setSelectedResult(null);
    setAllResult(null);
    setActiveViewState("selected");
    setFilteredCvesState([]);
    setSelectedRouteIdState(null);
    setGraphSelectionState(null);
    setError(null);
    setAllError(null);

    if (!enabled) {
      setError("The reasoning API is not available.");
      setPhase("error");
      return;
    }

    setPhase("loading-selected");
    try {
      const result = await reasonCves(selectedRequest, controller.signal);
      if (controller.signal.aborted) return;
      setSelectedResult(result);
      setFilteredCvesState([]);
      setSelectedRouteIdState(result.selected_routes[0]?.route_id ?? null);
      setPhase(result.status === "partial" ? "partial" : "selected-ready");
    } catch (caught) {
      if (controller.signal.aborted) return;
      const message = caught instanceof ApiError ? caught.message : "Multi-CVE analysis failed.";
      setError(message);
      setPhase("error");
    }
  };

  const loadAll = async () => {
    if (!requestState || !selectedResult || !enabled) return;
    const signature = batchRequestSignature(requestState);
    const cached = allCache.current.get(signature);
    if (cached) {
      setAllResult(cached);
      setActiveViewState("all");
      setPhase(cached.status === "partial" ? "partial" : "all-ready");
      setAllError(null);
      return;
    }

    allController.current?.abort();
    const controller = new AbortController();
    allController.current = controller;
    setPhase("loading-all");
    setAllError(null);
    try {
      const result = await reasonCves({ ...requestState, include_all_candidates: true }, controller.signal);
      if (controller.signal.aborted) return;
      allCache.current.set(signature, result);
      setAllResult(result);
      setActiveViewState("all");
      setPhase(result.status === "partial" ? "partial" : "all-ready");
    } catch (caught) {
      if (controller.signal.aborted) return;
      const message = caught instanceof ApiError ? caught.message : "The full candidate universe could not be loaded.";
      setAllError(message);
      setActiveViewState("selected");
      setPhase(selectedResult.status === "partial" ? "partial" : "selected-ready");
    }
  };

  const setActiveView = (view: BatchView) => {
    if (view === "all") {
      if (allResult) {
        setActiveViewState("all");
        setPhase(allResult.status === "partial" ? "partial" : "all-ready");
      } else {
        void loadAll();
      }
      return;
    }
    setActiveViewState("selected");
    setPhase(selectedResult?.status === "partial" ? "partial" : selectedResult ? "selected-ready" : "idle");
    if (selectedResult && !selectedResult.selected_routes.some((route) => route.route_id === selectedRouteId)) {
      setSelectedRouteIdState(selectedResult.selected_routes[0]?.route_id ?? null);
    }
    if (graphSelection?.kind === "node" && selectedResult) {
      const present = selectedResult.selected_graph.nodes.some((node) => node.id === graphSelection.id);
      if (!present) setGraphSelectionState(null);
    }
    if (graphSelection?.kind === "edge" && selectedResult) {
      const present = selectedResult.selected_graph.edges.some((edge) => edge.id === graphSelection.id);
      if (!present) setGraphSelectionState(null);
    }
  };

  const reset = () => {
    selectedController.current?.abort();
    allController.current?.abort();
    setPhase("idle");
    setRequestState(null);
    setSelectedResult(null);
    setAllResult(null);
    setActiveViewState("selected");
    setFilteredCvesState([]);
    setSelectedRouteIdState(null);
    setGraphSelectionState(null);
    setError(null);
    setAllError(null);
  };

  return {
    phase,
    request: requestState,
    selectedResult,
    allResult,
    activeView,
    filteredCves,
    selectedRouteId,
    graphSelection,
    error,
    allError,
    submit,
    loadAll,
    setActiveView,
    setFilteredCves: setFilteredCvesState,
    setSelectedRouteId: setSelectedRouteIdState,
    setGraphSelection: setGraphSelectionState,
    reset,
  };
}
