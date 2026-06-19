// Optional FastAPI sidecar client (`CVEzD3FEND api`, src/CVEzD3FEND/api/app.py).
// Every call here is best-effort: callers must handle rejection by disabling
// actions / showing ErrorState, never by leaving a dead button (UIX_CONTRACT §3, §8).
import type { AICandidate } from "./types";
import type { BatchAnalysisRequest, BatchReasoningResult, EnrichmentResult, RankedRoute, ReasoningEdge, ReasoningResult, SourceMode } from "./reasoningTypes";

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://127.0.0.1:8000";

export class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit, timeoutMs = 30_000): Promise<T> {
  const timeoutController = new AbortController();
  const timeoutId = window.setTimeout(() => timeoutController.abort(), timeoutMs);
  const externalSignal = init?.signal;
  const abortFromCaller = () => timeoutController.abort();
  if (externalSignal?.aborted) timeoutController.abort();
  else externalSignal?.addEventListener("abort", abortFromCaller, { once: true });

  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
      signal: timeoutController.signal,
    });
  } catch {
    if (timeoutController.signal.aborted) {
      throw new ApiError(externalSignal?.aborted ? "Request cancelled." : "The CVEzD3FEND API request timed out.");
    }
    throw new ApiError(
      `Cannot reach the CVEzD3FEND API sidecar at ${API_BASE_URL}. Start it with CVEzD3FEND api.`
    );
  } finally {
    window.clearTimeout(timeoutId);
    externalSignal?.removeEventListener("abort", abortFromCaller);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* body wasn't JSON — fall back to statusText */
    }
    throw new ApiError(detail || `Request failed with HTTP ${res.status}.`, res.status);
  }
  return res.json() as Promise<T>;
}

export interface ApiHealth {
  status: string;
  version: string;
  bundle_path: string;
  bundle_available: boolean;
}

export function apiHealth(): Promise<ApiHealth> {
  return request<ApiHealth>("/api/health");
}

export interface CandidateQueue {
  total: number;
  candidates: AICandidate[];
}

export function listCandidates(status?: string): Promise<CandidateQueue> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : "";
  return request<CandidateQueue>(`/api/ai/candidates${qs}`);
}

export function generateCandidates(limit: number): Promise<{ generated: number; candidates: AICandidate[] }> {
  return request("/api/ai/candidates/generate", { method: "POST", body: JSON.stringify({ limit }) });
}

export function validateCandidates(): Promise<{
  total: number;
  validated: number;
  rejected: number;
  candidates: AICandidate[];
}> {
  return request("/api/ai/candidates/validate", { method: "POST" });
}

export function promoteCandidate(candidateId: string, reviewer: string): Promise<{ promoted: unknown }> {
  return request(`/api/ai/candidates/${encodeURIComponent(candidateId)}/promote`, {
    method: "POST",
    body: JSON.stringify({ reviewer }),
  });
}

export function rejectCandidate(candidateId: string, reviewer: string): Promise<{ rejected: AICandidate }> {
  return request(`/api/ai/candidates/${encodeURIComponent(candidateId)}/reject`, {
    method: "POST",
    body: JSON.stringify({ reviewer }),
  });
}

export interface AiCitation {
  ref: string;
  source_url: string | null;
  confidence: number;
}

export interface AiContextResult {
  route_id?: string;
  attack_id?: string;
  text: string;
  citations: AiCitation[];
}

export function explainRoute(routeId: string): Promise<AiContextResult> {
  return request(`/api/ai/explain-route/${encodeURIComponent(routeId)}`, { method: "POST" });
}

export function huntHypothesis(attackId: string): Promise<AiContextResult> {
  return request(`/api/ai/hunt-hypothesis/${encodeURIComponent(attackId)}`, { method: "POST" });
}

export function detectionBrief(attackId: string): Promise<AiContextResult> {
  return request(`/api/ai/detection-brief/${encodeURIComponent(attackId)}`, { method: "POST" });
}

// ---------------------------------------------------------------------------
// Reasoning plane (live enrichment + multi-framework reasoning)
// ---------------------------------------------------------------------------

export interface ApiMeta {
  bundle_version: string;
  generated_at: string;
  schema_version: string;
  node_count: number;
  edge_count: number;
  route_count: number;
  sources: unknown[];
  enrichment_sources: string[];
  reasoning_available: boolean;
  quality: unknown;
  coverage_summary: unknown;
}

export function getMeta(): Promise<ApiMeta> {
  return request<ApiMeta>("/api/meta");
}

/** Live/cached/offline enrichment profile for a CVE (no reasoning/route work). */
export function enrichCve(cveId: string): Promise<EnrichmentResult> {
  return request<EnrichmentResult>(`/api/enrich/${encodeURIComponent(cveId)}`);
}

/** Full reasoning result: risk, classified route contract, narrative, SOC/detection/hunting/CTEM, exports. */
export function reasonCve(cveId: string): Promise<ReasoningResult> {
  return request<ReasoningResult>(`/api/reason/${encodeURIComponent(cveId)}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireStringArray(record: Record<string, unknown>, field: string): string[] {
  const value = record[field];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new ApiError(`Invalid batch response: ${field} must be a string array.`);
  }
  return value;
}

function validateGraphSlice(value: unknown, field: string): { nodeIds: Set<string>; edgeIds: Set<string> } {
  if (!isRecord(value) || !Array.isArray(value.nodes) || !Array.isArray(value.edges)) {
    throw new ApiError(`Invalid batch response: ${field} is not a GraphSlice.`);
  }
  const nodeIds = new Set<string>();
  for (const node of value.nodes) {
    if (!isRecord(node) || typeof node.id !== "string" || !node.id || nodeIds.has(node.id)) {
      throw new ApiError(`Invalid batch response: ${field} contains an invalid or duplicate node id.`);
    }
    if (typeof node.metadata !== "object" || node.metadata === null || Array.isArray(node.metadata)) {
      throw new ApiError(`Invalid batch response: ${field} contains invalid node metadata.`);
    }
    requireStringArray(node, "source_refs");
    requireStringArray(node, "external_refs");
    nodeIds.add(node.id);
  }
  const edgeIds = new Set<string>();
  for (const edge of value.edges) {
    if (!isRecord(edge) || typeof edge.id !== "string" || !edge.id || typeof edge.source !== "string" || typeof edge.target !== "string" || edgeIds.has(edge.id)) {
      throw new ApiError(`Invalid batch response: ${field} contains an invalid or duplicate edge.`);
    }
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) {
      throw new ApiError(`Invalid batch response: ${field} contains an edge with a missing endpoint.`);
    }
    requireStringArray(edge, "evidence");
    edgeIds.add(edge.id);
  }
  return { nodeIds, edgeIds };
}

function validateRoutes(value: unknown, field: string, graph: { nodeIds: Set<string>; edgeIds: Set<string> }): RankedRoute[] {
  if (!Array.isArray(value)) throw new ApiError(`Invalid batch response: ${field} must be an array.`);
  const routeIds = new Set<string>();
  return value.map((route, index) => {
    if (!isRecord(route) || typeof route.route_id !== "string" || !route.route_id || routeIds.has(route.route_id)) {
      throw new ApiError(`Invalid batch response: ${field}[${index}] has an invalid or duplicate route id.`);
    }
    if (typeof route.cve_id !== "string" || !/^CVE-\d{4}-\d{4,}$/i.test(route.cve_id)) {
      throw new ApiError(`Invalid batch response: ${field}[${index}] has an invalid CVE id.`);
    }
    const nodeIds = requireStringArray(route, "node_ids");
    const edgeIds = requireStringArray(route, "edge_ids");
    requireStringArray(route, "attack_ids");
    requireStringArray(route, "defend_ids");
    requireStringArray(route, "selection_reasons");
    requireStringArray(route, "provenance");
    requireStringArray(route, "gaps");
    if (nodeIds.some((id) => !graph.nodeIds.has(id)) || edgeIds.some((id) => !graph.edgeIds.has(id))) {
      throw new ApiError(`Invalid batch response: ${field}[${index}] references graph elements that were not delivered.`);
    }
    if (typeof route.score !== "number" || typeof route.confidence !== "number" || typeof route.completeness !== "number") {
      throw new ApiError(`Invalid batch response: ${field}[${index}] has invalid numeric fields.`);
    }
    routeIds.add(route.route_id);
    return route as unknown as RankedRoute;
  });
}

export function validateBatchReasoningResult(value: unknown, includeAllCandidates: boolean): BatchReasoningResult {
  if (!isRecord(value)) throw new ApiError("Invalid batch response: expected an object.");
  ["requested_cves", "found_cves", "missing_cves", "invalid_inputs", "shared_attack_techniques_selected", "shared_attack_techniques_all_candidates", "shared_defenses_selected", "shared_defenses_all_candidates", "warnings", "errors"].forEach((field) => requireStringArray(value, field));
  if (!Array.isArray(value.candidate_routes) || !Array.isArray(value.selected_routes)) {
    throw new ApiError("Invalid batch response: candidate_routes and selected_routes must be arrays.");
  }
  if (typeof value.status !== "string" || typeof value.available_route_count !== "number" || typeof value.selected_route_count !== "number") {
    throw new ApiError("Invalid batch response: status and route counts are required.");
  }
  if (!isRecord(value.selection_summary) || !isRecord(value.narrative) || !isRecord(value.provenance)) {
    throw new ApiError("Invalid batch response: selection_summary, narrative and provenance are required.");
  }
  if (typeof value.selection_summary.selection_mode !== "string" || typeof value.selection_summary.fallback_used !== "boolean") {
    throw new ApiError("Invalid batch response: selection mode and fallback state are required.");
  }
  const narrative = value.narrative;
  ["executive_summary_es", "operational_summary_es", "technical_summary_es"].forEach((field) => {
    if (typeof narrative[field] !== "string") throw new ApiError(`Invalid batch response: narrative.${field} must be text.`);
  });

  const selectedGraph = validateGraphSlice(value.selected_graph, "selected_graph");
  const selectedRoutes = validateRoutes(value.selected_routes, "selected_routes", selectedGraph);
  if (selectedRoutes.length !== value.selected_route_count) {
    throw new ApiError("Invalid batch response: selected route count does not match selected_routes.");
  }
  const ranks = selectedRoutes.map((route) => route.selection_rank);
  if (ranks.some((rank) => !Number.isInteger(rank) || (rank ?? 0) < 1) || new Set(ranks).size !== ranks.length) {
    throw new ApiError("Invalid batch response: selection_rank values must be unique positive integers.");
  }
  const sortedRanks = ranks.slice().sort((a, b) => (a ?? 0) - (b ?? 0));
  if (sortedRanks.some((rank, index) => rank !== index + 1)) {
    throw new ApiError("Invalid batch response: selection_rank values must be contiguous and one-based.");
  }

  if (includeAllCandidates) {
    const candidateGraph = validateGraphSlice(value.candidate_graph, "candidate_graph");
    const candidateRoutes = validateRoutes(value.candidate_routes, "candidate_routes", candidateGraph);
    if (candidateRoutes.length !== value.available_route_count) {
      throw new ApiError("Invalid batch response: available route count does not match candidate_routes.");
    }
    if ([...selectedGraph.nodeIds].some((id) => !candidateGraph.nodeIds.has(id)) || [...selectedGraph.edgeIds].some((id) => !candidateGraph.edgeIds.has(id))) {
      throw new ApiError("Invalid batch response: selected_graph is not a subset of candidate_graph.");
    }
  } else {
    if (value.candidate_graph !== undefined) throw new ApiError("Invalid batch response: candidate_graph was returned without opt-in.");
    if (value.candidate_routes.length !== 0) throw new ApiError("Invalid batch response: candidate_routes were returned without opt-in.");
  }
  return value as unknown as BatchReasoningResult;
}

/** Contextual multi-CVE analysis. The caller owns cancellation and Selected/All policy. */
export async function reasonCves(requestBody: BatchAnalysisRequest, signal?: AbortSignal): Promise<BatchReasoningResult> {
  const payload = await request<unknown>(
    "/api/reason/batch",
    { method: "POST", body: JSON.stringify(requestBody), signal },
    45_000
  );
  return validateBatchReasoningResult(payload, requestBody.include_all_candidates);
}

export interface ProvenanceResult {
  input: string;
  normalized_input: string;
  provenance: Record<string, ReasoningEdge[]>;
}

export function getProvenance(cveId: string): Promise<ProvenanceResult> {
  return request<ProvenanceResult>(`/api/provenance/${encodeURIComponent(cveId)}`);
}

export interface EvidenceResult {
  source: string;
  subject: string;
  mode: SourceMode;
  from_cache: boolean;
  fallback_used: boolean;
  evidence: Record<string, unknown>;
}

/** Raw normalized evidence from a single live source for `subject` (e.g. a CVE id). */
export function getEvidence(source: string, subject: string, mode: SourceMode = "live"): Promise<EvidenceResult> {
  const qs = new URLSearchParams({ subject, mode });
  return request<EvidenceResult>(`/api/evidence/${encodeURIComponent(source)}?${qs.toString()}`);
}

/** AI-proposed route for a CVE (AI_ASSISTANCE_CONTRACT: proposal only, never canonical). */
export function proposeRoute(cveId: string): Promise<Record<string, unknown>> {
  return request("/api/ai/propose-route", { method: "POST", body: JSON.stringify({ cve_id: cveId }) });
}

/** Deterministic validation of the reasoning route for a CVE against the bundle/contracts. */
export function validateRoute(cveId: string): Promise<Record<string, unknown>> {
  return request("/api/ai/validate-route", { method: "POST", body: JSON.stringify({ cve_id: cveId }) });
}

/** Promote a reasoning edge to the canonical overlay. Requires a named human reviewer. */
export function promoteEdge(edgeId: string, reviewer: string): Promise<Record<string, unknown>> {
  return request("/api/review/promote-edge", {
    method: "POST",
    body: JSON.stringify({ edge_id: edgeId, reviewer }),
  });
}
