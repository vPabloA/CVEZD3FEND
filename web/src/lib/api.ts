// Optional FastAPI sidecar client (`CVEzD3FEND api`, src/CVEzD3FEND/api/app.py).
// Every call here is best-effort: callers must handle rejection by disabling
// actions / showing ErrorState, never by leaving a dead button (UIX_CONTRACT §3, §8).
import type { AICandidate } from "./types";

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://127.0.0.1:8000";

export class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
    });
  } catch {
    throw new ApiError(
      `Cannot reach the CVEzD3FEND API sidecar at ${API_BASE_URL}. Start it with \`CVEzD3FEND api\`.`
    );
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* body wasn't JSON — fall back to statusText */
    }
    throw new ApiError(detail, res.status);
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
