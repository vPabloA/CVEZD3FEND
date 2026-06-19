import { afterEach, describe, expect, it, vi } from "vitest";
import { reasonCves, validateBatchReasoningResult } from "@/lib/api";
import type { BatchAnalysisRequest } from "@/lib/reasoningTypes";
import { makeBatchReasoningResult } from "@/test/fixtures/batchReasoningResult";

const request: BatchAnalysisRequest = {
  cve_ids: ["CVE-2025-0168", "CVE-2026-0544"],
  context: { technologies: ["Windows"], exposure: ["production"], priorities: ["initial access"], audience: "SOC" },
  top_k: 5,
  include_all_candidates: false,
  use_ai: false,
};

afterEach(() => vi.restoreAllMocks());

describe("batch API contract", () => {
  it("sends Selected explicitly without automatically requesting candidates", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(makeBatchReasoningResult()), { status: 200, headers: { "Content-Type": "application/json" } }));
    await reasonCves(request);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ include_all_candidates: false, top_k: 5 });
  });

  it("requires candidate_graph when All is explicitly requested", () => {
    expect(() => validateBatchReasoningResult(makeBatchReasoningResult(), true)).toThrow(/candidate_graph/i);
  });

  it("accepts a complete All payload", () => {
    expect(validateBatchReasoningResult(makeBatchReasoningResult({}, true), true).candidate_graph?.nodes).toHaveLength(9);
  });

  it("rejects candidate_graph returned without client opt-in", () => {
    expect(() => validateBatchReasoningResult(makeBatchReasoningResult({}, true), false)).toThrow(/without opt-in/i);
  });

  it("rejects graph edges whose endpoints are absent", () => {
    const malformed = makeBatchReasoningResult({ selected_graph: { nodes: [], edges: makeBatchReasoningResult().selected_graph.edges } });
    expect(() => validateBatchReasoningResult(malformed, false)).toThrow(/missing endpoint/i);
  });

  it("turns HTTP validation errors into readable ApiError messages", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ detail: "maximum is 50" }), { status: 422, headers: { "Content-Type": "application/json" } }));
    await expect(reasonCves(request)).rejects.toMatchObject({ name: "ApiError", message: "maximum is 50", status: 422 });
  });

  it("honors caller cancellation", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    }));
    const controller = new AbortController();
    const pending = reasonCves(request, controller.signal);
    controller.abort();
    await expect(pending).rejects.toEqual(expect.objectContaining({ name: "ApiError", message: "Request cancelled." }));
  });
  it("rejects routes that reference graph elements not delivered by the backend", () => {
    const malformed = makeBatchReasoningResult({
      selected_routes: [
        { ...makeBatchReasoningResult().selected_routes[0], node_ids: ["CVE-2025-0168", "CWE-NOT-DELIVERED"] },
        makeBatchReasoningResult().selected_routes[1],
      ],
    });
    expect(() => validateBatchReasoningResult(malformed, false)).toThrow(/not delivered/i);
  });

  it("rejects non-contiguous or duplicated selection ranks", () => {
    const base = makeBatchReasoningResult();
    const malformed = makeBatchReasoningResult({
      selected_routes: base.selected_routes.map((route) => ({ ...route, selection_rank: 2 })),
    });
    expect(() => validateBatchReasoningResult(malformed, false)).toThrow(/selection_rank/i);
  });

  it("rejects an All graph that does not contain the complete candidate universe", () => {
    const all = makeBatchReasoningResult({}, true);
    const malformed = makeBatchReasoningResult({
      candidate_graph: { ...all.candidate_graph!, edges: all.candidate_graph!.edges.slice(0, -1) },
    }, true);
    expect(() => validateBatchReasoningResult(malformed, true)).toThrow(/not delivered/i);
  });

});
