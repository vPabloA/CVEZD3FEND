import { describe, expect, it } from "vitest";
import { buildBatchGraphModel, projectGraphSliceByRoutes } from "@/components/reasoning/graph/graphAdapter";
import { candidateGraph, makeBatchReasoningResult, selectedGraph } from "@/test/fixtures/batchReasoningResult";

describe("batch graph projection", () => {
  const selected = makeBatchReasoningResult().selected_routes;
  const candidates = makeBatchReasoningResult({}, true).candidate_routes;

  it("uses only backend-delivered nodes and edges", () => {
    const model = buildBatchGraphModel(selectedGraph, selected, "focused-route", null, selected[0].route_id);
    expect(new Set(model.nodes.map((node) => node.id))).toEqual(new Set(selectedGraph.nodes.map((node) => node.id)));
    expect(new Set(model.links.map((link) => link.id))).toEqual(new Set(selectedGraph.edges.map((edge) => edge.id)));
  });

  it("does not create an edge while deduplicating shared paths", () => {
    const model = buildBatchGraphModel(selectedGraph, selected, "full-traceability", null, selected[0].route_id);
    expect(model.links).toHaveLength(selectedGraph.edges.length);
    expect(new Set(model.links.map((link) => link.id)).size).toBe(model.links.length);
  });

  it("preserves canonical source and target ids", () => {
    const model = buildBatchGraphModel(selectedGraph, selected, "full-traceability", null, selected[0].route_id);
    const link = model.links.find((item) => item.id === "E-CAPEC-ATTACK");
    expect(link).toMatchObject({ source: "CAPEC-13", target: "T1574.007" });
  });

  it("associates CVEs and routes with shared nodes", () => {
    const model = buildBatchGraphModel(selectedGraph, selected, "full-traceability", null, selected[0].route_id);
    const attack = model.nodes.find((node) => node.id === "T1574.007");
    expect(attack?.cveIds).toEqual(["CVE-2025-0168", "CVE-2026-0544"]);
    expect(attack?.routeIds).toHaveLength(2);
    expect(attack?.sharedCveCount).toBe(2);
  });

  it("marks reusable D3FEND nodes", () => {
    const model = buildBatchGraphModel(selectedGraph, selected, "full-traceability", null, selected[0].route_id);
    expect(model.nodes.find((node) => node.id === "D3-LFP")).toMatchObject({ routeRole: "defensive", defensiveReuseCount: 2 });
  });

  it("uses the focused route as the trace chain", () => {
    const model = buildBatchGraphModel(selectedGraph, selected, "focused-route", null, "ROUTE-CVE2-LFP");
    expect(model.routeChain[0]).toBe("CVE-2026-0544");
    expect(model.routeChain.at(-1)).toBe("D3-LFP");
  });

  it("projects a CVE filter without changing canonical identifiers", () => {
    const onlyFirst = projectGraphSliceByRoutes(selectedGraph, [selected[0]]);
    expect(onlyFirst.nodes.some((node) => node.id === "CVE-2025-0168")).toBe(true);
    expect(onlyFirst.nodes.some((node) => node.id === "CVE-2026-0544")).toBe(false);
    expect(onlyFirst.edges.every((edge) => onlyFirst.nodes.some((node) => node.id === edge.source) && onlyFirst.nodes.some((node) => node.id === edge.target))).toBe(true);
  });

  it("keeps All candidate relations supplied by candidate_graph", () => {
    const model = buildBatchGraphModel(candidateGraph, candidates, "full-traceability", null, "ROUTE-CVE2-FA");
    expect(model.nodes.some((node) => node.id === "T1027")).toBe(true);
    expect(model.links.some((link) => link.id === "E-T1027-D3FA")).toBe(true);
  });

  it("sanitizes unsafe source URLs instead of exposing javascript schemes", () => {
    const unsafe = {
      nodes: selectedGraph.nodes,
      edges: selectedGraph.edges.map((edge, index) => index === 0 ? { ...edge, source_url: "javascript:alert(1)" } : edge),
    };
    const model = buildBatchGraphModel(unsafe, selected, "full-traceability", null, selected[0].route_id);
    expect(model.links.find((link) => link.id === "E-CVE1-CWE")?.sourceUrl).toBeNull();
  });

  it("preserves the complete focused route while capping surrounding context", () => {
    const extraNodes = Array.from({ length: 40 }, (_, index) => ({
      ...candidateGraph.nodes[0], id: `EVID-${index}`, type: "evidence" as const, name: `Evidence ${index}`, title: `Evidence ${index}`,
    }));
    const extraEdges = extraNodes.map((node, index) => ({
      ...candidateGraph.edges[0], id: `E-CONTEXT-${index}`, source: "CVE-2025-0168", target: node.id, type: "has_evidence",
    }));
    const denseGraph = { nodes: [...candidateGraph.nodes, ...extraNodes], edges: [...candidateGraph.edges, ...extraEdges] };
    const focused = selected[0];
    const model = buildBatchGraphModel(denseGraph, candidates, "focused-route", null, focused.route_id);
    expect(model.hiddenNodeCount).toBeGreaterThan(0);
    expect(focused.node_ids.every((id) => model.visibleNodeIds.has(id))).toBe(true);
    expect(focused.edge_ids.every((id) => model.visibleLinkIds.has(id))).toBe(true);
    expect(model.focusedRouteComplete).toBe(true);
    expect(model.focusedRouteGaps).toEqual([]);
  });

  it("keeps a selected node and selected edge visible beyond the context cap", () => {
    const extraNodes = Array.from({ length: 40 }, (_, index) => ({ ...candidateGraph.nodes[0], id: `EVID-${index}`, type: "evidence" as const }));
    const extraEdges = extraNodes.map((node, index) => ({ ...candidateGraph.edges[0], id: `E-CONTEXT-${index}`, source: "CVE-2025-0168", target: node.id }));
    const denseGraph = { nodes: [...candidateGraph.nodes, ...extraNodes], edges: [...candidateGraph.edges, ...extraEdges] };
    const nodeModel = buildBatchGraphModel(denseGraph, candidates, "focused-route", { kind: "node", id: "EVID-39" }, selected[0].route_id);
    const edgeModel = buildBatchGraphModel(denseGraph, candidates, "focused-route", { kind: "edge", id: "E-CONTEXT-39" }, selected[0].route_id);
    expect(nodeModel.visibleNodeIds.has("EVID-39")).toBe(true);
    expect(edgeModel.visibleNodeIds.has("EVID-39")).toBe(true);
    expect(edgeModel.visibleLinkIds.has("E-CONTEXT-39")).toBe(true);
  });


  it("recalculates focused-route truth when focus changes", () => {
    const first = buildBatchGraphModel(candidateGraph, candidates, "focused-route", null, selected[0].route_id);
    const third = buildBatchGraphModel(candidateGraph, candidates, "focused-route", null, "ROUTE-CVE2-FA");
    expect(first.routeChain.at(-1)).toBe("D3-LFP");
    expect(third.routeChain.at(-1)).toBe("D3-FA");
    expect(third.focusedRouteComplete).toBe(true);
  });

  it("declares a genuinely missing backend edge as a route gap", () => {
    const incompleteGraph = {
      nodes: selectedGraph.nodes,
      edges: selectedGraph.edges.filter((edge) => edge.id !== "E-ATTACK-DEFEND"),
    };
    const model = buildBatchGraphModel(incompleteGraph, selected, "focused-route", null, selected[0].route_id);
    expect(model.focusedRouteComplete).toBe(false);
    expect(model.focusedRouteGaps).toContain("Missing edge E-ATTACK-DEFEND");
  });

});
