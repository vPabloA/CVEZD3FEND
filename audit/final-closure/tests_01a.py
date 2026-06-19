from pathlib import Path

path = Path("web/src/test/batchGraphAdapter.test.ts")
text = path.read_text(encoding="utf-8")
marker = "\n});"
index = text.rfind(marker)
if index < 0:
    raise RuntimeError("describe terminator not found")
addition = r'''

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
'''
path.write_text(text[:index] + addition + text[index:], encoding="utf-8")
