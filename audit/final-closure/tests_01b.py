from pathlib import Path

path = Path("web/src/test/batchGraphAdapter.test.ts")
text = path.read_text(encoding="utf-8")
marker = "\n});"
index = text.rfind(marker)
if index < 0:
    raise RuntimeError("describe terminator not found")
addition = r'''

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
'''
path.write_text(text[:index] + addition + text[index:], encoding="utf-8")
