from pathlib import Path

path = Path("web/src/test/AnalyzePage.test.tsx")
text = path.read_text(encoding="utf-8")
marker = "\n});"
index = text.rfind(marker)
if index < 0:
    raise RuntimeError("describe terminator not found")
addition = r'''

  it("keeps a complete five-layer focused route truthful above the visual cap", async () => {
    const user = await healthyPage();
    const selectedResult = makeBatchReasoningResult();
    const allResult = makeBatchReasoningResult({}, true);
    const graph = allResult.candidate_graph!;
    const extraNodes = Array.from({ length: 70 }, (_, index) => ({
      ...graph.nodes[0], id: `EVID-${index}`, type: "evidence" as const, name: `Evidence ${index}`, title: `Evidence ${index}`,
    }));
    const extraEdges = extraNodes.map((node, index) => ({
      ...graph.edges[0], id: `E-CONTEXT-${index}`, source: "CVE-2025-0168", target: node.id, type: "has_evidence",
    }));
    allResult.candidate_graph = { nodes: [...graph.nodes, ...extraNodes], edges: [...graph.edges, ...extraEdges] };
    allResult.available_route_count = 73;
    vi.mocked(api.reasonCves).mockResolvedValueOnce(selectedResult).mockResolvedValueOnce(allResult);

    await submitDefault(user);
    await user.click(await screen.findByRole("tab", { name: /Load all candidates/i }));
    const density = await screen.findByText(/complete universe contains 73 routes and 79 nodes/i);
    expect(density).toHaveClass("bg-violet-950", "text-violet-50");
    expect(density).toHaveTextContent(/progressive visual disclosure/i);
    expect(density).toHaveTextContent(/route list and backend evidence remain complete/i);
    expect(screen.queryByText(/This route is partial/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Trace step 1: CVE-2025-0168/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Trace step 5: D3-LFP/i })).toBeInTheDocument();
  });
'''
path.write_text(text[:index] + addition + text[index:], encoding="utf-8")
