import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import ThreatDefenseGraphNavigator from "@/components/reasoning/graph/ThreatDefenseGraphNavigator";
import { buildOfficialUrl } from "@/components/reasoning/graph/officialUrlBuilder";
import { buildGraphModel } from "@/components/reasoning/graph/graphAdapter";
import { graphLinkSourceId, graphLinkTargetId, graphNodeId } from "@/components/reasoning/graph/graphRuntime";
import { buildHighlightState } from "@/components/reasoning/graph/pathHighlighting";
import { applyTraceLayout, traceLayerIdForNode, traceLayerIndexForKind } from "@/components/reasoning/graph/traceLayout";
import type { GraphSelection } from "@/components/reasoning/graph/graphTypes";
import type { ReasoningResult } from "@/lib/reasoningTypes";
import { makeReasoningResult } from "@/test/fixtures/reasoningResult";

function GraphHarness({
  result = makeReasoningResult(),
  initialSelection,
}: {
  result?: ReasoningResult;
  initialSelection?: GraphSelection;
}) {
  const [selectedNode, setSelectedNode] = React.useState<string | null>(
    initialSelection?.kind === "node" ? initialSelection.id : null
  );
  const [selectedEdge, setSelectedEdge] = React.useState<string | null>(initialSelection?.kind === "edge" ? initialSelection.id : null);

  return (
    <ThreatDefenseGraphNavigator
      result={result}
      selection={selectedEdge ? { kind: "edge", id: selectedEdge } : selectedNode ? { kind: "node", id: selectedNode } : null}
      onSelectNode={(nodeId) => {
        setSelectedNode(nodeId);
        setSelectedEdge(null);
      }}
      onSelectEdge={(edgeId) => setSelectedEdge(edgeId || null)}
      onClearSelection={() => {
        setSelectedNode(null);
        setSelectedEdge(null);
      }}
    />
  );
}

afterEach(() => {
  vi.resetAllMocks();
});

describe("graph utilities", () => {
  it("builds official links for the main cyber taxonomies", () => {
    expect(buildOfficialUrl("CVE-2024-0001")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2024-0001");
    expect(buildOfficialUrl("CWE-89")).toBe("https://cwe.mitre.org/data/definitions/89.html");
    expect(buildOfficialUrl("CAPEC-66")).toBe("https://capec.mitre.org/data/definitions/66.html");
    expect(buildOfficialUrl("T1059.004")).toBe("https://attack.mitre.org/techniques/T1059/004/");
    expect(buildOfficialUrl("TA0001")).toBe("https://attack.mitre.org/tactics/TA0001/");
    expect(buildOfficialUrl("d3f:Urlanalysis")).toBe("https://d3fend.mitre.org/technique/d3f%3AUrlanalysis");
    expect(buildOfficialUrl("D3-EFA")).toBeNull();
    expect(buildOfficialUrl("D3-URLAnalysis")).toBeNull();
  });

  it("resolves graph source and target ids after force-graph mutates endpoints", () => {
    const sourceNode = { id: "CWE-89", label: "CWE-89" };
    const targetNode = { id: "CAPEC-66", label: "CAPEC-66" };

    expect(graphNodeId("CVE-2024-0001")).toBe("CVE-2024-0001");
    expect(graphNodeId(sourceNode)).toBe("CWE-89");
    expect(graphLinkSourceId({ source: "CVE-2024-0001" })).toBe("CVE-2024-0001");
    expect(graphLinkTargetId({ target: "CWE-89" })).toBe("CWE-89");
    expect(graphLinkSourceId({ source: sourceNode })).toBe("CWE-89");
    expect(graphLinkTargetId({ target: targetNode })).toBe("CAPEC-66");
  });

  it("maps the reasoning contract into a focused graph model and highlight state", () => {
    const result = makeReasoningResult();
    const model = buildGraphModel(result, "focused-route", { kind: "node", id: "CWE-89" });

    expect(model.routeChain).toEqual(["CVE-2024-0001", "CWE-89", "CAPEC-66", "T1190", "D3-IOPR"]);
    expect(model.nodes.some((node) => node.id === "CWE-89" && node.routeRole === "canonical")).toBe(true);
    expect(model.links).toHaveLength(3);
    expect(model.hiddenNodeCount).toBeGreaterThanOrEqual(0);

    const highlights = buildHighlightState(model, { kind: "node", id: "CWE-89" }, "focused-route");
    expect(highlights.highlightedNodes.has("CWE-89")).toBe(true);
    expect(highlights.focusedNodes.has("CWE-89")).toBe(true);
    expect(highlights.focusedLinks.size).toBeGreaterThan(0);
  });

  it("highlights selected edge endpoints when link endpoints are node objects", () => {
    const result = makeReasoningResult();
    const model = buildGraphModel(result, "focused-route", { kind: "edge", id: "edge-2" });
    const link = model.links.find((item) => item.id === "edge-2")!;
    const sourceNode = model.nodes.find((node) => node.id === graphLinkSourceId(link))!;
    const targetNode = model.nodes.find((node) => node.id === graphLinkTargetId(link))!;
    link.source = sourceNode;
    link.target = targetNode;

    const highlights = buildHighlightState(model, { kind: "edge", id: "edge-2" }, "focused-route");

    expect(highlights.focusedNodes.has("CWE-89")).toBe(true);
    expect(highlights.focusedNodes.has("CAPEC-66")).toBe(true);
    expect(highlights.focusedLinks.has("edge-2")).toBe(true);
  });

  it("pins nodes to semantic trace lanes with the canonical spine on the top row", () => {
    const result = makeReasoningResult();
    const model = buildGraphModel(result, "focused-route", null);
    const nodes = model.nodes.map((node) => ({ ...node }));
    const plan = applyTraceLayout(nodes, model.routeChain);

    // Left → right semantic ordering: CVE before CWE before CAPEC before ATT&CK before D3FEND.
    expect(traceLayerIndexForKind("cve")).toBeLessThan(traceLayerIndexForKind("cwe"));
    expect(traceLayerIndexForKind("cwe")).toBeLessThan(traceLayerIndexForKind("capec"));
    expect(traceLayerIndexForKind("capec")).toBeLessThan(traceLayerIndexForKind("attack"));
    expect(traceLayerIndexForKind("attack")).toBeLessThan(traceLayerIndexForKind("defend"));
    expect(traceLayerIndexForKind("defend")).toBeLessThan(traceLayerIndexForKind("context"));
    // Mitigations/controls share the defensive lane.
    expect(traceLayerIndexForKind("mitigation")).toBe(traceLayerIndexForKind("defend"));

    const byId = new Map(nodes.map((node) => [node.id, node]));
    const cve = byId.get("CVE-2024-0001")!;
    const cwe = byId.get("CWE-89")!;
    const capec = byId.get("CAPEC-66")!;
    const attack = byId.get("T1190")!;
    const defend = byId.get("D3-IOPR")!;

    // Every node is pinned, and the canonical chain reads strictly left → right on the top row.
    nodes.forEach((node) => {
      expect(node.fx).toEqual(expect.any(Number));
      expect(node.fy).toEqual(expect.any(Number));
    });
    expect(cve.fx!).toBeLessThan(cwe.fx!);
    expect(cwe.fx!).toBeLessThan(capec.fx!);
    expect(capec.fx!).toBeLessThan(attack.fx!);
    expect(attack.fx!).toBeLessThan(defend.fx!);
    [cve, cwe, capec, attack, defend].forEach((node) => expect(node.fy).toBe(0));

    // Off-spine alternatives stack below the canonical row in the same lane.
    const weakFit = byId.get("CAPEC-7")!;
    expect(weakFit.fx).toBe(capec.fx);
    expect(weakFit.fy!).toBeGreaterThan(capec.fy!);

    // The defensive lane is flagged so the stage can tint the D3FEND band.
    const defensiveLane = plan.lanes.find((lane) => lane.layer.defensive);
    expect(defensiveLane).toBeDefined();
    expect(defensiveLane!.nodeCount).toBeGreaterThan(0);
  });

  it("keeps route-role defensive nodes in the D3FEND lane even without a D3 id", () => {
    const result = makeReasoningResult({
      route: {
        canonical_chain: ["CVE-2024-0001"],
        primary_nodes: [],
        secondary_nodes: [],
        conditional_nodes: [],
        defensive_nodes: ["parcheo o configuración segura"],
        weak_fit_nodes: [],
      },
      edges: [
        {
          ...makeReasoningResult().edges[0],
          id: "edge-defense-intent",
          source: "CVE-2024-0001",
          target: "parcheo o configuración segura",
          type: "defensive_intent",
          classification: "unverified",
        },
      ],
    });
    const model = buildGraphModel(result, "focused-route", null);
    const defenseNode = model.nodes.find((node) => node.id === "parcheo o configuración segura")!;

    expect(defenseNode.kind).toBe("context");
    expect(defenseNode.routeRole).toBe("defensive");
    expect(traceLayerIdForNode(defenseNode)).toBe("defend");
  });

  it("emphasizes defensive/D3FEND relationships in mitigation path mode", () => {
    const result = makeReasoningResult();
    const model = buildGraphModel(result, "mitigation-path", null);
    const highlights = buildHighlightState(model, null, "mitigation-path");

    expect(highlights.mitigationNodes.has("T1190")).toBe(true);
    expect(highlights.mitigationNodes.has("D3-NTA")).toBe(true);
    expect(highlights.mitigationLinks.has("edge-3")).toBe(true);
    expect(highlights.highlightedLinks.has("edge-3")).toBe(true);
  });
});

describe("ThreatDefenseGraphNavigator", () => {
  it("renders the navigator, honors graph modes, and exposes the inspector for selected nodes and edges", async () => {
    render(
      <MemoryRouter>
        <GraphHarness />
      </MemoryRouter>
    );

    expect(screen.getByText("Threat-Defense Trace Graph Navigator")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /focused route/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /fit view/i })).toBeInTheDocument();
    expect(screen.getByTestId("force-graph-2d")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "CWE-89" }));
    const nodeInspector = await screen.findByText("Selected node");
    const nodePanel = nodeInspector.closest("aside")!;
    expect(within(nodePanel).getByText("CWE-89")).toBeInTheDocument();
    expect(within(nodePanel).getByRole("link", { name: /official source/i })).toBeInTheDocument();

    const edgeButton = screen.getByRole("button", { name: "edge-2" });
    await userEvent.click(edgeButton);

    const inspector = screen.getByText("Selected edge").closest("aside")!;
    expect(within(inspector).getByText(/CWE-89 → CAPEC-66/)).toBeInTheDocument();
    expect(within(inspector).getByText("Analytical (AI)")).toBeInTheDocument();
    expect(within(inspector).getByRole("button", { name: /focus source/i })).toBeInTheDocument();
  });

  it("clears the active inspector without snapping back to the route root", async () => {
    render(
      <MemoryRouter>
        <GraphHarness />
      </MemoryRouter>
    );

    await userEvent.click(screen.getByRole("button", { name: "Trace step 1: CVE-2024-0001" }));
    expect(await screen.findByText("Selected node")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Clear selection" }));

    expect(screen.queryByText("Selected node")).not.toBeInTheDocument();
    expect(screen.queryByText("Selected edge")).not.toBeInTheDocument();
  });

  it("renders clear empty and partial graph states", () => {
    const empty = makeReasoningResult({
      route: {
        canonical_chain: [],
        primary_nodes: [],
        secondary_nodes: [],
        conditional_nodes: [],
        defensive_nodes: [],
        weak_fit_nodes: [],
      },
      edges: [],
    });
    const partial = makeReasoningResult({
      route: {
        canonical_chain: ["CVE-2024-0001", "T1190", "D3-IOPR"],
        primary_nodes: ["T1190"],
        secondary_nodes: [],
        conditional_nodes: [],
        defensive_nodes: ["D3-IOPR"],
        weak_fit_nodes: [],
      },
      edges: [
        {
          ...makeReasoningResult().edges[2],
          id: "partial-edge",
          source: "T1190",
          target: "D3-IOPR",
          classification: "conditional",
        },
      ],
    });

    const { rerender } = render(
      <MemoryRouter>
        <ThreatDefenseGraphNavigator
          result={empty}
          selection={null}
          onSelectNode={vi.fn()}
          onSelectEdge={vi.fn()}
          onClearSelection={vi.fn()}
        />
      </MemoryRouter>
    );

    expect(screen.getByText("No graphable route was produced for this CVE.")).toBeInTheDocument();

    rerender(
      <MemoryRouter>
        <GraphHarness result={partial} />
      </MemoryRouter>
    );

    expect(screen.getByText("This route is partial: Missing CWE layer; Missing CAPEC layer.")).toBeInTheDocument();
  });

  it("cherry-picks trace steps from the route spine chips", async () => {
    render(
      <MemoryRouter>
        <GraphHarness />
      </MemoryRouter>
    );

    await userEvent.click(screen.getByRole("button", { name: "Trace step 2: CWE-89" }));

    const nodeInspector = await screen.findByText("Selected node");
    const nodePanel = nodeInspector.closest("aside")!;
    expect(within(nodePanel).getByText("CWE-89")).toBeInTheDocument();
    expect(within(nodePanel).getByText(/Role in trace:/)).toBeInTheDocument();
  });

  it("parks condition-dependent edges off-stage when primary route emphasis is active", async () => {
    render(
      <MemoryRouter>
        <GraphHarness />
      </MemoryRouter>
    );

    // edge-3 is the conditional T1190 → D3-NTA relation.
    expect(screen.getByRole("button", { name: "edge-3" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "D3-NTA" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Primary route" }));

    expect(screen.queryByRole("button", { name: "edge-3" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "D3-NTA" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "edge-1" })).toBeInTheDocument();
  });

  it("hides off-route context/evidence nodes behind the context toggle", async () => {
    const base = makeReasoningResult();
    const result = makeReasoningResult({
      edges: [
        ...base.edges,
        {
          ...base.edges[0],
          id: "edge-evidence",
          source: "T1190",
          target: "EVID-WAF",
          type: "supported_by",
          classification: "dataset_derived",
        },
      ],
    });

    render(
      <MemoryRouter>
        <GraphHarness result={result} />
      </MemoryRouter>
    );

    expect(screen.getByRole("button", { name: "EVID-WAF" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Hide context" }));

    expect(screen.queryByRole("button", { name: "EVID-WAF" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show context" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Show context" }));
    expect(screen.getByRole("button", { name: "EVID-WAF" })).toBeInTheDocument();
  });

  it("does not hide operational defensive nodes when context is parked", async () => {
    const result = makeReasoningResult({
      route: {
        canonical_chain: ["CVE-2024-0001"],
        primary_nodes: [],
        secondary_nodes: [],
        conditional_nodes: [],
        defensive_nodes: ["parcheo o configuración segura"],
        weak_fit_nodes: [],
      },
      edges: [
        {
          ...makeReasoningResult().edges[0],
          id: "edge-defense-intent",
          source: "CVE-2024-0001",
          target: "parcheo o configuración segura",
          type: "defensive_intent",
          classification: "unverified",
        },
      ],
    });

    render(
      <MemoryRouter>
        <GraphHarness result={result} />
      </MemoryRouter>
    );

    expect(screen.getByRole("button", { name: "parcheo o configuración segura" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Hide context" }));

    expect(screen.getByRole("button", { name: "parcheo o configuración segura" })).toBeInTheDocument();
  });

  it("explains when the selected edge is hidden by active filters", async () => {
    render(
      <MemoryRouter>
        <GraphHarness initialSelection={{ kind: "edge", id: "edge-3" }} />
      </MemoryRouter>
    );

    await userEvent.click(screen.getByRole("button", { name: /conditional/i }));

    expect(screen.getAllByText("The selected edge is hidden by the current filters.").length).toBeGreaterThan(0);
    expect(screen.getByText(/Reset filters or return to the route focus/i)).toBeInTheDocument();
  });
});
