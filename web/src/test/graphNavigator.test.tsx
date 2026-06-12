import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import ThreatDefenseGraphNavigator from "@/components/reasoning/graph/ThreatDefenseGraphNavigator";
import { buildOfficialUrl } from "@/components/reasoning/graph/officialUrlBuilder";
import { buildGraphModel } from "@/components/reasoning/graph/graphAdapter";
import { buildHighlightState } from "@/components/reasoning/graph/pathHighlighting";
import { makeReasoningResult } from "@/test/fixtures/reasoningResult";

function GraphHarness() {
  const result = makeReasoningResult();
  const [selectedNode, setSelectedNode] = React.useState<string | null>(result.route.canonical_chain[0] ?? result.normalized_input ?? result.input);
  const [selectedEdge, setSelectedEdge] = React.useState<string | null>(null);

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
        setSelectedNode(result.route.canonical_chain[0] ?? result.normalized_input ?? result.input);
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
    expect(buildOfficialUrl("D3-URLAnalysis")).toBe("https://d3fend.mitre.org/technique/d3f%3AUrlanalysis");
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
});

describe("ThreatDefenseGraphNavigator", () => {
  it("renders the navigator, honors graph modes, and exposes the inspector for selected nodes and edges", async () => {
    render(
      <MemoryRouter>
        <GraphHarness />
      </MemoryRouter>
    );

    expect(screen.getByText("Threat-Defense Knowledge Graph Navigator")).toBeInTheDocument();
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
});
