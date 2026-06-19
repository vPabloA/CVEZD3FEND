import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import BatchCandidateRouteList from "@/components/reasoning/batch/BatchCandidateRouteList";
import BatchConvergencePanel from "@/components/reasoning/batch/BatchConvergencePanel";
import BatchCveFilters from "@/components/reasoning/batch/BatchCveFilters";
import BatchDecisionSummary from "@/components/reasoning/batch/BatchDecisionSummary";
import BatchEvidencePanel from "@/components/reasoning/batch/BatchEvidencePanel";
import BatchNarrativePanel from "@/components/reasoning/batch/BatchNarrativePanel";
import BatchRouteRanking from "@/components/reasoning/batch/BatchRouteRanking";
import { makeBatchReasoningResult, selectedGraph } from "@/test/fixtures/batchReasoningResult";

describe("batch product components", () => {
  it("announces partial success without hiding missing or invalid inputs", () => {
    render(<BatchDecisionSummary result={makeBatchReasoningResult()} activeView="selected" allAvailable={false} loadingAll={false} onViewChange={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent(/Partial analysis/i);
    expect(screen.getAllByText(/CVE-2025-99999999/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/INVALID/).length).toBeGreaterThan(0);
  });


  it.each([
    ["unavailable", /Galeax data unavailable/i],
    ["not_found", /No requested CVE was found/i],
    ["invalid", /No valid CVE identifier/i],
  ])("never presents %s as a successful analysis", (status, expected) => {
    render(<BatchDecisionSummary result={makeBatchReasoningResult({ status, selected_routes: [], selected_route_count: 0, selected_graph: { nodes: [], edges: [] } })} activeView="selected" allAvailable={false} loadingAll={false} onViewChange={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent(expected);
    expect(screen.queryByText(/Contextual route selection ready/i)).not.toBeInTheDocument();
  });

  it("states Selected route count versus available route count", () => {
    render(<BatchDecisionSummary result={makeBatchReasoningResult()} activeView="selected" allAvailable={false} loadingAll={false} onViewChange={vi.fn()} />);
    expect(screen.getByText(/Showing 2 selected routes from 3 available/i)).toBeInTheDocument();
  });

  it("states the complete universe when All is active", () => {
    render(<BatchDecisionSummary result={makeBatchReasoningResult()} activeView="all" allAvailable loadingAll={false} onViewChange={vi.fn()} />);
    expect(screen.getByText(/Showing complete universe: 3 routes/i)).toBeInTheDocument();
  });

  it("offers keyboard-operable Selected and All tabs", async () => {
    const onViewChange = vi.fn();
    const user = userEvent.setup();
    render(<BatchDecisionSummary result={makeBatchReasoningResult()} activeView="selected" allAvailable={false} loadingAll={false} onViewChange={onViewChange} />);
    const all = screen.getByRole("tab", { name: /Load all candidates/i });
    all.focus();
    await user.keyboard("{Enter}");
    expect(onViewChange).toHaveBeenCalledWith("all");
  });

  it("orders ranked routes by selection_rank and exposes basis labels", () => {
    const result = makeBatchReasoningResult();
    render(<BatchRouteRanking routes={result.selected_routes} selectedRouteId={null} onSelect={vi.fn()} />);
    const buttons = screen.getAllByRole("button");
    expect(buttons[0]).toHaveTextContent("#1");
    expect(buttons[0]).toHaveTextContent("CVE-2026-0544");
    expect(screen.getAllByText("Cobertura mínima por CVE")).toHaveLength(2);
    expect(buttons[0]).toHaveTextContent(/CWE CWE-74/i);
    expect(buttons[0]).toHaveTextContent(/CAPEC CAPEC-13/i);
  });

  it("highlights a route through a semantic pressed button", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    const result = makeBatchReasoningResult();
    render(<BatchRouteRanking routes={result.selected_routes} selectedRouteId={result.selected_routes[0].route_id} onSelect={onSelect} />);
    const active = screen.getByRole("button", { pressed: true });
    expect(active).toHaveTextContent("#2");
    await user.click(screen.getByText("CVE-2026-0544").closest("button")!);
    expect(onSelect).toHaveBeenCalledWith("ROUTE-CVE2-LFP");
  });

  it("filters one or multiple found CVEs without invoking a backend", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<BatchCveFilters found={["CVE-2025-0168", "CVE-2026-0544"]} represented={["CVE-2025-0168"]} selected={[]} onChange={onChange} />);
    await user.click(screen.getByRole("button", { name: /CVE-2025-0168 represented/i }));
    expect(onChange).toHaveBeenCalledWith(["CVE-2025-0168"]);
    expect(screen.getByText(/outside Top-K/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Represented only/i }));
    expect(onChange).toHaveBeenLastCalledWith(["CVE-2025-0168"]);
  });

  it("progressively discloses the All candidate route list without changing mappings", async () => {
    const user = userEvent.setup();
    const onFocus = vi.fn();
    const base = makeBatchReasoningResult({}, true).candidate_routes;
    const routes = Array.from({ length: 55 }, (_, index) => ({
      ...base[index % base.length],
      route_id: `ROUTE-${index.toString().padStart(3, "0")}`,
      score: 1 - index / 100,
    }));
    render(<BatchCandidateRouteList routes={routes} onFocus={onFocus} />);
    await user.click(screen.getByText(/Candidate route universe \(55\)/i));
    expect(screen.getByText(/Showing 50 of 55 candidate records/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Show 5 more routes/i }));
    expect(screen.queryByText(/Showing 50 of 55 candidate records/i)).not.toBeInTheDocument();
    await user.click(screen.getAllByRole("button", { name: /CVE-/i })[0]);
    expect(onFocus).toHaveBeenCalledTimes(1);
  });

  it("presents ATT&CK convergence with CVE, route and D3FEND counts", () => {
    const result = makeBatchReasoningResult();
    render(<BatchConvergencePanel title="ATT&CK convergence — Selected" values={result.shared_attack_techniques_selected} routes={result.selected_routes} kind="attack" />);
    const panel = screen.getByLabelText(/ATT&CK convergence/i);
    expect(within(panel).getByText("T1574.007")).toBeInTheDocument();
    expect(within(panel).getByText(/2 CVE · 2 routes/i)).toBeInTheDocument();
    expect(within(panel).getByText(/D3-LFP/)).toBeInTheDocument();
  });

  it("presents reusable D3FEND with mitigated ATT&CK techniques", () => {
    const result = makeBatchReasoningResult();
    render(<BatchConvergencePanel title="D3FEND reuse — Selected" values={result.shared_defenses_selected} routes={result.selected_routes} kind="defense" />);
    expect(screen.getByText("D3-LFP")).toBeInTheDocument();
    expect(screen.getByText(/Mitigated ATT&CK: T1574.007/i)).toBeInTheDocument();
  });

  it("renders executive, operational and technical narratives as safe text", () => {
    const result = makeBatchReasoningResult({ narrative: { executive_summary_es: "<script>not executed</script>", operational_summary_es: "Operational", technical_summary_es: "Technical" } });
    render(<BatchNarrativePanel narrative={result.narrative} />);
    expect(screen.getByText("<script>not executed</script>")).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getAllByText("Operational").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Technical").length).toBeGreaterThan(0);
  });

  it("shows edge evidence, provenance, warnings and gaps", () => {
    const result = makeBatchReasoningResult();
    const route = { ...result.selected_routes[0], gaps: ["telemetry gap"] };
    render(<BatchEvidencePanel result={result} route={route} graph={selectedGraph} />);
    expect(screen.getByText(/CVE-2025-0168 → CWE-74/)).toBeInTheDocument();
    expect(screen.getByText(/Catalog assertion CVE-2025-0168 to CWE-74/)).toBeInTheDocument();
    expect(screen.getByText(/telemetry gap/)).toBeInTheDocument();
    expect(screen.getByText(/One CVE was not found/)).toBeInTheDocument();
    expect(screen.getAllByText("cve2capec:cve_2025").length).toBeGreaterThan(0);
  });

  it("does not render unsafe provenance URLs as links", () => {
    const result = makeBatchReasoningResult({ provenance: { bad: { source_url: "javascript:alert(1)" } } });
    render(<BatchEvidencePanel result={result} route={result.selected_routes[0]} graph={selectedGraph} />);
    expect(screen.queryByRole("link", { name: /Open source/i })).not.toBeInTheDocument();
  });
});
