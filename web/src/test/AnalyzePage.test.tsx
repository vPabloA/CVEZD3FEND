import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import AnalyzePage from "@/pages/AnalyzePage";
import * as api from "@/lib/api";
import { makeBatchReasoningResult } from "@/test/fixtures/batchReasoningResult";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    apiHealth: vi.fn(),
    getMeta: vi.fn(),
    reasonCves: vi.fn(),
  };
});

const HEALTHY = { status: "ok", version: "test", bundle_path: "", bundle_available: true };
const META_OK = {
  bundle_version: "test",
  generated_at: "2026-01-01T00:00:00Z",
  schema_version: "test",
  node_count: 0,
  edge_count: 0,
  route_count: 0,
  sources: [],
  enrichment_sources: ["nvd"],
  reasoning_available: true,
  quality: {},
  coverage_summary: {},
};

function renderAnalyze(initialEntry = "/analyze?cve=CVE-2025-0168") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes><Route path="/analyze" element={<AnalyzePage />} /></Routes>
    </MemoryRouter>
  );
}

async function healthyPage(entry?: string) {
  vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
  vi.mocked(api.getMeta).mockResolvedValue(META_OK);
  const user = userEvent.setup();
  renderAnalyze(entry);
  await screen.findByRole("form", { name: /Multi-CVE contextual analysis/i });
  return user;
}

async function submitDefault(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: /Analyze CVEs/i }));
}

afterEach(() => {
  vi.resetAllMocks();
  localStorage.clear();
});

describe("AnalyzePage multi-CVE workbench", () => {
  it("shows an honest degraded state when the API sidecar is unreachable", async () => {
    vi.mocked(api.apiHealth).mockRejectedValue(new api.ApiError("Cannot reach the CVEzD3FEND API sidecar"));
    renderAnalyze();
    expect(await screen.findByText(/API sidecar not reachable/i)).toBeInTheDocument();
    expect(screen.getByText(/No synthetic result or client-side mapping/i)).toBeInTheDocument();
    expect(api.reasonCves).not.toHaveBeenCalled();
  });

  it("starts idle and does not analyze a deep-linked CVE without user action", async () => {
    await healthyPage();
    expect(screen.getByText(/Analyze several CVEs in one operational context/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/CVE identifiers/i)).toHaveValue("CVE-2025-0168");
    expect(api.reasonCves).not.toHaveBeenCalled();
  });

  it("shows loading-selected while exact lookup and scoring are running", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockReturnValue(new Promise(() => {}));
    await submitDefault(user);
    expect(screen.getByText(/Running exact lookup, deterministic scoring and Selected route projection/i)).toBeInTheDocument();
  });

  it("sends multi-CVE context, Top-K and Selected opt-out explicitly", async () => {
    const user = await healthyPage("/analyze");
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult());
    await user.type(screen.getByLabelText(/CVE identifiers/i), "CVE-2025-0168, CVE-2026-0544, invalid");
    await user.type(screen.getByLabelText(/Technologies/i), "Windows, Active Directory");
    await user.click(screen.getByRole("checkbox", { name: /internet-facing/i }));
    await user.click(screen.getByRole("checkbox", { name: /credential theft/i }));
    await user.selectOptions(screen.getByLabelText(/Audience/i), "SOC");
    await user.selectOptions(screen.getByLabelText(/Top-K/i), "5");
    await submitDefault(user);
    await waitFor(() => expect(api.reasonCves).toHaveBeenCalledTimes(1));
    const request = vi.mocked(api.reasonCves).mock.calls[0][0];
    expect(request).toMatchObject({
      cve_ids: ["CVE-2025-0168", "CVE-2026-0544", "INVALID"],
      context: { technologies: ["Windows", "Active Directory"], exposure: ["internet-facing"], priorities: ["credential theft"], audience: "SOC" },
      top_k: 5,
      use_ai: false,
      include_all_candidates: false,
    });
  });

  it("renders Selected graph, ranking, partial status and textual summary", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult());
    await submitDefault(user);
    expect(await screen.findByText(/Partial analysis — usable results with declared gaps/i)).toBeInTheDocument();
    expect(screen.getByText(/Showing 2 selected routes from 3 available/i)).toBeInTheDocument();
    expect(screen.getByText("Selected contextual routes")).toBeInTheDocument();
    expect(screen.getByText("#1")).toBeInTheDocument();
    expect(screen.getByText("#2")).toBeInTheDocument();
    expect(screen.getAllByText(/CVE-2025-99999999/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/INVALID/).length).toBeGreaterThan(0);
  });

  it("loads All only after opt-in and consumes candidate_graph", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves)
      .mockResolvedValueOnce(makeBatchReasoningResult())
      .mockResolvedValueOnce(makeBatchReasoningResult({}, true));
    await submitDefault(user);
    await screen.findByText("Selected contextual routes");
    await user.click(screen.getByRole("tab", { name: /Load all candidates/i }));
    expect(await screen.findByText("Complete candidate universe")).toBeInTheDocument();
    expect(screen.getByText(/Showing complete universe: 3 routes/i)).toBeInTheDocument();
    expect(screen.getAllByText("T1027").length).toBeGreaterThan(0);
    expect(vi.mocked(api.reasonCves).mock.calls[1][0].include_all_candidates).toBe(true);
  });

  it("returns to Selected without a new request and reuses cached All", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves)
      .mockResolvedValueOnce(makeBatchReasoningResult())
      .mockResolvedValueOnce(makeBatchReasoningResult({}, true));
    await submitDefault(user);
    await user.click(await screen.findByRole("tab", { name: /Load all candidates/i }));
    await screen.findByText("Complete candidate universe");
    await user.click(screen.getByRole("tab", { name: /^Selected$/i }));
    expect(await screen.findByText("Selected contextual routes")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /All candidates/i }));
    await screen.findByText("Complete candidate universe");
    expect(api.reasonCves).toHaveBeenCalledTimes(2);
  });

  it("preserves Selected when the All request fails", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves)
      .mockResolvedValueOnce(makeBatchReasoningResult())
      .mockRejectedValueOnce(new api.ApiError("candidate graph unavailable"));
    await submitDefault(user);
    await user.click(await screen.findByRole("tab", { name: /Load all candidates/i }));
    expect(await screen.findByText(/candidate graph unavailable/i)).toBeInTheDocument();
    expect(screen.getByText("Selected contextual routes")).toBeInTheDocument();
    expect(screen.getByText("#1")).toBeInTheDocument();
  });

  it("filters the graph locally by CVE without requesting the backend", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult());
    await submitDefault(user);
    const chip = await screen.findByRole("button", { name: /CVE-2025-0168 represented/i });
    await user.click(chip);
    expect(api.reasonCves).toHaveBeenCalledTimes(1);
    const graph = screen.getByTestId("force-graph-2d");
    expect(within(graph).getByRole("button", { name: "CVE-2025-0168" })).toBeInTheDocument();
    expect(within(graph).queryByRole("button", { name: "CVE-2026-0544" })).not.toBeInTheDocument();
  });

  it("focuses a ranked route and exposes keyboard-operable inspector evidence", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult());
    await submitDefault(user);
    const routeButton = (await screen.findAllByText("CVE-2026-0544")).map((item) => item.closest("button")).find((item) => item?.getAttribute("aria-pressed") !== null)!;
    await user.click(routeButton);
    expect(routeButton).toHaveAttribute("aria-pressed", "true");
    const traceStep = screen.getByRole("button", { name: /Trace step 4: T1574.007/i });
    traceStep.focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByText("Selected node")).toBeInTheDocument();
    expect(screen.getByText(/Related CVEs:/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Catalog assertion/i).length).toBeGreaterThan(0);
  });

  it("shows Selected ATT&CK and D3FEND convergence with counts", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult());
    await submitDefault(user);
    const attackPanel = await screen.findByLabelText(/ATT&CK convergence — Selected/i);
    expect(within(attackPanel).getByText(/2 CVE · 2 routes/i)).toBeInTheDocument();
    expect(within(attackPanel).getByText(/D3-LFP/)).toBeInTheDocument();
    expect(screen.getByLabelText(/D3FEND reuse — Selected/i)).toHaveTextContent("T1574.007");
  });

  it("renders all three backend narratives and provenance", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult());
    await submitDefault(user);
    expect(await screen.findByText(/Se analizaron dos CVE/i)).toBeInTheDocument();
    expect(screen.getByText(/Validar T1574.007/i)).toBeInTheDocument();
    expect(screen.getByText(/Universo=3/i)).toBeInTheDocument();
    expect(screen.getAllByText("cve2capec:cve_2025").length).toBeGreaterThan(0);
  });

  it("shows deterministic fallback explicitly", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult({ selection_summary: { ...makeBatchReasoningResult().selection_summary, fallback_used: true } }));
    await submitDefault(user);
    const summary = await screen.findByRole("status");
    expect(within(summary).getByText("Used")).toBeInTheDocument();
  });

  it("shows a zero-route explanation instead of an empty unexplained graph", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult({
      status: "not_found",
      available_route_count: 0,
      selected_route_count: 0,
      selected_routes: [],
      selected_graph: { nodes: [], edges: [] },
      shared_attack_techniques_selected: [],
      shared_defenses_selected: [],
    }));
    await submitDefault(user);
    expect(await screen.findByText(/No graphable routes in the active projection/i)).toBeInTheDocument();
    expect(screen.getByText(/does not fabricate graph nodes/i)).toBeInTheDocument();
  });

  it("shows a readable API error", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockRejectedValue(new api.ApiError("maximum is 50", 422));
    await submitDefault(user);
    expect(await screen.findByText("maximum is 50")).toBeInTheDocument();
  });
});
