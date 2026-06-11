import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import AnalyzePage from "@/pages/AnalyzePage";
import * as api from "@/lib/api";
import { makeReasoningResult } from "@/test/fixtures/reasoningResult";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    apiHealth: vi.fn(),
    getMeta: vi.fn(),
    reasonCve: vi.fn(),
    proposeRoute: vi.fn(),
    validateRoute: vi.fn(),
    promoteEdge: vi.fn(),
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

function renderAnalyze(initialEntry = "/analyze?cve=CVE-2024-0001") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/analyze" element={<AnalyzePage />} />
      </Routes>
    </MemoryRouter>
  );
}

afterEach(() => {
  vi.resetAllMocks();
  localStorage.clear();
});

describe("AnalyzePage", () => {
  it("shows an honest degraded state when the API sidecar is unreachable", async () => {
    vi.mocked(api.apiHealth).mockRejectedValue(new api.ApiError("Cannot reach the CVEzD3FEND API sidecar"));

    renderAnalyze();

    expect(await screen.findByText(/API sidecar not reachable/i)).toBeInTheDocument();
    expect(screen.getByText(/CVEzD3FEND api/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /check again/i })).toBeInTheDocument();
    // No reasoning request should be attempted while the API is unreachable.
    expect(api.reasonCve).not.toHaveBeenCalled();
  });

  it("shows a loading state while the reasoning engine is running", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue(META_OK);
    vi.mocked(api.reasonCve).mockReturnValue(new Promise(() => {})); // never resolves

    renderAnalyze();

    expect(await screen.findByText(/Running reasoning engine for CVE-2024-0001/i)).toBeInTheDocument();
  });

  it("shows an error state with retry when reasoning fails", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue(META_OK);
    vi.mocked(api.reasonCve).mockRejectedValue(new api.ApiError("CVE not found"));

    renderAnalyze();

    expect(await screen.findByText("CVE not found")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });

  it("renders the full reasoning result: narrative, risk, route, edges, SOC/Detection/Hunting/CTEM, exports, provenance", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue(META_OK);
    vi.mocked(api.reasonCve).mockResolvedValue(makeReasoningResult());

    renderAnalyze();

    // Header / status
    expect(await screen.findByRole("heading", { name: "CVE-2024-0001" })).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(screen.getByText(/^Live$/)).toBeInTheDocument();

    // Narrative (Reasoning Summary)
    expect(screen.getByText("Reasoning summary")).toBeInTheDocument();
    expect(screen.getByText(/inyección SQL remota/)).toBeInTheDocument();

    // Risk summary — KEV listed pushes overall level to Critical
    expect(screen.getByText("Risk summary")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();

    // Route contract buckets
    const routeSection = screen.getByText("Route contract").closest("section")!;
    expect(within(routeSection).getByText("Canonical chain")).toBeInTheDocument();
    expect(within(routeSection).getAllByText("T1190").length).toBeGreaterThan(0);

    // Reasoning trace edges with classification badges
    expect(screen.getByText(/Reasoning trace/)).toBeInTheDocument();
    expect(screen.getAllByText("Official").length).toBeGreaterThan(0);
    expect(screen.getByText("Analytical (AI)")).toBeInTheDocument();
    expect(screen.getByText("Conditional")).toBeInTheDocument();

    // Provenance ledger
    const provenanceSection = screen.getByText("Provenance ledger").closest("section")!;
    expect(within(provenanceSection).getAllByText("nvd").length).toBeGreaterThan(0);

    // SOC / Detection / Hunting / CTEM
    expect(screen.getByText("SOC Action Pack")).toBeInTheDocument();
    expect(screen.getByText("Isolate affected host from the network")).toBeInTheDocument();
    expect(screen.getByText("Detection engineering")).toBeInTheDocument();
    expect(screen.getByText("Alert on UNION SELECT in HTTP parameters")).toBeInTheDocument();
    expect(screen.getByText("Threat hunting")).toBeInTheDocument();
    expect(screen.getByText("CTEM plan")).toBeInTheDocument();
    expect(screen.getByText("Apply vendor patch 1.2.3")).toBeInTheDocument();

    // Exports
    expect(screen.getByText("Exports")).toBeInTheDocument();
    expect(screen.getByText("Markdown report")).toBeInTheDocument();

    // Graph navigator placeholder reserves the next-iteration position
    expect(screen.getByText("Architectural graph navigator")).toBeInTheDocument();
    expect(screen.getByText("Next iteration")).toBeInTheDocument();
  });

  it("shows the human-review banner only when human_review.required is true", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue(META_OK);
    vi.mocked(api.reasonCve).mockResolvedValue(
      makeReasoningResult({ human_review: { required: true, reason: "Conditional edges need analyst confirmation." } })
    );

    renderAnalyze();

    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent(/human review required/i);
    expect(banner).toHaveTextContent("Conditional edges need analyst confirmation.");
  });

  it("does not show the human-review banner when not required", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue(META_OK);
    vi.mocked(api.reasonCve).mockResolvedValue(makeReasoningResult({ human_review: { required: false, reason: "" } }));

    renderAnalyze();

    await screen.findByText("Reasoning summary");
    expect(screen.queryByText(/human review required/i)).not.toBeInTheDocument();
  });

  it("warns honestly when the API is reachable but the reasoning plane is unavailable", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue({ ...META_OK, reasoning_available: false });
    vi.mocked(api.reasonCve).mockRejectedValue(new api.ApiError("reasoning plane unavailable"));

    renderAnalyze();

    expect(await screen.findByText(/reasoning plane reports itself unavailable/i)).toBeInTheDocument();
  });

  it("shows the empty state when no CVE is provided", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue(META_OK);

    renderAnalyze("/analyze");

    expect(await screen.findByText("Enter a CVE ID to begin analysis")).toBeInTheDocument();
    expect(api.reasonCve).not.toHaveBeenCalled();
  });

  it("waits for results before resolving", async () => {
    vi.mocked(api.apiHealth).mockResolvedValue(HEALTHY);
    vi.mocked(api.getMeta).mockResolvedValue(META_OK);
    vi.mocked(api.reasonCve).mockResolvedValue(makeReasoningResult());

    renderAnalyze();

    await waitFor(() => expect(api.reasonCve).toHaveBeenCalledWith("CVE-2024-0001"));
  });
});
