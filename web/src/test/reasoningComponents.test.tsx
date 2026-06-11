import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import AiReasoningActions from "@/components/reasoning/AiReasoningActions";
import ReasoningEdgesList from "@/components/reasoning/ReasoningEdgesList";
import * as api from "@/lib/api";
import { makeReasoningResult } from "@/test/fixtures/reasoningResult";

function renderEdges(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    proposeRoute: vi.fn(),
    validateRoute: vi.fn(),
  };
});

afterEach(() => {
  vi.resetAllMocks();
});

describe("AiReasoningActions", () => {
  it("shows an honest disabled state when the API is unavailable — no fake success", () => {
    render(<AiReasoningActions cveId="CVE-2024-0001" apiAvailable={false} />);

    expect(screen.getByRole("button", { name: /propose route/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /validate route/i })).toBeDisabled();
    expect(screen.getByText(/API offline/i)).toBeInTheDocument();
  });

  it("proposes and validates a route when the API is available, showing AI results as visible facts", async () => {
    vi.mocked(api.proposeRoute).mockResolvedValue({ proposed_edges: 2, status: "proposed" });
    vi.mocked(api.validateRoute).mockResolvedValue({ valid: true, issues: [] });

    render(<AiReasoningActions cveId="CVE-2024-0001" apiAvailable />);

    await userEvent.click(screen.getByRole("button", { name: /propose route/i }));
    expect(await screen.findByText("AI proposal (not canonical)")).toBeInTheDocument();
    expect(api.proposeRoute).toHaveBeenCalledWith("CVE-2024-0001");

    await userEvent.click(screen.getByRole("button", { name: /validate route/i }));
    expect(await screen.findByText("Route Validation")).toBeInTheDocument();
    expect(api.validateRoute).toHaveBeenCalledWith("CVE-2024-0001");
  });

  it("promotes only the selected review edge through one governed control", async () => {
    const onPromote = vi.fn();
    const edges = makeReasoningResult().edges;

    render(<AiReasoningActions cveId="CVE-2024-0001" apiAvailable reviewer="alice" edges={edges} onPromote={onPromote} />);

    const promoteButton = screen.getByRole("button", { name: /promote selected edge/i });
    expect(promoteButton).toBeEnabled();
    expect(screen.getByRole("combobox", { name: /edge to promote/i })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /promote selected edge/i })).toHaveLength(1);

    await userEvent.click(promoteButton);
    expect(onPromote).toHaveBeenCalledWith("edge-2");
  });
});

describe("ReasoningEdgesList — promotion requires a named reviewer", () => {
  const edges = makeReasoningResult().edges; // edge-2 / edge-3 are non-official, need review

  it("disables promotion and explains why when no reviewer name is set", () => {
    const onPromote = vi.fn();
    renderEdges(<ReasoningEdgesList edges={edges} apiAvailable reviewer="" onPromote={onPromote} />);

    const promoteButtons = screen.getAllByRole("button", { name: /promote to canonical/i });
    expect(promoteButtons.length).toBeGreaterThan(0);
    promoteButtons.forEach((btn) => expect(btn).toBeDisabled());
    expect(screen.getAllByText(/enter a reviewer name to act/i).length).toBeGreaterThan(0);
    expect(onPromote).not.toHaveBeenCalled();
  });

  it("enables promotion once a reviewer name is provided and invokes the callback", async () => {
    const onPromote = vi.fn();
    renderEdges(<ReasoningEdgesList edges={edges} apiAvailable reviewer="alice" onPromote={onPromote} />);

    const promoteButtons = screen.getAllByRole("button", { name: /promote to canonical/i });
    promoteButtons.forEach((btn) => expect(btn).toBeEnabled());

    await userEvent.click(promoteButtons[0]);
    expect(onPromote).toHaveBeenCalledTimes(1);
  });

  it("does not show promote actions for official_explicit edges", () => {
    const officialOnly = edges.filter((e) => e.classification === "official_explicit");
    renderEdges(<ReasoningEdgesList edges={officialOnly} apiAvailable reviewer="alice" onPromote={vi.fn()} />);

    expect(screen.queryByRole("button", { name: /promote to canonical/i })).not.toBeInTheDocument();
  });
});
