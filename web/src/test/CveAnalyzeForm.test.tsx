import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import CveAnalyzeForm from "@/components/reasoning/CveAnalyzeForm";

async function setup(initialValue = "") {
  const onSubmit = vi.fn();
  const onClear = vi.fn();
  const user = userEvent.setup();
  render(<CveAnalyzeForm initialValue={initialValue} busy={false} onSubmit={onSubmit} onClear={onClear} />);
  return { user, onSubmit, onClear };
}

describe("CveAnalyzeForm", () => {
  it("shows detected, valid, invalid and duplicate counts", async () => {
    const { user } = await setup();
    await user.type(screen.getByLabelText(/CVE identifiers/i), "CVE-2025-0168, invalid, CVE-2025-0168");
    expect(screen.getByText("2 detected")).toBeInTheDocument();
    expect(screen.getByText("1 valid")).toBeInTheDocument();
    expect(screen.getByText("1 invalid")).toBeInTheDocument();
    expect(screen.getByText("1 duplicate removed")).toBeInTheDocument();
  });

  it("renders invalid values and associates the error description", async () => {
    const { user } = await setup();
    const input = screen.getByLabelText(/CVE identifiers/i);
    await user.type(input, "CVE-2025-0168 invalid");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("INVALID")).toBeInTheDocument();
  });

  it("submits normalized multi-CVE input with Selected as the safe default", async () => {
    const { user, onSubmit } = await setup();
    await user.type(screen.getByLabelText(/CVE identifiers/i), "cve-2025-0168\nCVE-2026-0544 invalid");
    await user.click(screen.getByRole("button", { name: /Analyze CVEs/i }));
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
      cve_ids: ["CVE-2025-0168", "CVE-2026-0544", "INVALID"],
      include_all_candidates: false,
      use_ai: false,
    }));
  });

  it("normalizes comma-separated technologies", async () => {
    const { user, onSubmit } = await setup("CVE-2025-0168");
    await user.type(screen.getByLabelText(/Technologies/i), "Windows, Active Directory, Windows");
    await user.click(screen.getByRole("button", { name: /Analyze CVEs/i }));
    expect(onSubmit.mock.calls[0][0].context.technologies).toEqual(["Windows", "Active Directory"]);
  });

  it("submits multiple exposure values", async () => {
    const { user, onSubmit } = await setup("CVE-2025-0168");
    await user.click(screen.getByRole("checkbox", { name: /internet-facing/i }));
    await user.click(screen.getByRole("checkbox", { name: /production/i }));
    await user.click(screen.getByRole("button", { name: /Analyze CVEs/i }));
    expect(onSubmit.mock.calls[0][0].context.exposure).toEqual(["internet-facing", "production"]);
  });

  it("submits multiple priorities", async () => {
    const { user, onSubmit } = await setup("CVE-2025-0168");
    await user.click(screen.getByRole("checkbox", { name: /initial access/i }));
    await user.click(screen.getByRole("checkbox", { name: /credential theft/i }));
    await user.click(screen.getByRole("button", { name: /Analyze CVEs/i }));
    expect(onSubmit.mock.calls[0][0].context.priorities).toEqual(["initial access", "credential theft"]);
  });

  it("submits the selected audience and Top-K", async () => {
    const { user, onSubmit } = await setup("CVE-2025-0168");
    await user.selectOptions(screen.getByLabelText(/Audience/i), "Threat Hunting");
    await user.selectOptions(screen.getByLabelText(/Top-K/i), "20");
    await user.click(screen.getByRole("button", { name: /Analyze CVEs/i }));
    expect(onSubmit.mock.calls[0][0]).toMatchObject({ top_k: 20, context: { audience: "Threat Hunting" } });
  });

  it("keeps AI-assisted reranking off by default", async () => {
    await setup("CVE-2025-0168");
    expect(screen.getByRole("checkbox", { name: /AI-assisted reranking/i })).not.toBeChecked();
    expect(screen.getByText(/AI can only reorder validated shortlist route IDs/i)).toBeInTheDocument();
  });

  it("submits AI refinement only after explicit opt-in", async () => {
    const { user, onSubmit } = await setup("CVE-2025-0168");
    await user.click(screen.getByRole("checkbox", { name: /AI-assisted reranking/i }));
    await user.click(screen.getByRole("button", { name: /Analyze CVEs/i }));
    expect(onSubmit.mock.calls[0][0].use_ai).toBe(true);
  });

  it("clears the complete form and calls the workbench reset", async () => {
    const { user, onClear } = await setup("CVE-2025-0168");
    await user.type(screen.getByLabelText(/Technologies/i), "Windows");
    await user.click(screen.getByRole("button", { name: /Clear/i }));
    expect(screen.getByLabelText(/CVE identifiers/i)).toHaveValue("");
    expect(screen.getByLabelText(/Technologies/i)).toHaveValue("");
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it("disables submit and clear while busy", async () => {
    render(<CveAnalyzeForm initialValue="CVE-2025-0168" busy onSubmit={vi.fn()} />);
    expect(screen.getByRole("button", { name: /Analyzing/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Clear/i })).toBeDisabled();
  });
});
