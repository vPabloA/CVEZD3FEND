from pathlib import Path


def replace_once(old: str, new: str) -> None:
    path = Path("web/src/test/AnalyzePage.test.tsx")
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError("AnalyzePage test source changed")
    path.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    '''    expect(screen.getByText(/No synthetic result or client-side mapping/i)).toBeInTheDocument();
    expect(api.reasonCves).not.toHaveBeenCalled();''',
    '''    expect(screen.getByText(/No synthetic result or client-side mapping/i)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveClass("bg-amber-950", "text-amber-50");
    expect(api.reasonCves).not.toHaveBeenCalled();''',
)
replace_once(
    '''    expect(screen.getAllByText(/INVALID/).length).toBeGreaterThan(0);
  });''',
    '''    expect(screen.getAllByText(/INVALID/).length).toBeGreaterThan(0);
    const summary = screen.getByRole("status");
    expect(summary).toHaveClass("bg-amber-950");
    expect(within(summary).getByText(/Not found:/i).closest("div")).toHaveClass("text-amber-50");
    expect(within(summary).getByText(/Invalid:/i).closest("div")).toHaveClass("text-rose-50");
  });''',
)
replace_once(
    '''    expect(await screen.findByText(/candidate graph unavailable/i)).toBeInTheDocument();
    expect(screen.getByText("Selected contextual routes")).toBeInTheDocument();''',
    '''    const allError = await screen.findByRole("alert");
    expect(allError).toHaveTextContent(/candidate graph unavailable/i);
    expect(allError).toHaveClass("bg-rose-950", "text-rose-50");
    expect(screen.getByText("Selected contextual routes")).toBeInTheDocument();''',
)
replace_once(
    '''  it("shows deterministic fallback explicitly", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult({ selection_summary: { ...makeBatchReasoningResult().selection_summary, fallback_used: true } }));
    await submitDefault(user);
    const summary = await screen.findByRole("status");
    expect(within(summary).getByText("Used")).toBeInTheDocument();
  });''',
    '''  it("separates deterministic fallback from human review", async () => {
    const user = await healthyPage();
    vi.mocked(api.reasonCves).mockResolvedValue(makeBatchReasoningResult({ selection_summary: { ...makeBatchReasoningResult().selection_summary, fallback_used: true } }));
    await submitDefault(user);
    expect(await screen.findByText("Deterministic fallback")).toBeInTheDocument();
    expect(screen.getByText("Catalog-backed")).toBeInTheDocument();
    expect(screen.queryByText("Human review required")).not.toBeInTheDocument();
    expect(screen.getByText("#1")).toBeInTheDocument();
    expect(screen.getByText(/Se analizaron dos CVE/i)).toBeInTheDocument();
  });''',
)
