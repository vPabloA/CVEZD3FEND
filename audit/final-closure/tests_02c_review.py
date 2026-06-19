from pathlib import Path

path = Path("web/src/test/AnalyzePage.test.tsx")
text = path.read_text(encoding="utf-8")
index = text.rfind("\n});")
if index < 0:
    raise RuntimeError("describe terminator not found")
addition = r'''

  it("shows human review only for a real route gap, independently of fallback", async () => {
    const user = await healthyPage();
    const base = makeBatchReasoningResult();
    const incomplete = { ...base.selected_routes[0], completeness: 0.8, gaps: ["Missing D3FEND layer"] };
    vi.mocked(api.reasonCves).mockResolvedValue({
      ...base,
      selected_routes: [incomplete, base.selected_routes[1]],
      selection_summary: { ...base.selection_summary, fallback_used: true },
    });
    await submitDefault(user);
    expect(await screen.findByText("Human review required")).toBeInTheDocument();
    expect(screen.getByText("Deterministic fallback")).toBeInTheDocument();
    expect(screen.getByText(/This route is partial: Missing D3FEND layer/i)).toBeInTheDocument();
  });
'''
path.write_text(text[:index] + addition + text[index:], encoding="utf-8")
