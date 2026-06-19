from pathlib import Path

path = Path("web/src/test/AnalyzePage.test.tsx")
text = path.read_text(encoding="utf-8")
index = text.rfind("\n});")
if index < 0:
    raise RuntimeError("describe terminator not found")
addition = r'''

  it("shows AI reranked without fallback or human-review semantics", async () => {
    const user = await healthyPage();
    const base = makeBatchReasoningResult();
    vi.mocked(api.reasonCves).mockResolvedValue({
      ...base,
      selection_summary: { ...base.selection_summary, selection_mode: "ai_reranked", fallback_used: false },
    });
    await submitDefault(user);
    expect((await screen.findAllByText("AI reranked")).length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText("Deterministic fallback")).not.toBeInTheDocument();
    expect(screen.queryByText("Human review required")).not.toBeInTheDocument();
  });
'''
path.write_text(text[:index] + addition + text[index:], encoding="utf-8")
