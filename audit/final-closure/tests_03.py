from pathlib import Path

path = Path("web/src/test/graphNavigator.test.tsx")
text = path.read_text(encoding="utf-8")
old = '    expect(screen.getByText("This route is partial. Defensive intent is available, but no canonical CWE/CAPEC chain was found.")).toBeInTheDocument();'
new = '    expect(screen.getByText("This route is partial: Missing CWE layer; Missing CAPEC layer.")).toBeInTheDocument();'
if text.count(old) != 1:
    raise RuntimeError("Historical partial-route assertion not found exactly once")
path.write_text(text.replace(old, new), encoding="utf-8")
