from pathlib import Path

path = Path("web/src/pages/AnalyzePage.tsx")
text = path.read_text(encoding="utf-8")
replacements = [
    ("border border-amber-500/40 bg-amber-950/20 p-4 text-sm text-amber-100", "border border-amber-500/70 bg-amber-950 p-4 text-sm text-amber-50"),
    ("mt-1 text-amber-200", "mt-1 text-amber-100"),
    ("border border-rose-500/40 bg-rose-950/30 p-3 text-sm text-rose-100", "border border-rose-500/70 bg-rose-950 p-3 text-sm text-rose-50"),
    ("border border-amber-500/40 bg-amber-950/20 p-8 text-center text-amber-100", "border border-amber-500/70 bg-amber-950 p-8 text-center text-amber-50"),
    ("mt-2 text-sm text-amber-200", "mt-2 text-sm text-amber-100"),
    ("border border-violet-500/40 bg-violet-950/30 p-3 text-sm text-violet-100", "border border-violet-500/70 bg-violet-950 p-3 text-sm text-violet-50"),
]
for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"Unexpected AnalyzePage contrast source shape ({count}): {old}")
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
