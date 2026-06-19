from pathlib import Path

path = Path("web/src/components/reasoning/batch/BatchDecisionSummary.tsx")
text = path.read_text(encoding="utf-8")
replacements = [
    ("rounded-xl border border-slate-800 bg-slate-950/70 p-3", "rounded-xl border border-slate-700 bg-slate-900 p-3"),
    ('text-slate-500">{label}', 'text-slate-300">{label}'),
    ('text-xs text-slate-500">{detail}', 'text-xs text-slate-300">{detail}'),
    ("border-amber-500/40 bg-amber-950/20", "border-amber-500/70 bg-amber-950"),
    ("border-rose-500/40 bg-rose-950/20", "border-rose-500/70 bg-rose-950"),
    ("mt-1 text-sm text-slate-400", "mt-1 text-sm text-slate-300"),
    ("border border-amber-500/40 bg-amber-950/30 p-3 text-amber-100", "border border-amber-500/70 bg-amber-950 p-3 text-amber-50"),
    ("border border-rose-500/40 bg-rose-950/30 p-3 text-rose-100", "border border-rose-500/70 bg-rose-950 p-3 text-rose-50"),
    ("border border-violet-500/40 bg-violet-950/30 p-3 text-violet-100", "border border-violet-500/70 bg-violet-950 p-3 text-violet-50"),
]
for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"Unexpected decision summary source shape ({count}): {old}")
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
