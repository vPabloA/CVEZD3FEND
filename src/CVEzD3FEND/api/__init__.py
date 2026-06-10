"""Optional FastAPI sidecar (`pip install .[api]`, `CVEzD3FEND api`).

Read-only over `data/dist/knowledge-bundle.json`; AI candidate endpoints only
append to `data/review/ai-candidates.jsonl` / `data/dist/promoted-edges.json`,
never the bundle itself. See docs/ARCHITECTURE.md "API (optional)".
"""
