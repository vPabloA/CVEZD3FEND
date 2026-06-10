"""Governed retrieval for the AI layer (AI_ASSISTANCE_CONTRACT §6).

Retrieval is restricted to the local, already-validated corpus:
`data/dist/knowledge-bundle.json` (via the in-memory `Bundle`),
`data/dist/quality-report.json`, `contracts/**`, and `docs/**`. No network
access, no third-party search. Every result carries a citation so prompts and
candidates can be traced back to a `node_id`/`source_ref`/file path.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from CVEzD3FEND.models.bundle import Bundle

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_DOC_DIRS = ("contracts", "docs")


@dataclass
class Citation:
    ref: str
    source_url: str | None
    confidence: float


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if len(t) >= 2]


def retrieve_bundle(query: str, bundle: Bundle, top_k: int = 5) -> list[Citation]:
    """Rank `bundle.nodes` against `query` using the `by_text` index."""
    tokens = _tokenize(query)
    if not tokens:
        return []
    by_text: dict[str, list[str]] = bundle.indexes.get("by_text", {})
    scores: Counter[str] = Counter()
    for token in tokens:
        for node_id in by_text.get(token, []):
            scores[node_id] += 1
    nodes_by_id = {n.id: n for n in bundle.nodes}
    out: list[Citation] = []
    for node_id, score in scores.most_common(top_k):
        node = nodes_by_id.get(node_id)
        if node is None:
            continue
        source_url = node.external_refs[0] if node.external_refs else None
        out.append(Citation(ref=node_id, source_url=source_url, confidence=round(min(1.0, score / len(tokens)), 2)))
    return out


def retrieve_docs(query: str, repo_root: Path, top_k: int = 3) -> list[Citation]:
    """Keyword-match `query` against `contracts/*.md` and `docs/*.md`."""
    tokens = set(_tokenize(query))
    if not tokens:
        return []
    scored: list[tuple[int, Path]] = []
    for base in _DOC_DIRS:
        base_dir = repo_root / base
        if not base_dir.is_dir():
            continue
        for path in sorted(base_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8").lower()
            score = sum(text.count(token) for token in tokens)
            if score:
                scored.append((score, path))
    scored.sort(key=lambda item: item[0], reverse=True)
    out: list[Citation] = []
    for score, path in scored[:top_k]:
        out.append(Citation(ref=str(path.relative_to(repo_root)), source_url=None, confidence=round(min(1.0, score / 50), 2)))
    return out


def retrieve(query: str, bundle: Bundle, repo_root: Path, top_k: int = 5) -> list[Citation]:
    """Combined bundle + docs retrieval, bundle hits ranked first."""
    bundle_hits = retrieve_bundle(query, bundle, top_k=top_k)
    doc_hits = retrieve_docs(query, repo_root, top_k=max(1, top_k // 2))
    return [*bundle_hits, *doc_hits]
