"""Provenance classification helpers for reasoned output."""

from __future__ import annotations

from collections import defaultdict

from CVEzD3FEND.reasoning.models import ReasoningEdge, ReasoningEdgeClassification

ALL_BUCKETS: tuple[ReasoningEdgeClassification, ...] = (
    "official_explicit",
    "official_incomplete",
    "dataset_derived",
    "analytical_inferred",
    "conditional",
    "weak_fit",
    "unverified",
)


def bucket_edges(edges: list[ReasoningEdge]) -> dict[str, list[ReasoningEdge]]:
    buckets: dict[str, list[ReasoningEdge]] = defaultdict(list)
    for edge in edges:
        buckets[edge.classification].append(edge)
    return {bucket: buckets.get(bucket, []) for bucket in ALL_BUCKETS}


def needs_human_review(edges: list[ReasoningEdge]) -> tuple[bool, str]:
    flagged = [e for e in edges if e.classification in {"analytical_inferred", "conditional", "weak_fit", "unverified"}]
    if not flagged:
        return False, ""
    labels = sorted({e.classification for e in flagged})
    return True, f"El contrato contiene edges {', '.join(labels)} y requiere revisión humana antes de canonizar."


def classify_source_mode(statuses: list[str]) -> str:
    if any(status == "cached" for status in statuses):
        return "cached"
    if any(status in {"fallback", "unavailable", "error"} for status in statuses):
        return "static"
    return "live"
