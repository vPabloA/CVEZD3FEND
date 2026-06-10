"""Build `data/dist/quality-report.json` per contracts/VALIDATION_CONTRACT.md §5."""

from __future__ import annotations

from collections import Counter

from CVEzD3FEND.config import Settings
from CVEzD3FEND.models.bundle import Bundle, QualityReport, Warning
from CVEzD3FEND.util import now_iso


def build_quality_report(
    bundle: Bundle,
    settings: Settings,
    *,
    gap_totals: dict[str, int],
    gap_emitted: dict[str, int],
    framework_routes_total: int,
    framework_routes_emitted: int,
    fatal_errors: list[str],
    raw_warnings: list[str],
    ai_candidates_summary: dict | None = None,
) -> QualityReport:
    node_counts = Counter(n.type.value for n in bundle.nodes)
    edge_counts = Counter(e.type.value for e in bundle.edges)

    canonical_routes = sum(1 for r in bundle.routes if r.canonical)
    inferred_routes = sum(1 for r in bundle.routes if r.inferred)

    low_confidence_edges: Counter[str] = Counter()
    edges_without_provenance = 0
    for e in bundle.edges:
        if e.confidence < 0.5:
            low_confidence_edges[e.type.value] += 1
        if e.source_ref is None:
            edges_without_provenance += 1

    referenced: set[str] = set()
    for e in bundle.edges:
        referenced.add(e.source)
        referenced.add(e.target)
    orphan_by_type: Counter[str] = Counter()
    for n in bundle.nodes:
        if n.id not in referenced:
            orphan_by_type[n.type.value] += 1
    orphan_total = sum(orphan_by_type.values())

    source_status_counts: Counter[str] = Counter()
    source_details = []
    for s in bundle.sources:
        source_status_counts[s.status] += 1
        if s.status != "ok":
            source_details.append(
                {"source_id": s.source_id, "status": s.status, "notes": s.notes}
            )

    coverage_summary = {
        "covered": bundle.coverage.summary.covered,
        "partial": bundle.coverage.summary.partial,
        "gap": bundle.coverage.summary.gap,
        "unknown": bundle.coverage.summary.unknown,
        "not_applicable": bundle.coverage.summary.not_applicable,
    }

    warnings: list[Warning] = []
    for w in raw_warnings:
        warnings.append(Warning(code="build_warning", message=w))
    if framework_routes_total > framework_routes_emitted:
        warnings.append(
            Warning(
                code="framework_routes_truncated",
                message=(
                    f"Emitted {framework_routes_emitted}/{framework_routes_total} "
                    "framework (CWE->D3FEND) routes; raise "
                    "CVEZD3FEND_MAX_FRAMEWORK_ROUTES to emit more."
                ),
                context={"total": framework_routes_total, "emitted": framework_routes_emitted},
            )
        )
    for reason, total in gap_totals.items():
        emitted = gap_emitted.get(reason, 0)
        if total > emitted:
            warnings.append(
                Warning(
                    code="gaps_truncated",
                    message=(
                        f"Emitted {emitted}/{total} gap nodes for reason '{reason}'; raise "
                        "CVEZD3FEND_MAX_GAPS_PER_REASON to emit more."
                    ),
                    context={"reason": reason, "total": total, "emitted": emitted},
                )
            )

    return QualityReport(
        generated_at=now_iso(),
        bundle_version=bundle.bundle_version,
        node_counts=dict(sorted(node_counts.items())),
        edge_counts=dict(sorted(edge_counts.items())),
        routes={
            "total": len(bundle.routes),
            "canonical": canonical_routes,
            "inferred": inferred_routes,
            "framework_total": framework_routes_total,
            "framework_emitted": framework_routes_emitted,
        },
        gaps={"total": sum(gap_totals.values()), "by_reason": dict(gap_totals), "emitted": dict(gap_emitted)},
        warnings=warnings,
        sources={
            "ok": source_status_counts.get("ok", 0),
            "fallback": source_status_counts.get("fallback", 0),
            "unavailable": source_status_counts.get("unavailable", 0),
            "error": source_status_counts.get("error", 0),
            "details": source_details,
        },
        edges_without_provenance=edges_without_provenance,
        low_confidence_edges=dict(sorted(low_confidence_edges.items())),
        orphan_nodes={"total": orphan_total, "by_type": dict(sorted(orphan_by_type.items()))},
        coverage_summary=coverage_summary,
        ai_candidates=ai_candidates_summary or {"total": 0, "by_status": {}},
        fatal_errors=fatal_errors,
    )
