"""End-to-end build pipeline: ETL -> graph -> coverage -> routes -> indexes -> bundle -> validation.

This is the single entry point used by `CVEzD3FEND build` (and by tests) to
produce `data/dist/knowledge-bundle.json` + `data/dist/quality-report.json`.
"""

from __future__ import annotations

import httpx

from CVEzD3FEND import __version__
from CVEzD3FEND.config import Settings
from CVEzD3FEND.coverage.model import compute_coverage
from CVEzD3FEND.graph.builder import build_graph
from CVEzD3FEND.graph.context import GraphContext
from CVEzD3FEND.graph.index import build_indexes
from CVEzD3FEND.models.bundle import Bundle, QualityReport, Warning
from CVEzD3FEND.routing.routes import compute_routes
from CVEzD3FEND.util import now_iso
from CVEzD3FEND.validation.quality import build_quality_report
from CVEzD3FEND.validation.schema import validate_structure

SCHEMA_VERSION = "1.0.0"


def run_build(settings: Settings, client: httpx.Client | None = None) -> tuple[Bundle, QualityReport]:
    result = build_graph(settings, client)

    ctx = GraphContext()
    for node in result.nodes:
        ctx.nodes[node.id] = node
    for edge in result.edges:
        ctx.edges[edge.id] = edge

    coverage_result = compute_coverage(ctx, settings)

    nodes = sorted(ctx.nodes.values(), key=lambda n: n.id)
    edges = sorted(ctx.edges.values(), key=lambda e: e.id)

    route_result = compute_routes(nodes, edges, coverage_result.coverage_by_attack, settings)
    indexes = build_indexes(nodes, edges, route_result.routes, coverage_result.coverage_by_attack)

    bundle = Bundle(
        bundle_version=__version__,
        generated_at=now_iso(),
        schema_version=SCHEMA_VERSION,
        sources=result.sources,
        nodes=nodes,
        edges=edges,
        indexes=indexes,
        routes=route_result.routes,
        coverage=coverage_result.coverage,
        quality={},
        provenance={s.source_id: s.model_dump(mode="json") for s in result.sources},
        warnings=[Warning(code="build_warning", message=w) for w in result.warnings],
    )

    fatal_errors = validate_structure(bundle)
    quality_report = build_quality_report(
        bundle,
        settings,
        gap_totals=coverage_result.gap_totals,
        gap_emitted=coverage_result.gap_emitted,
        framework_routes_total=route_result.framework_routes_total,
        framework_routes_emitted=route_result.framework_routes_emitted,
        fatal_errors=fatal_errors,
        raw_warnings=result.warnings,
    )
    bundle.quality = quality_report.model_dump(mode="json")
    return bundle, quality_report
