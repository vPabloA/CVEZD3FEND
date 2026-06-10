"""Shared fixtures for the CVEzD3FEND test suite.

`sample_bundle` builds a small but structurally complete `Bundle` entirely
in-memory, by running the same coverage/routing/index/quality machinery as
`pipeline.run_build`, but over a handful of hand-written nodes/edges instead
of fetched ETL data. This keeps unit/integration tests fast, deterministic,
and offline while still exercising the real graph -> coverage -> routes ->
indexes -> quality pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from CVEzD3FEND import __version__
from CVEzD3FEND.config import Settings
from CVEzD3FEND.coverage.model import compute_coverage
from CVEzD3FEND.graph.builder import internal_sources
from CVEzD3FEND.graph.context import GraphContext, make_edge, make_node
from CVEzD3FEND.graph.index import build_indexes
from CVEzD3FEND.models.bundle import Bundle, Source
from CVEzD3FEND.models.graph import EdgeType, NodeType
from CVEzD3FEND.routing.routes import compute_routes
from CVEzD3FEND.util import now_iso
from CVEzD3FEND.validation.quality import build_quality_report
from CVEzD3FEND.validation.schema import validate_structure

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = REPO_ROOT / "data" / "dist" / "knowledge-bundle.json"

TEST_SOURCE_ID = "test:source"


def build_sample_bundle(settings: Settings | None = None) -> Bundle:
    """Build a small, internally-consistent Bundle for tests.

    Graph shape:
        CVE-2099-0001 -> CWE-79 -> CAPEC-100 -> T1059 -> D3-FA
                                              -> T1059.001 (no D3FEND mapping -> gap)
        CTRL-D3-FA implements D3-FA; MIT-D3-FA is its mitigation.
        DET-T1059-D3-FA detects T1059, supported by EVID-... and DS-1.
        HUNT-T1059 is a threat-hunt node for T1059.
    """
    settings = settings or Settings()
    ctx = GraphContext()

    source = Source(
        source_id=TEST_SOURCE_ID,
        name="Test Source",
        kind="test",
        fetched_at=now_iso(),
        status="ok",
    )

    def add(node_id: str, type_: NodeType, name: str, **kw) -> None:
        ctx.add_node(make_node(node_id, type_, name, source_refs=[TEST_SOURCE_ID], **kw))

    add("CVE-2099-0001", NodeType.CVE, "CVE-2099-0001")
    add("CWE-79", NodeType.CWE, "Improper Neutralization of Input")
    add("CAPEC-100", NodeType.CAPEC, "Overflow Buffers")
    add("T1059", NodeType.ATTACK, "Command and Scripting Interpreter", aliases=["cmd-interpreter"])
    add("T1059.001", NodeType.ATTACK, "PowerShell")
    add("D3-FA", NodeType.DEFEND, "File Analysis")
    add("CTRL-D3-FA", NodeType.CONTROL, "Control: File Analysis")
    add("MIT-D3-FA", NodeType.MITIGATION, "Mitigation: File Analysis")
    add("DET-T1059-D3-FA", NodeType.DETECTION, "Detection: T1059 via File Analysis")
    add("EVID-DET-T1059-D3-FA", NodeType.EVIDENCE, "Evidence for detection")
    add("DS-1", NodeType.DATA_SOURCE, "Process Monitoring")
    add("HUNT-T1059", NodeType.THREAT_HUNT, "Hunt hypothesis: T1059")

    def edge(type_: EdgeType, source: str, target: str, **kw) -> None:
        ctx.add_edge(make_edge(type_, source, target, source_ref=TEST_SOURCE_ID, **kw))

    edge(EdgeType.CVE_HAS_CWE, "CVE-2099-0001", "CWE-79")
    edge(EdgeType.CWE_MAPS_TO_CAPEC, "CWE-79", "CAPEC-100")
    edge(EdgeType.CAPEC_MAPS_TO_ATTACK, "CAPEC-100", "T1059")
    edge(EdgeType.CAPEC_MAPS_TO_ATTACK, "CAPEC-100", "T1059.001")
    edge(EdgeType.ATTACK_MAPS_TO_DEFEND, "T1059", "D3-FA")
    edge(EdgeType.CONTROL_IMPLEMENTS_DEFEND, "CTRL-D3-FA", "D3-FA")
    edge(EdgeType.DETECTION_DETECTS_ATTACK, "DET-T1059-D3-FA", "T1059")
    edge(EdgeType.EVIDENCE_SUPPORTS_DETECTION, "EVID-DET-T1059-D3-FA", "DET-T1059-D3-FA")
    edge(EdgeType.DATA_SOURCE_ENABLES_DETECTION, "DS-1", "DET-T1059-D3-FA")

    coverage_result = compute_coverage(ctx, settings)

    nodes = sorted(ctx.nodes.values(), key=lambda n: n.id)
    edges = sorted(ctx.edges.values(), key=lambda e: e.id)

    route_result = compute_routes(nodes, edges, coverage_result.coverage_by_attack, settings)
    indexes = build_indexes(nodes, edges, route_result.routes, coverage_result.coverage_by_attack)

    sources = [source, *internal_sources()]

    bundle = Bundle(
        bundle_version=__version__,
        generated_at=now_iso(),
        schema_version="1.0.0",
        sources=sources,
        nodes=nodes,
        edges=edges,
        indexes=indexes,
        routes=route_result.routes,
        coverage=coverage_result.coverage,
        quality={},
        provenance={s.source_id: s.model_dump(mode="json") for s in sources},
        warnings=[],
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
        raw_warnings=[],
    )
    return bundle.model_copy(update={"quality": quality_report.model_dump(mode="json")})


@pytest.fixture
def sample_bundle() -> Bundle:
    return build_sample_bundle()


@pytest.fixture(scope="session")
def real_bundle() -> Bundle:
    if not BUNDLE_PATH.exists():
        pytest.skip(f"{BUNDLE_PATH} not found; run `make build` first")
    data = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    return Bundle.model_validate(data)
