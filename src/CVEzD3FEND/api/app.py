"""FastAPI sidecar app factory.

Mirrors the read surface of `CVEzD3FEND.cli` and `contracts/MCP_CONTRACT.md`
over HTTP for local tooling/dashboards. The bundle is loaded once and cached;
`POST /api/reload` re-reads it from disk after `CVEzD3FEND build`. AI
candidate endpoints implement the AI_ASSISTANCE_CONTRACT state machine and
only ever write to `data/review/ai-candidates.jsonl` / `data/dist/promoted-edges.json`.
"""

from __future__ import annotations

import json
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from CVEzD3FEND import __version__
from CVEzD3FEND.actions.soc_action_pack import build_soc_action_pack
from CVEzD3FEND.config import Settings, get_settings
from CVEzD3FEND.enrichment import SourceOrchestrator, available_sources
from CVEzD3FEND.enrichment.models import SourceFetchError
from CVEzD3FEND.export import csv_export, json_export, markdown, mermaid
from CVEzD3FEND.intelligence import candidates as ai_candidates
from CVEzD3FEND.intelligence import explain as ai_explain
from CVEzD3FEND.intelligence.providers.base import ProviderError
from CVEzD3FEND.lookup import node_summary, resolve_attack_id, resolve_route, search_nodes
from CVEzD3FEND.models.bundle import Bundle
from CVEzD3FEND.models.graph import NodeType
from CVEzD3FEND.reasoning import ReasoningEngine


# ---------------------------------------------------------------------------
# Bundle cache
# ---------------------------------------------------------------------------


class BundleStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._bundle: Bundle | None = None

    def load(self, force: bool = False) -> Bundle:
        if self._bundle is None or force:
            path = self.settings.bundle_path
            if not path.exists():
                raise FileNotFoundError(
                    f"Bundle not found at {path}. Run `CVEzD3FEND build` first."
                )
            self._bundle = Bundle.model_validate(json.loads(path.read_text(encoding="utf-8")))
        return self._bundle


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class GenerateCandidatesRequest(BaseModel):
    limit: int = 10


class ReviewerRequest(BaseModel):
    reviewer: str


class CVERequest(BaseModel):
    cve_id: str


class PromoteEdgeRequest(BaseModel):
    edge_id: str
    reviewer: str | None = None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = BundleStore(settings)

    app = FastAPI(
        title="CVEzD3FEND API",
        version=__version__,
        description=(
            "Read-only sidecar over data/dist/knowledge-bundle.json. "
            "AI endpoints implement the AI_ASSISTANCE_CONTRACT candidate "
            "state machine and never mutate the bundle directly."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_bundle() -> Bundle:
        try:
            return store.load()
        except FileNotFoundError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    # -- Meta / health -----------------------------------------------------

    @app.get("/")
    def root() -> dict:
        return {
            "name": "CVEzD3FEND API",
            "version": __version__,
            "docs": "/docs",
            "bundle_available": settings.bundle_path.exists(),
        }

    @app.get("/api/health")
    def health() -> dict:
        return {
            "status": "ok",
            "version": __version__,
            "bundle_path": str(settings.bundle_path),
            "bundle_available": settings.bundle_path.exists(),
        }

    @app.post("/api/reload")
    def reload_bundle() -> dict:
        try:
            bundle = store.load(force=True)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"status": "reloaded", "generated_at": bundle.generated_at}

    @app.get("/api/meta")
    def get_meta(bundle: Bundle = Depends(get_bundle)) -> dict:
        return {
            "bundle_version": bundle.bundle_version,
            "generated_at": bundle.generated_at,
            "schema_version": bundle.schema_version,
            "node_count": len(bundle.nodes),
            "edge_count": len(bundle.edges),
            "route_count": len(bundle.routes),
            "sources": [s.model_dump(mode="json") for s in bundle.sources],
            "enrichment_sources": available_sources(),
            "reasoning_available": True,
            "quality": bundle.quality,
            "coverage_summary": bundle.coverage.summary.model_dump(mode="json"),
        }

    def _reasoning_engine() -> ReasoningEngine:
        return ReasoningEngine(settings)

    @app.get("/api/evidence/{source_name}")
    def get_evidence(
        source_name: str,
        subject: str = Query(..., min_length=1),
        mode: str = Query("live", pattern="^(live|cached|offline)$"),
    ) -> dict:
        orchestrator = SourceOrchestrator(settings)
        try:
            result = orchestrator.collect(source_name, subject, mode=mode)
        except SourceFetchError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        finally:
            orchestrator.close()
        return {
            "source": source_name,
            "subject": subject,
            "mode": mode,
            "from_cache": result.from_cache,
            "fallback_used": result.fallback_used,
            "evidence": result.evidence.model_dump(mode="json"),
        }

    @app.get("/api/enrich/{cve_id}")
    def enrich_cve(cve_id: str) -> dict:
        engine = _reasoning_engine()
        try:
            result = engine.enrich(cve_id)
            return result.model_dump(mode="json")
        finally:
            engine.close()

    @app.get("/api/reason/{cve_id}")
    def reason_cve(cve_id: str) -> dict:
        engine = _reasoning_engine()
        try:
            result = engine.reason(cve_id)
            return result.model_dump(mode="json")
        finally:
            engine.close()

    @app.get("/api/provenance/{cve_id}")
    def provenance_cve(cve_id: str) -> dict:
        engine = _reasoning_engine()
        try:
            result = engine.reason(cve_id)
            return {"input": cve_id, "normalized_input": result.normalized_input, "provenance": {k: [e.model_dump(mode="json") for e in v] for k, v in result.provenance.items()}}
        finally:
            engine.close()

    @app.post("/api/ai/propose-route")
    def propose_route(req: CVERequest) -> dict:
        engine = _reasoning_engine()
        try:
            return engine.propose_route(req.cve_id)
        finally:
            engine.close()

    @app.post("/api/ai/validate-route")
    def validate_route(req: CVERequest) -> dict:
        engine = _reasoning_engine()
        try:
            return engine.validate_route(req.cve_id)
        finally:
            engine.close()

    @app.post("/api/review/promote-edge")
    def promote_edge(req: PromoteEdgeRequest) -> dict:
        if not req.reviewer:
            raise HTTPException(status_code=400, detail="reviewer required")
        engine = _reasoning_engine()
        try:
            return engine.promote_edge(req.edge_id, req.reviewer)
        finally:
            engine.close()

    # -- Search / nodes ------------------------------------------------------

    @app.get("/api/search")
    def search(
        q: str = Query(..., min_length=1),
        types: Optional[str] = Query(None, description="Comma-separated NodeType filter"),
        limit: int = Query(20, ge=1, le=200),
        bundle: Bundle = Depends(get_bundle),
    ) -> dict:
        wanted: set[str] | None = None
        if types:
            wanted = {t.strip() for t in types.split(",") if t.strip()}
        results = search_nodes(bundle, q, limit * 5 if wanted else limit)
        if wanted:
            results = [n for n in results if n.type.value in wanted]
        results = results[:limit]
        return {"query": q, "total": len(results), "results": [node_summary(n) for n in results]}

    @app.get("/api/nodes/{node_id}")
    def get_node(
        node_id: str,
        limit: int = Query(20, ge=1, le=200),
        offset: int = Query(0, ge=0),
        bundle: Bundle = Depends(get_bundle),
    ) -> dict:
        nodes_by_id = {n.id: n for n in bundle.nodes}
        node = nodes_by_id.get(node_id)
        if node is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "id": node_id})

        outgoing = [e for e in bundle.edges if e.source == node_id]
        incoming = [e for e in bundle.edges if e.target == node_id]
        return {
            "node": node.model_dump(mode="json"),
            "outgoing": {
                "total": len(outgoing),
                "items": [e.model_dump(mode="json") for e in outgoing[offset : offset + limit]],
            },
            "incoming": {
                "total": len(incoming),
                "items": [e.model_dump(mode="json") for e in incoming[offset : offset + limit]],
            },
        }

    # -- Routes ---------------------------------------------------------------

    @app.get("/api/routes/{route_id}")
    def get_route(route_id: str, bundle: Bundle = Depends(get_bundle)) -> dict:
        route = next((r for r in bundle.routes if r.route_id == route_id), None)
        if route is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "id": route_id})
        return route.model_dump(mode="json")

    @app.get("/api/routes")
    def list_routes_for_cve(
        cve: str = Query(..., description="CVE id, e.g. CVE-2024-12345"),
        bundle: Bundle = Depends(get_bundle),
    ) -> dict:
        route_ids: list[str] = bundle.indexes.get("cve_routes", {}).get(cve, [])
        if not route_ids:
            nodes_by_id = {n.id: n for n in bundle.nodes}
            if cve not in nodes_by_id:
                raise HTTPException(status_code=404, detail={"error": "not_found", "id": cve})
        routes = [r for r in bundle.routes if r.route_id in route_ids]
        return {"cve": cve, "total": len(routes), "routes": [r.model_dump(mode="json") for r in routes]}

    @app.get("/api/export/route/{ref}")
    def export_route(
        ref: str,
        format: str = Query("json", pattern="^(md|mermaid|json|csv)$"),
        bundle: Bundle = Depends(get_bundle),
    ):
        route = resolve_route(bundle, ref)
        if route is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "id": ref})
        if format == "md":
            return PlainTextResponse(markdown.render_route_markdown(bundle, route), media_type="text/markdown")
        if format == "mermaid":
            return PlainTextResponse(mermaid.render_route_mermaid(bundle, route), media_type="text/plain")
        if format == "csv":
            return PlainTextResponse(csv_export.routes_csv([route]), media_type="text/csv")
        return json_export.export_json(route)

    # -- Coverage / gaps --------------------------------------------------------

    @app.get("/api/coverage")
    def get_coverage(
        technique: Optional[str] = Query(None),
        status: Optional[str] = Query(None),
        bundle: Bundle = Depends(get_bundle),
    ) -> dict:
        if technique:
            entry = next((t for t in bundle.coverage.techniques if t.attack_technique == technique), None)
            if entry is None:
                raise HTTPException(status_code=404, detail={"error": "not_found", "id": technique})
            return entry.model_dump(mode="json")

        techniques = bundle.coverage.techniques
        if status:
            techniques = [t for t in techniques if t.coverage_status == status]
        return {
            "summary": bundle.coverage.summary.model_dump(mode="json"),
            "total": len(techniques),
            "techniques": [t.model_dump(mode="json") for t in techniques],
        }

    @app.get("/api/export/coverage")
    def export_coverage(
        format: str = Query("json", pattern="^(json|csv)$"),
        bundle: Bundle = Depends(get_bundle),
    ):
        if format == "csv":
            return PlainTextResponse(csv_export.coverage_csv(bundle.coverage), media_type="text/csv")
        return json_export.export_json(bundle.coverage)

    @app.get("/api/gaps")
    def list_gaps(
        technique: Optional[str] = Query(None),
        reason: Optional[str] = Query(None),
        limit: int = Query(50, ge=1, le=500),
        bundle: Bundle = Depends(get_bundle),
    ) -> dict:
        nodes = [n for n in bundle.nodes if n.type == NodeType.GAP]
        if technique:
            gap_ids = set(bundle.indexes.get("gaps_by_technique", {}).get(technique, []))
            nodes = [n for n in nodes if n.id in gap_ids]
        if reason:
            nodes = [n for n in nodes if n.metadata.get("reason") == reason]
        total = len(nodes)
        return {"total": total, "items": [n.model_dump(mode="json") for n in nodes[:limit]]}

    # -- SOC Action Pack --------------------------------------------------------

    @app.get("/api/soc-action-pack/{ref}")
    def soc_action_pack(
        ref: str,
        format: str = Query("json", pattern="^(md|json)$"),
        bundle: Bundle = Depends(get_bundle),
    ):
        attack_id = resolve_attack_id(bundle, ref)
        if attack_id is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "id": ref})
        pack = build_soc_action_pack(bundle, attack_id)
        if format == "md":
            return PlainTextResponse(markdown.render_soc_action_pack_markdown(bundle, pack), media_type="text/markdown")
        return pack.model_dump(mode="json")

    # -- AI: context (always-available, template + optional expansion) --------

    @app.post("/api/ai/explain-route/{route_id}")
    def explain_route(route_id: str, bundle: Bundle = Depends(get_bundle)) -> dict:
        try:
            return ai_explain.explain_route(bundle, settings, route_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail={"error": "not_found", "id": route_id}) from exc

    @app.post("/api/ai/hunt-hypothesis/{attack_id}")
    def hunt_hypothesis(attack_id: str, bundle: Bundle = Depends(get_bundle)) -> dict:
        try:
            return ai_explain.generate_hunt_hypothesis(bundle, settings, attack_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail={"error": "not_found", "id": attack_id}) from exc

    @app.post("/api/ai/detection-brief/{attack_id}")
    def detection_brief(attack_id: str, bundle: Bundle = Depends(get_bundle)) -> dict:
        try:
            return ai_explain.generate_detection_brief(bundle, settings, attack_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail={"error": "not_found", "id": attack_id}) from exc

    # -- AI: candidate state machine (AI_ASSISTANCE_CONTRACT) -------------------

    @app.get("/api/ai/candidates")
    def list_candidates(status: Optional[str] = Query(None)) -> dict:
        queue = ai_candidates.load_candidates(settings)
        if status:
            queue = [c for c in queue if c.final_status == status]
        return {"total": len(queue), "candidates": [c.model_dump(mode="json") for c in queue]}

    @app.post("/api/ai/candidates/generate")
    def generate_candidates(
        req: GenerateCandidatesRequest = GenerateCandidatesRequest(),
        bundle: Bundle = Depends(get_bundle),
    ) -> dict:
        try:
            new = ai_candidates.generate_candidates(bundle, settings, limit=req.limit)
        except ProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"generated": len(new), "candidates": [c.model_dump(mode="json") for c in new]}

    @app.post("/api/ai/candidates/validate")
    def validate_candidates(bundle: Bundle = Depends(get_bundle)) -> dict:
        pending = ai_candidates.load_candidates(settings)
        updated = ai_candidates.validate_candidates(bundle, pending)
        ai_candidates.save_candidates(settings, updated)
        n_validated = sum(1 for c in updated if c.final_status == "validated_candidate")
        n_rejected = sum(1 for c in updated if c.validation_status == "rejected")
        return {
            "total": len(updated),
            "validated": n_validated,
            "rejected": n_rejected,
            "candidates": [c.model_dump(mode="json") for c in updated],
        }

    @app.post("/api/ai/candidates/{candidate_id}/promote")
    def promote_candidate(candidate_id: str, req: ReviewerRequest) -> dict:
        queue = ai_candidates.load_candidates(settings)
        try:
            promoted, updated = ai_candidates.promote_candidate(settings, queue, candidate_id, req.reviewer)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        ai_candidates.save_candidates(settings, updated)
        return {"promoted": promoted.model_dump(mode="json")}

    @app.post("/api/ai/candidates/{candidate_id}/reject")
    def reject_candidate(candidate_id: str, req: ReviewerRequest) -> dict:
        queue = ai_candidates.load_candidates(settings)
        try:
            updated = ai_candidates.reject_candidate(queue, candidate_id, req.reviewer)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        ai_candidates.save_candidates(settings, updated)
        rejected = next(c for c in updated if c.candidate_id == candidate_id)
        return {"rejected": rejected.model_dump(mode="json")}

    return app
