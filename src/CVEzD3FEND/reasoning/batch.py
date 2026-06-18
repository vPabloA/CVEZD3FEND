"""Deterministic multi-CVE reasoning orchestration.

Catalogs prove route edges. Exact Galeax records anchor CVE→CWE and only
corroborate later nodes. AI may rerank existing routes but cannot create them.
"""

from __future__ import annotations

import json
from collections import defaultdict

import httpx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.intelligence.providers import get_provider
from CVEzD3FEND.intelligence.providers.base import Provider, ProviderError
from CVEzD3FEND.models.bundle import Bundle
from CVEzD3FEND.reasoning.batch_candidates import (
    BatchLimitError,
    build_candidate_pool,
    normalize_cve_inputs,
)
from CVEzD3FEND.reasoning.batch_selection import (
    _parse_ai_route_order,
    score_routes,
    select_routes,
)
from CVEzD3FEND.reasoning.exact_lookup import ExactGaleaxLookup, ExactLookupResult
from CVEzD3FEND.reasoning.models import (
    BatchAnalysisRequest,
    BatchNarrative,
    BatchReasoningResult,
    BatchSelectionSummary,
    RankedRoute,
)

__all__ = [
    "BatchLimitError",
    "BatchReasoningEngine",
    "build_candidate_pool",
    "normalize_cve_inputs",
    "score_routes",
    "select_routes",
]


def _render_batch_narrative(
    found: list[str],
    selected: list[RankedRoute],
    available_count: int,
    missing: list[str],
    invalid: list[str],
    shared_attack: list[str],
    shared_defend: list[str],
    summary: BatchSelectionSummary,
) -> BatchNarrative:
    top_cves = list(dict.fromkeys(route.cve_id for route in selected))
    executive = (
        f"Se analizaron {len(found)} CVE encontradas y se redujeron {available_count} rutas válidas "
        f"a {len(selected)} rutas priorizadas. Las CVE representadas son "
        f"{', '.join(top_cves) if top_cves else 'ninguna'}; "
        f"{len(summary.unrepresented_cves)} quedaron fuera del Top-K por la política declarada."
    )
    operational = (
        f"Priorizar validación sobre ATT&CK compartido: {', '.join(shared_attack[:8]) or 'sin convergencias'}; "
        f"capacidades D3FEND reutilizables: {', '.join(shared_defend[:8]) or 'sin reutilización transversal'}."
    )
    technical = (
        f"Universo={available_count}; seleccionadas={len(selected)}; "
        f"política={summary.representation_policy}; modo={summary.selection_mode}. "
        f"Missing={', '.join(missing) or 'none'}; invalid={', '.join(invalid) or 'none'}. "
        "Cada salto de cada ruta está respaldado por una arista CVE2CAPEC/CWE/CAPEC/ATT&CK/D3FEND; "
        "las assertions agregadas del registro CVE solo se usan como corroboración."
    )
    return BatchNarrative(
        executive_summary_es=executive,
        operational_summary_es=operational,
        technical_summary_es=technical,
    )


class BatchReasoningEngine:
    def __init__(
        self,
        settings: Settings,
        bundle: Bundle,
        *,
        client: httpx.Client | None = None,
        provider: Provider | None = None,
    ) -> None:
        self.settings = settings
        self.bundle = bundle
        self.lookup = ExactGaleaxLookup(settings, client=client)
        self.provider = provider

    def close(self) -> None:
        self.lookup.close()

    def analyze(self, request: BatchAnalysisRequest) -> BatchReasoningResult:
        requested, invalid = normalize_cve_inputs(request.cve_ids)
        if len(requested) > self.settings.max_batch_cves:
            raise BatchLimitError(
                f"request contains {len(requested)} valid CVEs; maximum is {self.settings.max_batch_cves}"
            )
        years = {int(cve_id.split("-", 2)[1]) for cve_id in requested}
        if len(years) > self.settings.max_batch_years:
            raise BatchLimitError(
                f"request spans {len(years)} years; maximum is {self.settings.max_batch_years}"
            )
        if not requested:
            return BatchReasoningResult(
                status="invalid",
                requested_cves=[],
                invalid_inputs=invalid,
                selection_summary=BatchSelectionSummary(),
                narrative=_render_batch_narrative([], [], 0, [], invalid, [], [], BatchSelectionSummary()),
                warnings=["No valid CVE identifiers were provided."],
            )

        exact: ExactLookupResult = self.lookup.lookup(requested)
        found = [cve_id for cve_id in requested if cve_id in exact.records]
        pool = build_candidate_pool(
            self.bundle,
            {cve_id: exact.records[cve_id] for cve_id in found},
            exact.sources,
            max_routes=self.settings.max_batch_candidate_routes,
        )
        scored = score_routes(pool.routes, pool.nodes, request.context)

        shortlist_size = min(
            len(scored),
            max(request.top_k, request.top_k * max(1, self.settings.batch_shortlist_multiplier)),
        )
        deterministic_shortlist, _ = select_routes(scored, shortlist_size, requested)
        deterministic_selected, selection_summary = select_routes(
            deterministic_shortlist,
            min(request.top_k, len(deterministic_shortlist)),
            requested,
        )

        selected = deterministic_selected
        selection_mode = "deterministic"
        fallback_used = False
        warnings = list(exact.warnings)

        if request.use_ai:
            if not self.settings.ai_enabled:
                fallback_used = True
                warnings.append("AI reranking requested but AI is disabled; deterministic selection used.")
            elif deterministic_shortlist:
                try:
                    provider = self.provider or get_provider(self.settings)
                    prompt = json.dumps(
                        {
                            "top_k": request.top_k,
                            "context": request.context.model_dump(mode="json"),
                            "routes": [
                                {
                                    "route_id": route.route_id,
                                    "cve_id": route.cve_id,
                                    "score": route.score,
                                    "attack_ids": route.attack_ids,
                                    "defend_ids": route.defend_ids,
                                    "reasons": route.selection_reasons,
                                }
                                for route in deterministic_shortlist
                            ],
                            "response_schema": {"route_ids": ["existing route ids only"]},
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    response = provider.complete(
                        system=(
                            "Rerank only the supplied routes. Return JSON with route_ids. "
                            "Never create routes, nodes, edges, or identifiers."
                        ),
                        prompt=prompt,
                    )
                    ai_order = _parse_ai_route_order(
                        response,
                        {route.route_id for route in deterministic_shortlist},
                    )
                    ai_order.extend(
                        route.route_id
                        for route in deterministic_shortlist
                        if route.route_id not in ai_order
                    )
                    selected, selection_summary = select_routes(
                        deterministic_shortlist,
                        min(request.top_k, len(deterministic_shortlist)),
                        requested,
                        preference_order=ai_order,
                    )
                    selection_mode = "ai_reranked"
                except (ProviderError, ValueError, json.JSONDecodeError) as exc:
                    fallback_used = True
                    warnings.append(f"AI reranking rejected; deterministic fallback used: {exc}")

        selection_summary = selection_summary.model_copy(
            update={"selection_mode": selection_mode, "fallback_used": fallback_used}
        )

        attack_cves: dict[str, set[str]] = defaultdict(set)
        defend_cves: dict[str, set[str]] = defaultdict(set)
        for route in scored:
            for attack_id in route.attack_ids:
                attack_cves[attack_id].add(route.cve_id)
            for defend_id in route.defend_ids:
                defend_cves[defend_id].add(route.cve_id)
        shared_attack = sorted(
            (attack_id for attack_id, cves in attack_cves.items() if len(cves) > 1),
            key=lambda item: (-len(attack_cves[item]), item),
        )
        shared_defend = sorted(
            (defend_id for defend_id, cves in defend_cves.items() if len(cves) > 1),
            key=lambda item: (-len(defend_cves[item]), item),
        )

        selected_node_ids = {node_id for route in selected for node_id in route.node_ids}
        selected_edge_ids = {edge_id for route in selected for edge_id in route.edge_ids}
        nodes = [pool.nodes[node_id] for node_id in sorted(selected_node_ids) if node_id in pool.nodes]
        edges = [pool.edges[edge_id] for edge_id in sorted(selected_edge_ids) if edge_id in pool.edges]

        errors = list(exact.errors)
        status = "ok"
        if errors or exact.missing_cves or invalid:
            status = "partial"
        if not found:
            status = "unavailable" if errors else "not_found"

        provenance = {
            source.source_id: source.model_dump(mode="json") for source in exact.sources
        }
        provenance["selected_route_sources"] = {
            route.route_id: route.provenance for route in selected
        }
        narrative = _render_batch_narrative(
            found,
            selected,
            len(scored),
            exact.missing_cves,
            invalid,
            shared_attack,
            shared_defend,
            selection_summary,
        )
        return BatchReasoningResult(
            status=status,
            requested_cves=requested,
            found_cves=found,
            missing_cves=exact.missing_cves,
            invalid_inputs=invalid,
            available_route_count=len(scored),
            selected_route_count=len(selected),
            candidate_routes=scored if request.include_all_candidates else [],
            selected_routes=selected,
            nodes=nodes,
            edges=edges,
            shared_attack_techniques=shared_attack,
            shared_defenses=shared_defend,
            selection_summary=selection_summary,
            narrative=narrative,
            provenance=provenance,
            warnings=warnings,
            errors=errors,
        )
