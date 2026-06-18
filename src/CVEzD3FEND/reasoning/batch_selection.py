"""Deterministic scoring, diversity, and Top-K selection for batch routes."""

from __future__ import annotations

import json
import re
from collections import defaultdict

from CVEzD3FEND.models.graph import Node
from CVEzD3FEND.reasoning.models import AnalysisContext, BatchSelectionSummary, RankedRoute

_TOKEN_RE = re.compile(r"[a-z0-9]+")

SCORING_WEIGHTS: dict[str, float] = {
    "confidence": 0.30,
    "completeness": 0.20,
    "corroboration": 0.15,
    "context_match": 0.15,
    "attack_convergence": 0.10,
    "defensive_reuse": 0.10,
    "partial_penalty": 0.30,
}


def _context_tokens(context: AnalysisContext) -> set[str]:
    text = " ".join([*context.technologies, *context.exposure, *context.priorities])
    return {token for token in _TOKEN_RE.findall(text.lower()) if len(token) >= 3}


def _node_search_text(node: Node | None) -> str:
    if node is None:
        return ""
    metadata = json.dumps(node.metadata, ensure_ascii=False, sort_keys=True, default=str)
    return " ".join(
        [node.id, node.name, node.title, node.description, *node.aliases, *node.tags, metadata]
    ).lower()


def score_routes(
    routes: list[RankedRoute],
    nodes: dict[str, Node],
    context: AnalysisContext,
) -> list[RankedRoute]:
    attack_cves: dict[str, set[str]] = defaultdict(set)
    defend_cves: dict[str, set[str]] = defaultdict(set)
    signature_cves: dict[tuple[tuple[str, ...], tuple[str, ...]], set[str]] = defaultdict(set)
    for route in routes:
        for attack_id in route.attack_ids:
            attack_cves[attack_id].add(route.cve_id)
        for defend_id in route.defend_ids:
            defend_cves[defend_id].add(route.cve_id)
        signature_cves[(tuple(route.attack_ids), tuple(route.defend_ids))].add(route.cve_id)

    context_tokens = _context_tokens(context)
    scored: list[RankedRoute] = []
    for route in routes:
        shared_cves = max([len(attack_cves[item]) for item in route.attack_ids] or [1])
        reuse_cves = max([len(defend_cves[item]) for item in route.defend_ids] or [1])
        corroboration = len(route.corroborated_nodes) / max(len(route.node_ids), 1)
        searchable = " ".join(_node_search_text(nodes.get(node_id)) for node_id in route.node_ids)
        matched_tokens = sorted(token for token in context_tokens if token in searchable)
        context_match = len(matched_tokens) / len(context_tokens) if context_tokens else 0.0
        convergence = min(max(shared_cves - 1, 0) / 3, 1.0)
        defensive_reuse = min(max(reuse_cves - 1, 0) / 3, 1.0)
        partial_penalty = (1.0 - route.completeness) * SCORING_WEIGHTS["partial_penalty"]
        score = (
            route.confidence * SCORING_WEIGHTS["confidence"]
            + route.completeness * SCORING_WEIGHTS["completeness"]
            + corroboration * SCORING_WEIGHTS["corroboration"]
            + context_match * SCORING_WEIGHTS["context_match"]
            + convergence * SCORING_WEIGHTS["attack_convergence"]
            + defensive_reuse * SCORING_WEIGHTS["defensive_reuse"]
            - partial_penalty
        )
        reasons = [f"Mapping confidence {route.confidence:.2f}"]
        if route.completeness == 1.0:
            reasons.append("Complete catalog-backed CVE→CWE→CAPEC→ATT&CK→D3FEND route")
        else:
            reasons.append(f"Partial catalog-backed route ({route.completeness:.0%} complete)")
        if route.corroborated_nodes:
            reasons.append(
                f"{len(route.corroborated_nodes)}/{len(route.node_ids)} nodes corroborated by exact Galeax assertions"
            )
        if shared_cves > 1:
            reasons.append(f"ATT&CK convergence shared by {shared_cves} CVEs")
        if reuse_cves > 1:
            reasons.append(f"D3FEND defense reusable across {reuse_cves} CVEs")
        if matched_tokens:
            reasons.append(f"Matches request context: {', '.join(matched_tokens[:6])}")
        if route.gaps:
            reasons.append(f"Unresolved route gap: {', '.join(route.gaps)}")

        signature = (tuple(route.attack_ids), tuple(route.defend_ids))
        scored.append(
            route.model_copy(
                update={
                    "cve_ids": sorted(signature_cves[signature]),
                    "score": round(max(0.0, min(1.0, score)), 6),
                    "selection_reasons": reasons,
                    "shared_cve_count": shared_cves,
                    "defensive_reuse_count": reuse_cves,
                }
            )
        )
    return sorted(scored, key=lambda route: (-route.score, route.cve_id, route.route_id))


def _best_for_cve(
    routes: list[RankedRoute],
    cve_id: str,
    preference_rank: dict[str, int] | None,
) -> RankedRoute:
    options = [route for route in routes if route.cve_id == cve_id]
    return min(
        options,
        key=lambda route: (
            preference_rank.get(route.route_id, 10**9) if preference_rank else 0,
            -route.score,
            route.route_id,
        ),
    )


def _marginal_key(
    route: RankedRoute,
    selected: list[RankedRoute],
    preference_rank: dict[str, int] | None,
) -> tuple[float, int, str, str]:
    selected_attack = {item for chosen in selected for item in chosen.attack_ids}
    selected_defend = {item for chosen in selected for item in chosen.defend_ids}
    selected_signatures = {
        (tuple(chosen.attack_ids), tuple(chosen.defend_ids)) for chosen in selected
    }
    signature = (tuple(route.attack_ids), tuple(route.defend_ids))
    utility = route.score
    if any(item not in selected_attack for item in route.attack_ids):
        utility += 0.04
    if any(item not in selected_defend for item in route.defend_ids):
        utility += 0.04
    if route.shared_cve_count > 1:
        utility += 0.03
    if route.defensive_reuse_count > 1:
        utility += 0.03
    if signature in selected_signatures:
        utility -= 0.12
    if any(chosen.cve_id == route.cve_id for chosen in selected):
        utility -= 0.04
    preference = -(preference_rank.get(route.route_id, 10**9)) if preference_rank else 0
    return (utility, preference, route.cve_id, route.route_id)


def select_routes(
    routes: list[RankedRoute],
    top_k: int,
    requested_order: list[str],
    preference_order: list[str] | None = None,
) -> tuple[list[RankedRoute], BatchSelectionSummary]:
    if not routes or top_k <= 0:
        return [], BatchSelectionSummary()

    eligible = [cve for cve in requested_order if any(route.cve_id == cve for route in routes)]
    preference_rank = (
        {route_id: index for index, route_id in enumerate(preference_order)}
        if preference_order
        else None
    )
    selected: list[RankedRoute] = []

    if top_k < len(eligible):
        best_per_cve = [_best_for_cve(routes, cve, preference_rank) for cve in eligible]
        best_per_cve.sort(
            key=lambda route: (
                preference_rank.get(route.route_id, 10**9) if preference_rank else 0,
                -route.score,
                route.cve_id,
                route.route_id,
            )
        )
        selected = best_per_cve[:top_k]
        policy = "contextual_priority_due_to_top_k_constraint"
    else:
        selected = [_best_for_cve(routes, cve, preference_rank) for cve in eligible]
        policy = "coverage_floor_then_contextual_utility"
        remaining = [route for route in routes if route.route_id not in {item.route_id for item in selected}]
        while len(selected) < top_k and remaining:
            chosen = max(remaining, key=lambda route: _marginal_key(route, selected, preference_rank))
            selected.append(chosen)
            remaining = [route for route in remaining if route.route_id != chosen.route_id]

    represented = [cve for cve in requested_order if any(route.cve_id == cve for route in selected)]
    unrepresented = [cve for cve in eligible if cve not in represented]
    return selected, BatchSelectionSummary(
        eligible_cves=len(eligible),
        represented_cves=represented,
        unrepresented_cves=unrepresented,
        representation_policy=policy,
    )


def _parse_ai_route_order(text: str, allowed_ids: set[str]) -> list[str]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*|\s*```$", "", stripped, flags=re.IGNORECASE)
    payload = json.loads(stripped)
    values = payload.get("route_ids") if isinstance(payload, dict) else payload
    if not isinstance(values, list) or not values:
        raise ValueError("AI response must contain a non-empty route_ids list")
    route_ids = [str(value) for value in values]
    if len(route_ids) != len(set(route_ids)):
        raise ValueError("AI response contains duplicate route ids")
    unknown = [route_id for route_id in route_ids if route_id not in allowed_ids]
    if unknown:
        raise ValueError(f"AI returned unknown route ids: {', '.join(unknown)}")
    return route_ids
