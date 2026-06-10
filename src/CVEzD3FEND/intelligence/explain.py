"""AI-assisted narrative surfaces (AI_ASSISTANCE_CONTRACT §7).

`explain_route`, `generate_hunt_hypothesis`, and `generate_detection_brief`
are always backed by a deterministic, templated summary derived from the
bundle — never empty, never blocked. When `CVEZD3FEND_AI_ENABLED=true`, the
provider is asked to expand on the template; if the provider call fails for
any reason, the deterministic template is returned unchanged.

These are "context" outputs in the AI_ASSISTANCE_CONTRACT §3 sense: grounded
explanatory text with citations, not proposals, and are never written back
into the canonical bundle.
"""

from __future__ import annotations

from CVEzD3FEND.config import Settings
from CVEzD3FEND.intelligence import rag
from CVEzD3FEND.intelligence.candidates import REPO_ROOT
from CVEzD3FEND.intelligence.providers import get_provider
from CVEzD3FEND.intelligence.providers.base import ProviderError
from CVEzD3FEND.models.bundle import Bundle, Route
from CVEzD3FEND.models.graph import Node


def _node(bundle: Bundle, node_id: str) -> Node | None:
    return next((n for n in bundle.nodes if n.id == node_id), None)


def _maybe_expand(settings: Settings, system: str, prompt: str, template: str) -> str:
    if not settings.ai_enabled:
        return template
    try:
        provider = get_provider(settings)
        completion = provider.complete(system=system, prompt=f"{prompt}\n\nDeterministic summary:\n{template}")
    except ProviderError:
        return template
    return completion or template


def explain_route(bundle: Bundle, settings: Settings, route_id: str) -> dict:
    route: Route | None = next((r for r in bundle.routes if r.route_id == route_id), None)
    if route is None:
        raise ValueError(f"Unknown route: {route_id}")

    steps = []
    for node_id in route.nodes:
        node = _node(bundle, node_id)
        steps.append(f"{node_id} ({node.name})" if node else node_id)

    template = (
        f"Route {route.route_id} runs {route.start_node} -> {route.end_node} "
        f"via {len(route.nodes)} node(s): {' -> '.join(steps)}. "
        f"Aggregate confidence is {route.confidence:.2f}; coverage status is "
        f"'{route.coverage_status}'. "
        + (
            f"Recommended actions: {', '.join(route.recommended_actions)}. "
            if route.recommended_actions
            else "No recommended actions are linked yet. "
        )
        + (
            f"Evidence required: {', '.join(route.evidence_required)}."
            if route.evidence_required
            else "No evidence requirements recorded."
        )
    )

    citations = rag.retrieve(route.start_node, bundle, REPO_ROOT, top_k=5)
    text = _maybe_expand(
        settings,
        system=(
            "You are a defensive security analyst explaining a CVE-to-defense "
            "route to a SOC analyst. Be concise and ground every claim in the "
            "provided summary; do not invent technique or control ids."
        ),
        prompt=f"Explain route {route.route_id} for a SOC analyst.",
        template=template,
    )
    return {"route_id": route.route_id, "text": text, "citations": [c.__dict__ for c in citations]}


def generate_detection_brief(bundle: Bundle, settings: Settings, attack_id: str) -> dict:
    attack_node = _node(bundle, attack_id)
    if attack_node is None:
        raise ValueError(f"Unknown ATT&CK technique: {attack_id}")

    detections = bundle.indexes.get("attack_to_detections", {}).get(attack_id, [])
    coverage_status = bundle.indexes.get("coverage_by_technique", {}).get(attack_id, "unknown")

    if detections:
        names = []
        for det_id in detections:
            det_node = _node(bundle, det_id)
            names.append(f"{det_id} ({det_node.name})" if det_node else det_id)
        template = (
            f"{attack_id} ({attack_node.name}) has {len(detections)} detection "
            f"opportunity(ies) on file: {', '.join(names)}. Coverage status: "
            f"'{coverage_status}'."
        )
    else:
        template = (
            f"{attack_id} ({attack_node.name}) currently has no detections "
            f"mapped (coverage status: '{coverage_status}'). Review the linked "
            "D3FEND techniques and existing detections for sibling sub-techniques "
            "as a starting point, or run `CVEzD3FEND ai generate-candidates` for "
            "an analogy-based proposal."
        )

    citations = rag.retrieve_bundle(f"{attack_id} {attack_node.name}", bundle, top_k=5)
    text = _maybe_expand(
        settings,
        system=(
            "You are a detection engineer drafting a brief for a SOC analyst. "
            "Be concise and ground every claim in the provided summary; do not "
            "invent detection or data source ids."
        ),
        prompt=f"Draft a detection brief for {attack_id}.",
        template=template,
    )
    return {"attack_id": attack_id, "text": text, "citations": [c.__dict__ for c in citations]}


def generate_hunt_hypothesis(bundle: Bundle, settings: Settings, attack_id: str) -> dict:
    attack_node = _node(bundle, attack_id)
    if attack_node is None:
        raise ValueError(f"Unknown ATT&CK technique: {attack_id}")

    hunt_id = f"HUNT-{attack_id.replace('.', '_')}"
    hunt_node = _node(bundle, hunt_id)
    data_sources = bundle.indexes.get("attack_to_detections", {}).get(attack_id, [])

    if hunt_node:
        template = (
            f"Existing threat hunt {hunt_node.id} ({hunt_node.name}) covers "
            f"{attack_id} ({attack_node.name}). {hunt_node.description}"
        )
    else:
        template = (
            f"No threat hunt is currently catalogued for {attack_id} "
            f"({attack_node.name}). A reasonable starting hypothesis: search for "
            f"anomalous activity consistent with {attack_node.name} across the "
            f"data/log sources tied to its {len(data_sources)} known detection(s), "
            "then pivot on related ATT&CK sub-techniques sharing the same base "
            "technique id."
        )

    citations = rag.retrieve_bundle(f"{attack_id} {attack_node.name}", bundle, top_k=5)
    text = _maybe_expand(
        settings,
        system=(
            "You are a threat hunter drafting a hypothesis for a SOC analyst. "
            "Be concise, hedge appropriately, and ground every claim in the "
            "provided summary."
        ),
        prompt=f"Draft a threat hunting hypothesis for {attack_id}.",
        template=template,
    )
    return {"attack_id": attack_id, "text": text, "citations": [c.__dict__ for c in citations]}
