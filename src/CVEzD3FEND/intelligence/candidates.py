"""AI candidate queue: generate, validate, promote, reject.

Implements the state machine of contracts/AI_ASSISTANCE_CONTRACT.md §3-4:

    generate              -> candidate
    validate-candidates   -> validated_candidate | rejected
    promote-candidate     -> canonical (human-invoked, writes promoted-edges.json)
    reject-candidate      -> rejected (human-invoked)

Candidate generation is a deterministic *analogy* heuristic over the existing
canonical graph (no invented ids, no dangling refs): for each
`attack_without_defend` gap, if a sibling sub-technique (sharing the same base
ATT&CK technique id) already has `attack_maps_to_defend` edges, propose the
same D3FEND techniques for the gapped technique with low confidence. The AI
provider is only used to produce the human-readable rationale text.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from CVEzD3FEND.config import Settings
from CVEzD3FEND.graph.context import make_edge
from CVEzD3FEND.intelligence import rag
from CVEzD3FEND.intelligence.providers import get_provider
from CVEzD3FEND.intelligence.providers.base import Provider
from CVEzD3FEND.models.ai import AICandidate
from CVEzD3FEND.models.bundle import Bundle
from CVEzD3FEND.models.graph import Edge, EdgeType, Node, NodeType
from CVEzD3FEND.util import now_iso, safe_id_fragment

REPO_ROOT = Path(__file__).resolve().parents[3]


def _prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def load_candidates(settings: Settings) -> list[AICandidate]:
    path = settings.ai_candidates_path
    if not path.exists():
        return []
    candidates: list[AICandidate] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            candidates.append(AICandidate.model_validate(json.loads(line)))
    return candidates


def save_candidates(settings: Settings, candidates: list[AICandidate]) -> None:
    settings.review_dir.mkdir(parents=True, exist_ok=True)
    with settings.ai_candidates_path.open("w", encoding="utf-8") as f:
        for candidate in candidates:
            f.write(candidate.model_dump_json() + "\n")


def _base_technique(attack_id: str) -> str:
    return attack_id.split(".")[0]


def generate_candidates(
    bundle: Bundle,
    settings: Settings,
    *,
    limit: int = 10,
    provider: Provider | None = None,
) -> list[AICandidate]:
    """Generate up to `limit` new candidates from open `attack_without_defend` gaps.

    Candidates already proposed for a gap (matched via `input_refs`) are
    skipped, so repeated calls accumulate distinct candidates.
    """
    provider = provider or get_provider(settings)
    nodes_by_id: dict[str, Node] = {n.id: n for n in bundle.nodes}
    attack_to_defend: dict[str, list[str]] = bundle.indexes.get("attack_to_defend", {})

    base_groups: dict[str, list[str]] = {}
    for attack_id in attack_to_defend:
        base_groups.setdefault(_base_technique(attack_id), []).append(attack_id)

    existing = load_candidates(settings)
    seen_inputs = {tuple(c.input_refs[:2]) for c in existing}

    gap_nodes = [
        n
        for n in bundle.nodes
        if n.type == NodeType.GAP and n.metadata.get("reason") == "attack_without_defend"
    ]

    new_candidates: list[AICandidate] = []
    for gap in sorted(gap_nodes, key=lambda n: n.id):
        if len(new_candidates) >= limit:
            break
        attack_id = gap.metadata.get("target")
        attack_node = nodes_by_id.get(attack_id)
        if attack_id is None or attack_node is None:
            continue

        analogues = sorted(
            a for a in base_groups.get(_base_technique(attack_id), []) if a != attack_id
        )
        if not analogues:
            continue
        analogue = analogues[0]
        if (attack_id, analogue) in seen_inputs:
            continue

        proposed_defends = attack_to_defend.get(analogue, [])
        if not proposed_defends:
            continue

        proposed_edges: list[Edge] = []
        for defend_id in proposed_defends:
            if defend_id not in nodes_by_id:
                continue
            proposed_edges.append(
                make_edge(
                    EdgeType.ATTACK_MAPS_TO_DEFEND,
                    attack_id,
                    defend_id,
                    label="ai-proposed by analogy",
                    confidence=0.20,
                    deterministic=False,
                    inferred=True,
                    source_ref=None,
                    metadata={
                        "derivation": "ai_candidate_analogy",
                        "analogue_technique": analogue,
                    },
                )
            )
        if not proposed_edges:
            continue

        analogue_node = nodes_by_id.get(analogue)
        prompt = (
            f"ATT&CK technique {attack_id} ({attack_node.name}) currently has no "
            f"D3FEND mapping. Its sibling sub-technique {analogue} "
            f"({analogue_node.name if analogue_node else analogue}) maps to "
            f"D3FEND technique(s) {', '.join(proposed_defends)}. In 1-2 sentences, "
            "explain why these D3FEND techniques may also be applicable defensive "
            f"countermeasures for {attack_id}, and note any caveats."
        )
        rationale = provider.complete(
            system=(
                "You are a defensive security analyst proposing candidate "
                "ATT&CK-to-D3FEND mappings for human review. Be concise, "
                "hedge appropriately, and never claim certainty."
            ),
            prompt=prompt,
        )

        citations = rag.retrieve_bundle(f"{attack_id} {attack_node.name}", bundle, top_k=3)
        candidate_id = f"AIC-{safe_id_fragment(attack_id)}-{safe_id_fragment(analogue)}"

        new_candidates.append(
            AICandidate(
                candidate_id=candidate_id,
                created_at=now_iso(),
                provider=provider.name,
                prompt_hash=_prompt_hash(prompt),
                input_refs=[attack_id, analogue, gap.id, *[c.ref for c in citations]],
                proposed_nodes=[],
                proposed_edges=[e.model_dump(mode="json") for e in proposed_edges],
                rationale=rationale,
                confidence=0.20,
                validation_status="pending",
                policy_decision=None,
                reviewer=None,
                final_status="candidate",
            )
        )
        seen_inputs.add((attack_id, analogue))

    all_candidates = existing + new_candidates
    save_candidates(settings, all_candidates)
    return new_candidates


def validate_candidates(bundle: Bundle, candidates: list[AICandidate]) -> list[AICandidate]:
    """Run deterministic validation on every `pending` candidate.

    Checks: GRAPH_CONTRACT shape, `deterministic=false`/`inferred=true` on
    proposed edges, `canonical=false`/`inferred=true` on proposed nodes, no
    dangling `source`/`target` references, and no duplicate of an existing
    canonical edge id.
    """
    node_ids = {n.id for n in bundle.nodes}
    edge_ids = {e.id for e in bundle.edges}

    out: list[AICandidate] = []
    for candidate in candidates:
        if candidate.validation_status != "pending":
            out.append(candidate)
            continue

        errors: list[str] = []
        proposed_node_ids: set[str] = set()

        for raw_node in candidate.proposed_nodes:
            try:
                node = Node.model_validate(raw_node)
            except ValidationError as exc:
                errors.append(f"invalid proposed node: {exc}")
                continue
            if node.canonical or not node.inferred:
                errors.append(f"proposed node {node.id} must have canonical=false, inferred=true")
            proposed_node_ids.add(node.id)

        for raw_edge in candidate.proposed_edges:
            try:
                edge = Edge.model_validate(raw_edge)
            except ValidationError as exc:
                errors.append(f"invalid proposed edge: {exc}")
                continue
            if edge.deterministic or not edge.inferred:
                errors.append(f"proposed edge {edge.id} must have deterministic=false, inferred=true")
            if edge.source not in node_ids and edge.source not in proposed_node_ids:
                errors.append(f"proposed edge {edge.id} references unknown source '{edge.source}'")
            if edge.target not in node_ids and edge.target not in proposed_node_ids:
                errors.append(f"proposed edge {edge.id} references unknown target '{edge.target}'")
            if edge.id in edge_ids:
                errors.append(f"proposed edge {edge.id} duplicates an existing canonical edge")

        if errors:
            candidate = candidate.model_copy(
                update={
                    "validation_status": "rejected",
                    "final_status": "rejected",
                    "validation_errors": errors,
                }
            )
        else:
            candidate = candidate.model_copy(
                update={
                    "validation_status": "validated",
                    "final_status": "validated_candidate",
                    "validation_errors": [],
                }
            )
        out.append(candidate)
    return out


def promote_candidate(
    settings: Settings, candidates: list[AICandidate], candidate_id: str, reviewer: str
) -> tuple[AICandidate, list[AICandidate]]:
    """Promote a `validated_candidate` to `canonical`, writing `promoted-edges.json`.

    Returns the updated candidate and the full updated candidate list (caller
    persists via `save_candidates`).
    """
    if not reviewer.strip():
        raise ValueError("--reviewer is required to promote a candidate")

    out: list[AICandidate] = []
    promoted: AICandidate | None = None
    for candidate in candidates:
        if candidate.candidate_id != candidate_id:
            out.append(candidate)
            continue
        if candidate.final_status != "validated_candidate":
            raise ValueError(
                f"Candidate {candidate_id} is not validated_candidate "
                f"(final_status={candidate.final_status}); run `ai validate-candidates` first"
            )
        promoted = candidate.model_copy(
            update={
                "final_status": "canonical",
                "policy_decision": "promoted",
                "reviewer": reviewer,
            }
        )
        out.append(promoted)

    if promoted is None:
        raise ValueError(f"Unknown candidate: {candidate_id}")

    promoted_path = settings.promoted_edges_path
    overlay: list[dict] = []
    if promoted_path.exists():
        overlay = json.loads(promoted_path.read_text(encoding="utf-8"))

    for raw_edge in promoted.proposed_edges:
        edge = dict(raw_edge)
        edge["inferred"] = True
        edge["metadata"] = {
            **edge.get("metadata", {}),
            "promoted_from_candidate": {"candidate_id": candidate_id, "reviewer": reviewer},
        }
        overlay.append(edge)

    promoted_path.parent.mkdir(parents=True, exist_ok=True)
    promoted_path.write_text(json.dumps(overlay, indent=2), encoding="utf-8")

    return promoted, out


def reject_candidate(candidates: list[AICandidate], candidate_id: str, reviewer: str) -> list[AICandidate]:
    """Mark a candidate as `rejected` by human review."""
    if not reviewer.strip():
        raise ValueError("--reviewer is required to reject a candidate")

    out: list[AICandidate] = []
    found = False
    for candidate in candidates:
        if candidate.candidate_id == candidate_id:
            found = True
            candidate = candidate.model_copy(
                update={
                    "validation_status": "rejected",
                    "final_status": "rejected",
                    "policy_decision": "rejected_by_reviewer",
                    "reviewer": reviewer,
                }
            )
        out.append(candidate)

    if not found:
        raise ValueError(f"Unknown candidate: {candidate_id}")
    return out
