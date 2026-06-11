from __future__ import annotations

from CVEzD3FEND.reasoning.attack_mapping import attack_candidates
from CVEzD3FEND.reasoning.capec_fit import score_capec_fit
from CVEzD3FEND.reasoning.d3fend_intent import defensive_intents
from CVEzD3FEND.reasoning.models import ReasoningEdge
from CVEzD3FEND.reasoning.provenance import needs_human_review


def test_attack_candidates_use_canonical_semantics():
    tags = [
        "rce",
        "public_facing_application",
        "command_injection",
        "remote_service",
        "cloud_context",
        "container_context",
        "shell_execution",
    ]

    attack_ids = [candidate.attack_id for candidate in attack_candidates(tags)]

    assert "T1190" in attack_ids
    assert "T1210" in attack_ids
    assert "T1059" in attack_ids
    assert "T1059.004" in attack_ids


def test_defensive_intents_include_execution_containment():
    intents = defensive_intents(["rce", "command_injection", "shell_execution"])

    labels = [intent.label for intent in intents]

    assert "contención de ejecución" in labels
    assert all(intent.status == "unverified" for intent in intents)


def test_capec_fit_normalizes_contextual_tags():
    fit = score_capec_fit("CAPEC-123", ["public facing application", "cloud context", "container"])

    assert fit.fit > 0.25
    assert fit.weak is False


def test_conditional_edges_force_human_review():
    edges = [
        ReasoningEdge(
            id="E-1",
            source="CVE-1",
            target="T1190",
            type="conditional_attack_mapping",
            classification="conditional",
            conditional=True,
        ),
        ReasoningEdge(
            id="E-2",
            source="CAPEC-1",
            target="T1059",
            type="capec_semantic_fit",
            classification="weak_fit",
            weak_fit=True,
        ),
    ]

    required, reason = needs_human_review(edges)

    assert required is True
    assert "conditional" in reason
    assert "weak_fit" in reason
