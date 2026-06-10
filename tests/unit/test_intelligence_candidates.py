import json

import pytest

from CVEzD3FEND.config import Settings
from CVEzD3FEND.intelligence import candidates as ai_candidates
from CVEzD3FEND.intelligence.providers.mock import MockProvider


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(data_dir=tmp_path)


def test_generate_candidates_proposes_analogy_for_gap(sample_bundle, settings):
    new_candidates = ai_candidates.generate_candidates(
        sample_bundle, settings, limit=10, provider=MockProvider()
    )

    assert len(new_candidates) == 1
    candidate = new_candidates[0]
    assert candidate.candidate_id == "AIC-T1059_001-T1059"
    assert candidate.provider == "mock"
    assert candidate.final_status == "candidate"
    assert candidate.validation_status == "pending"
    assert candidate.input_refs[:2] == ["T1059.001", "T1059"]

    assert len(candidate.proposed_edges) == 1
    edge = candidate.proposed_edges[0]
    assert edge["source"] == "T1059.001"
    assert edge["target"] == "D3-FA"
    assert edge["type"] == "attack_maps_to_defend"
    assert edge["deterministic"] is False
    assert edge["inferred"] is True
    assert edge["confidence"] == 0.20

    # Persisted to data/review/ai-candidates.jsonl
    assert settings.ai_candidates_path.exists()
    persisted = ai_candidates.load_candidates(settings)
    assert [c.candidate_id for c in persisted] == [candidate.candidate_id]


def test_generate_candidates_is_idempotent(sample_bundle, settings):
    first = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())
    second = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())

    assert len(first) == 1
    assert len(second) == 0  # already proposed for this (attack, analogue) pair
    assert len(ai_candidates.load_candidates(settings)) == 1


def test_validate_candidates_marks_well_formed_candidate_validated(sample_bundle, settings):
    generated = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())
    validated = ai_candidates.validate_candidates(sample_bundle, generated)

    assert len(validated) == 1
    candidate = validated[0]
    assert candidate.validation_status == "validated"
    assert candidate.final_status == "validated_candidate"
    assert candidate.validation_errors == []


def test_validate_candidates_rejects_malformed_proposed_edge(sample_bundle, settings):
    generated = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())
    candidate = generated[0]

    # Tamper: a deterministic, non-inferred edge violates the AI candidate contract.
    bad_edge = dict(candidate.proposed_edges[0])
    bad_edge["deterministic"] = True
    bad_edge["inferred"] = False
    tampered = candidate.model_copy(update={"proposed_edges": [bad_edge]})

    validated = ai_candidates.validate_candidates(sample_bundle, [tampered])
    assert validated[0].validation_status == "rejected"
    assert validated[0].final_status == "rejected"
    assert validated[0].validation_errors


def test_promote_candidate_writes_promoted_edges_overlay(sample_bundle, settings):
    generated = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())
    validated = ai_candidates.validate_candidates(sample_bundle, generated)
    ai_candidates.save_candidates(settings, validated)

    candidate_id = validated[0].candidate_id
    promoted, updated = ai_candidates.promote_candidate(settings, validated, candidate_id, reviewer="alice")
    ai_candidates.save_candidates(settings, updated)

    assert promoted.final_status == "canonical"
    assert promoted.policy_decision == "promoted"
    assert promoted.reviewer == "alice"

    overlay = json.loads(settings.promoted_edges_path.read_text(encoding="utf-8"))
    assert len(overlay) == 1
    assert overlay[0]["source"] == "T1059.001"
    assert overlay[0]["target"] == "D3-FA"
    assert overlay[0]["metadata"]["promoted_from_candidate"]["candidate_id"] == candidate_id
    assert overlay[0]["metadata"]["promoted_from_candidate"]["reviewer"] == "alice"


def test_promote_candidate_requires_reviewer(sample_bundle, settings):
    generated = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())
    validated = ai_candidates.validate_candidates(sample_bundle, generated)

    with pytest.raises(ValueError):
        ai_candidates.promote_candidate(settings, validated, validated[0].candidate_id, reviewer="  ")


def test_promote_candidate_requires_validated_status(sample_bundle, settings):
    generated = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())

    with pytest.raises(ValueError, match="not validated_candidate"):
        ai_candidates.promote_candidate(settings, generated, generated[0].candidate_id, reviewer="alice")


def test_reject_candidate(sample_bundle, settings):
    generated = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())

    updated = ai_candidates.reject_candidate(generated, generated[0].candidate_id, reviewer="bob")
    assert updated[0].final_status == "rejected"
    assert updated[0].validation_status == "rejected"
    assert updated[0].policy_decision == "rejected_by_reviewer"
    assert updated[0].reviewer == "bob"


def test_reject_candidate_unknown_id_raises(sample_bundle, settings):
    generated = ai_candidates.generate_candidates(sample_bundle, settings, limit=10, provider=MockProvider())

    with pytest.raises(ValueError, match="Unknown candidate"):
        ai_candidates.reject_candidate(generated, "AIC-does-not-exist", reviewer="bob")
