from __future__ import annotations

import gzip
import json

from fastapi.testclient import TestClient

from CVEzD3FEND.api.app import create_app
from CVEzD3FEND.config import Settings


def test_batch_reasoning_endpoint_multi_year_partial_success(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    settings.bundle_path.write_text(sample_bundle.model_dump_json(), encoding="utf-8")

    records = {
        2019: {"CVE-2019-0001": {"CWE": ["79"], "CAPEC": ["100"], "TECHNIQUES": ["1059"], "DEFEND": [{"id": "D3-FA"}]}},
        2026: {"CVE-2026-0002": {"CWE": ["79"], "CAPEC": ["100"], "TECHNIQUES": ["1059"], "DEFEND": [{"id": "D3-FA"}]}},
    }
    records[2023] = {"CVE-2023-9999": {"CWE": ["79"]}}
    for year, record in records.items():
        with gzip.open(settings.sources_dir / f"CVE-{year}.jsonl.gz", "wt", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    client = TestClient(create_app(settings))
    response = client.post(
        "/api/reason/batch",
        json={
            "cve_ids": "CVE-2019-0001, CVE-2026-0002, CVE-2023-4040, invalid",
            "context": {
                "technologies": ["PowerShell"],
                "exposure": ["internet-facing"],
                "priorities": ["execution"],
                "audience": "SOC",
            },
            "top_k": 2,
            "include_all_candidates": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["requested_cves"] == ["CVE-2019-0001", "CVE-2026-0002", "CVE-2023-4040"]
    assert body["found_cves"] == ["CVE-2019-0001", "CVE-2026-0002"]
    assert body["missing_cves"] == ["CVE-2023-4040"]
    assert body["invalid_inputs"] == ["INVALID"]
    assert body["available_route_count"] > 2
    assert body["selected_route_count"] == 2
    assert body["selection_summary"]["selection_mode"] == "deterministic"
    assert body["selection_summary"]["fallback_used"] is False
    assert set(body["selection_summary"]["represented_cves"]) == {
        "CVE-2019-0001",
        "CVE-2026-0002",
    }
    assert "T1059" in body["shared_attack_techniques_selected"]
    assert "T1059" in body["shared_attack_techniques_all_candidates"]
    assert "D3-FA" in body["shared_defenses_selected"]
    assert "D3-FA" in body["shared_defenses_all_candidates"]
    assert body["shared_attack_techniques"] == body["shared_attack_techniques_selected"]
    assert body["shared_defenses"] == body["shared_defenses_selected"]
    assert body["candidate_graph"]["nodes"]
    assert body["candidate_graph"]["edges"]
    assert body["selected_graph"]["nodes"]
    assert body["selected_graph"]["edges"]
    candidate_nodes = {node["id"] for node in body["candidate_graph"]["nodes"]}
    candidate_edges = {edge["id"] for edge in body["candidate_graph"]["edges"]}
    selected_nodes = {node["id"] for node in body["selected_graph"]["nodes"]}
    selected_edges = {edge["id"] for edge in body["selected_graph"]["edges"]}
    assert selected_nodes <= candidate_nodes
    assert selected_edges <= candidate_edges
    assert body["nodes"] == body["selected_graph"]["nodes"]
    assert body["edges"] == body["selected_graph"]["edges"]
    assert [route["selection_rank"] for route in body["selected_routes"]] == [1, 2]
    for route in body["candidate_routes"]:
        assert set(route["node_ids"]) <= candidate_nodes
        assert set(route["edge_ids"]) <= candidate_edges


def test_single_cve_is_supported_as_batch_of_one(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    settings.bundle_path.write_text(sample_bundle.model_dump_json(), encoding="utf-8")
    with gzip.open(settings.sources_dir / "CVE-2099.jsonl.gz", "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({"CVE-2099-0001": {"CWE": ["79"]}}) + "\n")

    client = TestClient(create_app(settings))
    response = client.post("/api/reason/batch", json={"cve_ids": "CVE-2099-0001", "top_k": 5})

    assert response.status_code == 200
    body = response.json()
    assert body["requested_cves"] == ["CVE-2099-0001"]
    assert body["found_cves"] == ["CVE-2099-0001"]
    assert body["selection_summary"]["eligible_cves"] == 1
    assert body["selected_routes"]
    assert body["candidate_routes"] == []
    assert "candidate_graph" not in body
    assert body["selected_graph"]["nodes"]
    assert body["selected_graph"]["edges"]
    assert body["nodes"] == body["selected_graph"]["nodes"]
    assert body["edges"] == body["selected_graph"]["edges"]
