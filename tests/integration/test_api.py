"""Integration tests for the optional FastAPI sidecar (`api/app.py`).

Each test gets its own `Settings(data_dir=tmp_path)` with the in-memory
`sample_bundle` written out as `data/dist/knowledge-bundle.json`, so the API
can be exercised end-to-end (including AI candidate generation, which writes
to `data/review/`) without touching the real `data/` directory.
"""

from __future__ import annotations

import pytest
import httpx
import respx
from fastapi.testclient import TestClient

from CVEzD3FEND.api.app import create_app
from CVEzD3FEND.config import Settings


@pytest.fixture
def client(tmp_path, sample_bundle):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    settings.bundle_path.write_text(sample_bundle.model_dump_json(), encoding="utf-8")
    app = create_app(settings)
    return TestClient(app)


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["bundle_available"] is True


def test_meta(client):
    resp = client.get("/api/meta")
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 14
    assert body["route_count"] >= 1
    assert "nvd" in body["enrichment_sources"]


@respx.mock
def test_evidence_endpoint(client):
    cve_id = "CVE-2099-0001"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            json={
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": cve_id,
                            "descriptions": [
                                {"lang": "en", "value": "Path traversal leads to secret disclosure."}
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {"baseScore": 7.5},
                                        "baseSeverity": "HIGH",
                                    }
                                ]
                            },
                            "references": {"referenceData": [{"url": "https://example.test/nvd"}]},
                        }
                    }
                ],
            },
        )
    )

    resp = client.get("/api/evidence/nvd", params={"subject": cve_id})
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "nvd"
    assert body["evidence"]["data"]["cve"] == cve_id
    assert "traversal" in body["evidence"]["data"]["semantic_traits"]


def test_search(client):
    resp = client.get("/api/search", params={"q": "PowerShell"})
    assert resp.status_code == 200
    body = resp.json()
    assert any(r["id"] == "T1059.001" for r in body["results"])


def test_get_node(client):
    resp = client.get("/api/nodes/T1059")
    assert resp.status_code == 200
    body = resp.json()
    assert body["node"]["id"] == "T1059"
    assert body["outgoing"]["total"] >= 1


def test_get_node_not_found(client):
    resp = client.get("/api/nodes/DOES-NOT-EXIST")
    assert resp.status_code == 404


def test_routes_for_cve(client):
    resp = client.get("/api/routes", params={"cve": "CVE-2099-0001"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1


def test_coverage_summary(client):
    resp = client.get("/api/coverage")
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["covered"] == 1
    assert body["summary"]["gap"] == 1


def test_coverage_for_technique(client):
    resp = client.get("/api/coverage", params={"technique": "T1059"})
    assert resp.status_code == 200
    assert resp.json()["coverage_status"] == "covered"


def test_soc_action_pack(client):
    resp = client.get("/api/soc-action-pack/T1059")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "PACK-T1059"

    resp_md = client.get("/api/soc-action-pack/T1059", params={"format": "md"})
    assert resp_md.status_code == 200
    assert resp_md.text.startswith("# SOC Action Pack")


def test_soc_action_pack_not_found(client):
    resp = client.get("/api/soc-action-pack/NOPE")
    assert resp.status_code == 404


def test_export_route_markdown(client):
    resp = client.get("/api/export/route/CVE-2099-0001", params={"format": "md"})
    assert resp.status_code == 200
    assert resp.text.startswith("# Route ROUTE-")


def test_ai_explain_route(client, sample_bundle):
    route_id = sample_bundle.routes[0].route_id

    resp = client.post(f"/api/ai/explain-route/{route_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_id"] == route_id
    assert body["text"]


def test_ai_candidate_lifecycle(client):
    # Empty queue initially.
    resp = client.get("/api/ai/candidates")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0

    # Generate by analogy over the T1059.001 gap.
    resp = client.post("/api/ai/candidates/generate", json={"limit": 10})
    assert resp.status_code == 200
    generated = resp.json()
    assert generated["generated"] == 1
    candidate_id = generated["candidates"][0]["candidate_id"]

    # Validate.
    resp = client.post("/api/ai/candidates/validate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["validated"] == 1
    assert body["rejected"] == 0

    # Promote requires a reviewer.
    resp = client.post(f"/api/ai/candidates/{candidate_id}/promote", json={"reviewer": ""})
    assert resp.status_code == 400

    resp = client.post(f"/api/ai/candidates/{candidate_id}/promote", json={"reviewer": "alice"})
    assert resp.status_code == 200
    assert resp.json()["promoted"]["final_status"] == "canonical"

    resp = client.get("/api/ai/candidates", params={"status": "canonical"})
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


def test_ai_candidate_reject(client):
    client.post("/api/ai/candidates/generate", json={"limit": 10})
    resp = client.get("/api/ai/candidates")
    candidate_id = resp.json()["candidates"][0]["candidate_id"]

    resp = client.post(f"/api/ai/candidates/{candidate_id}/reject", json={"reviewer": "bob"})
    assert resp.status_code == 200
    assert resp.json()["rejected"]["final_status"] == "rejected"


def test_bundle_unavailable_returns_503(tmp_path):
    settings = Settings(data_dir=tmp_path)
    app = create_app(settings)
    client = TestClient(app)

    resp = client.get("/api/meta")
    assert resp.status_code == 503
