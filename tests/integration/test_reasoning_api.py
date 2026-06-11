"""Integration tests for the reasoning-plane HTTP endpoints."""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from CVEzD3FEND.api.app import create_app
from CVEzD3FEND.config import Settings


@pytest.fixture
def reasoning_client(tmp_path, real_bundle):
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    settings.bundle_path.write_text(real_bundle.model_dump_json(), encoding="utf-8")
    app = create_app(settings)
    return TestClient(app)


def _mock_live_sources(cve_id: str):
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    ghsa_url = f"https://api.github.com/advisories?cve_id={cve_id}"
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    respx.get(nvd_url).mock(
        return_value=httpx.Response(
            200,
            json={
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": cve_id,
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": "Remote code execution in a public-facing service.",
                                }
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.1,
                                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        },
                                        "baseSeverity": "CRITICAL",
                                    }
                                ]
                            },
                            "references": {"referenceData": [{"url": "https://example.test/nvd"}]},
                            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {"criteria": "cpe:2.3:a:acme:gateway:1.0:*:*:*:*:*:*:*"}
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ],
            },
        )
    )
    respx.get(epss_url).mock(return_value=httpx.Response(200, json={"data": [{"cve": cve_id, "epss": "0.88", "percentile": "0.96", "date": "2026-06-11"}]}))
    respx.get(ghsa_url).mock(return_value=httpx.Response(200, json=[{"cve_id": cve_id, "ghsa_id": "GHSA-test", "severity": "moderate", "summary": "Public-facing service issue.", "description": "Public-facing service issue.", "cwes": ["CWE-79"], "references": [{"url": "https://example.test/ghsa"}]}]))
    respx.get(kev_url).mock(return_value=httpx.Response(200, json={"catalogVersion": "2026.06.11", "vulnerabilities": [{"cveID": cve_id, "vendorProject": "Acme", "product": "Gateway"}]}))


@respx.mock
def test_reasoning_endpoints(reasoning_client):
    cve_id = "CVE-2025-0168"
    _mock_live_sources(cve_id)

    enrich = reasoning_client.get(f"/api/enrich/{cve_id}")
    assert enrich.status_code == 200
    enrich_json = enrich.json()
    assert enrich_json["normalized_input"] == cve_id
    assert enrich_json["profile"]["semantic_tags"]
    assert {"rce", "public_facing_application"} <= set(enrich_json["profile"]["semantic_tags"])

    reason = reasoning_client.get(f"/api/reason/{cve_id}")
    assert reason.status_code == 200
    reason_json = reason.json()
    assert reason_json["route"]["canonical_chain"]
    assert reason_json["provenance"]
    assert reason_json["human_review"]["required"] is True
    assert reason_json["provenance"]["conditional"]
    assert any(edge["target"] == "T1190" for edge in reason_json["edges"])
    assert any(edge["target"] in {"T1059", "T1059.004"} for edge in reason_json["edges"])

    provenance = reasoning_client.get(f"/api/provenance/{cve_id}")
    assert provenance.status_code == 200
    prov_json = provenance.json()
    assert prov_json["normalized_input"] == cve_id
    assert "conditional" in prov_json["provenance"]

    propose = reasoning_client.post("/api/ai/propose-route", json={"cve_id": cve_id})
    assert propose.status_code == 200
    assert propose.json()["status"] == "disabled"

    validate = reasoning_client.post("/api/ai/validate-route", json={"cve_id": cve_id})
    assert validate.status_code == 200
    assert validate.json()["status"] in {"validated", "review_required"}

    promote = reasoning_client.post("/api/review/promote-edge", json={"edge_id": "EDGE-1"})
    assert promote.status_code == 400

    promote_with_reviewer = reasoning_client.post(
        "/api/review/promote-edge",
        json={"edge_id": "EDGE-1", "reviewer": "alice"},
    )
    assert promote_with_reviewer.status_code == 200
    assert promote_with_reviewer.json()["promoted"] is False


@respx.mock
def test_reasoning_api_reports_warnings_on_failure(reasoning_client):
    cve_id = "CVE-2025-0168"
    respx.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}").mock(return_value=httpx.Response(500))
    respx.get(f"https://api.first.org/data/v1/epss?cve={cve_id}").mock(return_value=httpx.Response(500))
    respx.get(f"https://api.github.com/advisories?cve_id={cve_id}").mock(return_value=httpx.Response(500))
    respx.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").mock(return_value=httpx.Response(500))

    resp = reasoning_client.get(f"/api/reason/{cve_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["warnings"]
    assert body["status"] in {"degraded", "ok"}


@respx.mock
def test_cve_2026_4342_smoke(reasoning_client):
    cve_id = "CVE-2026-4342"
    _mock_live_sources(cve_id)

    enrich = reasoning_client.get(f"/api/enrich/{cve_id}")
    assert enrich.status_code == 200
    assert enrich.json()["normalized_input"] == cve_id

    reason = reasoning_client.get(f"/api/reason/{cve_id}")
    assert reason.status_code == 200
    body = reason.json()
    assert body["normalized_input"] == cve_id
    assert body["narrative"]["summary_es"]
    assert body["human_review"]["required"] is True
    assert body["provenance"]["conditional"] or body["provenance"]["weak_fit"]
