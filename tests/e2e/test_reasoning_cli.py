"""End-to-end tests for the functional reasoning plane CLI commands."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from CVEzD3FEND.cli import app
from CVEzD3FEND.config import Settings
from CVEzD3FEND.etl.http import FetchResult

runner = CliRunner()


@pytest.fixture
def reasoning_env(tmp_path, monkeypatch, real_bundle):
    monkeypatch.setenv("CVEZD3FEND_DATA_DIR", str(tmp_path))
    settings = Settings(data_dir=tmp_path)
    settings.ensure_dirs()
    settings.bundle_path.write_text(real_bundle.model_dump_json(), encoding="utf-8")
    return settings


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
                                    "value": "Remote code execution and command injection in a public-facing service.",
                                }
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.8,
                                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        },
                                        "baseSeverity": "CRITICAL",
                                    }
                                ]
                            },
                            "references": {"referenceData": [{"url": "https://example.test/nvd"}]},
                            "weaknesses": [{"description": [{"value": "CWE-78"}]}],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {"criteria": "cpe:2.3:a:acme:webapp:1.0:*:*:*:*:*:*:*"}
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
    respx.get(epss_url).mock(return_value=httpx.Response(200, json={"data": [{"cve": cve_id, "epss": "0.93", "percentile": "0.99", "date": "2026-06-11"}]}))
    respx.get(ghsa_url).mock(return_value=httpx.Response(200, json=[{"cve_id": cve_id, "ghsa_id": "GHSA-test", "severity": "high", "summary": "Public-facing command injection.", "description": "Public-facing command injection in web service.", "cwes": ["CWE-78"], "references": [{"url": "https://example.test/ghsa"}]}]))
    respx.get(kev_url).mock(return_value=httpx.Response(200, json={"catalogVersion": "2026.06.11", "vulnerabilities": [{"cveID": cve_id, "vendorProject": "Acme", "product": "WebApp"}]}))


def test_help_includes_reasoning_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("enrich", "reason", "explain", "hunt", "detect", "ctem"):
        assert cmd in result.stdout


@respx.mock
def test_enrich_reason_explain_hunt_detect_ctem_smoke(reasoning_env):
    cve_id = "CVE-2025-0168"
    _mock_live_sources(cve_id)

    enrich = runner.invoke(app, ["enrich", cve_id, "--format", "json"])
    assert enrich.exit_code == 0
    enrich_json = json.loads(enrich.stdout)
    assert enrich_json["normalized_input"] == cve_id
    assert enrich_json["profile"]["semantic_tags"]
    assert {"rce", "command_injection", "public_facing_application"} <= set(enrich_json["profile"]["semantic_tags"])
    assert enrich_json["status"] in {"ok", "degraded"}

    reason = runner.invoke(app, ["reason", cve_id, "--format", "json"])
    assert reason.exit_code == 0
    reason_json = json.loads(reason.stdout)
    assert reason_json["normalized_input"] == cve_id
    assert reason_json["baseline_provider"] == "CVE2CAPEC"
    assert reason_json["route"]["canonical_chain"]
    assert reason_json["provenance"]
    assert reason_json["human_review"]["required"] is True
    assert reason_json["provenance"]["conditional"]
    assert any(edge["target"] == "T1190" for edge in reason_json["edges"])
    assert any(edge["target"] in {"T1059", "T1059.004"} for edge in reason_json["edges"])
    assert all(
        not (edge["inferred"] and edge["classification"] == "official_explicit")
        for edge in reason_json["edges"]
    )
    assert sum(len(v) for v in reason_json["provenance"].values()) == len(reason_json["edges"])

    tree = runner.invoke(app, ["reason", cve_id, "--format", "tree"])
    assert tree.exit_code == 0
    assert cve_id in tree.stdout

    md = runner.invoke(app, ["reason", cve_id, "--format", "md"])
    assert md.exit_code == 0
    assert "# Reasoning for" in md.stdout

    explain = runner.invoke(app, ["explain", cve_id])
    assert explain.exit_code == 0
    words = explain.stdout.split()
    assert 120 <= len(words) <= 180
    assert "Para Tier 1 significa" in explain.stdout

    hunt = runner.invoke(app, ["hunt", cve_id])
    assert hunt.exit_code == 0
    assert "Threat Hunt" in hunt.stdout

    detect = runner.invoke(app, ["detect", cve_id])
    assert detect.exit_code == 0
    assert "Detection Brief" in detect.stdout

    ctem = runner.invoke(app, ["ctem", cve_id])
    assert ctem.exit_code == 0
    assert "CTEM" in ctem.stdout


@respx.mock
def test_enrich_uses_cache_fallback_on_subsequent_run(reasoning_env, monkeypatch):
    cve_id = "CVE-2025-0168"
    _mock_live_sources(cve_id)

    first = runner.invoke(app, ["enrich", cve_id, "--format", "json"])
    assert first.exit_code == 0
    first_json = json.loads(first.stdout)
    assert first_json["status"] in {"ok", "degraded"}

    def offline_fetch(*args, **kwargs):
        url = args[1] if len(args) > 1 else kwargs.get("url", "offline")
        return FetchResult(ok=False, url=url, error="offline")

    monkeypatch.setattr("CVEzD3FEND.enrichment.adapters.fetch_url", offline_fetch)

    second = runner.invoke(app, ["enrich", cve_id, "--format", "json"])
    assert second.exit_code == 0
    second_json = json.loads(second.stdout)
    assert second_json["status"] in {"ok", "degraded"}
    assert second_json["warnings"] or second_json["source_mode"] in {"cached", "static"}
