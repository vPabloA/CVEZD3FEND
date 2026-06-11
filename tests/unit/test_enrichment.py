from __future__ import annotations

from pathlib import Path

import httpx
import respx

from CVEzD3FEND.config import Settings
from CVEzD3FEND.enrichment import SourceOrchestrator
from CVEzD3FEND.enrichment.normalizers import extract_semantic_traits


def test_semantic_trait_extraction():
    traits = extract_semantic_traits(
        "This issue allows remote code execution and command injection.",
        "The vulnerability can lead to privilege escalation and data exfiltration.",
    )

    assert "remote code execution" in traits
    assert "command injection" in traits
    assert "privilege escalation" in traits
    assert "data exfiltration potential" in traits


@respx.mock
def test_nvd_enrichment_caches_and_reuses(tmp_path):
    settings = Settings(data_dir=tmp_path)
    orchestrator = SourceOrchestrator(settings)
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
                                {"lang": "en", "value": "Remote code execution via command injection."}
                            ],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {"baseScore": 9.8},
                                        "baseSeverity": "CRITICAL",
                                    }
                                ]
                            },
                            "references": {"referenceData": [{"url": "https://example.test/advisory"}]},
                            "weaknesses": [
                                {"description": [{"value": "CWE-78"}]}
                            ],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {"criteria": "cpe:2.3:a:demo:app:*:*:*:*:*:*:*:*"}
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

    live = orchestrator.collect("nvd", cve_id, mode="live")
    assert live.evidence.status == "ok"
    assert live.evidence.cache_path is not None
    assert Path(live.evidence.cache_path).exists()
    assert "remote code execution" in live.evidence.data["semantic_traits"]

    orchestrator.close()

    fallback_orchestrator = SourceOrchestrator(settings)
    cached = fallback_orchestrator.collect("nvd", cve_id, mode="cached")
    assert cached.from_cache is True
    assert cached.evidence.status == "cached"
    assert cached.evidence.data["cve"] == cve_id
    fallback_orchestrator.close()
