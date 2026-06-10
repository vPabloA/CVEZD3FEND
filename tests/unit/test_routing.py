def test_cve_route_to_defend_exists(sample_bundle):
    route = next(
        (r for r in sample_bundle.routes if r.start_node == "CVE-2099-0001" and r.end_node == "D3-FA"),
        None,
    )
    assert route is not None
    assert route.path == ["cve", "cwe", "capec", "attack", "defend"]
    assert route.nodes == ["CVE-2099-0001", "CWE-79", "CAPEC-100", "T1059", "D3-FA"]
    assert route.confidence == 1.0
    assert route.canonical is True
    assert route.inferred is False
    assert route.coverage_status == "covered"
    assert route.recommended_actions == ["CTRL-D3-FA"]
    assert route.evidence_required == ["EVID-DET-T1059-D3-FA"]
    assert route.source_refs == ["test:source"]
    assert len(route.edges) == 4


def test_cve_route_without_defend_for_gapped_technique(sample_bundle):
    route = next(
        (r for r in sample_bundle.routes if r.start_node == "CVE-2099-0001" and r.end_node == "T1059.001"),
        None,
    )
    assert route is not None
    assert route.path == ["cve", "cwe", "capec", "attack"]
    assert route.coverage_status == "gap"
    assert route.recommended_actions == []


def test_framework_route_cwe_to_defend(sample_bundle):
    route = next(
        (r for r in sample_bundle.routes if r.path == ["cwe", "capec", "attack", "defend"]),
        None,
    )
    assert route is not None
    assert route.start_node == "CWE-79"
    assert route.end_node == "D3-FA"
    assert route.nodes == ["CWE-79", "CAPEC-100", "T1059", "D3-FA"]


def test_route_ids_are_unique(sample_bundle):
    route_ids = [r.route_id for r in sample_bundle.routes]
    assert len(route_ids) == len(set(route_ids))


def test_cve_routes_index(sample_bundle):
    cve_routes = sample_bundle.indexes["cve_routes"]["CVE-2099-0001"]
    assert set(cve_routes) == {
        r.route_id for r in sample_bundle.routes if r.start_node == "CVE-2099-0001"
    }
