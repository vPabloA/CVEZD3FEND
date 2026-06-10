from CVEzD3FEND.lookup import node_summary, resolve_attack_id, resolve_route, search_nodes


def test_resolve_route_by_route_id(sample_bundle):
    route = sample_bundle.routes[0]
    resolved = resolve_route(sample_bundle, route.route_id)
    assert resolved is not None
    assert resolved.route_id == route.route_id


def test_resolve_route_by_cve_id(sample_bundle):
    resolved = resolve_route(sample_bundle, "CVE-2099-0001")
    assert resolved is not None
    assert resolved.start_node == "CVE-2099-0001"


def test_resolve_route_unknown_ref_returns_none(sample_bundle):
    assert resolve_route(sample_bundle, "does-not-exist") is None


def test_resolve_attack_id_direct(sample_bundle):
    assert resolve_attack_id(sample_bundle, "T1059") == "T1059"


def test_resolve_attack_id_via_cve_route(sample_bundle):
    route = resolve_route(sample_bundle, "CVE-2099-0001")
    expected = route.nodes[route.path.index("attack")]
    assert resolve_attack_id(sample_bundle, "CVE-2099-0001") == expected


def test_resolve_attack_id_unknown(sample_bundle):
    assert resolve_attack_id(sample_bundle, "nope") is None


def test_search_nodes_exact_id(sample_bundle):
    results = search_nodes(sample_bundle, "T1059", limit=5)
    assert results[0].id == "T1059"


def test_search_nodes_by_text_token(sample_bundle):
    results = search_nodes(sample_bundle, "PowerShell", limit=5)
    ids = [n.id for n in results]
    assert "T1059.001" in ids


def test_search_nodes_by_alias_outranks_text(sample_bundle):
    # "cmd-interpreter" is only an alias of T1059, weighted 2x over by_text hits.
    results = search_nodes(sample_bundle, "cmd-interpreter", limit=5)
    assert results[0].id == "T1059"


def test_search_nodes_no_match_returns_empty(sample_bundle):
    assert search_nodes(sample_bundle, "zzz_nonexistent_zzz", limit=5) == []


def test_node_summary_shape(sample_bundle):
    node = next(n for n in sample_bundle.nodes if n.id == "T1059")
    summary = node_summary(node)
    assert summary == {
        "id": "T1059",
        "type": "attack",
        "name": "Command and Scripting Interpreter",
        "confidence": node.confidence,
        "canonical": node.canonical,
        "inferred": node.inferred,
    }
