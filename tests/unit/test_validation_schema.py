from CVEzD3FEND.validation.schema import validate_structure


def test_sample_bundle_has_no_fatal_errors(sample_bundle):
    assert validate_structure(sample_bundle) == []


def test_duplicate_node_id_is_fatal(sample_bundle):
    extra = sample_bundle.nodes[0]
    broken = sample_bundle.model_copy(update={"nodes": [*sample_bundle.nodes, extra]})
    errors = validate_structure(broken)
    assert any("Duplicate node ids" in e for e in errors)


def test_edge_with_unknown_target_is_fatal(sample_bundle):
    bad_edge = sample_bundle.edges[0].model_copy(update={"target": "DOES-NOT-EXIST"})
    broken = sample_bundle.model_copy(update={"edges": [bad_edge, *sample_bundle.edges[1:]]})
    errors = validate_structure(broken)
    assert any("unknown target node: DOES-NOT-EXIST" in e for e in errors)


def test_edge_with_missing_source_ref_is_fatal(sample_bundle):
    bad_edge = sample_bundle.edges[0].model_copy(update={"source_ref": None})
    broken = sample_bundle.model_copy(update={"edges": [bad_edge, *sample_bundle.edges[1:]]})
    errors = validate_structure(broken)
    assert any(f"Edge {bad_edge.id} has source_ref=null" in e for e in errors)


def test_deterministic_and_inferred_edge_is_fatal(sample_bundle):
    bad_edge = sample_bundle.edges[0].model_copy(update={"deterministic": True, "inferred": True})
    broken = sample_bundle.model_copy(update={"edges": [bad_edge, *sample_bundle.edges[1:]]})
    errors = validate_structure(broken)
    assert any("deterministic=true AND inferred=true" in e for e in errors)


def test_route_referencing_unknown_node_is_fatal(sample_bundle):
    bad_route = sample_bundle.routes[0].model_copy(update={"nodes": [*sample_bundle.routes[0].nodes, "GHOST"]})
    broken = sample_bundle.model_copy(update={"routes": [bad_route, *sample_bundle.routes[1:]]})
    errors = validate_structure(broken)
    assert any("references unknown node: GHOST" in e for e in errors)
