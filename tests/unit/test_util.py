from CVEzD3FEND.util import edge_id, now_iso, safe_id_fragment, slugify


def test_edge_id_is_deterministic_and_type_specific():
    a = edge_id("attack_maps_to_defend", "T1059", "D3-FA")
    b = edge_id("attack_maps_to_defend", "T1059", "D3-FA")
    c = edge_id("control_implements_defend", "T1059", "D3-FA")
    assert a == b
    assert a != c
    assert len(a) == 16


def test_safe_id_fragment_replaces_unsafe_characters():
    assert safe_id_fragment("T1059.001") == "T1059_001"
    assert safe_id_fragment("CVE-2025-0168") == "CVE-2025-0168"
    assert safe_id_fragment("foo/bar.baz") == "foo_bar_baz"


def test_slugify():
    assert slugify("  Hello, World!  ") == "hello-world"
    assert slugify("Already-slugged") == "already-slugged"


def test_now_iso_format():
    ts = now_iso()
    assert ts.endswith("Z")
    assert "T" in ts
