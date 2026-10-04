import pytest

from xray.model import EDGE_KINDS, EDGE_STATUSES, Edge, FileInfo


def test_file_info_holds_its_fields():
    info = FileInfo("/bin/tool", "shell", "shell")

    assert info.path == "/bin/tool"
    assert info.kind == "shell"
    assert info.language == "shell"


def test_edge_holds_its_fields():
    edge = Edge("a.py", "b.py", "imports", "resolved")

    assert edge.source == "a.py"
    assert edge.target == "b.py"
    assert edge.kind == "imports"
    assert edge.status == "resolved"


def test_edge_target_may_be_missing_when_unresolved():
    edge = Edge("a.py:f", None, "calls", "unresolved")

    assert edge.target is None


def test_edge_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Edge("a", "b", "bogus", "resolved")


def test_edge_rejects_unknown_status():
    with pytest.raises(ValueError):
        Edge("a", "b", "calls", "bogus")


def test_edges_are_hashable_and_comparable():
    one = Edge("a", "b", "calls", "resolved")
    two = Edge("a", "b", "calls", "resolved")

    assert one == two
    assert len({one, two}) == 1


def test_kind_and_status_lists_cover_current_features():
    for kind in ("imports", "calls", "inherits", "runs", "sources", "links"):
        assert kind in EDGE_KINDS

    assert set(EDGE_STATUSES) == {"resolved", "unresolved", "external"}
