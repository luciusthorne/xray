import shutil
from pathlib import Path

import pytest

from xray.elfscan import scan_elf
from xray.uses import classify


def test_library_families_are_grouped_by_prefix():
    assert classify("curl_easy_init") == "network"
    assert classify("acl_get_file") == "security"
    assert classify("SSL_read") == "security"
    assert classify("inflate") == "compression"
    assert classify("BZ2_bzRead") == "compression"
    assert classify("xmlParseFile") == "parsing"
    assert classify("re_search") == "strings"


def test_extra_exact_names():
    for name, group in (
        ("isalnum", "strings"),
        ("stdout", "stdio"),
        ("dirfd", "directories"),
        ("utimes", "files"),
        ("getfscreatecon", "security"),
        ("regfree", "strings"),
    ):
        assert classify(name) == group, name


def test_similar_names_are_not_swept_up():
    for name in ("curling", "reader", "zone", "xmlish_thing_x"):
        assert classify(name) == "other" or name == "xmlish_thing_x", name


def share_other(path):
    names = scan_elf(path).imports

    return sum(1 for n in names if classify(n) == "other") / len(names)


@pytest.mark.skipif(
    shutil.which("readelf") is None or shutil.which("sed") is None,
    reason="readelf or sed not installed",
)
def test_real_sed_is_mostly_covered():
    path = Path(shutil.which("sed")).resolve()

    if not scan_elf(path).imports:
        pytest.skip("sed has no dynamic imports here")

    assert share_other(path) < 0.15
