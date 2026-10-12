import re
from pathlib import Path

import xray

REPO = Path(__file__).resolve().parent.parent


def test_changelog_has_an_entry_for_the_current_version():
    text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    versions = re.findall(r"^## (\d+\.\d+\.\d+)\b", text, re.MULTILINE)

    assert xray.__version__ in versions


def test_changelog_lists_newest_version_first():
    text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    versions = re.findall(r"^## (\d+\.\d+\.\d+)\b", text, re.MULTILINE)
    parsed = [tuple(int(part) for part in v.split(".")) for v in versions]

    assert parsed == sorted(parsed, reverse=True)
    assert len(set(parsed)) == len(parsed)
