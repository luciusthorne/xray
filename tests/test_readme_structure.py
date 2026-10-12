import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_every_module_is_in_the_project_structure():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Project structure", 1)[1].split("## Testing", 1)[0]
    listed = set(re.findall(r"[├└]── (\S+\.py)", section))
    actual = {p.name for p in (REPO / "xray").glob("*.py")}

    assert sorted(actual - listed) == []
    assert sorted(listed - actual) == []
