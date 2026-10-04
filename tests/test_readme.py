import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_every_help_option_is_in_the_readme():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    result = subprocess.run(
        [sys.executable, "-m", "xray", "--help"],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    options = set(re.findall(r"^\s+(--[a-z-]+)", result.stdout, re.MULTILINE))
    options -= {"--help", "--version"}

    assert options
    assert [o for o in sorted(options) if f"`{o}" not in readme] == []
