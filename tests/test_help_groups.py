import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def help_text():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray", "--help"],
        cwd=REPO, env=env, capture_output=True, text=True, check=False,
    ).stdout


def test_help_has_named_groups():
    text = help_text()

    for title in ("Code:", "Binaries:", "Scripts:", "Graph:", "Python:", "Export:"):
        assert title in text, title


def test_every_option_appears_exactly_once():
    options = re.findall(r"^\s+(--[a-z-]+)", help_text(), re.MULTILINE)

    assert len(options) == len(set(options))
    assert "--code" in options and "--tree" in options and "--html" in options
