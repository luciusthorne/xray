"""The Emacs package (editors/emacs/xray.el): byte-compiles cleanly and its ERT tests pass."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EMACS_DIR = REPO / "editors" / "emacs"

pytestmark = pytest.mark.skipif(shutil.which("emacs") is None, reason="needs emacs")


def test_byte_compiles_without_warnings(tmp_path):
    copy = tmp_path / "xray.el"
    shutil.copy(EMACS_DIR / "xray.el", copy)
    result = subprocess.run(
        ["emacs", "--batch", "-Q", "--eval", "(setq byte-compile-error-on-warn t)",
         "-f", "batch-byte-compile", str(copy)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_ert_suite(tmp_path):
    wrapper = tmp_path / "xray"
    wrapper.write_text(f"#!/bin/sh\nPYTHONPATH={REPO} exec {sys.executable} -m xray.cli \"$@\"\n")
    wrapper.chmod(0o755)
    result = subprocess.run(
        ["emacs", "--batch", "-Q", "-L", str(EMACS_DIR), "-l", "xray-tests.el",
         "-f", "ert-run-tests-batch-and-exit"],
        capture_output=True, text=True, check=False,
        env={**os.environ, "XRAY_TEST_PROGRAM": str(wrapper)},
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "Ran 4 tests, 4 results as expected" in output, output  # the end-to-end test ran, not skipped
    assert "skipped" not in output, output
