"""Read-only Git change discovery for local project analysis."""

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileChange:
    status: str
    path: str
    previous_path: str | None = None


def _git(cwd, *args):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )


def project_root_for(path):
    """Return the containing Git worktree root, or raise ValueError."""
    path = Path(path).resolve()
    result = _git(path.parent, "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        raise ValueError("target is not inside a Git worktree")
    return Path(result.stdout.strip()).resolve()


def _parse_name_status(output):
    tokens = output.split("\0")
    changes = []
    index = 0
    while index < len(tokens) and tokens[index]:
        status = tokens[index]
        index += 1
        if status.startswith(("R", "C")):
            previous, current = tokens[index : index + 2]
            index += 2
            changes.append(FileChange(status, current, previous))
        else:
            path = tokens[index]
            index += 1
            changes.append(FileChange(status, path))
    return changes


def changes_since(path, base="HEAD"):
    """Return (root, changes) including staged, unstaged, and untracked files."""
    if not base or base.startswith("-") or "\0" in base or "\n" in base:
        raise ValueError("base must be a Git commit or ref name")
    root = project_root_for(path)
    verified = _git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
    if verified.returncode != 0:
        raise ValueError(f"Git base does not resolve to a commit: {base}")

    diff = _git(
        root, "diff", "--name-status", "-z", "--find-renames", base, "--"
    )
    if diff.returncode != 0:
        raise ValueError(diff.stderr.strip() or "could not read Git changes")
    changes = _parse_name_status(diff.stdout)

    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    if untracked.returncode != 0:
        raise ValueError(untracked.stderr.strip() or "could not list untracked files")
    known = {change.path for change in changes}
    changes.extend(
        FileChange("??", path)
        for path in untracked.stdout.split("\0")
        if path and path not in known
    )
    return root, sorted(changes, key=lambda change: (change.path, change.status))
