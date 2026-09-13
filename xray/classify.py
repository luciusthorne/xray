from pathlib import Path


def detect_shebang(path: Path) -> str | None:
    """
    Detect the interpreter specified by a Unix shebang.
    """

    try:
        with path.open("rb") as file:
            first_line = file.readline(256)

    except (OSError, PermissionError):
        return None

    if not first_line.startswith(b"#!"):
        return None

    return first_line.decode("utf-8", errors="replace").strip()
