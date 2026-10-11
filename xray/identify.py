import subprocess
from pathlib import Path

FALLBACK = "unknown (the file command is not available)"


def identify_file(path: Path) -> str:
    """
    Ask Linux what kind of file this is.
    """

    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return FALLBACK

    return result.stdout.strip()


def get_file_metadata(path: Path) -> dict:
    """
    Collect basic filesystem metadata.
    """

    stat = path.stat()

    return {
        "size": stat.st_size,
        "mode": oct(stat.st_mode & 0o777),
        "owner_uid": stat.st_uid,
        "group_gid": stat.st_gid,
        "modified": stat.st_mtime,
    }
