from dataclasses import dataclass


EDGE_KINDS = (
    "imports",
    "depends_on",
    "calls",
    "references",
    "inherits",
    "runs",
    "sources",
    "links",
)

EDGE_STATUSES = (
    "resolved",
    "unresolved",
    "external",
)


@dataclass(frozen=True)
class FileInfo:
    """A file XRAY knows about, in any language.

    kind is how XRAY reads it: "python", "shell", "elf" or "library".
    language is the source language when there is one.
    """

    path: str
    kind: str
    language: str | None = None


@dataclass(frozen=True)
class Edge:
    """A relationship from one thing to another.

    source and target are file paths or "path:name" symbols. target is
    None when the relationship could not be resolved.
    """

    source: str
    target: str | None
    kind: str
    status: str

    def __post_init__(self):
        if self.kind not in EDGE_KINDS:
            raise ValueError(f"Unknown edge kind: {self.kind}")

        if self.status not in EDGE_STATUSES:
            raise ValueError(f"Unknown edge status: {self.status}")
