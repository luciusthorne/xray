from __future__ import annotations

from dataclasses import dataclass, field

from .symbols import Symbol

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
MODEL_SCHEMA_VERSION = 1

LANGUAGE_NAMES = {
    "python": "Python",
    "shell": "Shell",
    "perl": "Perl",
    "ruby": "Ruby",
    "javascript": "JavaScript",
    "lua": "Lua",
    "typescript": "TypeScript",
    "c": "C",
    "elf": "ELF",
    "library": "Library",
    "script": "Script",
}


def symbol_data(symbol):
    """Serialize a language-neutral symbol without dropping its metadata."""

    return {
        "name": symbol.name,
        "qualified_name": symbol.qualified_name,
        "kind": symbol.kind,
        "file": symbol.file,
        "line": symbol.line,
        "parent": symbol.parent,
        "metadata": dict(symbol.metadata),
    }


def edge_data(edge):
    """Serialize a language-neutral relationship."""

    target = edge.target
    name = edge.name
    if edge.status == "external":
        if name is None:
            name = target
        target = None

    return {
        "source": edge.source,
        "target": target,
        "kind": edge.kind,
        "status": edge.status,
        "name": name,
    }


@dataclass(frozen=True)
class FileInfo:
    """A file XRAY knows about, in any language.

    kind is how XRAY reads it: "python", "shell", "perl", "ruby",
    "javascript", "lua", "typescript", "c", "elf" or "library".
    language is the source language when there is one.
    """

    path: str
    kind: str
    language: str | None = None
    metadata: dict = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self):
        if self.language is None:
            object.__setattr__(self, "language", LANGUAGE_NAMES.get(self.kind))


@dataclass(frozen=True)
class AnalysisDocument:
    """Common analysis result shared by every registered language analyzer."""

    file: FileInfo
    analyzer: str | None
    symbols: tuple[Symbol, ...] = ()
    relationships: tuple[Edge, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self):
        """Return the stable JSON shape used by XRAY's single-file export."""

        return {
            "schema_version": MODEL_SCHEMA_VERSION,
            "file": self.file.path,
            "kind": self.file.kind,
            "language": self.file.language,
            "analyzer": self.analyzer,
            "symbols": [symbol_data(symbol) for symbol in self.symbols],
            "edges": [edge_data(edge) for edge in self.relationships],
            "notes": list(self.notes),
            "metadata": dict(self.file.metadata),
        }


@dataclass(frozen=True)
class Edge:
    """A relationship from one thing to another.

    A resolved target is a file path or "path:name" symbol. Unresolved
    and external relationships have no target. name preserves the
    dependency's written name when there is one. It is not part of equality.
    """

    source: str
    target: str | None
    kind: str
    status: str
    name: str | None = field(default=None, compare=False)

    def __post_init__(self):
        if self.kind not in EDGE_KINDS:
            raise ValueError(f"Unknown edge kind: {self.kind}")

        if self.status not in EDGE_STATUSES:
            raise ValueError(f"Unknown edge status: {self.status}")
