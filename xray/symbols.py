from dataclasses import dataclass, field


SYMBOL_KINDS = (
    "function",
    "class",
    "method",
    "variable",
)


@dataclass(frozen=True)
class Symbol:
    """A named definition found inside a source file."""

    name: str
    kind: str
    file: str
    line: int
    parent: str | None = None
    metadata: dict = field(
        default_factory=dict,
        compare=False,
        hash=False,
    )

    def __post_init__(self):
        if self.kind not in SYMBOL_KINDS:
            raise ValueError(
                f"Unknown symbol kind: {self.kind}"
            )

    @property
    def qualified_name(self):
        if self.parent:
            return f"{self.parent}.{self.name}"

        return self.name
