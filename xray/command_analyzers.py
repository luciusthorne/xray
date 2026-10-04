from pathlib import Path

from .analyzers import Analyzer, registry
from .calls import _locate
from .elfscan import scan_elf
from .libresolve import find_library, ldconfig_cache
from .model import Edge
from .shellscan import scan_shell


class ShellAnalyzer(Analyzer):
    """Reads shell scripts: the commands they run and files they source.

    Targets are resolved paths when found, and the name as written
    (status "unresolved") when not. Relative sourced files are looked
    up next to the script. Commands run through variables or eval are
    not visible.
    """

    name = "shell"
    kinds = ("shell",)

    def edges(self, path):
        path = Path(path).resolve()
        scan = scan_shell(path)
        found = []

        for command in scan.commands:
            target = _locate(command)

            if target is None:
                found.append(
                    Edge(
                        str(path),
                        command,
                        "runs",
                        "unresolved",
                        name=command,
                    )
                )
            else:
                found.append(
                    Edge(
                        str(path),
                        str(target),
                        "runs",
                        "resolved",
                        name=command,
                    )
                )

        for name in scan.sources:
            candidate = Path(name).expanduser()

            if not candidate.is_absolute():
                candidate = path.parent / candidate

            if candidate.is_file():
                found.append(
                    Edge(
                        str(path),
                        str(candidate.resolve()),
                        "sources",
                        "resolved",
                        name=name,
                    )
                )
            else:
                found.append(
                    Edge(
                        str(path),
                        name,
                        "sources",
                        "unresolved",
                        name=name,
                    )
                )

        return found


class ELFAnalyzer(Analyzer):
    """Reads ELF binaries: the shared libraries they link against."""

    name = "elf"
    kinds = ("elf",)

    def edges(self, path):
        path = Path(path).resolve()
        scan = scan_elf(path)
        cache = ldconfig_cache() if scan.needed else None
        found = []

        for name in scan.needed:
            target = find_library(name, cache)

            if target is None:
                found.append(
                    Edge(
                        str(path),
                        name,
                        "links",
                        "unresolved",
                        name=name,
                    )
                )
            else:
                found.append(
                    Edge(
                        str(path),
                        str(Path(target).resolve()),
                        "links",
                        "resolved",
                        name=name,
                    )
                )

        return found


for _analyzer in (ShellAnalyzer(), ELFAnalyzer()):
    if _analyzer.name not in registry.names():
        registry.register(_analyzer)
