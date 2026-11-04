from pathlib import Path

from .analyzers import Analyzer, registry
from .elfscan import scan_elf
from .javascript_analyzer import JavaScriptAnalyzer
from .libresolve import find_library, ldconfig_cache
from .locate import locate
from .minidebug import read_function_table
from .model import Edge
from .perlscan import perl_inc, resolve_module, scan_perl
from .ruby_analyzer import RubyAnalyzer
from .shellscan import function_lines, scan_shell
from .symbols import Symbol
from .treesitter_analyzers import CAnalyzer, LuaAnalyzer, TypeScriptAnalyzer


class ShellAnalyzer(Analyzer):
    """Reads shell scripts: the commands they run and files they source.

    Targets are resolved paths when found, and the name as written
    (status "unresolved") when not. Relative sourced files are looked
    up next to the script. Commands run through variables or eval are
    not visible.
    """

    name = "shell"
    kinds = ("shell",)

    def symbols(self, path):
        path = Path(path).resolve()
        lines = function_lines(path)

        return [
            Symbol(name, "function", str(path), lines.get(name, 1))
            for name in scan_shell(path).functions
        ]

    def edges(self, path):
        path = Path(path).resolve()
        scan = scan_shell(path)
        found = []

        for command in scan.commands:
            target = locate(command)

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

    def symbols(self, path):
        path = Path(path).resolve()

        return [
            Symbol(name, "function", str(path), 1)
            for _address, _size, name in read_function_table(path)
        ]

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


class PerlAnalyzer(Analyzer):
    """Reads Perl scripts: the modules they load and the subs they define.

    Modules are resolved under perl's include paths. A module that is
    not found is an unresolved edge that keeps its name.
    """

    name = "perl"
    kinds = ("perl",)

    def symbols(self, path):
        path = Path(path).resolve()

        return [
            Symbol(name, "function", str(path), line)
            for name, line in scan_perl(path).subs
        ]

    def edges(self, path):
        path = Path(path).resolve()
        found = []
        inc = perl_inc()

        for name, _line in scan_perl(path).modules:
            target = resolve_module(name, inc)

            if target is None:
                found.append(
                    Edge(str(path), None, "imports", "unresolved", name=name)
                )
            else:
                found.append(
                    Edge(
                        str(path),
                        str(target),
                        "imports",
                        "resolved",
                        name=name,
                    )
                )

        return found


for _analyzer in (
    ShellAnalyzer(),
    ELFAnalyzer(),
    PerlAnalyzer(),
    RubyAnalyzer(),
    JavaScriptAnalyzer(),
    LuaAnalyzer(),
    TypeScriptAnalyzer(),
    CAnalyzer(),
):
    if _analyzer.name not in registry.names():
        registry.register(_analyzer)
