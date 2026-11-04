from pathlib import Path

from . import command_analyzers, python_analyzer  # noqa: F401  (register analyzers)
from .analyzers import registry
from .entrypoints import command_kind
from .identify import get_file_metadata
from .model import AnalysisDocument, FileInfo
from .provenance import package_of
from .shellscan import scan_shell


def export_data(path):
    """Return everything XRAY knows about one file as plain data.

    The analyzer is chosen by the file's kind through the registry.
    Files no analyzer handles give empty symbols and edges.
    """

    path = Path(path).resolve()
    analyzer = registry.analyzer_for(path)
    notes = []

    if analyzer is not None:
        result = analyzer.analyze(path)
    else:
        kind = command_kind(path)
        result = AnalysisDocument(
            file=FileInfo(str(path), kind),
            analyzer=None,
        )

    if analyzer is not None and analyzer.name == "shell":
        scan = scan_shell(path)

        if scan.dynamic:
            dynamic_note = (
                f"{scan.dynamic} command(s) run through variables or eval "
                "(not resolved)"
            )
        else:
            dynamic_note = None

        if not scan.commands:
            notes.append(
                "no external commands found by static reading "
                "(commands run through variables or eval are not visible)"
            )

        if dynamic_note:
            notes.append(dynamic_note)

    if notes:
        result = AnalysisDocument(
            file=result.file,
            analyzer=result.analyzer,
            symbols=result.symbols,
            relationships=result.relationships,
            notes=tuple(notes),
        )

    result = AnalysisDocument(
        file=FileInfo(
            result.file.path,
            result.file.kind,
            result.file.language,
            {
                "filesystem": get_file_metadata(path),
                "package": package_of(path),
            },
        ),
        analyzer=result.analyzer,
        symbols=result.symbols,
        relationships=result.relationships,
        notes=result.notes,
    )
    return result.to_dict()
