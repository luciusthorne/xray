import re
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_INC = (
    "/usr/local/lib64/perl5",
    "/usr/local/share/perl5",
    "/usr/lib64/perl5/vendor_perl",
    "/usr/share/perl5/vendor_perl",
    "/usr/lib64/perl5",
    "/usr/share/perl5",
)

PRAGMAS = frozenset(
    "strict warnings utf8 vars lib constant parent base feature integer "
    "overload bytes locale open subs fields diagnostics autodie bigint "
    "bignum less sort if experimental mro".split()
)

_USE = re.compile(r"^\s*(?:use|require)\s+([A-Za-z_]\w*(?:::\w+)*)")
_SUB = re.compile(r"^\s*sub\s+([A-Za-z_]\w*(?:::\w+)*)")
_POD = re.compile(r"^=[A-Za-z]")


@dataclass(frozen=True)
class PerlScan:
    """What a Perl script loads and defines.

    modules holds (name, line) for each "use" or "require" of a module,
    once per name. Pragmas and version numbers are left out. subs holds
    (name, line) for each "sub". Both skip POD documentation and stop
    at __END__ or __DATA__. This is a line-based reading: modules named
    through "use parent", "use base" or built strings are not seen.
    """

    modules: tuple = ()
    subs: tuple = ()


def scan_perl(path):
    """Return a PerlScan for a Perl file. An unreadable file gives an empty one."""

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return PerlScan()

    modules = []
    seen = set()
    subs = []
    in_pod = False

    for number, line in enumerate(text.splitlines(), 1):
        if in_pod:
            if line.startswith("=cut"):
                in_pod = False

            continue

        if _POD.match(line):
            in_pod = True
            continue

        stripped = line.strip()

        if stripped in ("__END__", "__DATA__"):
            break

        if stripped.startswith("#"):
            continue

        match = _USE.match(line)

        if match:
            name = match.group(1)

            if (
                name not in PRAGMAS
                and not re.fullmatch(r"v\d+", name)
                and name not in seen
            ):
                seen.add(name)
                modules.append((name, number))

            continue

        match = _SUB.match(line)

        if match:
            subs.append((match.group(1), number))

    return PerlScan(tuple(modules), tuple(subs))


@lru_cache(maxsize=1)
def perl_inc():
    """Return perl's include paths, or a default list when perl cannot be run."""

    try:
        result = subprocess.run(
            ["perl", "-e", 'print join("\\n", @INC)'],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return DEFAULT_INC

    paths = tuple(line for line in result.stdout.splitlines() if line.strip())

    return paths if result.returncode == 0 and paths else DEFAULT_INC


def resolve_module(name, inc):
    """Return the .pm file a module name refers to, or None."""

    relative = name.replace("::", "/") + ".pm"

    for directory in inc:
        candidate = Path(directory) / relative

        if candidate.is_file():
            return candidate.resolve()

    return None
