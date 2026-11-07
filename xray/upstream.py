"""Upstream source for installed programs that have no debug information.

For a pacman-owned binary, the package's .SRCINFO in Arch's packaging
repository names the exact source archives the package was built from, with
their SHA-256 checksums. XRAY downloads that archive (checksum checked),
extracts it into its cache, and finds a function's definition in it by name.

The archive is the one Arch built from, but the match is by name: Arch's
patches and build options may change the code, overloads share a name, and
inlined or generated functions may have no single definition. Results are
labelled as such.
"""

import hashlib
import os
import re
import subprocess
import tarfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

GITLAB = "https://gitlab.archlinux.org/archlinux/packaging/packages/{base}/-/raw/{tag}/.SRCINFO"
MAX_ARCHIVE = 512 * 1024 * 1024
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".inl", ".tcc")
ARCHIVES = (".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar.zst", ".tzst", ".tar")
_SKIP_DIRS = {".git", "test", "tests", "testsuite", "examples", "example", "docs", "doc", "third_party_tests"}


@dataclass
class Upstream:
    package: str
    version: str
    base: str
    archives: list = field(default_factory=list)    # [(name, url, sha256 or None)]
    patches: list = field(default_factory=list)     # local patch files Arch applies
    root: Path | None = None                         # extracted tree
    verified: bool = False
    problem: str | None = None


def pacman_package(path):
    """(name, version, base) of the pacman package owning path, or None."""

    try:
        out = subprocess.run(["pacman", "-Qo", str(path)], capture_output=True, text=True,
                             check=False, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"is owned by (\S+) (\S+)", out)
    if not match:
        return None
    name, version = match.groups()
    base = name
    desc = Path("/var/lib/pacman/local") / f"{name}-{version}" / "desc"
    try:
        lines = desc.read_text().splitlines()
        if "%BASE%" in lines:
            base = lines[lines.index("%BASE%") + 1]
    except (OSError, IndexError):
        pass
    return name, version, base


def parse_srcinfo(text):
    """(sources, sha256sums) for the x86_64 build, in order."""

    sources, sums = [], []
    for raw in text.splitlines():
        key, _, value = raw.strip().partition(" = ")
        if key in ("source", "source_x86_64"):
            sources.append(value)
        elif key in ("sha256sums", "sha256sums_x86_64"):
            sums.append(value)
    return sources, sums


def _archive_url(entry):
    """(file name, download URL) for a .SRCINFO source entry, or None for local files."""

    name, sep, url = entry.partition("::")
    if not sep:
        name, url = "", entry
    if url.startswith("git+"):
        # git+https://github.com/o/r.git#tag=v1.2 -> GitHub's archive of that tag or commit
        parsed = urllib.parse.urlparse(url[4:])
        ref = parsed.fragment.split("=", 1)[1] if "=" in parsed.fragment else None
        if parsed.netloc == "github.com" and ref:
            repo = parsed.path.removesuffix(".git").strip("/")
            return f"{repo.split('/')[-1]}-{ref}.tar.gz", f"https://github.com/{repo}/archive/{ref}.tar.gz"
        return None
    if "://" not in url:
        return None
    return (name or url.rsplit("/", 1)[-1]), url


def find_upstream(path, fetch_text=None):
    """Upstream for an installed binary: package, archives and patches (not yet downloaded)."""

    owner = pacman_package(path)
    if owner is None:
        return None
    name, version, base = owner
    info = Upstream(name, version, base)
    tag = version.replace(":", "-")
    fetch_text = fetch_text or (lambda url: _download(url, 4 * 1024 * 1024).decode("utf-8", "replace"))
    try:
        text = fetch_text(GITLAB.format(base=urllib.parse.quote(base), tag=urllib.parse.quote(tag)))
    except OSError as error:
        info.problem = f"no .SRCINFO for {base} {version} in Arch's packaging repository ({error})"
        return info
    sources, sums = parse_srcinfo(text)
    for index, entry in enumerate(sources):
        digest = sums[index] if index < len(sums) and sums[index] not in ("SKIP", "") else None
        found = _archive_url(entry)
        if found is None:
            if entry.endswith((".patch", ".diff")):
                info.patches.append(entry)
            continue
        file_name, url = found
        if file_name.endswith(ARCHIVES) or url.endswith(ARCHIVES):
            info.archives.append((file_name, url, digest))
    if not info.archives:
        info.problem = "the package's sources are not a downloadable archive"
    return info


def _download(url, limit):
    import urllib.request

    from xray import __version__

    request = urllib.request.Request(url, headers={"User-Agent": f"xray-trust/{__version__} (source viewer)"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"{url} is larger than {limit // (1024 * 1024)} MiB")
    return data


def _safe_members(archive, dest):
    dest = dest.resolve()
    for member in archive.getmembers():
        if not (member.isfile() or member.isdir()):
            continue  # no links, devices or fifos
        target = (dest / member.name).resolve()
        if dest not in target.parents and target != dest:
            continue  # absolute paths and ../ escapes
        if member.isfile() and not member.name.endswith(SOURCE_SUFFIXES + (".txt", ".md", "LICENSE")):
            continue  # only source text is needed
        yield member


def prepare(info, fetch=None):
    """Download, check and extract the first archive into the cache; sets info.root."""

    from xray.evidencestore import cache_dir

    if not info.archives:
        return info
    file_name, url, digest = info.archives[0]
    root = cache_dir() / "upstream" / f"{info.base}-{info.version}"
    marker = root / ".xray-extracted"
    if marker.is_file():
        info.root, info.verified = root, marker.read_text().strip() == "verified"
        return info
    try:
        data = (fetch or (lambda u: _download(u, MAX_ARCHIVE)))(url)
    except OSError as error:
        info.problem = f"could not download {url}: {error}"
        return info
    if digest is not None:
        if hashlib.sha256(data).hexdigest() != digest:
            info.problem = f"{file_name} does not match the checksum in .SRCINFO; not used"
            return info
        info.verified = True
    import io

    mode = "r:*"
    if file_name.endswith((".tar.zst", ".tzst")) or url.endswith((".tar.zst", ".tzst")):
        try:
            import zstandard  # noqa: F401
        except ImportError:
            data = subprocess.run(["zstd", "-dc"], input=data, capture_output=True, check=False).stdout
            mode = "r:"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as archive:
            members = list(_safe_members(archive, root))
            try:
                archive.extractall(root, members=members, filter="data")
            except TypeError:  # Python without extraction filters
                archive.extractall(root, members=members)
    except (tarfile.TarError, OSError, EOFError) as error:
        info.problem = f"could not unpack {file_name}: {error}"
        return info
    marker.write_text("verified" if info.verified else "unverified")
    info.root = root
    return info


def _qualified_forms(name):
    """Name forms to search for, most specific first: a::B::m -> B::m, m."""

    base = name.split("(", 1)[0].strip()
    base = re.sub(r"\[abi:[^\]]*\]", "", base)
    parts = [part for part in base.split("::") if part]
    forms = []
    if len(parts) >= 2:
        forms.append("::".join(parts[-2:]))
    if parts:
        forms.append(parts[-1])
    return forms


_NOT_DEFINITIONS = re.compile(r"^\s*(?:return|if|while|for|switch|else|case|delete|new|throw|co_return)\b")


def find_definition(root, name, max_lines=400):
    """(file, start line, lines) of the most likely definition of name under root, or None."""

    from xray.codemap import body_end

    forms = _qualified_forms(name)
    if not forms:
        return None
    klass = forms[0].split("::")[0] if "::" in forms[0] else None
    best = None
    for form in forms:
        pattern = re.compile(rf"(?<![\w:]){re.escape(form)}\s*\(")
        for folder, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d.lower() not in _SKIP_DIRS)
            for file_name in sorted(files):
                if not file_name.endswith(SOURCE_SUFFIXES):
                    continue
                path = Path(folder) / file_name
                try:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for index, line in enumerate(lines):
                    match = pattern.search(line)
                    if not match or _NOT_DEFINITIONS.match(line) or "=" in line[:match.start()]:
                        continue
                    rest = " ".join(lines[index:index + 15])[match.start():]
                    brace, semi = rest.find("{"), rest.find(";")
                    if brace < 0 or (0 <= semi < brace):
                        continue  # a declaration or a call, not a definition
                    end = body_end(lines, index + 1, "c")
                    if end is None:
                        continue
                    start = index + 1
                    while start > 1 and lines[start - 2].strip() and not lines[start - 2].rstrip().endswith((";", "}", "{")) \
                            and not lines[start - 2].lstrip().startswith(("#", "//")):
                        start -= 1  # return type or template line above
                    score = (
                        0 if form == forms[0] else 1,
                        0 if file_name.endswith((".c", ".cc", ".cpp", ".cxx", ".c++")) else 1,
                        0 if klass and Path(file_name).stem.lower() == klass.lstrip("C").lower() else 1,
                        len(path.parts),
                    )
                    if best is None or score < best[0]:
                        best = (score, path, start, lines[start - 1:end][:max_lines])
        if best is not None and best[0][0] == 0:
            break
    if best is None:
        return None
    return best[1], best[2], best[3]


def note(info):
    """One line saying what the source is and how far to trust a match."""

    where = f"{info.archives[0][0]} from Arch's {info.base} {info.version} build sources"
    check = "checksum verified" if info.verified else "no checksum to verify"
    patches = f"; Arch applies {len(info.patches)} patch(es) not shown" if info.patches else ""
    return (f"(source: {where}, {check}{patches}. Matched by name, a guess: "
            "patches, build options and overloads can make it differ.)")
