import shutil

import pytest

from xray.perlscan import PerlScan, resolve_module, scan_perl


def script(tmp_path, body):
    path = tmp_path / "tool"
    path.write_text(body, encoding="utf-8")

    return path


def test_use_and_require_modules(tmp_path):
    body = (
        "#!/usr/bin/perl\n"
        "use strict;\n"
        "use Encode ;\n"
        "use Encode::Alias;\n"
        "use Getopt::Long qw(:config no_ignore_case);\n"
        "use Pod::Man ();\n"
        "require Pod::Usage;\n"
    )

    assert scan_perl(script(tmp_path, body)).modules == (
        ("Encode", 3),
        ("Encode::Alias", 4),
        ("Getopt::Long", 5),
        ("Pod::Man", 6),
        ("Pod::Usage", 7),
    )


def test_pragmas_and_versions_are_ignored(tmp_path):
    body = (
        "use 5.8.0;\nuse v5.10;\nuse 5.012;\nrequire 5;\n"
        "use strict;\nuse warnings;\nuse utf8;\nuse lib 'x';\n"
    )

    assert scan_perl(script(tmp_path, body)).modules == ()


def test_pod_is_skipped(tmp_path):
    body = (
        "#!/usr/bin/perl\n"
        "use Real::One;\n"
        "\n"
        "=head1 NAME\n"
        "\n"
        "use Fake::Module;\n"
        "sub fake {\n"
        "\n"
        "=cut\n"
        "\n"
        "sub real {\n"
        "}\n"
    )
    scan = scan_perl(script(tmp_path, body))

    assert scan.modules == (("Real::One", 2),)
    assert scan.subs == (("real", 11),)


def test_end_marker_stops_the_scan(tmp_path):
    body = "use A::B;\n__END__\nuse C::D;\nsub late {}\n"
    scan = scan_perl(script(tmp_path, body))

    assert scan.modules == (("A::B", 1),)
    assert scan.subs == ()


def test_subs_have_line_numbers(tmp_path):
    body = (
        "#!/usr/bin/perl\n"
        "sub list_encodings {\n"
        "}\n"
        "\n"
        "sub resolve_encoding {\n"
        "}\n"
        "  sub Pkg::help {\n"
        "}\n"
    )

    assert scan_perl(script(tmp_path, body)).subs == (
        ("list_encodings", 2),
        ("resolve_encoding", 5),
        ("Pkg::help", 7),
    )


def test_missing_file_gives_an_empty_scan(tmp_path):
    assert scan_perl(tmp_path / "missing") == PerlScan()


def test_resolve_module_looks_through_the_include_paths(tmp_path):
    module = tmp_path / "lib" / "Foo" / "Bar.pm"
    module.parent.mkdir(parents=True)
    module.write_text("1;\n", encoding="utf-8")

    assert resolve_module("Foo::Bar", (str(tmp_path / "lib"),)) == module.resolve()
    assert resolve_module("No::Such", (str(tmp_path / "lib"),)) is None


@pytest.mark.skipif(
    shutil.which("pod2man") is None, reason="pod2man not installed"
)
def test_real_pod2man():
    scan = scan_perl(shutil.which("pod2man"))
    names = [name for name, _ in scan.modules]

    assert "Pod::Man" in names
    assert "Getopt::Long" in names
    assert "strict" not in names
    assert "warnings" not in names
    assert "format_file" in [name for name, _ in scan.subs]
