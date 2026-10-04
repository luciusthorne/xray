from xray import cli


def test_every_query_is_in_help(capsys):
    cli.print_help()
    output = capsys.readouterr().out

    for option in cli.QUERIES:
        if option is not None:
            assert option in output, option


def test_default_view_is_registered():
    assert None in cli.QUERIES
