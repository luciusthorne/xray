from xray import sourcelookup


def test_source_rpm_size_reads_dnf_metadata(monkeypatch):
    class Result:
        returncode = 0
        stdout = "2173897\n"
        stderr = ""

    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return Result()

    monkeypatch.setattr(sourcelookup.subprocess, "run", run)

    assert sourcelookup.source_rpm_size("gmp-6.3.0-5.fc44") == 2173897
    assert calls[0][0:3] == ["dnf", "repoquery", "--srpm"]


def test_source_rpm_size_returns_none_when_metadata_is_unavailable(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
        stderr = "repository unavailable"

    monkeypatch.setattr(
        sourcelookup.subprocess,
        "run",
        lambda *args, **kwargs: Result(),
    )

    assert sourcelookup.source_rpm_size("missing-package") is None


def test_small_source_download_needs_no_confirmation():
    messages = []

    assert sourcelookup.confirm_source_download(
        2_173_897,
        messages.append,
        max_bytes=10 * 1024 * 1024,
        input_fn=lambda prompt: (_ for _ in ()).throw(
            AssertionError("small download should not prompt")
        ),
    )
    assert messages == []


def test_large_source_download_can_be_declined():
    messages = []

    assert not sourcelookup.confirm_source_download(
        20 * 1024 * 1024,
        messages.append,
        max_bytes=10 * 1024 * 1024,
        input_fn=lambda prompt: "n",
    )
    assert any("large" in message.lower() or "20" in message for message in messages)


def test_large_source_download_can_be_accepted():
    assert sourcelookup.confirm_source_download(
        20 * 1024 * 1024,
        lambda message: None,
        max_bytes=10 * 1024 * 1024,
        input_fn=lambda prompt: "y",
    )


def test_unknown_size_does_not_invent_a_size():
    messages = []

    assert sourcelookup.confirm_source_download(
        None,
        messages.append,
        max_bytes=10 * 1024 * 1024,
        input_fn=lambda prompt: (_ for _ in ()).throw(
            AssertionError("unknown size should not prompt using a guessed size")
        ),
    )
    assert any("unknown" in message.lower() for message in messages)
