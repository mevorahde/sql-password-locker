from __future__ import annotations

from collections.abc import Sequence

import pytest

from pw_locker_sql import cli, pwsql
from pw_locker_sql.errors import ConfigurationError


def _capture_delegation(
    monkeypatch: pytest.MonkeyPatch,
    *,
    exit_code: int = cli.EXIT_OK,
) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_main(arguments: Sequence[str] | None = None) -> int:
        calls.append(list(arguments or ()))
        return exit_code

    monkeypatch.setattr(cli, "main", fake_main)
    return calls


@pytest.mark.parametrize(
    ("arguments", "delegated"),
    [
        (["iTunes"], ["copy", "iTunes"]),
        (["Apple ID"], ["copy", "Apple ID"]),
        (
            ["Apple ID", "--clear-after", "30"],
            ["copy", "Apple ID", "--clear-after", "30"],
        ),
    ],
)
def test_pwsql_delegates_copy_arguments_unchanged(
    arguments: list[str],
    delegated: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_delegation(monkeypatch)

    assert pwsql.main(arguments) == cli.EXIT_OK
    assert calls == [delegated]


@pytest.mark.parametrize(
    ("arguments", "delegated"),
    [
        (
            ["--no-env-file", "Apple ID", "--clear-after", "30"],
            ["--no-env-file", "copy", "Apple ID", "--clear-after", "30"],
        ),
        (
            ["--env-file", "CONFIG_PATH_PLACEHOLDER", "Apple ID"],
            ["--env-file", "CONFIG_PATH_PLACEHOLDER", "copy", "Apple ID"],
        ),
        (
            ["--env-file=CONFIG_PATH_PLACEHOLDER", "Apple ID"],
            ["--env-file=CONFIG_PATH_PLACEHOLDER", "copy", "Apple ID"],
        ),
        (["--env-file"], ["--env-file"]),
    ],
)
def test_pwsql_preserves_supported_configuration_selection_order(
    arguments: list[str],
    delegated: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_delegation(monkeypatch)

    assert pwsql.main(arguments) == cli.EXIT_OK
    assert calls == [delegated]


@pytest.mark.parametrize(
    ("arguments", "delegated"),
    [
        (["--help"], ["copy", "--help"]),
        ([], ["copy"]),
        (["--no-env-file", "--help"], ["--no-env-file", "copy", "--help"]),
    ],
)
def test_pwsql_help_and_no_account_delegate_without_side_effects(
    arguments: list[str],
    delegated: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_delegation(monkeypatch)

    assert pwsql.main(arguments) == cli.EXIT_OK
    assert calls == [delegated]


def test_pwsql_help_and_no_account_are_handled_by_existing_cli(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert pwsql.main(["--help"]) == cli.EXIT_OK
    help_output = capsys.readouterr()
    assert "account" in help_output.out
    assert help_output.err == ""

    assert pwsql.main([]) == cli.EXIT_USAGE
    usage_output = capsys.readouterr()
    assert usage_output.out == ""
    assert "required" in usage_output.err
    assert "Master password:" not in usage_output.out + usage_output.err


@pytest.mark.parametrize(
    "exit_code",
    [
        cli.EXIT_USAGE,
        cli.EXIT_CONFIGURATION,
        cli.EXIT_DOMAIN,
        cli.EXIT_CLIPBOARD,
        cli.EXIT_SQL,
        cli.EXIT_CANCELLED,
        cli.EXIT_INTERNAL,
        cli.EXIT_INTERRUPTED,
    ],
)
def test_pwsql_propagates_existing_cli_exit_codes(
    exit_code: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _capture_delegation(monkeypatch, exit_code=exit_code)

    assert pwsql.main(["ACCOUNT_PLACEHOLDER"]) == exit_code
    assert calls == [["copy", "ACCOUNT_PLACEHOLDER"]]


@pytest.mark.parametrize(
    ("arguments", "expected_code"),
    [
        ([], cli.EXIT_USAGE),
        (["--env-file"], cli.EXIT_USAGE),
        (["ACCOUNT_PLACEHOLDER", "--clear-after", "INVALID"], cli.EXIT_USAGE),
    ],
)
def test_pwsql_invalid_arguments_are_handled_by_existing_cli(
    arguments: list[str],
    expected_code: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert pwsql.main(arguments) == expected_code
    output = capsys.readouterr()
    assert "SYNTHETIC_MASTER_PASSWORD" not in output.out + output.err
    assert "SYNTHETIC_CREDENTIAL_PASSWORD" not in output.out + output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize(
    ("error", "expected_code", "expected_message"),
    [
        (ConfigurationError(), cli.EXIT_CONFIGURATION, "Configuration is invalid.\n"),
        (KeyboardInterrupt(), cli.EXIT_INTERRUPTED, "Operation interrupted.\n"),
        (RuntimeError("SENSITIVE_DIAGNOSTIC"), cli.EXIT_INTERNAL, "Unexpected internal failure.\n"),
    ],
)
def test_pwsql_failures_and_interruptions_remain_safely_translated(
    error: BaseException,
    expected_code: int,
    expected_message: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FailingFactory:
        def load_config(self, _selection: object) -> None:
            raise error

        def compose(self, _config: object) -> None:
            raise AssertionError("runtime composition must not occur")

    monkeypatch.setattr(cli, "RuntimeComposition", FailingFactory)

    assert pwsql.main(["--no-env-file", "ACCOUNT_PLACEHOLDER"]) == expected_code
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == expected_message
    assert "SENSITIVE_DIAGNOSTIC" not in output.err
    assert "Traceback" not in output.err
