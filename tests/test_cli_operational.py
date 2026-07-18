from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
from typing import NoReturn

import pytest

from pw_locker_sql import cli
from pw_locker_sql.config import SQLServerConfig
from pw_locker_sql.domain import CredentialId, CredentialMetadata
from pw_locker_sql.errors import (
    AuthenticationError,
    ClipboardError,
    ConfigurationError,
    CredentialNotFoundError,
    InvalidMasterPasswordError,
    RepositoryError,
    SchemaMigrationError,
    SecurePromptError,
    VaultAlreadyInitializedError,
)
from pw_locker_sql.prompting import TerminalPromptProvider
from pw_locker_sql.services import CredentialWriteResult

MASTER_PLACEHOLDER = "SYNTHETIC_MASTER_PASSWORD"
CREDENTIAL_PLACEHOLDER = "SYNTHETIC_CREDENTIAL_PASSWORD"
NOW = datetime(2026, 3, 4, 5, 6, tzinfo=timezone.utc)


class FakeSchemaManager:
    def __init__(self) -> None:
        self.version = 1
        self.current_calls = 0
        self.migrate_calls = 0
        self.error: Exception | None = None

    def current_version(self) -> int:
        self.current_calls += 1
        if self.error is not None:
            raise self.error
        return self.version

    def migrate(self) -> int:
        self.migrate_calls += 1
        if self.error is not None:
            raise self.error
        self.version = 1
        return self.version


class FakeService:
    def __init__(self) -> None:
        self.initialize_calls = 0
        self.unlock_calls = 0
        self.set_calls: list[str] = []
        self.get_calls: list[str] = []
        self.list_calls = 0
        self.delete_calls: list[str] = []
        self.close_calls = 0
        self.write_result = CredentialWriteResult.CREATED
        self.credential_value = CREDENTIAL_PLACEHOLDER
        self.metadata: tuple[CredentialMetadata, ...] = ()
        self.errors: dict[str, Exception] = {}

    def _raise(self, operation: str) -> None:
        error = self.errors.get(operation)
        if error is not None:
            raise error

    def initialize(self, master_password: str) -> None:
        self.initialize_calls += 1
        self._raise("initialize")

    def unlock(self, master_password: str) -> None:
        self.unlock_calls += 1
        self._raise("unlock")

    def lock(self) -> None:
        self._raise("lock")

    def set_credential(self, account: str, plaintext: str) -> CredentialWriteResult:
        self.set_calls.append(account)
        self._raise("set")
        return self.write_result

    def get_credential(self, account: str) -> str:
        self.get_calls.append(account)
        self._raise("get")
        return self.credential_value

    def list_credentials(self) -> tuple[CredentialMetadata, ...]:
        self.list_calls += 1
        self._raise("list")
        return self.metadata

    def delete_credential(self, account: str) -> None:
        self.delete_calls.append(account)
        self._raise("delete")

    def close(self) -> None:
        self.close_calls += 1


class FakeClipboard:
    def __init__(self) -> None:
        self.current = ""
        self.copied: list[str] = []
        self.clear_calls = 0
        self.fail_on: str | None = None

    def copy(self, value: str) -> None:
        if self.fail_on == "copy":
            raise ClipboardError()
        self.copied.append(value)
        self.current = value

    def read(self) -> str:
        if self.fail_on == "read":
            raise ClipboardError()
        return self.current

    def clear(self) -> None:
        if self.fail_on == "clear":
            raise ClipboardError()
        self.clear_calls += 1
        self.current = ""


class FakeRuntime:
    def __init__(self) -> None:
        self.schema_manager = FakeSchemaManager()
        self.service = FakeService()
        self.clipboard = FakeClipboard()
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.service.close()


class FakeFactory:
    def __init__(self, *runtimes: FakeRuntime) -> None:
        self.runtimes = list(runtimes)
        self.load_calls = 0
        self.compose_calls = 0
        self.load_error: Exception | None = None
        self.config = SQLServerConfig.from_mapping(
            {
                "SERVER": "SERVER_PLACEHOLDER",
                "DATABASE": "DATABASE_PLACEHOLDER",
                "AUTH_MODE": "integrated",
            }
        )

    def load_config(self, selection: object) -> SQLServerConfig:
        self.load_calls += 1
        if self.load_error is not None:
            raise self.load_error
        return self.config

    def compose(self, config: SQLServerConfig) -> FakeRuntime:
        self.compose_calls += 1
        if not self.runtimes:
            raise AssertionError("unexpected runtime composition")
        return self.runtimes.pop(0)


class FakePrompt:
    def __init__(self, secrets: list[str] | None = None, confirmations: list[bool] | None = None):
        self.secrets = list(secrets or [])
        self.confirmations = list(confirmations or [])
        self.secret_prompts: list[str] = []
        self.confirm_prompts: list[str] = []

    def secret(self, prompt: str) -> str:
        self.secret_prompts.append(prompt)
        if not self.secrets:
            raise AssertionError("unexpected secret prompt")
        return self.secrets.pop(0)

    def confirm(self, prompt: str) -> bool:
        self.confirm_prompts.append(prompt)
        if not self.confirmations:
            raise AssertionError("unexpected confirmation prompt")
        return self.confirmations.pop(0)


def _run(
    arguments: list[str],
    factory: FakeFactory,
    prompts: FakePrompt | None = None,
    wait=lambda _seconds: None,
) -> int:
    return cli.main(
        ["--no-env-file", *arguments],
        runtime_factory=factory,  # type: ignore[arg-type]
        prompt_provider=prompts or FakePrompt(),
        wait=wait,
    )


def _metadata(account: str) -> CredentialMetadata:
    return CredentialMetadata(CredentialId(account), NOW, NOW)


def test_help_performs_no_configuration_composition_prompt_or_wait(
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = FakeFactory()
    prompts = FakePrompt()

    def forbidden_wait(_seconds: float) -> NoReturn:
        raise AssertionError("wait must not run")

    assert cli.main(
        ["--help"],
        runtime_factory=factory,  # type: ignore[arg-type]
        prompt_provider=prompts,
        wait=forbidden_wait,
    ) == cli.EXIT_OK
    output = capsys.readouterr()
    assert "check-config" in output.out
    assert output.err == ""
    assert factory.load_calls == factory.compose_calls == 0
    assert prompts.secret_prompts == []


def test_check_config_validates_without_composition_or_connection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = FakeFactory()
    assert _run(["check-config"], factory) == cli.EXIT_OK
    output = capsys.readouterr()
    assert output.out == "Configuration is valid (authentication: integrated).\n"
    assert output.err == ""
    assert factory.load_calls == 1
    assert factory.compose_calls == 0


def test_configuration_failure_is_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    factory = FakeFactory()
    factory.load_error = ConfigurationError()
    assert cli.main(
        ["--env-file", "SENSITIVE_PATH_PLACEHOLDER", "check-config"],
        runtime_factory=factory,  # type: ignore[arg-type]
    ) == cli.EXIT_CONFIGURATION
    output = capsys.readouterr()
    assert "SENSITIVE_PATH_PLACEHOLDER" not in output.out + output.err
    assert output.err == "Configuration is invalid.\n"


def test_init_success_and_cleanup(capsys: pytest.CaptureFixture[str]) -> None:
    runtime = FakeRuntime()
    prompts = FakePrompt([MASTER_PLACEHOLDER, MASTER_PLACEHOLDER])
    assert _run(["init"], FakeFactory(runtime), prompts) == cli.EXIT_OK
    assert capsys.readouterr().out == "Vault initialized.\n"
    assert runtime.schema_manager.migrate_calls == 1
    assert runtime.service.initialize_calls == 1
    assert runtime.close_calls == runtime.service.close_calls == 1


def test_init_confirmation_mismatch_never_composes_runtime(
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = FakeFactory()
    prompts = FakePrompt([MASTER_PLACEHOLDER, "DIFFERENT_SYNTHETIC_PASSWORD"])
    assert _run(["init"], factory, prompts) == cli.EXIT_DOMAIN
    assert "confirmation" in capsys.readouterr().err.casefold()
    assert factory.compose_calls == 0


def test_init_refuses_existing_vault_and_cleans_up(capsys: pytest.CaptureFixture[str]) -> None:
    runtime = FakeRuntime()
    runtime.service.errors["initialize"] = VaultAlreadyInitializedError()
    prompts = FakePrompt([MASTER_PLACEHOLDER, MASTER_PLACEHOLDER])
    assert _run(["init"], FakeFactory(runtime), prompts) == cli.EXIT_DOMAIN
    assert capsys.readouterr().err == "Vault is already initialized.\n"
    assert runtime.close_calls == 1


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (CredentialWriteResult.CREATED, "Credential created.\n"),
        (CredentialWriteResult.UPDATED, "Credential updated.\n"),
    ],
)
def test_set_create_and_update(
    result: CredentialWriteResult,
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    runtime.service.write_result = result
    prompts = FakePrompt(
        [MASTER_PLACEHOLDER, CREDENTIAL_PLACEHOLDER, CREDENTIAL_PLACEHOLDER]
    )
    assert _run(["set", " Mixed ACCOUNT "], FakeFactory(runtime), prompts) == cli.EXIT_OK
    assert capsys.readouterr().out == message
    assert runtime.service.set_calls == ["mixed account"]
    assert runtime.close_calls == 1


def test_set_confirmation_mismatch_occurs_before_runtime_composition(
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = FakeFactory()
    prompts = FakePrompt(
        [MASTER_PLACEHOLDER, CREDENTIAL_PLACEHOLDER, "DIFFERENT_SYNTHETIC_PASSWORD"]
    )
    assert _run(["set", "ACCOUNT_PLACEHOLDER"], factory, prompts) == cli.EXIT_DOMAIN
    assert "confirmation" in capsys.readouterr().err.casefold()
    assert factory.compose_calls == 0


@pytest.mark.parametrize("account", ["", "   "])
def test_set_rejects_invalid_account_before_prompt_or_composition(
    account: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = FakeFactory()
    prompts = FakePrompt()
    assert _run(["set", account], factory, prompts) == cli.EXIT_DOMAIN
    assert capsys.readouterr().err == "Input is invalid.\n"
    assert prompts.secret_prompts == []
    assert factory.compose_calls == 0


def test_empty_prompt_value_is_rejected_before_runtime_composition(
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = FakeFactory()
    assert _run(["list"], factory, FakePrompt([""])) == cli.EXIT_DOMAIN
    assert capsys.readouterr().err == "Input is invalid.\n"
    assert factory.compose_calls == 0


def test_copy_retrieves_only_requested_account_and_clears_conditionally(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    waits: list[float] = []
    prompts = FakePrompt([MASTER_PLACEHOLDER])
    assert _run(
        ["copy", "Requested ACCOUNT"],
        FakeFactory(runtime),
        prompts,
        waits.append,
    ) == cli.EXIT_OK
    output = capsys.readouterr()
    assert CREDENTIAL_PLACEHOLDER not in output.out + output.err
    assert runtime.service.get_calls == ["requested account"]
    assert runtime.clipboard.copied == [CREDENTIAL_PLACEHOLDER]
    assert runtime.clipboard.clear_calls == 1
    assert waits == [30]
    assert runtime.close_calls == 1


def test_copy_preserves_newer_clipboard_content(capsys: pytest.CaptureFixture[str]) -> None:
    runtime = FakeRuntime()

    def replace_clipboard(_seconds: float) -> None:
        runtime.clipboard.current = "NEWER_USER_CLIPBOARD_PLACEHOLDER"

    assert _run(
        ["copy", "ACCOUNT_PLACEHOLDER", "--clear-after", "5"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
        replace_clipboard,
    ) == cli.EXIT_OK
    assert runtime.clipboard.clear_calls == 0
    assert runtime.clipboard.current == "NEWER_USER_CLIPBOARD_PLACEHOLDER"
    assert "preserved" in capsys.readouterr().out


def test_copy_clipboard_failure_maps_to_exit_five_and_cleans_up(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    runtime.clipboard.fail_on = "copy"
    assert _run(
        ["copy", "ACCOUNT_PLACEHOLDER"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_CLIPBOARD
    output = capsys.readouterr()
    assert output.err == "Clipboard operation failed.\n"
    assert CREDENTIAL_PLACEHOLDER not in output.out + output.err
    assert runtime.close_calls == 1


def test_copy_conditional_clear_failure_maps_safely(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    runtime.clipboard.fail_on = "clear"
    assert _run(
        ["copy", "ACCOUNT_PLACEHOLDER"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_CLIPBOARD
    output = capsys.readouterr()
    assert output.err == "Clipboard operation failed.\n"
    assert CREDENTIAL_PLACEHOLDER not in output.out + output.err
    assert runtime.close_calls == 1


def test_copy_interruption_attempts_conditional_clear_and_locks(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()

    def interrupt(_seconds: float) -> NoReturn:
        raise KeyboardInterrupt

    assert _run(
        ["copy", "ACCOUNT_PLACEHOLDER"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
        interrupt,
    ) == cli.EXIT_INTERRUPTED
    assert runtime.clipboard.clear_calls == 1
    assert runtime.close_calls == 1
    assert capsys.readouterr().err == "Operation interrupted.\n"


def test_copy_interruption_preserves_newer_clipboard_content(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()

    def replace_then_interrupt(_seconds: float) -> NoReturn:
        runtime.clipboard.current = "NEWER_USER_CLIPBOARD_PLACEHOLDER"
        raise KeyboardInterrupt

    assert _run(
        ["copy", "ACCOUNT_PLACEHOLDER"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
        replace_then_interrupt,
    ) == cli.EXIT_INTERRUPTED
    assert runtime.clipboard.current == "NEWER_USER_CLIPBOARD_PLACEHOLDER"
    assert runtime.clipboard.clear_calls == 0
    assert runtime.close_calls == 1
    assert capsys.readouterr().err == "Operation interrupted.\n"


def test_list_is_sorted_and_never_decrypts(capsys: pytest.CaptureFixture[str]) -> None:
    runtime = FakeRuntime()
    runtime.service.metadata = (_metadata("zeta"), _metadata("alpha"))
    assert _run(
        ["list"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_OK
    assert capsys.readouterr().out == "alpha\nzeta\n"
    assert runtime.service.list_calls == 1
    assert runtime.service.get_calls == []


def test_list_empty_vault(capsys: pytest.CaptureFixture[str]) -> None:
    runtime = FakeRuntime()
    assert _run(
        ["list"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_OK
    assert capsys.readouterr().out == "Vault contains no credentials.\n"


def test_delete_confirmation_cancellation_avoids_runtime(
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = FakeFactory()
    prompts = FakePrompt(confirmations=[False])
    assert _run(["delete", "ACCOUNT_PLACEHOLDER"], factory, prompts) == cli.EXIT_CANCELLED
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Deletion cancelled.\n"
    assert factory.compose_calls == 0
    assert prompts.secret_prompts == []


@pytest.mark.parametrize("assume_yes", [False, True])
def test_delete_confirmation_and_yes_paths(
    assume_yes: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    prompts = FakePrompt(
        [MASTER_PLACEHOLDER],
        confirmations=[] if assume_yes else [True],
    )
    arguments = ["delete", "Mixed ACCOUNT"] + (["--yes"] if assume_yes else [])
    assert _run(arguments, FakeFactory(runtime), prompts) == cli.EXIT_OK
    assert runtime.service.delete_calls == ["mixed account"]
    assert capsys.readouterr().out == "Credential deleted.\n"
    assert len(prompts.confirm_prompts) == (0 if assume_yes else 1)


def test_missing_account_and_wrong_master_are_safe(
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = FakeRuntime()
    missing.service.errors["delete"] = CredentialNotFoundError()
    assert _run(
        ["delete", "ACCOUNT_PLACEHOLDER", "--yes"],
        FakeFactory(missing),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_DOMAIN
    assert capsys.readouterr().err == "Credential not found.\n"

    wrong = FakeRuntime()
    wrong.service.errors["unlock"] = InvalidMasterPasswordError()
    assert _run(
        ["list"],
        FakeFactory(wrong),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_DOMAIN
    assert capsys.readouterr().err == "Vault authentication failed.\n"
    assert wrong.close_calls == 1


def test_corrupted_envelope_uses_same_safe_authentication_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    runtime.service.errors["get"] = AuthenticationError()
    assert _run(
        ["copy", "ACCOUNT_PLACEHOLDER"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_DOMAIN
    output = capsys.readouterr()
    assert output.err == "Vault authentication failed.\n"
    assert CREDENTIAL_PLACEHOLDER not in output.out + output.err
    assert runtime.close_calls == 1


def test_schema_and_repository_failures_map_without_raw_diagnostics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    runtime.schema_manager.error = SchemaMigrationError()
    assert _run(
        ["list"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_SQL
    assert capsys.readouterr().err == "SQL storage operation failed.\n"

    repository = FakeRuntime()
    repository.service.errors["list"] = RepositoryError()
    assert _run(
        ["list"],
        FakeFactory(repository),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_SQL
    assert capsys.readouterr().err == "SQL storage operation failed.\n"
    assert repository.close_calls == 1


def test_unexpected_failure_is_generic_and_resources_close(
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = FakeRuntime()
    runtime.service.errors["list"] = RuntimeError("SYNTHETIC_INTERNAL_DIAGNOSTIC")
    assert _run(
        ["list"],
        FakeFactory(runtime),
        FakePrompt([MASTER_PLACEHOLDER]),
    ) == cli.EXIT_INTERNAL
    output = capsys.readouterr()
    assert output.err == "Unexpected internal failure.\n"
    assert "SYNTHETIC_INTERNAL_DIAGNOSTIC" not in output.out + output.err
    assert runtime.close_calls == 1


def test_exit_codes_are_stable_and_documented() -> None:
    assert (
        cli.EXIT_OK,
        cli.EXIT_USAGE,
        cli.EXIT_CONFIGURATION,
        cli.EXIT_DOMAIN,
        cli.EXIT_CLIPBOARD,
        cli.EXIT_SQL,
        cli.EXIT_CANCELLED,
        cli.EXIT_INTERNAL,
        cli.EXIT_INTERRUPTED,
    ) == (0, 2, 3, 4, 5, 6, 7, 70, 130)


def test_argparse_never_accepts_or_stores_password_options() -> None:
    parser = cli.build_parser()
    namespace = parser.parse_args(["--no-env-file", "set", "ACCOUNT_PLACEHOLDER"])
    names = set(vars(namespace))
    assert "master_password" not in names
    assert "credential_password" not in names
    help_text = parser.format_help().casefold()
    assert "--master-password" not in help_text
    assert "--password" not in help_text


@pytest.mark.parametrize("value", ["4", "301", "not-an-integer"])
def test_copy_clear_delay_rejects_unsafe_values(value: str) -> None:
    assert cli.main(["copy", "ACCOUNT_PLACEHOLDER", "--clear-after", value]) == cli.EXIT_USAGE


def test_terminal_prompt_rejects_noninteractive_input_without_calling_getpass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = StringIO("SYNTHETIC_REDIRECTED_VALUE\n")

    def forbidden_getpass(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("getpass must not read redirected input")

    monkeypatch.setattr("getpass.getpass", forbidden_getpass)
    with pytest.raises(SecurePromptError):
        TerminalPromptProvider(stream).secret("Master password: ")
