"""Import-safe operational command line for the encrypted SQL Server vault."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from pw_locker_sql.config import SQLServerConfig
from pw_locker_sql.domain import CredentialId
from pw_locker_sql.errors import (
    AuthenticationError,
    ClipboardError,
    ConfigurationError,
    CredentialNotFoundError,
    CryptographicOperationError,
    InvalidMasterPasswordError,
    PasswordConfirmationError,
    PasswordLockerError,
    RepositoryError,
    SchemaMigrationError,
    SecurePromptError,
    UnsupportedFormatError,
    UnsupportedSchemaVersionError,
    ValidationError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
)
from pw_locker_sql.prompting import PromptProvider, TerminalPromptProvider
from pw_locker_sql.runtime import (
    ConfigurationSelection,
    OperationalRuntimeProtocol,
    RuntimeComposition,
    RuntimeFactoryProtocol,
)
from pw_locker_sql.schema.version import CURRENT_SCHEMA_VERSION
from pw_locker_sql.services import CredentialWriteResult

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CONFIGURATION = 3
EXIT_DOMAIN = 4
EXIT_CLIPBOARD = 5
EXIT_SQL = 6
EXIT_CANCELLED = 7
EXIT_INTERNAL = 70
EXIT_INTERRUPTED = 130
DEFAULT_CLEAR_AFTER_SECONDS = 30
MIN_CLEAR_AFTER_SECONDS = 5
MAX_CLEAR_AFTER_SECONDS = 300


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pw-locker-sql",
        description="Client-side encrypted SQL Server password vault",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--env-file",
        type=Path,
        help="load recognized settings from an explicitly selected dotenv file",
    )
    source.add_argument(
        "--no-env-file",
        action="store_true",
        help="use recognized process environment variables only",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    subparsers.add_parser("check-config", help="validate configuration without connecting")
    subparsers.add_parser("init", help="initialize schema and create a new encrypted vault")

    set_parser = subparsers.add_parser("set", help="create or update one credential")
    set_parser.add_argument("account")

    copy_parser = subparsers.add_parser("copy", help="copy one credential to the clipboard")
    copy_parser.add_argument("account")
    copy_parser.add_argument(
        "--clear-after",
        type=_clear_delay,
        default=DEFAULT_CLEAR_AFTER_SECONDS,
        metavar="SECONDS",
    )

    subparsers.add_parser("list", help="list normalized account identifiers")

    delete_parser = subparsers.add_parser("delete", help="delete one credential")
    delete_parser.add_argument("account")
    delete_parser.add_argument("--yes", action="store_true", help="skip deletion confirmation")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runtime_factory: RuntimeFactoryProtocol | None = None,
    prompt_provider: PromptProvider | None = None,
    wait: Callable[[float], None] | None = None,
) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return error.code if isinstance(error.code, int) else EXIT_USAGE
    if arguments.command is None:
        parser.print_help()
        return EXIT_OK

    factory: RuntimeFactoryProtocol = runtime_factory or RuntimeComposition()
    prompts = prompt_provider or TerminalPromptProvider()
    wait_function = wait or time.sleep
    try:
        selection = ConfigurationSelection(
            env_file=arguments.env_file,
            use_env_file=not arguments.no_env_file,
        )
        config = factory.load_config(selection)
        if arguments.command == "check-config":
            print(
                "Configuration is valid "
                f"(authentication: {config.authentication_mode.value})."
            )
            return EXIT_OK
        return _execute(arguments, config, factory, prompts, wait_function)
    except KeyboardInterrupt:
        print("Operation interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except ConfigurationError:
        print("Configuration is invalid.", file=sys.stderr)
        return EXIT_CONFIGURATION
    except ClipboardError:
        print("Clipboard operation failed.", file=sys.stderr)
        return EXIT_CLIPBOARD
    except (
        VaultAlreadyInitializedError,
        VaultNotInitializedError,
        CredentialNotFoundError,
        InvalidMasterPasswordError,
        AuthenticationError,
        UnsupportedFormatError,
        CryptographicOperationError,
        ValidationError,
        SecurePromptError,
        PasswordConfirmationError,
    ) as error:
        print(_safe_domain_message(error), file=sys.stderr)
        return EXIT_DOMAIN
    except (UnsupportedSchemaVersionError, SchemaMigrationError, RepositoryError):
        print("SQL storage operation failed.", file=sys.stderr)
        return EXIT_SQL
    except PasswordLockerError:
        print("Vault operation failed.", file=sys.stderr)
        return EXIT_DOMAIN
    except Exception:
        print("Unexpected internal failure.", file=sys.stderr)
        return EXIT_INTERNAL


def _execute(
    arguments: argparse.Namespace,
    config: SQLServerConfig,
    factory: RuntimeFactoryProtocol,
    prompts: PromptProvider,
    wait: Callable[[float], None],
) -> int:
    command = arguments.command
    if command == "init":
        return _initialize(config, factory, prompts)
    if command == "set":
        return _set_credential(arguments.account, config, factory, prompts)
    if command == "copy":
        return _copy_credential(
            arguments.account,
            arguments.clear_after,
            config,
            factory,
            prompts,
            wait,
        )
    if command == "list":
        return _list_credentials(config, factory, prompts)
    if command == "delete":
        return _delete_credential(
            arguments.account,
            arguments.yes,
            config,
            factory,
            prompts,
        )
    raise ValidationError()


def _initialize(
    config: SQLServerConfig,
    factory: RuntimeFactoryProtocol,
    prompts: PromptProvider,
) -> int:
    master_password = _confirmed_secret(
        prompts,
        "New master password: ",
        "Confirm new master password: ",
    )
    runtime = factory.compose(config)
    try:
        runtime.schema_manager.migrate()
        runtime.service.initialize(master_password)
        print("Vault initialized.")
        return EXIT_OK
    finally:
        runtime.close()


def _set_credential(
    account: str,
    config: SQLServerConfig,
    factory: RuntimeFactoryProtocol,
    prompts: PromptProvider,
) -> int:
    normalized = CredentialId.from_account(account).value
    master_password = _secret(prompts, "Master password: ")
    credential_password = _confirmed_secret(
        prompts,
        "Credential password: ",
        "Confirm credential password: ",
    )
    runtime = factory.compose(config)
    try:
        _require_current_schema(runtime)
        runtime.service.unlock(master_password)
        outcome = runtime.service.set_credential(normalized, credential_password)
        if outcome is CredentialWriteResult.CREATED:
            print("Credential created.")
        else:
            print("Credential updated.")
        return EXIT_OK
    finally:
        runtime.close()


def _copy_credential(
    account: str,
    clear_after: int,
    config: SQLServerConfig,
    factory: RuntimeFactoryProtocol,
    prompts: PromptProvider,
    wait: Callable[[float], None],
) -> int:
    normalized = CredentialId.from_account(account).value
    master_password = _secret(prompts, "Master password: ")
    runtime = factory.compose(config)
    plaintext = ""
    try:
        _require_current_schema(runtime)
        runtime.service.unlock(master_password)
        plaintext = runtime.service.get_credential(normalized)
        runtime.clipboard.copy(plaintext)
        try:
            wait(clear_after)
        except KeyboardInterrupt:
            try:
                _conditionally_clear(runtime, plaintext)
            except ClipboardError:
                pass
            raise
        cleared = _conditionally_clear(runtime, plaintext)
        if cleared:
            print("Credential copied and clipboard cleared.")
        else:
            print("Credential copied; newer clipboard content was preserved.")
        return EXIT_OK
    finally:
        # Python cannot guarantee zeroization of immutable strings. Dropping this
        # reference and locking the mutable-key session are the available controls.
        plaintext = ""
        runtime.close()


def _list_credentials(
    config: SQLServerConfig,
    factory: RuntimeFactoryProtocol,
    prompts: PromptProvider,
) -> int:
    master_password = _secret(prompts, "Master password: ")
    runtime = factory.compose(config)
    try:
        _require_current_schema(runtime)
        runtime.service.unlock(master_password)
        identifiers = sorted(
            item.credential_id.value for item in runtime.service.list_credentials()
        )
        if not identifiers:
            print("Vault contains no credentials.")
            return EXIT_OK
        for identifier in identifiers:
            print(identifier)
        return EXIT_OK
    finally:
        runtime.close()


def _delete_credential(
    account: str,
    assume_yes: bool,
    config: SQLServerConfig,
    factory: RuntimeFactoryProtocol,
    prompts: PromptProvider,
) -> int:
    normalized = CredentialId.from_account(account).value
    if not assume_yes and not prompts.confirm("Delete this credential? [y/N]: "):
        print("Deletion cancelled.", file=sys.stderr)
        return EXIT_CANCELLED
    master_password = _secret(prompts, "Master password: ")
    runtime = factory.compose(config)
    try:
        _require_current_schema(runtime)
        runtime.service.unlock(master_password)
        runtime.service.delete_credential(normalized)
        print("Credential deleted.")
        return EXIT_OK
    finally:
        runtime.close()


def _confirmed_secret(prompts: PromptProvider, first: str, second: str) -> str:
    value = _secret(prompts, first)
    confirmation = _secret(prompts, second)
    if value != confirmation:
        raise PasswordConfirmationError()
    return value


def _secret(prompts: PromptProvider, prompt: str) -> str:
    value = prompts.secret(prompt)
    if not isinstance(value, str) or not value:
        raise ValidationError()
    return value


def _require_current_schema(runtime: OperationalRuntimeProtocol) -> None:
    if runtime.schema_manager.current_version() != CURRENT_SCHEMA_VERSION:
        raise SchemaMigrationError()


def _conditionally_clear(runtime: OperationalRuntimeProtocol, expected: str) -> bool:
    if runtime.clipboard.read() != expected:
        return False
    runtime.clipboard.clear()
    return True


def _clear_delay(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("clear delay must be an integer") from error
    if not MIN_CLEAR_AFTER_SECONDS <= seconds <= MAX_CLEAR_AFTER_SECONDS:
        raise argparse.ArgumentTypeError(
            f"clear delay must be between {MIN_CLEAR_AFTER_SECONDS} and "
            f"{MAX_CLEAR_AFTER_SECONDS} seconds"
        )
    return seconds


def _safe_domain_message(error: PasswordLockerError) -> str:
    if isinstance(error, VaultAlreadyInitializedError):
        return "Vault is already initialized."
    if isinstance(error, VaultNotInitializedError):
        return "Vault is not initialized."
    if isinstance(error, CredentialNotFoundError):
        return "Credential not found."
    if isinstance(error, PasswordConfirmationError):
        return "Password confirmation did not match."
    if isinstance(error, SecurePromptError):
        return "Secure interactive input is required."
    if isinstance(
        error,
        (
            InvalidMasterPasswordError,
            AuthenticationError,
            UnsupportedFormatError,
            CryptographicOperationError,
        ),
    ):
        return "Vault authentication failed."
    if isinstance(error, ValidationError):
        return "Input is invalid."
    return "Vault operation failed."


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
