"""Operational composition root with explicit, protected configuration loading."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from pw_locker_sql.clipboard import ClipboardProvider, PyperclipClipboardProvider
from pw_locker_sql.config import SQLServerConfig
from pw_locker_sql.domain import CredentialMetadata
from pw_locker_sql.errors import ConfigurationError
from pw_locker_sql.services import CredentialWriteResult, VaultService

if TYPE_CHECKING:
    from pw_locker_sql.crypto.protocol import VaultCryptographicProvider
    from pw_locker_sql.repositories.sql_server import OdbcConnector
    from pw_locker_sql.schema.manager import SqlServerSchemaManager

ENVIRONMENT_KEY_MAP = {
    "PW_LOCKER_SQL_SERVER": "SERVER",
    "PW_LOCKER_SQL_DATABASE": "DATABASE",
    "PW_LOCKER_SQL_AUTH_MODE": "AUTH_MODE",
    "PW_LOCKER_SQL_USERNAME": "USERNAME",
    "PW_LOCKER_SQL_PASSWORD": "PASSWORD",
    "PW_LOCKER_SQL_DRIVER": "ODBC_DRIVER",
    "PW_LOCKER_SQL_CONNECT_TIMEOUT": "CONNECTION_TIMEOUT",
}


@dataclass(frozen=True, slots=True)
class ConfigurationSelection:
    """Selects a configuration source without exposing its path in repr."""

    env_file: Path | None = field(default=None, repr=False)
    use_env_file: bool = True

    def __post_init__(self) -> None:
        if self.env_file is not None and not self.use_env_file:
            raise ConfigurationError()

    def __repr__(self) -> str:
        source = "env-and-file" if self.use_env_file else "environment-only"
        return f"ConfigurationSelection(source={source!r})"


class SchemaManagerProtocol(Protocol):
    def current_version(self) -> int: ...

    def migrate(self) -> int: ...


class VaultServiceProtocol(Protocol):
    def initialize(self, master_password: str) -> None: ...

    def unlock(self, master_password: str) -> None: ...

    def lock(self) -> None: ...

    def set_credential(self, account: str, plaintext: str) -> CredentialWriteResult: ...

    def get_credential(self, account: str) -> str: ...

    def list_credentials(self) -> tuple[CredentialMetadata, ...]: ...

    def delete_credential(self, account: str) -> None: ...

    def close(self) -> None: ...


class OperationalRuntimeProtocol(Protocol):
    @property
    def schema_manager(self) -> SchemaManagerProtocol: ...

    @property
    def service(self) -> VaultServiceProtocol: ...

    @property
    def clipboard(self) -> ClipboardProvider: ...

    def close(self) -> None: ...


class RuntimeFactoryProtocol(Protocol):
    def load_config(self, selection: ConfigurationSelection) -> SQLServerConfig: ...

    def compose(self, config: SQLServerConfig) -> OperationalRuntimeProtocol: ...


@dataclass(slots=True)
class OperationalRuntime:
    schema_manager: SqlServerSchemaManager
    service: VaultService
    clipboard: ClipboardProvider
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.service.close()
        finally:
            self._closed = True

    def __enter__(self) -> OperationalRuntime:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self._closed else "ready"
        return f"OperationalRuntime(state={state!r})"


class RuntimeComposition:
    """Creates production boundaries without performing I/O during construction."""

    def __init__(
        self,
        *,
        connector: OdbcConnector | None = None,
        cryptographic_provider_factory: Callable[[], VaultCryptographicProvider] | None = None,
        clipboard_factory: Callable[[], ClipboardProvider] | None = None,
        environment: Mapping[str, str] | None = None,
        working_directory: Path | None = None,
    ) -> None:
        self._connector = connector
        self._cryptographic_provider_factory = cryptographic_provider_factory
        self._clipboard_factory = clipboard_factory or PyperclipClipboardProvider
        self._environment = environment
        self._working_directory = working_directory

    def load_config(self, selection: ConfigurationSelection) -> SQLServerConfig:
        environment = self._environment if self._environment is not None else os.environ
        directory = self._working_directory or Path.cwd()
        return load_sql_server_config(selection, environment, directory)

    def compose(self, config: SQLServerConfig) -> OperationalRuntime:
        from pw_locker_sql.crypto.argon2_aesgcm import Argon2idAesGcmProvider
        from pw_locker_sql.repositories.sql_server import (
            SqlServerConnectionFactory,
            SqlServerCredentialRepository,
        )
        from pw_locker_sql.schema.manager import SqlServerSchemaManager

        connection_factory = SqlServerConnectionFactory(config, self._connector)
        repository = SqlServerCredentialRepository(connection_factory)
        schema_manager = SqlServerSchemaManager(connection_factory)
        try:
            provider_factory = self._cryptographic_provider_factory or Argon2idAesGcmProvider
            service = VaultService(repository, provider_factory())
            clipboard = self._clipboard_factory()
        except Exception:
            repository.close()
            raise
        return OperationalRuntime(schema_manager, service, clipboard)

    def __repr__(self) -> str:
        return "RuntimeComposition(<redacted>)"

    __str__ = __repr__


def load_sql_server_config(
    selection: ConfigurationSelection,
    environment: Mapping[str, str],
    working_directory: Path,
) -> SQLServerConfig:
    """Load recognized settings without interpolation or environment mutation."""
    selected: dict[str, str] = {}
    if selection.use_env_file:
        explicit = selection.env_file is not None
        path = selection.env_file or (working_directory / ".env")
        if explicit and not path.is_file():
            raise ConfigurationError()
        if path.is_file():
            selected.update(_read_dotenv(path))
    for external_name, internal_name in ENVIRONMENT_KEY_MAP.items():
        value = environment.get(external_name)
        if isinstance(value, str):
            selected[internal_name] = value
    return SQLServerConfig.from_mapping(selected)


def _read_dotenv(path: Path) -> dict[str, str]:
    try:
        from dotenv import dotenv_values

        raw_values = dotenv_values(path, interpolate=False)
    except Exception:
        raise ConfigurationError() from None
    selected: dict[str, str] = {}
    for external_name, internal_name in ENVIRONMENT_KEY_MAP.items():
        value = raw_values.get(external_name)
        if isinstance(value, str):
            selected[internal_name] = value
    return selected
