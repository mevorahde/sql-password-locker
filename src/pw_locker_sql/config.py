"""Explicit, typed SQL Server configuration parsing without environment access."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from pw_locker_sql.errors import ConfigurationError


class AuthenticationMode(str, Enum):
    WINDOWS_INTEGRATED = "integrated"
    SQL = "sql"


@dataclass(frozen=True, slots=True)
class SecretValue:
    """A deliberately redacted wrapper for a supplied configuration secret."""

    _value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._value, str) or not self._value:
            raise ConfigurationError()

    def get_secret_value(self) -> str:
        """Return the value only to a future connection factory."""
        return self._value

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class SQLServerConfig:
    """Validated settings for a future SQL Server repository."""

    odbc_driver: str = field(repr=False)
    server: str = field(repr=False)
    database: str = field(repr=False)
    authentication_mode: AuthenticationMode
    username: str | None = field(default=None, repr=False)
    password: SecretValue | None = field(default=None, repr=False)
    encrypt: bool = True
    trust_server_certificate: bool = False
    connection_timeout: int = 15

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> SQLServerConfig:
        required = tuple(_required(values, key) for key in ("ODBC_DRIVER", "SERVER", "DATABASE"))
        try:
            mode = AuthenticationMode(_required(values, "AUTH_MODE").strip().casefold())
        except ValueError as error:
            raise ConfigurationError() from error

        username = _optional(values, "USERNAME")
        raw_password = _optional(values, "PASSWORD")
        if mode is AuthenticationMode.WINDOWS_INTEGRATED:
            if username is not None or raw_password is not None:
                raise ConfigurationError()
            password = None
        else:
            if username is None or raw_password is None:
                raise ConfigurationError()
            password = SecretValue(raw_password)

        encrypt = _parse_bool(values, "ENCRYPT", default=True)
        trust_certificate = _parse_bool(values, "TRUST_SERVER_CERTIFICATE", default=False)
        timeout = _parse_timeout(values.get("CONNECTION_TIMEOUT", "15"))
        return cls(
            odbc_driver=required[0],
            server=required[1],
            database=required[2],
            authentication_mode=mode,
            username=username,
            password=password,
            encrypt=encrypt,
            trust_server_certificate=trust_certificate,
            connection_timeout=timeout,
        )

    def redacted_diagnostics(self) -> Mapping[str, object]:
        """Return useful state without configuration values."""
        return MappingProxyType(
            {
                "odbc_driver": "<configured>",
                "server": "<configured>",
                "database": "<configured>",
                "authentication_mode": self.authentication_mode.value,
                "username": "<configured>" if self.username is not None else "<not-used>",
                "password": "<configured>" if self.password is not None else "<not-used>",
                "encrypt": self.encrypt,
                "trust_server_certificate": self.trust_server_certificate,
                "connection_timeout": self.connection_timeout,
            }
        )


def _required(values: Mapping[str, str], key: str) -> str:
    value = _optional(values, key)
    if value is None:
        raise ConfigurationError()
    return value


def _optional(values: Mapping[str, str], key: str) -> str | None:
    value = values.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError()
    stripped = value.strip()
    return stripped or None


def _parse_bool(values: Mapping[str, str], key: str, *, default: bool) -> bool:
    value = _optional(values, key)
    if value is None:
        return default
    normalized = value.casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError()


def _parse_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as error:
        raise ConfigurationError() from error
    if not 1 <= timeout <= 120:
        raise ConfigurationError()
    return timeout
