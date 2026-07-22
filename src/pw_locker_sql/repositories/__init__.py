"""Encrypted repository exports loaded only when explicitly requested."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pw_locker_sql.repositories.memory import InMemoryCredentialRepository
    from pw_locker_sql.repositories.protocol import CredentialRepository
    from pw_locker_sql.repositories.sql_server import (
        SqlServerConnectionFactory,
        SqlServerCredentialRepository,
    )

__all__ = [
    "CredentialRepository",
    "InMemoryCredentialRepository",
    "SqlServerConnectionFactory",
    "SqlServerCredentialRepository",
]


def __getattr__(name: str) -> object:
    if name == "CredentialRepository":
        return getattr(import_module("pw_locker_sql.repositories.protocol"), name)
    if name == "InMemoryCredentialRepository":
        return getattr(import_module("pw_locker_sql.repositories.memory"), name)
    if name in {"SqlServerConnectionFactory", "SqlServerCredentialRepository"}:
        return getattr(import_module("pw_locker_sql.repositories.sql_server"), name)
    raise AttributeError(name)
