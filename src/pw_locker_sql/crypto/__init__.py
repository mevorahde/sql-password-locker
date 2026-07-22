"""Authenticated cryptography exports loaded only when explicitly requested."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pw_locker_sql.crypto.argon2_aesgcm import (
        Argon2idAesGcmProvider,
        Argon2idParameters,
    )
    from pw_locker_sql.crypto.protocol import (
        UnlockedVaultSession,
        VaultCryptographicProvider,
    )

__all__ = [
    "Argon2idAesGcmProvider",
    "Argon2idParameters",
    "UnlockedVaultSession",
    "VaultCryptographicProvider",
]


def __getattr__(name: str) -> object:
    if name in {"Argon2idAesGcmProvider", "Argon2idParameters"}:
        return getattr(import_module("pw_locker_sql.crypto.argon2_aesgcm"), name)
    if name in {"UnlockedVaultSession", "VaultCryptographicProvider"}:
        return getattr(import_module("pw_locker_sql.crypto.protocol"), name)
    raise AttributeError(name)
