"""Narrow cryptographic contracts consumed by the application service."""

from __future__ import annotations

from typing import Protocol

from pw_locker_sql.domain import (
    CredentialId,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
    VaultMetadata,
)


class UnlockedVaultSession(Protocol):
    """An in-memory vault session which owns an unwrapped data-encryption key."""

    def encrypt_credential(
        self,
        credential_id: CredentialId,
        plaintext: str,
    ) -> EncryptedEnvelope: ...

    def decrypt_credential(self, record: EncryptedCredentialRecord) -> str: ...

    def close(self) -> None: ...

    def __enter__(self) -> UnlockedVaultSession: ...

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None: ...


class VaultCryptographicProvider(Protocol):
    """Creates or unlocks sessions without exposing cryptographic implementation details."""

    def initialize(self, master_password: str) -> tuple[VaultMetadata, UnlockedVaultSession]: ...

    def unlock(
        self,
        metadata: VaultMetadata,
        master_password: str,
    ) -> UnlockedVaultSession: ...
