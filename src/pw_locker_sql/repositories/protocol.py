"""Persistence protocol restricted to encrypted domain records."""

from __future__ import annotations

from typing import Protocol

from pw_locker_sql.domain import (
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
    VaultMetadata,
)


class CredentialRepository(Protocol):
    def get_vault_metadata(self) -> VaultMetadata: ...

    def initialize_vault_metadata(self, metadata: VaultMetadata) -> None: ...

    def get(self, credential_id: CredentialId) -> EncryptedCredentialRecord: ...

    def list_metadata(self) -> tuple[CredentialMetadata, ...]: ...

    def insert(self, record: EncryptedCredentialRecord) -> None: ...

    def update(self, record: EncryptedCredentialRecord) -> None: ...

    def delete(self, credential_id: CredentialId) -> None: ...

    def close(self) -> None: ...

    def __enter__(self) -> CredentialRepository: ...

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None: ...
