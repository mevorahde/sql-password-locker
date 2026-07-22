"""Non-persistent encrypted repository used only as a test double."""

from __future__ import annotations

from pw_locker_sql.domain import (
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
    VaultMetadata,
)
from pw_locker_sql.errors import (
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    RepositoryError,
    ValidationError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
)


class InMemoryCredentialRepository:
    """A deterministic in-memory test double that never stores plaintext."""

    def __init__(self) -> None:
        self._records: dict[CredentialId, EncryptedCredentialRecord] = {}
        self._vault_metadata: VaultMetadata | None = None
        self._closed = False

    def _ensure_open(self) -> None:
        if self._closed:
            raise RepositoryError()

    def get_vault_metadata(self) -> VaultMetadata:
        self._ensure_open()
        if self._vault_metadata is None:
            raise VaultNotInitializedError()
        return self._vault_metadata

    def initialize_vault_metadata(self, metadata: VaultMetadata) -> None:
        self._ensure_open()
        if not isinstance(metadata, VaultMetadata):
            raise RepositoryError()
        if self._vault_metadata is not None:
            raise VaultAlreadyInitializedError()
        self._vault_metadata = metadata

    def get(self, credential_id: CredentialId) -> EncryptedCredentialRecord:
        self._ensure_open()
        if not isinstance(credential_id, CredentialId):
            raise ValidationError()
        try:
            return self._records[credential_id]
        except KeyError as error:
            raise CredentialNotFoundError() from error

    def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        self._ensure_open()
        return tuple(self._records[key].metadata for key in sorted(self._records))

    def insert(self, record: EncryptedCredentialRecord) -> None:
        self._ensure_open()
        self._validate_record(record)
        credential_id = record.metadata.credential_id
        if credential_id in self._records:
            raise CredentialAlreadyExistsError()
        self._records[credential_id] = record

    def update(self, record: EncryptedCredentialRecord) -> None:
        self._ensure_open()
        self._validate_record(record)
        credential_id = record.metadata.credential_id
        if credential_id not in self._records:
            raise CredentialNotFoundError()
        self._records[credential_id] = record

    def delete(self, credential_id: CredentialId) -> None:
        self._ensure_open()
        if not isinstance(credential_id, CredentialId):
            raise ValidationError()
        try:
            del self._records[credential_id]
        except KeyError as error:
            raise CredentialNotFoundError() from error

    def close(self) -> None:
        if self._closed:
            return
        self._records.clear()
        self._vault_metadata = None
        self._closed = True

    def __enter__(self) -> InMemoryCredentialRepository:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _validate_record(record: EncryptedCredentialRecord) -> None:
        if not isinstance(record, EncryptedCredentialRecord):
            raise ValidationError()
