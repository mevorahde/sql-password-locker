"""Application boundary for a future cryptographically unlocked vault session."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum

from pw_locker_sql.crypto.protocol import UnlockedVaultSession, VaultCryptographicProvider
from pw_locker_sql.domain import (
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
)
from pw_locker_sql.errors import (
    CredentialNotFoundError,
    PasswordLockerError,
    VaultAlreadyInitializedError,
    VaultLockedError,
    VaultNotInitializedError,
)
from pw_locker_sql.repositories.protocol import CredentialRepository


class VaultState(str, Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"


class CredentialWriteResult(str, Enum):
    CREATED = "created"
    UPDATED = "updated"


class VaultService:
    """Coordinates unlocked cryptography and encrypted persistence."""

    def __init__(
        self,
        repository: CredentialRepository,
        cryptographic_provider: VaultCryptographicProvider,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository = repository
        self._provider = cryptographic_provider
        self._session: UnlockedVaultSession | None = None
        self._state = VaultState.LOCKED
        self._closed = False
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def state(self) -> VaultState:
        return self._state

    def initialize(self, master_password: str) -> None:
        self._ensure_open()
        try:
            self._repository.get_vault_metadata()
        except VaultNotInitializedError:
            pass
        else:
            raise VaultAlreadyInitializedError()
        metadata, session = self._provider.initialize(master_password)
        try:
            self._repository.initialize_vault_metadata(metadata)
        except Exception:
            session.close()
            raise
        self._session = session
        self._state = VaultState.UNLOCKED

    def unlock(self, master_password: str) -> None:
        self._ensure_open()
        if self._state is VaultState.UNLOCKED:
            return
        metadata = self._repository.get_vault_metadata()
        self._session = self._provider.unlock(metadata, master_password)
        self._state = VaultState.UNLOCKED

    def lock(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None
        self._state = VaultState.LOCKED

    def set_credential(self, account: str, plaintext: str) -> CredentialWriteResult:
        session = self._require_session()
        credential_id = CredentialId.from_account(account)
        envelope = session.encrypt_credential(credential_id, plaintext)
        now = self._clock()
        try:
            existing = self._repository.get(credential_id)
        except CredentialNotFoundError:
            metadata = CredentialMetadata(credential_id, now, now)
            self._repository.insert(EncryptedCredentialRecord(metadata, envelope))
            return CredentialWriteResult.CREATED
        else:
            metadata = CredentialMetadata(
                credential_id,
                existing.metadata.created_at,
                now,
                existing.metadata.revision + 1,
            )
            self._repository.update(EncryptedCredentialRecord(metadata, envelope))
            return CredentialWriteResult.UPDATED

    def get_credential(self, account: str) -> str:
        session = self._require_session()
        record = self._repository.get(CredentialId.from_account(account))
        return session.decrypt_credential(record)

    def list_credentials(self) -> tuple[CredentialMetadata, ...]:
        self._require_session()
        return self._repository.list_metadata()

    def delete_credential(self, account: str) -> None:
        self._require_session()
        self._repository.delete(CredentialId.from_account(account))

    def close(self) -> None:
        if self._closed:
            return
        self.lock()
        self._repository.close()
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise PasswordLockerError()

    def _require_session(self) -> UnlockedVaultSession:
        self._ensure_open()
        if self._session is None or self._state is VaultState.LOCKED:
            raise VaultLockedError()
        return self._session
