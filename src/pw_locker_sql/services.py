"""Application boundary for a future cryptographically unlocked vault session."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from pw_locker_sql.domain import (
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
    VaultMetadata,
)
from pw_locker_sql.errors import (
    CredentialNotFoundError,
    CryptographicProviderUnavailableError,
    PasswordLockerError,
    VaultLockedError,
)
from pw_locker_sql.repositories.protocol import CredentialRepository


class VaultState(str, Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"


class UnlockedVaultSession(Protocol):
    """Future in-memory cryptographic session; never implemented by persistence."""

    def encrypt_credential(
        self,
        credential_id: CredentialId,
        plaintext: str,
    ) -> EncryptedEnvelope: ...

    def decrypt_credential(self, record: EncryptedCredentialRecord) -> str: ...

    def close(self) -> None: ...


class VaultCryptographicProvider(Protocol):
    """Future provider configured with an out-of-band master-secret source."""

    def initialize(self) -> tuple[VaultMetadata, UnlockedVaultSession]: ...

    def unlock(self, metadata: VaultMetadata) -> UnlockedVaultSession: ...


class VaultService:
    """Coordinates state and encrypted persistence without implementing cryptography."""

    def __init__(
        self,
        repository: CredentialRepository,
        cryptographic_provider: VaultCryptographicProvider | None = None,
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

    def initialize(self) -> None:
        self._ensure_open()
        provider = self._require_provider()
        metadata, session = provider.initialize()
        try:
            self._repository.initialize_vault_metadata(metadata)
        except Exception:
            session.close()
            raise
        self._session = session
        self._state = VaultState.UNLOCKED

    def unlock(self) -> None:
        self._ensure_open()
        if self._state is VaultState.UNLOCKED:
            return
        provider = self._require_provider()
        metadata = self._repository.get_vault_metadata()
        self._session = provider.unlock(metadata)
        self._state = VaultState.UNLOCKED

    def lock(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None
        self._state = VaultState.LOCKED

    def set_credential(self, account: str, plaintext: str) -> None:
        session = self._require_session()
        credential_id = CredentialId.from_account(account)
        envelope = session.encrypt_credential(credential_id, plaintext)
        now = self._clock()
        try:
            existing = self._repository.get(credential_id)
        except CredentialNotFoundError:
            metadata = CredentialMetadata(credential_id, now, now)
            self._repository.insert(EncryptedCredentialRecord(metadata, envelope))
        else:
            metadata = CredentialMetadata(
                credential_id,
                existing.metadata.created_at,
                now,
                existing.metadata.revision + 1,
            )
            self._repository.update(EncryptedCredentialRecord(metadata, envelope))

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

    def _require_provider(self) -> VaultCryptographicProvider:
        if self._provider is None:
            raise CryptographicProviderUnavailableError()
        return self._provider

    def _require_session(self) -> UnlockedVaultSession:
        self._ensure_open()
        if self._session is None or self._state is VaultState.LOCKED:
            raise VaultLockedError()
        return self._session
