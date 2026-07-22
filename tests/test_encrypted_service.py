from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from pw_locker_sql.crypto.argon2_aesgcm import (
    MIN_MEMORY_COST,
    Argon2idAesGcmProvider,
    Argon2idParameters,
)
from pw_locker_sql.crypto.protocol import UnlockedVaultSession, VaultCryptographicProvider
from pw_locker_sql.domain import (
    CredentialId,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
    VaultMetadata,
)
from pw_locker_sql.errors import (
    InvalidMasterPasswordError,
    RepositoryError,
    VaultAlreadyInitializedError,
    VaultLockedError,
    VaultNotInitializedError,
)
from pw_locker_sql.gui.controller import VaultController
from pw_locker_sql.repositories.memory import InMemoryCredentialRepository
from pw_locker_sql.services import VaultService, VaultState

MASTER_PASSWORD_ALPHA = "MASTER_PASSWORD_PLACEHOLDER_ALPHA"
MASTER_PASSWORD_BETA = "MASTER_PASSWORD_PLACEHOLDER_BETA"
CREDENTIAL_PASSWORD_ALPHA = "CREDENTIAL_PASSWORD_PLACEHOLDER_ALPHA"
CREDENTIAL_PASSWORD_BETA = "CREDENTIAL_PASSWORD_PLACEHOLDER_BETA"
FIXED_TIME = datetime(2026, 2, 3, 4, 5, tzinfo=timezone.utc)


class IncrementingRandom:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        return bytes(((self.counter + index) % 251) + 1 for index in range(length))


def provider() -> Argon2idAesGcmProvider:
    return Argon2idAesGcmProvider(
        _new_vault_parameters=Argon2idParameters(
            memory_cost=MIN_MEMORY_COST,
            time_cost=1,
            parallelism=1,
        ),
        _random_bytes=IncrementingRandom(),
        _uuid_factory=lambda: UUID("00000000-0000-0000-0000-000000000303"),
    )


class TrackingRepository(InMemoryCredentialRepository):
    def __init__(self) -> None:
        super().__init__()
        self.get_calls: list[CredentialId] = []
        self.list_calls = 0
        self.inserted: list[EncryptedCredentialRecord] = []
        self.updated: list[EncryptedCredentialRecord] = []

    def get(self, credential_id: CredentialId) -> EncryptedCredentialRecord:
        self.get_calls.append(credential_id)
        return super().get(credential_id)

    def list_metadata(self):
        self.list_calls += 1
        return super().list_metadata()

    def insert(self, record: EncryptedCredentialRecord) -> None:
        self.inserted.append(record)
        super().insert(record)

    def update(self, record: EncryptedCredentialRecord) -> None:
        self.updated.append(record)
        super().update(record)


class CountingSession:
    def __init__(self, delegate: UnlockedVaultSession) -> None:
        self.delegate = delegate
        self.decrypt_calls = 0

    def encrypt_credential(
        self,
        credential_id: CredentialId,
        plaintext: str,
    ) -> EncryptedEnvelope:
        return self.delegate.encrypt_credential(credential_id, plaintext)

    def decrypt_credential(self, record: EncryptedCredentialRecord) -> str:
        self.decrypt_calls += 1
        return self.delegate.decrypt_credential(record)

    def close(self) -> None:
        self.delegate.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()


class CountingProvider:
    def __init__(self, delegate: VaultCryptographicProvider) -> None:
        self.delegate = delegate
        self.last_session: CountingSession | None = None

    def _wrap(self, session: UnlockedVaultSession) -> CountingSession:
        wrapped = CountingSession(session)
        self.last_session = wrapped
        return wrapped

    def initialize(self, master_password: str):
        metadata, session = self.delegate.initialize(master_password)
        return metadata, self._wrap(session)

    def unlock(self, metadata: VaultMetadata, master_password: str):
        return self._wrap(self.delegate.unlock(metadata, master_password))


class FailingInitializationRepository(InMemoryCredentialRepository):
    def initialize_vault_metadata(self, metadata: VaultMetadata) -> None:
        raise RepositoryError()


def test_service_initializes_empty_vault_and_rejects_second_initialization() -> None:
    repository = InMemoryCredentialRepository()
    service = VaultService(repository, provider(), clock=lambda: FIXED_TIME)
    service.initialize(MASTER_PASSWORD_ALPHA)
    assert service.state is VaultState.UNLOCKED
    assert repository.list_metadata() == ()
    service.lock()
    with pytest.raises(VaultAlreadyInitializedError):
        service.initialize(MASTER_PASSWORD_ALPHA)


def test_uninitialized_and_incorrect_master_unlock_fail_safely() -> None:
    repository = InMemoryCredentialRepository()
    service = VaultService(repository, provider(), clock=lambda: FIXED_TIME)
    with pytest.raises(VaultNotInitializedError):
        service.unlock(MASTER_PASSWORD_ALPHA)
    service.initialize(MASTER_PASSWORD_ALPHA)
    service.lock()
    with pytest.raises(InvalidMasterPasswordError):
        service.unlock(MASTER_PASSWORD_BETA)
    assert service.state is VaultState.LOCKED


def test_set_inserts_then_updates_encrypted_record_with_fresh_nonce() -> None:
    repository = TrackingRepository()
    service = VaultService(repository, provider(), clock=lambda: FIXED_TIME)
    service.initialize(MASTER_PASSWORD_ALPHA)
    service.set_credential("  ACCOUNT_PLACEHOLDER_ALPHA  ", CREDENTIAL_PASSWORD_ALPHA)
    inserted = repository.inserted[-1]
    service.set_credential("account_placeholder_alpha", CREDENTIAL_PASSWORD_BETA)
    updated = repository.updated[-1]
    assert inserted.metadata.credential_id == CredentialId("ACCOUNT_PLACEHOLDER_ALPHA")
    assert updated.metadata.revision == 2
    assert inserted.envelope.nonce != updated.envelope.nonce
    assert service.get_credential("ACCOUNT_PLACEHOLDER_ALPHA") == CREDENTIAL_PASSWORD_BETA


def test_repository_receives_only_encrypted_records_and_no_plaintext() -> None:
    repository = TrackingRepository()
    service = VaultService(repository, provider(), clock=lambda: FIXED_TIME)
    service.initialize(MASTER_PASSWORD_ALPHA)
    service.set_credential("ACCOUNT_PLACEHOLDER_ALPHA", CREDENTIAL_PASSWORD_ALPHA)
    record = repository.inserted[-1]
    assert isinstance(record, EncryptedCredentialRecord)
    plaintext_is_absent = CREDENTIAL_PASSWORD_ALPHA.encode() not in record.envelope.ciphertext
    assert plaintext_is_absent
    assert CREDENTIAL_PASSWORD_ALPHA not in repr(record)


def test_get_retrieves_and_decrypts_only_requested_record() -> None:
    repository = TrackingRepository()
    counting_provider = CountingProvider(provider())
    service = VaultService(repository, counting_provider, clock=lambda: FIXED_TIME)
    service.initialize(MASTER_PASSWORD_ALPHA)
    service.set_credential("ACCOUNT_PLACEHOLDER_ALPHA", CREDENTIAL_PASSWORD_ALPHA)
    service.set_credential("ACCOUNT_PLACEHOLDER_BETA", CREDENTIAL_PASSWORD_BETA)
    repository.get_calls.clear()
    repository.list_calls = 0
    assert service.get_credential("ACCOUNT_PLACEHOLDER_BETA") == CREDENTIAL_PASSWORD_BETA
    assert repository.get_calls == [CredentialId("ACCOUNT_PLACEHOLDER_BETA")]
    assert repository.list_calls == 0
    assert counting_provider.last_session is not None
    assert counting_provider.last_session.decrypt_calls == 1


def test_list_returns_metadata_only_and_delete_requires_unlock() -> None:
    repository = InMemoryCredentialRepository()
    service = VaultService(repository, provider(), clock=lambda: FIXED_TIME)
    service.initialize(MASTER_PASSWORD_ALPHA)
    service.set_credential("ACCOUNT_PLACEHOLDER_ALPHA", CREDENTIAL_PASSWORD_ALPHA)
    listed = service.list_credentials()
    assert len(listed) == 1
    assert not hasattr(listed[0], "envelope")
    service.lock()
    with pytest.raises(VaultLockedError):
        service.delete_credential("ACCOUNT_PLACEHOLDER_ALPHA")
    service.unlock(MASTER_PASSWORD_ALPHA)
    service.delete_credential("ACCOUNT_PLACEHOLDER_ALPHA")
    assert service.list_credentials() == ()


def test_lock_then_reunlock_restores_access_and_close_is_idempotent() -> None:
    repository = InMemoryCredentialRepository()
    service = VaultService(repository, provider(), clock=lambda: FIXED_TIME)
    service.initialize(MASTER_PASSWORD_ALPHA)
    service.set_credential("ACCOUNT_PLACEHOLDER_ALPHA", CREDENTIAL_PASSWORD_ALPHA)
    service.lock()
    with pytest.raises(VaultLockedError):
        service.get_credential("ACCOUNT_PLACEHOLDER_ALPHA")
    service.unlock(MASTER_PASSWORD_ALPHA)
    assert service.get_credential("ACCOUNT_PLACEHOLDER_ALPHA") == CREDENTIAL_PASSWORD_ALPHA
    service.close()
    service.close()
    assert service.state is VaultState.LOCKED


def test_failed_repository_initialization_closes_generated_session() -> None:
    counting_provider = CountingProvider(provider())
    service = VaultService(
        FailingInitializationRepository(),
        counting_provider,
        clock=lambda: FIXED_TIME,
    )
    with pytest.raises(RepositoryError):
        service.initialize(MASTER_PASSWORD_ALPHA)
    assert counting_provider.last_session is not None
    with pytest.raises(VaultLockedError):
        counting_provider.last_session.encrypt_credential(
            CredentialId("ACCOUNT_PLACEHOLDER_ALPHA"),
            CREDENTIAL_PASSWORD_ALPHA,
        )
    assert service.state is VaultState.LOCKED


def test_controller_uses_functional_service_without_exposing_secrets_in_status() -> None:
    controller = VaultController(
        VaultService(InMemoryCredentialRepository(), provider(), clock=lambda: FIXED_TIME)
    )
    initialized = controller.initialize(MASTER_PASSWORD_ALPHA)
    saved = controller.set_credential(
        "ACCOUNT_PLACEHOLDER_ALPHA",
        CREDENTIAL_PASSWORD_ALPHA,
    )
    retrieved = controller.get_credential("ACCOUNT_PLACEHOLDER_ALPHA")
    for result in (initialized, saved, retrieved):
        assert MASTER_PASSWORD_ALPHA not in result.message
        assert CREDENTIAL_PASSWORD_ALPHA not in result.message
    assert retrieved.value == CREDENTIAL_PASSWORD_ALPHA
    assert CREDENTIAL_PASSWORD_ALPHA not in repr(retrieved)
    assert controller.lock().ok is True
    locked = controller.get_credential("ACCOUNT_PLACEHOLDER_ALPHA")
    assert locked.ok is False
    assert CREDENTIAL_PASSWORD_ALPHA not in locked.message
