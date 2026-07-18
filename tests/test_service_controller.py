from __future__ import annotations

from typing import NoReturn

from pw_locker_sql.domain import CredentialId, EncryptedCredentialRecord
from pw_locker_sql.errors import CryptographicProviderUnavailableError
from pw_locker_sql.gui.controller import ControllerResult, VaultController
from pw_locker_sql.repositories.memory import InMemoryCredentialRepository
from pw_locker_sql.services import UnlockedVaultSession, VaultService, VaultState


class StateOnlySession:
    def __init__(self) -> None:
        self.closed = False

    def encrypt_credential(self, credential_id: CredentialId, plaintext: str) -> NoReturn:
        raise CryptographicProviderUnavailableError()

    def decrypt_credential(self, record: EncryptedCredentialRecord) -> NoReturn:
        raise CryptographicProviderUnavailableError()

    def close(self) -> None:
        self.closed = True


class StateOnlyProvider:
    def __init__(self, vault_metadata) -> None:
        self.vault_metadata = vault_metadata
        self.sessions: list[StateOnlySession] = []

    def _session(self) -> StateOnlySession:
        session = StateOnlySession()
        self.sessions.append(session)
        return session

    def initialize(self) -> tuple[object, UnlockedVaultSession]:
        return self.vault_metadata, self._session()  # type: ignore[return-value]

    def unlock(self, metadata: object) -> UnlockedVaultSession:
        return self._session()


def test_controller_starts_locked_and_missing_provider_fails_safely() -> None:
    controller = VaultController(VaultService(InMemoryCredentialRepository()))
    assert controller.state is VaultState.LOCKED
    result = controller.unlock()
    assert result.ok is False
    assert result.message == "Operation unavailable until a cryptographic provider is configured."


def test_initialize_unlock_lock_transitions(vault_metadata) -> None:
    provider = StateOnlyProvider(vault_metadata)
    controller = VaultController(
        VaultService(InMemoryCredentialRepository(), provider)  # type: ignore[arg-type]
    )
    assert controller.initialize().ok is True
    assert controller.state is VaultState.UNLOCKED
    assert controller.lock().ok is True
    assert controller.state is VaultState.LOCKED
    assert provider.sessions[0].closed is True
    assert controller.unlock().ok is True
    assert controller.state is VaultState.UNLOCKED


def test_operations_requiring_crypto_fail_without_placeholder_security(vault_metadata) -> None:
    provider = StateOnlyProvider(vault_metadata)
    controller = VaultController(
        VaultService(InMemoryCredentialRepository(), provider)  # type: ignore[arg-type]
    )
    assert controller.initialize().ok is True
    result = controller.set_credential("ACCOUNT_PLACEHOLDER", "PLAINTEXT_PLACEHOLDER")
    assert result.ok is False
    assert "cryptographic provider" in result.message
    assert "PLAINTEXT_PLACEHOLDER" not in result.message


def test_locked_operation_and_missing_record_have_safe_messages(vault_metadata) -> None:
    provider = StateOnlyProvider(vault_metadata)
    controller = VaultController(
        VaultService(InMemoryCredentialRepository(), provider)  # type: ignore[arg-type]
    )
    locked = controller.get_credential("ACCOUNT_PLACEHOLDER")
    assert locked.message == "Unlock the vault before continuing."
    assert controller.initialize().ok is True
    missing = controller.get_credential("ACCOUNT_PLACEHOLDER")
    assert missing.message == "Credential not found."


def test_repeated_lock_and_close_are_safe(vault_metadata) -> None:
    provider = StateOnlyProvider(vault_metadata)
    controller = VaultController(
        VaultService(InMemoryCredentialRepository(), provider)  # type: ignore[arg-type]
    )
    assert controller.lock().ok is True
    assert controller.lock().ok is True
    assert controller.close().ok is True
    assert controller.close().ok is True
    assert controller.lock().ok is True


def test_controller_result_repr_does_not_expose_value() -> None:
    result = ControllerResult(True, "Safe status.", "PLAINTEXT_PLACEHOLDER")
    assert "PLAINTEXT_PLACEHOLDER" not in repr(result)
