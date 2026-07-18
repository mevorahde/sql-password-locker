"""GUI-independent controller with secret-safe status messages."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from pw_locker_sql.domain import CredentialMetadata
from pw_locker_sql.errors import (
    AuthenticationError,
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    CryptographicOperationError,
    CryptographicProviderUnavailableError,
    InvalidMasterPasswordError,
    PasswordLockerError,
    RepositoryError,
    UnsupportedFormatError,
    ValidationError,
    VaultLockedError,
)
from pw_locker_sql.services import VaultService, VaultState

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ControllerResult(Generic[T]):
    ok: bool
    message: str
    value: T | None = field(default=None, repr=False)


class VaultController:
    """Maps domain outcomes to safe view-ready results without importing Tkinter."""

    def __init__(self, service: VaultService) -> None:
        self._service = service
        self._closed = False

    @property
    def state(self) -> VaultState:
        return self._service.state

    def initialize(self, master_password: str) -> ControllerResult[None]:
        return self._run(
            lambda: self._service.initialize(master_password),
            "Vault initialized.",
        )

    def unlock(self, master_password: str) -> ControllerResult[None]:
        return self._run(lambda: self._service.unlock(master_password), "Vault unlocked.")

    def lock(self) -> ControllerResult[None]:
        if self._closed:
            return ControllerResult(True, "Vault is closed.")
        return self._run(self._service.lock, "Vault locked.")

    def set_credential(self, account: str, plaintext: str) -> ControllerResult[None]:
        return self._run(
            lambda: self._service.set_credential(account, plaintext),
            "Credential saved.",
        )

    def get_credential(self, account: str) -> ControllerResult[str]:
        return self._run_value(
            lambda: self._service.get_credential(account),
            "Credential retrieved.",
        )

    def list_credentials(self) -> ControllerResult[tuple[CredentialMetadata, ...]]:
        return self._run_value(self._service.list_credentials, "Credentials listed.")

    def delete_credential(self, account: str) -> ControllerResult[None]:
        return self._run(lambda: self._service.delete_credential(account), "Credential deleted.")

    def close(self) -> ControllerResult[None]:
        if self._closed:
            return ControllerResult(True, "Vault is closed.")
        result = self._run(self._service.close, "Vault closed.")
        if result.ok:
            self._closed = True
        return result

    def _run(self, action: Callable[[], object], success: str) -> ControllerResult[None]:
        try:
            action()
        except Exception as error:
            return ControllerResult(False, _safe_message(error))
        return ControllerResult(True, success)

    def _run_value(self, action: Callable[[], T], success: str) -> ControllerResult[T]:
        try:
            value = action()
        except Exception as error:
            return ControllerResult(False, _safe_message(error))
        return ControllerResult(True, success, value)


def _safe_message(error: Exception) -> str:
    if isinstance(error, CryptographicProviderUnavailableError):
        return "Operation unavailable until a cryptographic provider is configured."
    if isinstance(error, (InvalidMasterPasswordError, AuthenticationError)):
        return "Encrypted data authentication failed."
    if isinstance(error, CryptographicOperationError):
        return "The secure operation could not be completed."
    if isinstance(error, UnsupportedFormatError):
        return "The encrypted data format is not supported."
    if isinstance(error, VaultLockedError):
        return "Unlock the vault before continuing."
    if isinstance(error, CredentialNotFoundError):
        return "Credential not found."
    if isinstance(error, CredentialAlreadyExistsError):
        return "Credential already exists."
    if isinstance(error, ValidationError):
        return "Check the supplied input."
    if isinstance(error, RepositoryError):
        return "Encrypted storage is unavailable."
    if isinstance(error, PasswordLockerError):
        return "The requested operation could not be completed."
    return "An unexpected error occurred."
