"""Secret-safe immutable domain models for encrypted vault persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Final
from unicodedata import normalize
from uuid import UUID

from pw_locker_sql.errors import UnsupportedFormatError, ValidationError

CURRENT_ENVELOPE_VERSION: Final = 1
CURRENT_VAULT_VERSION: Final = 1
SUPPORTED_ENVELOPE_ALGORITHMS: Final = frozenset({"AES-256-GCM"})


def _immutable_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValidationError()
    copied = bytes(value)
    if not copied:
        raise ValidationError()
    return copied


def _validate_aware_datetime(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError()


@dataclass(frozen=True, slots=True, order=True)
class CredentialId:
    """A deterministic Unicode-normalized account identifier."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise ValidationError()
        normalized = normalize("NFKC", self.value.strip()).casefold()
        if not normalized:
            raise ValidationError()
        object.__setattr__(self, "value", normalized)

    @classmethod
    def from_account(cls, account: str) -> CredentialId:
        return cls(account)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    """List-safe metadata which contains no encrypted or plaintext value."""

    credential_id: CredentialId
    created_at: datetime
    updated_at: datetime
    revision: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.credential_id, CredentialId):
            raise ValidationError()
        _validate_aware_datetime(self.created_at)
        _validate_aware_datetime(self.updated_at)
        if self.updated_at < self.created_at or self.revision < 1:
            raise ValidationError()


@dataclass(frozen=True, slots=True)
class EncryptedEnvelope:
    """Versioned authenticated ciphertext; encryption is implemented later."""

    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    authentication_tag: bytes = field(repr=False)
    associated_data: bytes = field(repr=False)
    algorithm: str = "AES-256-GCM"
    format_version: int = CURRENT_ENVELOPE_VERSION

    def __post_init__(self) -> None:
        if self.format_version != CURRENT_ENVELOPE_VERSION:
            raise UnsupportedFormatError()
        if self.algorithm not in SUPPORTED_ENVELOPE_ALGORITHMS:
            raise UnsupportedFormatError()
        for name in ("ciphertext", "nonce", "authentication_tag", "associated_data"):
            object.__setattr__(self, name, _immutable_bytes(getattr(self, name)))


@dataclass(frozen=True, slots=True)
class EncryptedCredentialRecord:
    """The only credential representation accepted by repositories."""

    metadata: CredentialMetadata
    envelope: EncryptedEnvelope = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, CredentialMetadata):
            raise ValidationError()
        if not isinstance(self.envelope, EncryptedEnvelope):
            raise ValidationError()


@dataclass(frozen=True, slots=True)
class VaultMetadata:
    """Non-secret vault format and wrapped-key metadata."""

    vault_id: UUID
    created_at: datetime
    key_derivation_algorithm: str
    key_derivation_salt: bytes = field(repr=False)
    wrapped_data_encryption_key: EncryptedEnvelope = field(repr=False)
    format_version: int = CURRENT_VAULT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != CURRENT_VAULT_VERSION:
            raise UnsupportedFormatError()
        if not isinstance(self.vault_id, UUID):
            raise ValidationError()
        _validate_aware_datetime(self.created_at)
        if not self.key_derivation_algorithm.strip():
            raise ValidationError()
        object.__setattr__(self, "key_derivation_salt", _immutable_bytes(self.key_derivation_salt))
        if not isinstance(self.wrapped_data_encryption_key, EncryptedEnvelope):
            raise ValidationError()
