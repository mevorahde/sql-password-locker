"""Argon2id and AES-256-GCM production cryptographic provider.

Mutable key buffers are overwritten on a best-effort basis when control leaves this
module. Python and third-party libraries may retain copies outside that control, so
this module does not claim guaranteed memory zeroization.
"""

from __future__ import annotations

import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final
from uuid import UUID, uuid4

from pw_locker_sql.crypto.protocol import UnlockedVaultSession
from pw_locker_sql.domain import (
    CURRENT_ENVELOPE_VERSION,
    CURRENT_VAULT_VERSION,
    CredentialId,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
    VaultMetadata,
)
from pw_locker_sql.errors import (
    AuthenticationError,
    CryptographicOperationError,
    InvalidMasterPasswordError,
    UnsupportedFormatError,
    ValidationError,
    VaultLockedError,
)

APPLICATION_FORMAT: Final = "pw-locker-sql"
KDF_ALGORITHM: Final = "argon2id"
ENCRYPTION_ALGORITHM: Final = "AES-256-GCM"
ARGON2ID_VERSION: Final = 19
SALT_LENGTH: Final = 16
KEY_LENGTH: Final = 32
NONCE_LENGTH: Final = 12
TAG_LENGTH: Final = 16

MIN_MEMORY_COST: Final = 8_192
MAX_MEMORY_COST: Final = 262_144
MIN_TIME_COST: Final = 1
MAX_TIME_COST: Final = 10
MIN_PARALLELISM: Final = 1
MAX_PARALLELISM: Final = 16

PRODUCTION_MEMORY_COST: Final = 65_536
PRODUCTION_TIME_COST: Final = 3
PRODUCTION_PARALLELISM: Final = 4


@dataclass(frozen=True, slots=True)
class Argon2idParameters:
    """Explicit persisted Argon2id parameters without secret material."""

    memory_cost: int
    time_cost: int
    parallelism: int
    version: int = ARGON2ID_VERSION
    salt_length: int = SALT_LENGTH
    output_length: int = KEY_LENGTH

    @classmethod
    def production(cls) -> Argon2idParameters:
        return cls(
            memory_cost=PRODUCTION_MEMORY_COST,
            time_cost=PRODUCTION_TIME_COST,
            parallelism=PRODUCTION_PARALLELISM,
        )


class Argon2idAesGcmProvider:
    """Production provider; private injection points exist only for tests."""

    def __init__(
        self,
        *,
        _new_vault_parameters: Argon2idParameters | None = None,
        _random_bytes: Callable[[int], bytes] | None = None,
        _uuid_factory: Callable[[], UUID] | None = None,
    ) -> None:
        self._new_vault_parameters = _new_vault_parameters or Argon2idParameters.production()
        self._random_bytes = _random_bytes or secrets.token_bytes
        self._uuid_factory = _uuid_factory or uuid4

    def initialize(self, master_password: str) -> tuple[VaultMetadata, UnlockedVaultSession]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        _validate_master_password(master_password)
        parameters = self._new_vault_parameters
        _validate_parameters(parameters)
        salt = self._secure_random(SALT_LENGTH)
        data_key = bytearray(self._secure_random(KEY_LENGTH))
        wrapping_key = bytearray()
        try:
            vault_id = self._uuid_factory()
            if not isinstance(vault_id, UUID):
                raise CryptographicOperationError()
            wrapping_key = _derive_key(master_password, salt, parameters)
            associated_data = _vault_key_associated_data(vault_id)
            wrapping_nonce = self._secure_random(NONCE_LENGTH)
            combined = AESGCM(bytes(wrapping_key)).encrypt(
                wrapping_nonce,
                bytes(data_key),
                associated_data,
            )
            envelope = EncryptedEnvelope(
                ciphertext=combined[:-TAG_LENGTH],
                nonce=wrapping_nonce,
                authentication_tag=combined[-TAG_LENGTH:],
                associated_data=associated_data,
            )
            metadata = VaultMetadata(
                vault_id=vault_id,
                key_derivation_algorithm=KDF_ALGORITHM,
                key_derivation_version=parameters.version,
                key_derivation_memory_cost=parameters.memory_cost,
                key_derivation_time_cost=parameters.time_cost,
                key_derivation_parallelism=parameters.parallelism,
                derived_key_length=parameters.output_length,
                key_derivation_salt=salt,
                wrapped_data_encryption_key=envelope,
            )
            session = AesGcmUnlockedSession(vault_id, data_key, self._random_bytes)
            return metadata, session
        except (ValidationError, UnsupportedFormatError, CryptographicOperationError):
            raise
        except Exception as error:
            raise CryptographicOperationError() from error
        finally:
            _overwrite(data_key)
            _overwrite(wrapping_key)

    def unlock(
        self,
        metadata: VaultMetadata,
        master_password: str,
    ) -> UnlockedVaultSession:
        from argon2.exceptions import HashingError
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        _validate_master_password(master_password)
        parameters = _parameters_from_metadata(metadata)
        envelope = metadata.wrapped_data_encryption_key
        expected_associated_data = _vault_key_associated_data(metadata.vault_id)
        _validate_wrapped_key_envelope(envelope, expected_associated_data)
        wrapping_key = bytearray()
        data_key = bytearray()
        try:
            wrapping_key = _derive_key(
                master_password,
                metadata.key_derivation_salt,
                parameters,
            )
            combined = envelope.ciphertext + envelope.authentication_tag
            plaintext = AESGCM(bytes(wrapping_key)).decrypt(
                envelope.nonce,
                combined,
                expected_associated_data,
            )
            data_key = bytearray(plaintext)
            if len(data_key) != KEY_LENGTH:
                raise InvalidMasterPasswordError()
            return AesGcmUnlockedSession(metadata.vault_id, data_key, self._random_bytes)
        except InvalidTag as error:
            raise InvalidMasterPasswordError() from error
        except InvalidMasterPasswordError:
            raise
        except (HashingError, ValueError) as error:
            raise CryptographicOperationError() from error
        finally:
            _overwrite(wrapping_key)
            _overwrite(data_key)

    def _secure_random(self, length: int) -> bytes:
        try:
            value = self._random_bytes(length)
        except Exception as error:
            raise CryptographicOperationError() from error
        if not isinstance(value, bytes) or len(value) != length:
            raise CryptographicOperationError()
        return value

    def __repr__(self) -> str:
        return "Argon2idAesGcmProvider()"

    __str__ = __repr__


class AesGcmUnlockedSession:
    """Owns a mutable data-key buffer for one unlocked vault."""

    def __init__(
        self,
        vault_id: UUID,
        data_encryption_key: bytes | bytearray,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if not isinstance(vault_id, UUID):
            raise ValidationError()
        if not isinstance(data_encryption_key, (bytes, bytearray)):
            raise ValidationError()
        if len(data_encryption_key) != KEY_LENGTH:
            raise ValidationError()
        self._vault_id = vault_id
        self._key_buffer = bytearray(data_encryption_key)
        self._random_bytes = random_bytes
        self._closed = False

    def encrypt_credential(
        self,
        credential_id: CredentialId,
        plaintext: str,
    ) -> EncryptedEnvelope:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._ensure_open()
        if not isinstance(credential_id, CredentialId):
            raise ValidationError()
        if not isinstance(plaintext, str) or not plaintext:
            raise ValidationError()
        nonce = self._new_nonce()
        associated_data = _credential_associated_data(self._vault_id, credential_id)
        try:
            combined = AESGCM(bytes(self._key_buffer)).encrypt(
                nonce,
                plaintext.encode("utf-8"),
                associated_data,
            )
        except Exception as error:
            raise CryptographicOperationError() from error
        return EncryptedEnvelope(
            ciphertext=combined[:-TAG_LENGTH],
            nonce=nonce,
            authentication_tag=combined[-TAG_LENGTH:],
            associated_data=associated_data,
        )

    def decrypt_credential(self, record: EncryptedCredentialRecord) -> str:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._ensure_open()
        if not isinstance(record, EncryptedCredentialRecord):
            raise ValidationError()
        envelope = record.envelope
        expected_associated_data = _credential_associated_data(
            self._vault_id,
            record.metadata.credential_id,
        )
        _validate_credential_envelope(envelope, expected_associated_data)
        try:
            plaintext = AESGCM(bytes(self._key_buffer)).decrypt(
                envelope.nonce,
                envelope.ciphertext + envelope.authentication_tag,
                expected_associated_data,
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError, ValueError) as error:
            raise AuthenticationError() from error

    def close(self) -> None:
        if self._closed:
            return
        _overwrite(self._key_buffer)
        self._closed = True

    def __enter__(self) -> AesGcmUnlockedSession:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def _new_nonce(self) -> bytes:
        try:
            nonce = self._random_bytes(NONCE_LENGTH)
        except Exception as error:
            raise CryptographicOperationError() from error
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_LENGTH:
            raise CryptographicOperationError()
        return nonce

    def _ensure_open(self) -> None:
        if self._closed:
            raise VaultLockedError()

    def __repr__(self) -> str:
        state = "closed" if self._closed else "unlocked"
        return f"AesGcmUnlockedSession(state={state!r})"

    __str__ = __repr__


def _derive_key(
    master_password: str,
    salt: bytes,
    parameters: Argon2idParameters,
) -> bytearray:
    from argon2.exceptions import HashingError
    from argon2.low_level import Type, hash_secret_raw

    try:
        derived = hash_secret_raw(
            secret=master_password.encode("utf-8"),
            salt=salt,
            time_cost=parameters.time_cost,
            memory_cost=parameters.memory_cost,
            parallelism=parameters.parallelism,
            hash_len=parameters.output_length,
            type=Type.ID,
            version=parameters.version,
        )
    except (HashingError, ValueError, OverflowError) as error:
        raise CryptographicOperationError() from error
    return bytearray(derived)


def _parameters_from_metadata(metadata: VaultMetadata) -> Argon2idParameters:
    if not isinstance(metadata, VaultMetadata):
        raise UnsupportedFormatError()
    if metadata.format_version != CURRENT_VAULT_VERSION:
        raise UnsupportedFormatError()
    if metadata.key_derivation_algorithm != KDF_ALGORITHM:
        raise UnsupportedFormatError()
    if len(metadata.key_derivation_salt) != SALT_LENGTH:
        raise UnsupportedFormatError()
    parameters = Argon2idParameters(
        memory_cost=metadata.key_derivation_memory_cost,
        time_cost=metadata.key_derivation_time_cost,
        parallelism=metadata.key_derivation_parallelism,
        version=metadata.key_derivation_version,
        salt_length=len(metadata.key_derivation_salt),
        output_length=metadata.derived_key_length,
    )
    _validate_parameters(parameters)
    return parameters


def _validate_parameters(parameters: Argon2idParameters) -> None:
    numeric_values = (
        parameters.version,
        parameters.salt_length,
        parameters.output_length,
        parameters.memory_cost,
        parameters.time_cost,
        parameters.parallelism,
    )
    if any(not isinstance(value, int) or isinstance(value, bool) for value in numeric_values):
        raise UnsupportedFormatError()
    if parameters.version != ARGON2ID_VERSION:
        raise UnsupportedFormatError()
    if parameters.salt_length != SALT_LENGTH or parameters.output_length != KEY_LENGTH:
        raise UnsupportedFormatError()
    if not MIN_MEMORY_COST <= parameters.memory_cost <= MAX_MEMORY_COST:
        raise UnsupportedFormatError()
    if not MIN_TIME_COST <= parameters.time_cost <= MAX_TIME_COST:
        raise UnsupportedFormatError()
    if not MIN_PARALLELISM <= parameters.parallelism <= MAX_PARALLELISM:
        raise UnsupportedFormatError()


def _validate_master_password(master_password: str) -> None:
    if not isinstance(master_password, str) or not master_password:
        raise ValidationError()


def _validate_wrapped_key_envelope(
    envelope: EncryptedEnvelope,
    expected_associated_data: bytes,
) -> None:
    _validate_envelope_structure(envelope)
    if len(envelope.ciphertext) != KEY_LENGTH:
        raise UnsupportedFormatError()
    if not hmac.compare_digest(envelope.associated_data, expected_associated_data):
        raise InvalidMasterPasswordError()


def _validate_credential_envelope(
    envelope: EncryptedEnvelope,
    expected_associated_data: bytes,
) -> None:
    try:
        _validate_envelope_structure(envelope)
    except UnsupportedFormatError as error:
        raise AuthenticationError() from error
    if not hmac.compare_digest(envelope.associated_data, expected_associated_data):
        raise AuthenticationError()


def _validate_envelope_structure(envelope: EncryptedEnvelope) -> None:
    if not isinstance(envelope, EncryptedEnvelope):
        raise UnsupportedFormatError()
    if envelope.format_version != CURRENT_ENVELOPE_VERSION:
        raise UnsupportedFormatError()
    if envelope.algorithm != ENCRYPTION_ALGORITHM:
        raise UnsupportedFormatError()
    if len(envelope.nonce) != NONCE_LENGTH or len(envelope.authentication_tag) != TAG_LENGTH:
        raise UnsupportedFormatError()
    if not envelope.ciphertext:
        raise UnsupportedFormatError()


def _vault_key_associated_data(vault_id: UUID) -> bytes:
    return _canonical_associated_data(
        {
            "algorithm": ENCRYPTION_ALGORITHM,
            "application": APPLICATION_FORMAT,
            "context": "vault-key",
            "envelope_version": CURRENT_ENVELOPE_VERSION,
            "format_version": CURRENT_VAULT_VERSION,
            "vault_id": str(vault_id),
        }
    )


def _credential_associated_data(vault_id: UUID, credential_id: CredentialId) -> bytes:
    return _canonical_associated_data(
        {
            "account": credential_id.value,
            "algorithm": ENCRYPTION_ALGORITHM,
            "application": APPLICATION_FORMAT,
            "context": "credential",
            "envelope_version": CURRENT_ENVELOPE_VERSION,
            "format_version": CURRENT_VAULT_VERSION,
            "vault_id": str(vault_id),
        }
    )


def _canonical_associated_data(values: dict[str, object]) -> bytes:
    return json.dumps(
        values,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _overwrite(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0
