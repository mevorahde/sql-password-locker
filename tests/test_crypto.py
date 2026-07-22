from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timezone
from uuid import UUID

import pytest

from pw_locker_sql.crypto.argon2_aesgcm import (
    MAX_MEMORY_COST,
    MAX_PARALLELISM,
    MAX_TIME_COST,
    MIN_MEMORY_COST,
    NONCE_LENGTH,
    PRODUCTION_MEMORY_COST,
    PRODUCTION_PARALLELISM,
    PRODUCTION_TIME_COST,
    TAG_LENGTH,
    AesGcmUnlockedSession,
    Argon2idAesGcmProvider,
    Argon2idParameters,
)
from pw_locker_sql.domain import (
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
)
from pw_locker_sql.errors import (
    AuthenticationError,
    CryptographicOperationError,
    InvalidMasterPasswordError,
    PasswordLockerError,
    UnsupportedFormatError,
    ValidationError,
    VaultLockedError,
)

MASTER_PASSWORD_ALPHA = "MASTER_PASSWORD_PLACEHOLDER_ALPHA"
MASTER_PASSWORD_BETA = "MASTER_PASSWORD_PLACEHOLDER_BETA"
CREDENTIAL_PASSWORD_ALPHA = "CREDENTIAL_PASSWORD_PLACEHOLDER_ALPHA"
FAST_PARAMETERS = Argon2idParameters(memory_cost=MIN_MEMORY_COST, time_cost=1, parallelism=1)
FIXED_TIME = datetime(2026, 2, 3, 4, 5, tzinfo=timezone.utc)
DEFAULT_VAULT_ID = UUID("00000000-0000-0000-0000-000000000101")


class DeterministicRandom:
    """Private test-only deterministic source with distinct outputs per call."""

    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        return bytes(((self.counter + index) % 251) + 1 for index in range(length))


def fast_provider(
    *,
    vault_id: UUID = DEFAULT_VAULT_ID,
) -> Argon2idAesGcmProvider:
    return Argon2idAesGcmProvider(
        _new_vault_parameters=FAST_PARAMETERS,
        _random_bytes=DeterministicRandom(),
        _uuid_factory=lambda: vault_id,
    )


def record_for(
    account: str,
    envelope: EncryptedEnvelope,
) -> EncryptedCredentialRecord:
    metadata = CredentialMetadata(CredentialId(account), FIXED_TIME, FIXED_TIME)
    return EncryptedCredentialRecord(metadata, envelope)


def altered(value: bytes) -> bytes:
    return bytes([value[0] ^ 1]) + value[1:]


def test_production_profile_is_used_for_new_vault() -> None:
    metadata, session = Argon2idAesGcmProvider().initialize(MASTER_PASSWORD_ALPHA)
    try:
        assert metadata.key_derivation_algorithm == "argon2id"
        assert metadata.key_derivation_version == 19
        assert metadata.key_derivation_memory_cost == PRODUCTION_MEMORY_COST == 65_536
        assert metadata.key_derivation_time_cost == PRODUCTION_TIME_COST == 3
        assert metadata.key_derivation_parallelism == PRODUCTION_PARALLELISM == 4
        assert len(metadata.key_derivation_salt) == 16
        assert metadata.derived_key_length == 32
    finally:
        session.close()


def test_new_vault_rejects_empty_master_password() -> None:
    with pytest.raises(ValidationError):
        fast_provider().initialize("")


def test_metadata_stores_no_master_password_or_plaintext_data_key() -> None:
    metadata, session = fast_provider().initialize(MASTER_PASSWORD_ALPHA)
    try:
        field_names = {item.name for item in fields(metadata)}
        assert field_names == {
            "derived_key_length",
            "format_version",
            "key_derivation_algorithm",
            "key_derivation_memory_cost",
            "key_derivation_parallelism",
            "key_derivation_salt",
            "key_derivation_time_cost",
            "key_derivation_version",
            "vault_id",
            "wrapped_data_encryption_key",
        }
        rendered = repr(metadata)
        assert MASTER_PASSWORD_ALPHA not in rendered
        salt_is_redacted = metadata.key_derivation_salt.hex() not in rendered
        assert salt_is_redacted
        assert repr(metadata.wrapped_data_encryption_key).count("ciphertext") == 0
    finally:
        session.close()


def test_empty_vault_unlocks_with_correct_master_password() -> None:
    provider = fast_provider()
    metadata, initialized = provider.initialize(MASTER_PASSWORD_ALPHA)
    initialized.close()
    unlocked = provider.unlock(metadata, MASTER_PASSWORD_ALPHA)
    unlocked.close()


def test_wrong_master_password_is_rejected_generically() -> None:
    provider = fast_provider()
    metadata, session = provider.initialize(MASTER_PASSWORD_ALPHA)
    session.close()
    with pytest.raises(InvalidMasterPasswordError) as captured:
        provider.unlock(metadata, MASTER_PASSWORD_BETA)
    assert str(captured.value) == "Vault authentication failed."


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("key_derivation_memory_cost", MIN_MEMORY_COST - 1),
        ("key_derivation_memory_cost", MAX_MEMORY_COST + 1),
        ("key_derivation_time_cost", MAX_TIME_COST + 1),
        ("key_derivation_parallelism", MAX_PARALLELISM + 1),
        ("key_derivation_version", 18),
        ("derived_key_length", 31),
    ],
)
def test_stored_kdf_parameters_outside_policy_are_rejected(
    field_name: str,
    value: int,
) -> None:
    provider = fast_provider()
    metadata, session = provider.initialize(MASTER_PASSWORD_ALPHA)
    session.close()
    malformed = replace(metadata, **{field_name: value})
    with pytest.raises(UnsupportedFormatError):
        provider.unlock(malformed, MASTER_PASSWORD_ALPHA)


@pytest.mark.parametrize(
    "parameters",
    [
        Argon2idParameters(memory_cost=MIN_MEMORY_COST - 1, time_cost=1, parallelism=1),
        Argon2idParameters(memory_cost=MIN_MEMORY_COST, time_cost=0, parallelism=1),
        Argon2idParameters(memory_cost=MIN_MEMORY_COST, time_cost=1, parallelism=0),
    ],
)
def test_private_new_vault_parameters_below_policy_are_rejected(
    parameters: Argon2idParameters,
) -> None:
    provider = Argon2idAesGcmProvider(_new_vault_parameters=parameters)
    with pytest.raises(UnsupportedFormatError):
        provider.initialize(MASTER_PASSWORD_ALPHA)


def test_malformed_salt_and_unsupported_kdf_are_rejected_before_derivation() -> None:
    provider = fast_provider()
    metadata, session = provider.initialize(MASTER_PASSWORD_ALPHA)
    session.close()
    with pytest.raises(UnsupportedFormatError):
        provider.unlock(replace(metadata, key_derivation_salt=b"SHORT_SALT"), MASTER_PASSWORD_ALPHA)
    with pytest.raises(UnsupportedFormatError):
        provider.unlock(
            replace(metadata, key_derivation_algorithm="UNSUPPORTED_KDF_PLACEHOLDER"),
            MASTER_PASSWORD_ALPHA,
        )


@pytest.mark.parametrize("field_name", ["ciphertext", "nonce", "authentication_tag"])
def test_wrapped_key_tampering_is_rejected_without_distinguishing_cause(field_name: str) -> None:
    provider = fast_provider()
    metadata, session = provider.initialize(MASTER_PASSWORD_ALPHA)
    session.close()
    envelope = metadata.wrapped_data_encryption_key
    tampered_envelope = replace(envelope, **{field_name: altered(getattr(envelope, field_name))})
    tampered_metadata = replace(metadata, wrapped_data_encryption_key=tampered_envelope)
    with pytest.raises(InvalidMasterPasswordError) as captured:
        provider.unlock(tampered_metadata, MASTER_PASSWORD_ALPHA)
    assert str(captured.value) == "Vault authentication failed."


def test_wrapped_key_associated_data_tampering_is_rejected_generically() -> None:
    provider = fast_provider()
    metadata, session = provider.initialize(MASTER_PASSWORD_ALPHA)
    session.close()
    envelope = metadata.wrapped_data_encryption_key
    tampered = replace(envelope, associated_data=altered(envelope.associated_data))
    with pytest.raises(InvalidMasterPasswordError):
        provider.unlock(
            replace(metadata, wrapped_data_encryption_key=tampered),
            MASTER_PASSWORD_ALPHA,
        )


def test_credential_encrypts_and_decrypts_with_fresh_nonce() -> None:
    provider = fast_provider()
    _, session = provider.initialize(MASTER_PASSWORD_ALPHA)
    account = CredentialId("ACCOUNT_PLACEHOLDER_ALPHA")
    first = session.encrypt_credential(account, CREDENTIAL_PASSWORD_ALPHA)
    second = session.encrypt_credential(account, CREDENTIAL_PASSWORD_ALPHA)
    try:
        assert len(first.nonce) == NONCE_LENGTH
        assert len(first.authentication_tag) == TAG_LENGTH
        nonces_are_distinct = first.nonce != second.nonce
        assert nonces_are_distinct
        assert session.decrypt_credential(record_for(account.value, first)) == (
            CREDENTIAL_PASSWORD_ALPHA
        )
    finally:
        session.close()


@pytest.mark.parametrize("field_name", ["ciphertext", "nonce", "authentication_tag"])
def test_credential_tampering_fails_authentication(field_name: str) -> None:
    _, session = fast_provider().initialize(MASTER_PASSWORD_ALPHA)
    account = CredentialId("ACCOUNT_PLACEHOLDER_ALPHA")
    envelope = session.encrypt_credential(account, CREDENTIAL_PASSWORD_ALPHA)
    tampered = replace(envelope, **{field_name: altered(getattr(envelope, field_name))})
    try:
        with pytest.raises(AuthenticationError):
            session.decrypt_credential(record_for(account.value, tampered))
    finally:
        session.close()


def test_account_associated_data_mismatch_fails_authentication() -> None:
    _, session = fast_provider().initialize(MASTER_PASSWORD_ALPHA)
    envelope = session.encrypt_credential(
        CredentialId("ACCOUNT_PLACEHOLDER_ALPHA"),
        CREDENTIAL_PASSWORD_ALPHA,
    )
    try:
        with pytest.raises(AuthenticationError):
            session.decrypt_credential(record_for("ACCOUNT_PLACEHOLDER_BETA", envelope))
    finally:
        session.close()


def test_vault_associated_data_mismatch_fails_authentication() -> None:
    _, first_session = fast_provider().initialize(MASTER_PASSWORD_ALPHA)
    _, second_session = fast_provider(
        vault_id=UUID("00000000-0000-0000-0000-000000000202")
    ).initialize(MASTER_PASSWORD_ALPHA)
    envelope = first_session.encrypt_credential(
        CredentialId("ACCOUNT_PLACEHOLDER_ALPHA"),
        CREDENTIAL_PASSWORD_ALPHA,
    )
    try:
        with pytest.raises(AuthenticationError):
            second_session.decrypt_credential(record_for("ACCOUNT_PLACEHOLDER_ALPHA", envelope))
    finally:
        first_session.close()
        second_session.close()


def test_format_version_context_mismatch_and_unsupported_algorithm_are_rejected() -> None:
    _, session = fast_provider().initialize(MASTER_PASSWORD_ALPHA)
    account = CredentialId("ACCOUNT_PLACEHOLDER_ALPHA")
    envelope = session.encrypt_credential(account, CREDENTIAL_PASSWORD_ALPHA)
    mismatched_context = envelope.associated_data.replace(
        b'"format_version":1',
        b'"format_version":2',
    )
    assert mismatched_context != envelope.associated_data
    mismatched = replace(envelope, associated_data=mismatched_context)
    try:
        with pytest.raises(AuthenticationError):
            session.decrypt_credential(record_for(account.value, mismatched))
        with pytest.raises(UnsupportedFormatError):
            replace(envelope, algorithm="UNSUPPORTED_ALGORITHM_PLACEHOLDER")
        with pytest.raises(UnsupportedFormatError):
            replace(envelope, format_version=999)
    finally:
        session.close()


def test_unicode_normalization_is_bound_into_credential_context() -> None:
    _, session = fast_provider().initialize(MASTER_PASSWORD_ALPHA)
    normalized = CredentialId("  KELVIN-Straße  ")
    envelope = session.encrypt_credential(normalized, CREDENTIAL_PASSWORD_ALPHA)
    try:
        assert session.decrypt_credential(record_for("kelvin-strasse", envelope)) == (
            CREDENTIAL_PASSWORD_ALPHA
        )
    finally:
        session.close()


def test_session_close_overwrites_mutable_key_buffer_and_is_idempotent() -> None:
    _, protocol_session = fast_provider().initialize(MASTER_PASSWORD_ALPHA)
    assert isinstance(protocol_session, AesGcmUnlockedSession)
    key_buffer = protocol_session._key_buffer
    key_buffer_was_populated = any(key_buffer)
    assert key_buffer_was_populated
    protocol_session.close()
    protocol_session.close()
    assert not any(key_buffer)
    with pytest.raises(VaultLockedError):
        protocol_session.encrypt_credential(
            CredentialId("ACCOUNT_PLACEHOLDER_ALPHA"),
            CREDENTIAL_PASSWORD_ALPHA,
        )


def test_session_context_manager_closes_and_repr_is_redacted() -> None:
    provider = fast_provider()
    _, session = provider.initialize(MASTER_PASSWORD_ALPHA)
    rendered_provider = repr(provider)
    rendered_session = repr(session)
    assert MASTER_PASSWORD_ALPHA not in rendered_provider + rendered_session
    assert "key" not in rendered_session.casefold()
    with session:
        assert "unlocked" in repr(session)
    assert "closed" in repr(session)


def test_safe_crypto_exception_messages_do_not_accept_secret_values() -> None:
    for error_type in (
        InvalidMasterPasswordError,
        AuthenticationError,
        CryptographicOperationError,
    ):
        error: PasswordLockerError = error_type()
        rendered = str(error)
        assert MASTER_PASSWORD_ALPHA not in rendered
        assert CREDENTIAL_PASSWORD_ALPHA not in rendered


def test_invalid_random_source_fails_safely() -> None:
    provider = Argon2idAesGcmProvider(
        _new_vault_parameters=FAST_PARAMETERS,
        _random_bytes=lambda length: b"SHORT",
    )
    with pytest.raises(CryptographicOperationError):
        provider.initialize(MASTER_PASSWORD_ALPHA)
