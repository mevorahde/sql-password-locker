from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from pw_locker_sql.domain import (
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
    VaultMetadata,
)


@pytest.fixture
def fixed_time() -> datetime:
    return datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)


@pytest.fixture
def envelope() -> EncryptedEnvelope:
    return EncryptedEnvelope(
        ciphertext=b"SYNTHETIC_CIPHERTEXT",
        nonce=b"SYNTHETIC_NONCE",
        authentication_tag=b"SYNTHETIC_AUTH_TAG",
        associated_data=b"SYNTHETIC_ASSOCIATED_DATA",
    )


@pytest.fixture
def record_factory(fixed_time: datetime, envelope: EncryptedEnvelope):
    def make(account: str, *, revision: int = 1) -> EncryptedCredentialRecord:
        metadata = CredentialMetadata(
            CredentialId.from_account(account),
            fixed_time,
            fixed_time,
            revision,
        )
        return EncryptedCredentialRecord(metadata, envelope)

    return make


@pytest.fixture
def vault_metadata(fixed_time: datetime, envelope: EncryptedEnvelope) -> VaultMetadata:
    return VaultMetadata(
        vault_id=UUID("00000000-0000-0000-0000-000000000001"),
        created_at=fixed_time,
        key_derivation_algorithm="SYNTHETIC_KDF_PLACEHOLDER",
        key_derivation_salt=b"SYNTHETIC_SALT",
        wrapped_data_encryption_key=envelope,
    )
