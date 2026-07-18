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


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("sqlserver-integration")
    group.addoption(
        "--run-sqlserver-integration",
        action="store_true",
        default=False,
        help="run explicitly configured SQL Server integration tests",
    )
    group.addoption(
        "--sqlserver-test-database",
        default=None,
        help="explicit test-only database designation for integration tests",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-sqlserver-integration"):
        return
    skip = pytest.mark.skip(reason="requires explicit SQL Server integration opt-in")
    for item in items:
        if "sqlserver_integration" in item.keywords:
            item.add_marker(skip)


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
        key_derivation_algorithm="argon2id",
        key_derivation_version=19,
        key_derivation_memory_cost=8192,
        key_derivation_time_cost=1,
        key_derivation_parallelism=1,
        derived_key_length=32,
        key_derivation_salt=b"SYNTHETIC_SALT",
        wrapped_data_encryption_key=envelope,
    )
