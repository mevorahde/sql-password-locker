from __future__ import annotations

import pytest

from pw_locker_sql.domain import CredentialId, EncryptedCredentialRecord
from pw_locker_sql.errors import (
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    RepositoryError,
    ValidationError,
)
from pw_locker_sql.repositories.memory import InMemoryCredentialRepository


def test_repository_insert_get_list_update_delete(record_factory) -> None:
    repository = InMemoryCredentialRepository()
    record = record_factory("ACCOUNT_BETA")
    repository.insert(record)
    assert repository.get(CredentialId("account_beta")) == record
    assert repository.list_metadata() == (record.metadata,)

    updated = record_factory("ACCOUNT_BETA", revision=2)
    repository.update(updated)
    assert repository.get(CredentialId("ACCOUNT_BETA")) == updated

    repository.delete(CredentialId("ACCOUNT_BETA"))
    assert repository.list_metadata() == ()
    with pytest.raises(CredentialNotFoundError):
        repository.get(CredentialId("ACCOUNT_BETA"))


def test_repository_detects_normalized_duplicates(record_factory) -> None:
    repository = InMemoryCredentialRepository()
    repository.insert(record_factory("  ACCOUNT_DUPLICATE  "))
    with pytest.raises(CredentialAlreadyExistsError):
        repository.insert(record_factory("account_duplicate"))


def test_repository_distinguishes_missing_update_and_delete(record_factory) -> None:
    repository = InMemoryCredentialRepository()
    with pytest.raises(CredentialNotFoundError):
        repository.update(record_factory("ACCOUNT_MISSING"))
    with pytest.raises(CredentialNotFoundError):
        repository.delete(CredentialId("ACCOUNT_MISSING"))


def test_repository_lists_accounts_deterministically(record_factory) -> None:
    repository = InMemoryCredentialRepository()
    for account in ("ACCOUNT_ZULU", "ACCOUNT_ALPHA", "ACCOUNT_MIDDLE"):
        repository.insert(record_factory(account))
    assert [item.credential_id.value for item in repository.list_metadata()] == [
        "account_alpha",
        "account_middle",
        "account_zulu",
    ]


def test_repository_accepts_only_encrypted_records() -> None:
    repository = InMemoryCredentialRepository()
    with pytest.raises(ValidationError):
        repository.insert("PLAINTEXT_PLACEHOLDER")  # type: ignore[arg-type]


def test_repository_vault_metadata_and_close_are_predictable(vault_metadata) -> None:
    repository = InMemoryCredentialRepository()
    repository.initialize_vault_metadata(vault_metadata)
    assert repository.get_vault_metadata() == vault_metadata
    with pytest.raises(RepositoryError):
        repository.initialize_vault_metadata(vault_metadata)

    repository.close()
    repository.close()
    with pytest.raises(RepositoryError):
        repository.get_vault_metadata()
    with pytest.raises(RepositoryError):
        repository.list_metadata()


def test_repository_context_manager_closes(record_factory) -> None:
    repository = InMemoryCredentialRepository()
    with repository as active:
        active.insert(record_factory("ACCOUNT_CONTEXT"))
    with pytest.raises(RepositoryError):
        repository.list_metadata()


def test_record_and_repository_do_not_expose_mutable_caller_state(record_factory) -> None:
    repository = InMemoryCredentialRepository()
    record: EncryptedCredentialRecord = record_factory("ACCOUNT_ISOLATED")
    repository.insert(record)
    listed = list(repository.list_metadata())
    listed.clear()
    assert repository.get(CredentialId("ACCOUNT_ISOLATED")) == record
