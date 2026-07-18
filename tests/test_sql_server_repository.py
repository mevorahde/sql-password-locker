from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import pytest

from pw_locker_sql.config import SQLServerConfig
from pw_locker_sql.domain import (
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
    VaultMetadata,
)
from pw_locker_sql.errors import (
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    RepositoryError,
    VaultAlreadyInitializedError,
)
from pw_locker_sql.repositories.sql_server import (
    DELETE_CREDENTIAL_SQL,
    INSERT_CREDENTIAL_SQL,
    INSERT_VAULT_SQL,
    LIST_CREDENTIAL_METADATA_SQL,
    SELECT_CREDENTIAL_SQL,
    SELECT_VAULT_SQL,
    UPDATE_CREDENTIAL_SQL,
    SqlServerConnectionFactory,
    SqlServerCredentialRepository,
)

NOW = datetime(2026, 2, 3, 4, 5, tzinfo=timezone.utc)
VAULT_ID = UUID("00000000-0000-0000-0000-000000000101")


@dataclass
class Step:
    rows: tuple[tuple[object, ...], ...] = ()
    rowcount: int = -1
    error: Exception | None = None


class FakeCursor:
    def __init__(self, steps: Sequence[Step]) -> None:
        self.steps = list(steps)
        self.current = Step()
        self.executions: list[tuple[str, tuple[object, ...]]] = []
        self.rowcount = -1
        self.closed = False

    def execute(self, operation: str, *parameters: object) -> FakeCursor:
        self.executions.append((operation, parameters))
        if not self.steps:
            raise AssertionError("unexpected database operation")
        self.current = self.steps.pop(0)
        self.rowcount = self.current.rowcount
        if self.current.error is not None:
            raise self.current.error
        return self

    def fetchone(self) -> tuple[object, ...] | None:
        return self.current.rows[0] if self.current.rows else None

    def fetchall(self) -> tuple[tuple[object, ...], ...]:
        return self.current.rows

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self, steps: Sequence[Step]) -> None:
        self.fake_cursor = FakeCursor(steps)
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self) -> FakeCursor:
        return self.fake_cursor

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakeFactory:
    def __init__(self, *connections: FakeConnection) -> None:
        self.connections = list(connections)
        self.calls = 0

    def __call__(self) -> FakeConnection:
        self.calls += 1
        if not self.connections:
            raise AssertionError("unexpected connection")
        return self.connections.pop(0)


class CaptureConnector:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.calls: list[tuple[str, bool, int]] = []

    def connect(
        self,
        connection_string: str,
        *,
        autocommit: bool,
        timeout: int,
    ) -> FakeConnection:
        self.calls.append((connection_string, autocommit, timeout))
        return self.connection


class FakeDriverError(Exception):
    def __init__(self, *, sqlstate: str | None = None, native_error: int | None = None) -> None:
        super().__init__("SYNTHETIC_DRIVER_DIAGNOSTIC")
        self.sqlstate = sqlstate
        self.native_error = native_error


def _vault() -> VaultMetadata:
    envelope = EncryptedEnvelope(
        ciphertext=b"W" * 32,
        nonce=b"N" * 12,
        authentication_tag=b"T" * 16,
        associated_data=b"SYNTHETIC_VAULT_CONTEXT",
    )
    return VaultMetadata(
        vault_id=VAULT_ID,
        key_derivation_algorithm="argon2id",
        key_derivation_version=19,
        key_derivation_memory_cost=65536,
        key_derivation_time_cost=3,
        key_derivation_parallelism=4,
        derived_key_length=32,
        key_derivation_salt=b"S" * 16,
        wrapped_data_encryption_key=envelope,
    )


def _vault_row() -> tuple[object, ...]:
    metadata = _vault()
    envelope = metadata.wrapped_data_encryption_key
    return (
        str(metadata.vault_id),
        metadata.format_version,
        metadata.key_derivation_algorithm,
        metadata.key_derivation_version,
        metadata.key_derivation_memory_cost,
        metadata.key_derivation_time_cost,
        metadata.key_derivation_parallelism,
        metadata.derived_key_length,
        metadata.key_derivation_salt,
        envelope.algorithm,
        envelope.format_version,
        envelope.ciphertext,
        envelope.nonce,
        envelope.authentication_tag,
        envelope.associated_data,
    )


def _record(account: str = "synthetic account", revision: int = 1) -> EncryptedCredentialRecord:
    return EncryptedCredentialRecord(
        CredentialMetadata(CredentialId(account), NOW, NOW, revision),
        EncryptedEnvelope(
            ciphertext=b"C" * 24,
            nonce=b"Q" * 12,
            authentication_tag=b"A" * 16,
            associated_data=b"SYNTHETIC_CREDENTIAL_CONTEXT",
        ),
    )


def _credential_row(record: EncryptedCredentialRecord | None = None) -> tuple[object, ...]:
    value = record or _record()
    return (
        value.metadata.credential_id.value,
        value.metadata.created_at,
        value.metadata.updated_at,
        value.metadata.revision,
        value.envelope.format_version,
        value.envelope.algorithm,
        value.envelope.ciphertext,
        value.envelope.nonce,
        value.envelope.authentication_tag,
        value.envelope.associated_data,
    )


def _integrated_config(**overrides: str) -> SQLServerConfig:
    values = {
        "SERVER": "SERVER_PLACEHOLDER",
        "DATABASE": "DATABASE_PLACEHOLDER",
        "AUTH_MODE": "integrated",
        **overrides,
    }
    return SQLServerConfig.from_mapping(values)


def test_connection_factory_is_lazy_secure_and_disables_autocommit() -> None:
    connection = FakeConnection([])
    connector = CaptureConnector(connection)
    factory = SqlServerConnectionFactory(_integrated_config(), connector)
    assert connector.calls == []
    assert factory() is connection
    connection_string, autocommit, timeout = connector.calls[0]
    assert "DRIVER={ODBC Driver 18 for SQL Server}" in connection_string
    assert "Encrypt=Yes" in connection_string
    assert "TrustServerCertificate=No" in connection_string
    assert "Trusted_Connection=Yes" in connection_string
    assert "UID=" not in connection_string
    assert "PWD=" not in connection_string
    assert autocommit is False
    assert timeout == 15


def test_sql_auth_connection_string_quotes_password_and_excludes_integrated_auth() -> None:
    marker = " SYNTHETIC password;with}braces! "
    config = SQLServerConfig.from_mapping(
        {
            "SERVER": "SERVER_PLACEHOLDER",
            "DATABASE": "DATABASE_PLACEHOLDER",
            "AUTH_MODE": "sql",
            "USERNAME": "USERNAME_PLACEHOLDER",
            "PASSWORD": marker,
        }
    )
    connector = CaptureConnector(FakeConnection([]))
    SqlServerConnectionFactory(config, connector)()
    connection_string = connector.calls[0][0]
    assert "Trusted_Connection" not in connection_string
    assert "UID={USERNAME_PLACEHOLDER}" in connection_string
    assert "PWD={ SYNTHETIC password;with}}braces! }" in connection_string


def test_public_odbc_values_with_closing_braces_are_escaped() -> None:
    connector = CaptureConnector(FakeConnection([]))
    config = _integrated_config(SERVER="SERVER}PLACEHOLDER")
    SqlServerConnectionFactory(config, connector)()
    assert "SERVER={SERVER}}PLACEHOLDER}" in connector.calls[0][0]


def test_connection_factory_representations_are_redacted() -> None:
    config = _integrated_config()
    rendered = repr(SqlServerConnectionFactory(config, CaptureConnector(FakeConnection([]))))
    assert rendered == "SqlServerConnectionFactory(<redacted>)"
    assert config.server not in rendered
    assert config.database not in rendered


def test_connection_driver_errors_are_redacted(caplog: pytest.LogCaptureFixture) -> None:
    class FailingConnector:
        def connect(self, *_args: Any, **_kwargs: Any) -> FakeConnection:
            raise FakeDriverError()

    with pytest.raises(RepositoryError) as captured:
        SqlServerConnectionFactory(_integrated_config(), FailingConnector())()
    assert "SYNTHETIC_DRIVER_DIAGNOSTIC" not in str(captured.value)
    assert "SERVER_PLACEHOLDER" not in str(captured.value)
    assert caplog.records == []


def test_vault_metadata_round_trip_preserves_binary_values() -> None:
    connection = FakeConnection([Step(rows=(_vault_row(),))])
    result = SqlServerCredentialRepository(FakeFactory(connection)).get_vault_metadata()
    assert result == _vault()
    assert isinstance(result.key_derivation_salt, bytes)
    assert isinstance(result.wrapped_data_encryption_key.ciphertext, bytes)
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.fake_cursor.closed and connection.closed


def test_vault_initialization_is_parameterized_and_committed() -> None:
    connection = FakeConnection([Step(rowcount=1)])
    SqlServerCredentialRepository(FakeFactory(connection)).initialize_vault_metadata(_vault())
    sql, parameters = connection.fake_cursor.executions[0]
    assert sql == INSERT_VAULT_SQL
    assert sql.count("?") == len(parameters) == 15
    assert _vault().key_derivation_salt in parameters
    assert connection.commits == 1


@pytest.mark.parametrize(
    ("sqlstate", "native_error"),
    [("23000", None), (None, 2601), (None, 2627)],
)
def test_vault_duplicate_key_indicators_are_translated(
    sqlstate: str | None,
    native_error: int | None,
) -> None:
    connection = FakeConnection(
        [Step(error=FakeDriverError(sqlstate=sqlstate, native_error=native_error))]
    )
    with pytest.raises(VaultAlreadyInitializedError):
        SqlServerCredentialRepository(FakeFactory(connection)).initialize_vault_metadata(_vault())
    assert connection.rollbacks == 1
    assert connection.commits == 0


def test_credential_insert_uses_encrypted_binary_parameters() -> None:
    record = _record("Mixed Case")
    connection = FakeConnection([Step(rows=(_vault_row(),)), Step(rowcount=1)])
    SqlServerCredentialRepository(FakeFactory(connection)).insert(record)
    sql, parameters = connection.fake_cursor.executions[1]
    assert sql == INSERT_CREDENTIAL_SQL
    assert parameters[1] == "mixed case"
    assert record.envelope.ciphertext in parameters
    assert record.envelope.nonce in parameters
    assert record.envelope.authentication_tag in parameters
    assert connection.commits == 1


def test_credential_duplicate_is_translated_without_driver_diagnostics() -> None:
    connection = FakeConnection(
        [
            Step(rows=(_vault_row(),)),
            Step(error=FakeDriverError(native_error=2627)),
        ]
    )
    with pytest.raises(CredentialAlreadyExistsError) as captured:
        SqlServerCredentialRepository(FakeFactory(connection)).insert(_record())
    assert "SYNTHETIC_DRIVER_DIAGNOSTIC" not in str(captured.value)
    assert connection.rollbacks == 1


def test_get_retrieves_only_requested_encrypted_record() -> None:
    record = _record("Requested Account")
    connection = FakeConnection(
        [Step(rows=(_vault_row(),)), Step(rows=(_credential_row(record),))]
    )
    result = SqlServerCredentialRepository(FakeFactory(connection)).get(
        CredentialId("REQUESTED ACCOUNT")
    )
    assert result == record
    sql, parameters = connection.fake_cursor.executions[1]
    assert sql == SELECT_CREDENTIAL_SQL
    assert parameters == (str(VAULT_ID), "requested account")
    assert "WHERE vault_id = ? AND normalized_account = ?" in sql


def test_get_rejects_a_row_for_a_different_normalized_account() -> None:
    connection = FakeConnection(
        [Step(rows=(_vault_row(),)), Step(rows=(_credential_row(_record("other")),))]
    )
    with pytest.raises(RepositoryError):
        SqlServerCredentialRepository(FakeFactory(connection)).get(CredentialId("requested"))
    assert connection.rollbacks == 1


def test_missing_credential_is_distinct_and_rolls_back() -> None:
    connection = FakeConnection([Step(rows=(_vault_row(),)), Step(rows=())])
    with pytest.raises(CredentialNotFoundError):
        SqlServerCredentialRepository(FakeFactory(connection)).get(CredentialId("missing"))
    assert connection.rollbacks == 1
    assert connection.fake_cursor.closed and connection.closed


def test_list_returns_metadata_only_in_deterministic_order() -> None:
    rows = (
        ("alpha", NOW, NOW, 1),
        ("beta", NOW, NOW, 2),
    )
    connection = FakeConnection([Step(rows=(_vault_row(),)), Step(rows=rows)])
    result = SqlServerCredentialRepository(FakeFactory(connection)).list_metadata()
    assert [item.credential_id.value for item in result] == ["alpha", "beta"]
    sql, _ = connection.fake_cursor.executions[1]
    assert sql == LIST_CREDENTIAL_METADATA_SQL
    assert "ciphertext" not in sql.casefold()
    assert "order by normalized_account asc" in sql.casefold()


def test_update_and_delete_check_affected_rows() -> None:
    update_connection = FakeConnection([Step(rows=(_vault_row(),)), Step(rowcount=1)])
    delete_connection = FakeConnection([Step(rows=(_vault_row(),)), Step(rowcount=1)])
    factory = FakeFactory(update_connection, delete_connection)
    repository = SqlServerCredentialRepository(factory)
    repository.update(_record(revision=2))
    repository.delete(CredentialId("synthetic account"))
    assert update_connection.fake_cursor.executions[1][0] == UPDATE_CREDENTIAL_SQL
    assert delete_connection.fake_cursor.executions[1][0] == DELETE_CREDENTIAL_SQL
    assert update_connection.commits == delete_connection.commits == 1


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_missing_write_target_rolls_back(operation: str) -> None:
    connection = FakeConnection([Step(rows=(_vault_row(),)), Step(rowcount=0)])
    repository = SqlServerCredentialRepository(FakeFactory(connection))
    with pytest.raises(CredentialNotFoundError):
        if operation == "update":
            repository.update(_record(revision=2))
        else:
            repository.delete(CredentialId("synthetic account"))
    assert connection.rollbacks == 1


def test_generic_write_failure_rolls_back_and_is_redacted() -> None:
    connection = FakeConnection(
        [Step(rows=(_vault_row(),)), Step(error=FakeDriverError())]
    )
    with pytest.raises(RepositoryError) as captured:
        SqlServerCredentialRepository(FakeFactory(connection)).insert(_record())
    assert "SYNTHETIC_DRIVER_DIAGNOSTIC" not in str(captured.value)
    assert connection.rollbacks == 1
    assert connection.fake_cursor.closed and connection.closed


def test_closed_repository_never_creates_a_connection() -> None:
    factory = FakeFactory()
    repository = SqlServerCredentialRepository(factory)
    repository.close()
    repository.close()
    with pytest.raises(RepositoryError):
        repository.list_metadata()
    assert factory.calls == 0


def test_sql_uses_fixed_identifiers_placeholders_and_never_merge() -> None:
    statements = (
        SELECT_VAULT_SQL,
        INSERT_VAULT_SQL,
        SELECT_CREDENTIAL_SQL,
        LIST_CREDENTIAL_METADATA_SQL,
        INSERT_CREDENTIAL_SQL,
        UPDATE_CREDENTIAL_SQL,
        DELETE_CREDENTIAL_SQL,
    )
    assert all("dbo.PasswordLocker" in sql for sql in statements)
    assert all("merge" not in sql.casefold() for sql in statements)
    for sql in statements:
        assert "SERVER_PLACEHOLDER" not in sql
        assert "DATABASE_PLACEHOLDER" not in sql
