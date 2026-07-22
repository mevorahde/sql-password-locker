from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files

import pytest

from pw_locker_sql.errors import SchemaMigrationError, UnsupportedSchemaVersionError
from pw_locker_sql.schema.manager import (
    CURRENT_SCHEMA_VERSION,
    DETECT_SCHEMA_OBJECTS_SQL,
    INSERT_SCHEMA_VERSION_SQL,
    SELECT_SCHEMA_VERSION_SQL,
    SqlServerSchemaManager,
)


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
            raise AssertionError("unexpected schema operation")
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


def test_uninitialized_schema_is_version_zero() -> None:
    connection = FakeConnection([Step(rows=((None, None, None),))])
    assert SqlServerSchemaManager(lambda: connection).current_version() == 0
    assert connection.fake_cursor.executions[0][0] == DETECT_SCHEMA_OBJECTS_SQL
    assert connection.commits == 1
    assert connection.fake_cursor.closed and connection.closed


def test_initial_migration_is_transactional_and_records_version_last() -> None:
    connection = FakeConnection(
        [
            Step(rows=((None, None, None),)),
            Step(),
            Step(rowcount=1),
        ]
    )
    assert SqlServerSchemaManager(lambda: connection).migrate() == CURRENT_SCHEMA_VERSION
    executions = connection.fake_cursor.executions
    assert executions[0] == (DETECT_SCHEMA_OBJECTS_SQL, ())
    assert "CREATE TABLE dbo.PasswordLockerVault" in executions[1][0]
    assert executions[2] == (INSERT_SCHEMA_VERSION_SQL, (1,))
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.fake_cursor.closed and connection.closed


def test_migration_failure_rolls_back_everything_and_closes_resources() -> None:
    connection = FakeConnection(
        [
            Step(rows=((None, None, None),)),
            Step(error=RuntimeError("SYNTHETIC_MIGRATION_FAILURE")),
        ]
    )
    with pytest.raises(SchemaMigrationError) as captured:
        SqlServerSchemaManager(lambda: connection).migrate()
    assert "SYNTHETIC_MIGRATION_FAILURE" not in str(captured.value)
    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert connection.fake_cursor.closed and connection.closed


def test_supported_schema_version_one_is_not_reapplied() -> None:
    connection = FakeConnection(
        [
            Step(rows=((101, 102, 103),)),
            Step(rows=((1,),)),
        ]
    )
    assert SqlServerSchemaManager(lambda: connection).migrate() == 1
    assert [item[0] for item in connection.fake_cursor.executions] == [
        DETECT_SCHEMA_OBJECTS_SQL,
        SELECT_SCHEMA_VERSION_SQL,
    ]
    assert connection.commits == 1


def test_future_schema_version_is_refused_and_rolled_back() -> None:
    connection = FakeConnection(
        [
            Step(rows=((101, 102, 103),)),
            Step(rows=((2,),)),
        ]
    )
    with pytest.raises(UnsupportedSchemaVersionError):
        SqlServerSchemaManager(lambda: connection).migrate()
    assert connection.commits == 0
    assert connection.rollbacks == 1


@pytest.mark.parametrize(
    "objects",
    [(101, None, None), (101, 102, None), (None, 102, 103)],
)
def test_partial_schema_is_rejected(objects: tuple[int | None, ...]) -> None:
    connection = FakeConnection([Step(rows=(objects,))])
    with pytest.raises(SchemaMigrationError):
        SqlServerSchemaManager(lambda: connection).migrate()
    assert connection.rollbacks == 1


@pytest.mark.parametrize("rows", [(), ((0,),), ((1,), (1,)), (("1",),)])
def test_malformed_version_state_is_rejected(rows: tuple[tuple[object, ...], ...]) -> None:
    connection = FakeConnection(
        [
            Step(rows=((101, 102, 103),)),
            Step(rows=rows),
        ]
    )
    with pytest.raises(SchemaMigrationError):
        SqlServerSchemaManager(lambda: connection).current_version()
    assert connection.rollbacks == 1


def test_migration_resource_has_fixed_encrypted_schema_and_no_batch_separator() -> None:
    migration = (
        files("pw_locker_sql.schema.migrations")
        .joinpath("001_initial.sql")
        .read_text(encoding="utf-8")
    )
    assert "CREATE TABLE dbo.PasswordLockerSchemaVersion" in migration
    assert "CREATE TABLE dbo.PasswordLockerVault" in migration
    assert "CREATE TABLE dbo.PasswordLockerCredential" in migration
    assert "UNIQUEIDENTIFIER" in migration
    assert "VARBINARY" in migration
    assert "ROWVERSION" in migration
    assert "PRIMARY KEY (vault_id, normalized_account)" in migration
    assert "UNIQUE (singleton_id)" in migration
    assert "CHECK (singleton_id = 1)" in migration
    assert all(line.strip().casefold() != "go" for line in migration.splitlines())
    lowered = migration.casefold()
    for forbidden in (
        "master_password",
        "plaintext_password",
        "data_encryption_key varbinary",
        "key_encryption_key",
        "connection_string",
    ):
        assert forbidden not in lowered


def test_schema_statements_use_only_fixed_identifiers_and_parameterized_version() -> None:
    assert "dbo.PasswordLockerSchemaVersion" in DETECT_SCHEMA_OBJECTS_SQL
    assert "dbo.PasswordLockerVault" in DETECT_SCHEMA_OBJECTS_SQL
    assert "dbo.PasswordLockerCredential" in DETECT_SCHEMA_OBJECTS_SQL
    assert INSERT_SCHEMA_VERSION_SQL.count("?") == 1
    assert "merge" not in (
        DETECT_SCHEMA_OBJECTS_SQL + SELECT_SCHEMA_VERSION_SQL + INSERT_SCHEMA_VERSION_SQL
    ).casefold()
