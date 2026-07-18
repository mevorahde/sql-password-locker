"""Transactional package-resource migrations for the fixed SQL Server schema."""

from __future__ import annotations

from collections.abc import Callable
from importlib.resources import files

from pw_locker_sql.errors import (
    PasswordLockerError,
    SchemaMigrationError,
    UnsupportedSchemaVersionError,
)
from pw_locker_sql.repositories.sql_server import DbApiConnection, DbApiCursor

CURRENT_SCHEMA_VERSION = 1

DETECT_SCHEMA_OBJECTS_SQL = """
SELECT
    OBJECT_ID(N'dbo.PasswordLockerSchemaVersion', N'U'),
    OBJECT_ID(N'dbo.PasswordLockerVault', N'U'),
    OBJECT_ID(N'dbo.PasswordLockerCredential', N'U');
"""

SELECT_SCHEMA_VERSION_SQL = """
SELECT schema_version
FROM dbo.PasswordLockerSchemaVersion
WHERE singleton_id = 1;
"""

INSERT_SCHEMA_VERSION_SQL = """
INSERT INTO dbo.PasswordLockerSchemaVersion (singleton_id, schema_version)
VALUES (1, ?);
"""


class SqlServerSchemaManager:
    """Detects and advances only the package-owned schema to version 1."""

    def __init__(self, connection_factory: Callable[[], DbApiConnection]) -> None:
        self._connection_factory = connection_factory

    def current_version(self) -> int:
        return self._run(lambda cursor: _detect_schema_version(cursor))

    def migrate(self) -> int:
        def operation(cursor: DbApiCursor) -> int:
            version = _detect_schema_version(cursor)
            if version == CURRENT_SCHEMA_VERSION:
                return version
            if version > CURRENT_SCHEMA_VERSION:
                raise UnsupportedSchemaVersionError()
            if version != 0:
                raise SchemaMigrationError()
            migration = _load_initial_migration()
            cursor.execute(migration)
            cursor.execute(INSERT_SCHEMA_VERSION_SQL, CURRENT_SCHEMA_VERSION)
            if cursor.rowcount != 1:
                raise SchemaMigrationError()
            return CURRENT_SCHEMA_VERSION

        return self._run(operation)

    def _run(self, operation: Callable[[DbApiCursor], int]) -> int:
        connection: DbApiConnection | None = None
        cursor: DbApiCursor | None = None
        try:
            connection = self._connection_factory()
            cursor = connection.cursor()
            result = operation(cursor)
            connection.commit()
            return result
        except PasswordLockerError:
            _safe_rollback(connection)
            raise
        except Exception:
            _safe_rollback(connection)
            raise SchemaMigrationError() from None
        finally:
            _safe_close(cursor)
            _safe_close(connection)

    def __repr__(self) -> str:
        return "SqlServerSchemaManager()"


def _detect_schema_version(cursor: DbApiCursor) -> int:
    cursor.execute(DETECT_SCHEMA_OBJECTS_SQL)
    object_row = cursor.fetchone()
    if object_row is None or len(object_row) != 3:
        raise SchemaMigrationError()
    present = tuple(value is not None for value in object_row)
    if present == (False, False, False):
        return 0
    if present != (True, True, True):
        raise SchemaMigrationError()
    cursor.execute(SELECT_SCHEMA_VERSION_SQL)
    rows = list(cursor.fetchall())
    if len(rows) != 1 or len(rows[0]) != 1:
        raise SchemaMigrationError()
    version = _schema_integer(rows[0][0])
    if version > CURRENT_SCHEMA_VERSION:
        raise UnsupportedSchemaVersionError()
    if version < 1:
        raise SchemaMigrationError()
    return version


def _load_initial_migration() -> str:
    migration = (
        files("pw_locker_sql.schema.migrations")
        .joinpath("001_initial.sql")
        .read_text(encoding="utf-8")
    )
    if not migration.strip() or _contains_go_batch_separator(migration):
        raise SchemaMigrationError()
    return migration


def _contains_go_batch_separator(sql: str) -> bool:
    return any(line.strip().casefold() == "go" for line in sql.splitlines())


def _schema_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SchemaMigrationError()
    return value


def _safe_rollback(connection: DbApiConnection | None) -> None:
    if connection is None:
        return
    try:
        connection.rollback()
    except Exception:
        pass


def _safe_close(resource: DbApiCursor | DbApiConnection | None) -> None:
    if resource is None:
        return
    try:
        resource.close()
    except Exception:
        pass
