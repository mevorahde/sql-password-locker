"""SQL Server encrypted repository with lazy, injectable DB-API connections."""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Protocol, TypeVar, cast
from uuid import UUID

from pw_locker_sql.config import AuthenticationMode, SQLServerConfig
from pw_locker_sql.domain import (
    CURRENT_ENVELOPE_VERSION,
    CURRENT_VAULT_VERSION,
    CredentialId,
    CredentialMetadata,
    EncryptedCredentialRecord,
    EncryptedEnvelope,
    VaultMetadata,
)
from pw_locker_sql.errors import (
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    PasswordLockerError,
    RepositoryError,
    ValidationError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
)
from pw_locker_sql.repositories.datetimeoffset import (
    OutputConverterConnection,
    register_sql_server_datetimeoffset_converter,
)

VAULT_TABLE = "dbo.PasswordLockerVault"
CREDENTIAL_TABLE = "dbo.PasswordLockerCredential"

SELECT_VAULT_SQL = f"""
SELECT
    vault_id,
    format_version,
    kdf_algorithm,
    kdf_version,
    kdf_memory_cost,
    kdf_time_cost,
    kdf_parallelism,
    derived_key_length,
    kdf_salt,
    wrap_algorithm,
    wrap_envelope_version,
    wrapped_key_ciphertext,
    wrapping_nonce,
    wrapping_authentication_tag,
    wrap_associated_data
FROM {VAULT_TABLE};
"""

INSERT_VAULT_SQL = f"""
INSERT INTO {VAULT_TABLE} (
    vault_id,
    format_version,
    kdf_algorithm,
    kdf_version,
    kdf_memory_cost,
    kdf_time_cost,
    kdf_parallelism,
    derived_key_length,
    kdf_salt,
    wrap_algorithm,
    wrap_envelope_version,
    wrapped_key_ciphertext,
    wrapping_nonce,
    wrapping_authentication_tag,
    wrap_associated_data
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

SELECT_CREDENTIAL_SQL = f"""
SELECT
    normalized_account,
    created_at,
    updated_at,
    revision,
    envelope_version,
    algorithm,
    ciphertext,
    nonce,
    authentication_tag,
    associated_data
FROM {CREDENTIAL_TABLE}
WHERE vault_id = ? AND normalized_account = ?;
"""

LIST_CREDENTIAL_METADATA_SQL = f"""
SELECT normalized_account, created_at, updated_at, revision
FROM {CREDENTIAL_TABLE}
WHERE vault_id = ?
ORDER BY normalized_account ASC;
"""

INSERT_CREDENTIAL_SQL = f"""
INSERT INTO {CREDENTIAL_TABLE} (
    vault_id,
    normalized_account,
    envelope_version,
    algorithm,
    ciphertext,
    nonce,
    authentication_tag,
    associated_data,
    created_at,
    updated_at,
    revision
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

UPDATE_CREDENTIAL_SQL = f"""
UPDATE {CREDENTIAL_TABLE}
SET envelope_version = ?,
    algorithm = ?,
    ciphertext = ?,
    nonce = ?,
    authentication_tag = ?,
    associated_data = ?,
    updated_at = ?,
    revision = ?
WHERE vault_id = ? AND normalized_account = ?;
"""

DELETE_CREDENTIAL_SQL = f"""
DELETE FROM {CREDENTIAL_TABLE}
WHERE vault_id = ? AND normalized_account = ?;
"""


class DbApiCursor(Protocol):
    rowcount: int

    def execute(self, operation: str, *parameters: object) -> DbApiCursor: ...

    def fetchone(self) -> Sequence[object] | None: ...

    def fetchall(self) -> Sequence[Sequence[object]]: ...

    def close(self) -> None: ...


class DbApiConnection(Protocol):
    def cursor(self) -> DbApiCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


class OdbcConnection(DbApiConnection, OutputConverterConnection, Protocol):
    """DB-API connection with pyodbc output-converter registration."""


class OdbcConnector(Protocol):
    def connect(
        self,
        connection_string: str,
        *,
        autocommit: bool,
        timeout: int,
    ) -> OdbcConnection: ...


class _PyodbcConnector:
    """Imports pyodbc only when a runtime connection is explicitly requested."""

    def connect(
        self,
        connection_string: str,
        *,
        autocommit: bool,
        timeout: int,
    ) -> OdbcConnection:
        module = importlib.import_module("pyodbc")
        connection = module.connect(
            connection_string,
            autocommit=autocommit,
            timeout=timeout,
        )
        return cast(OdbcConnection, connection)


class SqlServerConnectionFactory:
    """Builds a secure connection string internally and never exposes it in repr."""

    def __init__(
        self,
        config: SQLServerConfig,
        connector: OdbcConnector | None = None,
    ) -> None:
        self._config = config
        self._connector = connector or _PyodbcConnector()

    def __call__(self) -> DbApiConnection:
        connection: OdbcConnection | None = None
        try:
            connection = self._connector.connect(
                _build_connection_string(self._config),
                autocommit=False,
                timeout=self._config.connection_timeout,
            )
            register_sql_server_datetimeoffset_converter(connection)
            return connection
        except PasswordLockerError:
            _safe_close(connection)
            raise
        except Exception:
            _safe_close(connection)
            raise RepositoryError() from None

    def __repr__(self) -> str:
        return "SqlServerConnectionFactory(<redacted>)"

    __str__ = __repr__


class SqlServerCredentialRepository:
    """Persists only encrypted vault and credential domain records."""

    def __init__(self, connection_factory: Callable[[], DbApiConnection]) -> None:
        self._connection_factory = connection_factory
        self._closed = False

    def get_vault_metadata(self) -> VaultMetadata:
        return self._run_transaction(_select_vault_metadata)

    def initialize_vault_metadata(self, metadata: VaultMetadata) -> None:
        _validate_vault_metadata(metadata)

        def operation(cursor: DbApiCursor) -> None:
            envelope = metadata.wrapped_data_encryption_key
            cursor.execute(
                INSERT_VAULT_SQL,
                str(metadata.vault_id),
                metadata.format_version,
                metadata.key_derivation_algorithm,
                metadata.key_derivation_version,
                metadata.key_derivation_memory_cost,
                metadata.key_derivation_time_cost,
                metadata.key_derivation_parallelism,
                metadata.derived_key_length,
                bytes(metadata.key_derivation_salt),
                envelope.algorithm,
                envelope.format_version,
                bytes(envelope.ciphertext),
                bytes(envelope.nonce),
                bytes(envelope.authentication_tag),
                bytes(envelope.associated_data),
            )
            _require_one_affected_row(cursor)

        self._run_transaction(operation, duplicate_error=VaultAlreadyInitializedError)

    def get(self, credential_id: CredentialId) -> EncryptedCredentialRecord:
        _validate_credential_id(credential_id)

        def operation(cursor: DbApiCursor) -> EncryptedCredentialRecord:
            vault = _select_vault_metadata(cursor)
            cursor.execute(SELECT_CREDENTIAL_SQL, str(vault.vault_id), credential_id.value)
            rows = list(cursor.fetchall())
            if not rows:
                raise CredentialNotFoundError()
            if len(rows) != 1:
                raise RepositoryError()
            record = _credential_from_row(rows[0])
            if record.metadata.credential_id != credential_id:
                raise RepositoryError()
            return record

        return self._run_transaction(operation)

    def list_metadata(self) -> tuple[CredentialMetadata, ...]:
        def operation(cursor: DbApiCursor) -> tuple[CredentialMetadata, ...]:
            vault = _select_vault_metadata(cursor)
            cursor.execute(LIST_CREDENTIAL_METADATA_SQL, str(vault.vault_id))
            return tuple(_credential_metadata_from_row(row) for row in cursor.fetchall())

        return self._run_transaction(operation)

    def insert(self, record: EncryptedCredentialRecord) -> None:
        _validate_credential_record(record)

        def operation(cursor: DbApiCursor) -> None:
            vault = _select_vault_metadata(cursor)
            envelope = record.envelope
            metadata = record.metadata
            cursor.execute(
                INSERT_CREDENTIAL_SQL,
                str(vault.vault_id),
                metadata.credential_id.value,
                envelope.format_version,
                envelope.algorithm,
                bytes(envelope.ciphertext),
                bytes(envelope.nonce),
                bytes(envelope.authentication_tag),
                bytes(envelope.associated_data),
                metadata.created_at,
                metadata.updated_at,
                metadata.revision,
            )
            _require_one_affected_row(cursor)

        self._run_transaction(operation, duplicate_error=CredentialAlreadyExistsError)

    def update(self, record: EncryptedCredentialRecord) -> None:
        _validate_credential_record(record)

        def operation(cursor: DbApiCursor) -> None:
            vault = _select_vault_metadata(cursor)
            envelope = record.envelope
            metadata = record.metadata
            cursor.execute(
                UPDATE_CREDENTIAL_SQL,
                envelope.format_version,
                envelope.algorithm,
                bytes(envelope.ciphertext),
                bytes(envelope.nonce),
                bytes(envelope.authentication_tag),
                bytes(envelope.associated_data),
                metadata.updated_at,
                metadata.revision,
                str(vault.vault_id),
                metadata.credential_id.value,
            )
            if cursor.rowcount == 0:
                raise CredentialNotFoundError()
            _require_one_affected_row(cursor)

        self._run_transaction(operation)

    def delete(self, credential_id: CredentialId) -> None:
        _validate_credential_id(credential_id)

        def operation(cursor: DbApiCursor) -> None:
            vault = _select_vault_metadata(cursor)
            cursor.execute(DELETE_CREDENTIAL_SQL, str(vault.vault_id), credential_id.value)
            if cursor.rowcount == 0:
                raise CredentialNotFoundError()
            _require_one_affected_row(cursor)

        self._run_transaction(operation)

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> SqlServerCredentialRepository:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RepositoryError()

    def _run_transaction(
        self,
        operation: Callable[[DbApiCursor], T],
        *,
        duplicate_error: type[PasswordLockerError] | None = None,
    ) -> T:
        self._ensure_open()
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
        except Exception as error:
            _safe_rollback(connection)
            if duplicate_error is not None and _is_duplicate_key_error(error):
                raise duplicate_error() from None
            raise RepositoryError() from None
        finally:
            _safe_close(cursor)
            _safe_close(connection)

    def __repr__(self) -> str:
        state = "closed" if self._closed else "ready"
        return f"SqlServerCredentialRepository(state={state!r})"

    __str__ = __repr__


T = TypeVar("T")


def _build_connection_string(config: SQLServerConfig) -> str:
    attributes = [
        f"DRIVER={_quote_odbc_value(config.odbc_driver)}",
        f"SERVER={_quote_odbc_value(config.server)}",
        f"DATABASE={_quote_odbc_value(config.database)}",
        "Encrypt=Yes",
        "TrustServerCertificate=No",
        f"Connection Timeout={config.connection_timeout}",
    ]
    if config.authentication_mode is AuthenticationMode.WINDOWS_INTEGRATED:
        attributes.append("Trusted_Connection=Yes")
    else:
        if config.username is None or config.password is None:
            raise RepositoryError()
        attributes.extend(
            (
                f"UID={_quote_odbc_value(config.username)}",
                f"PWD={_quote_odbc_value(config.password.get_secret_value())}",
            )
        )
    return ";".join(attributes) + ";"


def _quote_odbc_value(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def _select_vault_metadata(cursor: DbApiCursor) -> VaultMetadata:
    cursor.execute(SELECT_VAULT_SQL)
    rows = list(cursor.fetchall())
    if not rows:
        raise VaultNotInitializedError()
    if len(rows) != 1:
        raise RepositoryError()
    return _vault_metadata_from_row(rows[0])


def _vault_metadata_from_row(row: Sequence[object]) -> VaultMetadata:
    try:
        envelope = EncryptedEnvelope(
            ciphertext=_binary(row[11]),
            nonce=_binary(row[12]),
            authentication_tag=_binary(row[13]),
            associated_data=_binary(row[14]),
            algorithm=_text(row[9]),
            format_version=_integer(row[10]),
        )
        metadata = VaultMetadata(
            vault_id=UUID(str(row[0])),
            format_version=_integer(row[1]),
            key_derivation_algorithm=_text(row[2]),
            key_derivation_version=_integer(row[3]),
            key_derivation_memory_cost=_integer(row[4]),
            key_derivation_time_cost=_integer(row[5]),
            key_derivation_parallelism=_integer(row[6]),
            derived_key_length=_integer(row[7]),
            key_derivation_salt=_binary(row[8]),
            wrapped_data_encryption_key=envelope,
        )
        _validate_vault_metadata(metadata)
        return metadata
    except PasswordLockerError:
        raise
    except Exception:
        raise RepositoryError() from None


def _credential_from_row(row: Sequence[object]) -> EncryptedCredentialRecord:
    try:
        metadata = _credential_metadata_from_row(row[:4])
        envelope = EncryptedEnvelope(
            ciphertext=_binary(row[6]),
            nonce=_binary(row[7]),
            authentication_tag=_binary(row[8]),
            associated_data=_binary(row[9]),
            algorithm=_text(row[5]),
            format_version=_integer(row[4]),
        )
        record = EncryptedCredentialRecord(metadata, envelope)
        _validate_credential_record(record)
        return record
    except PasswordLockerError:
        raise
    except Exception:
        raise RepositoryError() from None


def _credential_metadata_from_row(row: Sequence[object]) -> CredentialMetadata:
    try:
        raw_account = _text(row[0])
        credential_id = CredentialId(raw_account)
        if credential_id.value != raw_account:
            raise RepositoryError()
        created_at = row[1]
        updated_at = row[2]
        if not isinstance(created_at, datetime) or not isinstance(updated_at, datetime):
            raise RepositoryError()
        return CredentialMetadata(
            credential_id=credential_id,
            created_at=created_at,
            updated_at=updated_at,
            revision=_integer(row[3]),
        )
    except PasswordLockerError:
        raise
    except Exception:
        raise RepositoryError() from None


def _validate_vault_metadata(metadata: VaultMetadata) -> None:
    if not isinstance(metadata, VaultMetadata):
        raise ValidationError()
    envelope = metadata.wrapped_data_encryption_key
    if metadata.format_version != CURRENT_VAULT_VERSION:
        raise ValidationError()
    if len(metadata.key_derivation_salt) != 16 or metadata.derived_key_length != 32:
        raise ValidationError()
    if envelope.format_version != CURRENT_ENVELOPE_VERSION:
        raise ValidationError()
    if len(envelope.ciphertext) != 32:
        raise ValidationError()
    _validate_envelope_binary(envelope)


def _validate_credential_record(record: EncryptedCredentialRecord) -> None:
    if not isinstance(record, EncryptedCredentialRecord):
        raise ValidationError()
    _validate_credential_id(record.metadata.credential_id)
    if record.envelope.format_version != CURRENT_ENVELOPE_VERSION:
        raise ValidationError()
    _validate_envelope_binary(record.envelope)


def _validate_envelope_binary(envelope: EncryptedEnvelope) -> None:
    if len(envelope.nonce) != 12 or len(envelope.authentication_tag) != 16:
        raise ValidationError()
    if not envelope.ciphertext or not envelope.associated_data:
        raise ValidationError()


def _validate_credential_id(credential_id: CredentialId) -> None:
    if not isinstance(credential_id, CredentialId) or not credential_id.value:
        raise ValidationError()


def _require_one_affected_row(cursor: DbApiCursor) -> None:
    if cursor.rowcount != 1:
        raise RepositoryError()


def _binary(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RepositoryError()
    result = bytes(value)
    if not result:
        raise RepositoryError()
    return result


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RepositoryError()
    return value


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RepositoryError()
    return value


def _is_duplicate_key_error(error: Exception) -> bool:
    sqlstate = getattr(error, "sqlstate", None)
    if sqlstate == "23000":
        return True
    native_values = (
        getattr(error, "native_error", None),
        getattr(error, "native_code", None),
        getattr(error, "errno", None),
    )
    if any(value in (2601, 2627) for value in native_values):
        return True
    for argument in getattr(error, "args", ()):
        if argument == "23000" or argument == 2601 or argument == 2627:
            return True
        if isinstance(argument, tuple) and any(item in {"23000", 2601, 2627} for item in argument):
            return True
        if isinstance(argument, str) and re.search(r"(?<!\d)(?:2601|2627)(?!\d)", argument):
            return True
    return False


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
