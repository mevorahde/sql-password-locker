from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from struct import pack
from typing import Any

import pytest

from pw_locker_sql.config import SQLServerConfig
from pw_locker_sql.errors import RepositoryError
from pw_locker_sql.repositories.datetimeoffset import (
    SQL_SS_TIMESTAMPOFFSET,
    decode_sql_server_datetimeoffset,
)
from pw_locker_sql.repositories.sql_server import (
    SqlServerConnectionFactory,
    SqlServerCredentialRepository,
)


def _payload(
    *,
    year: int = 2026,
    month: int = 1,
    day: int = 2,
    hour: int = 3,
    minute: int = 4,
    second: int = 5,
    fraction: int = 0,
    timezone_hour: int = 0,
    timezone_minute: int = 0,
) -> bytes:
    return pack(
        "<6hI2h",
        year,
        month,
        day,
        hour,
        minute,
        second,
        fraction,
        timezone_hour,
        timezone_minute,
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (_payload(), datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        (
            _payload(timezone_hour=2),
            datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2))),
        ),
        (
            _payload(timezone_hour=-7),
            datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=-7))),
        ),
        (
            _payload(timezone_hour=5, timezone_minute=30),
            datetime(
                2026,
                1,
                2,
                3,
                4,
                5,
                tzinfo=timezone(timedelta(hours=5, minutes=30)),
            ),
        ),
        (
            _payload(fraction=123_456_700),
            datetime(2026, 1, 2, 3, 4, 5, 123_456, tzinfo=timezone.utc),
        ),
        (
            _payload(year=2024, month=2, day=29),
            datetime(2024, 2, 29, 3, 4, 5, tzinfo=timezone.utc),
        ),
    ],
    ids=("utc", "positive", "negative", "half-hour", "fraction", "leap-day"),
)
def test_datetimeoffset_decoder_returns_aware_datetime(
    payload: bytes,
    expected: datetime,
) -> None:
    assert decode_sql_server_datetimeoffset(payload) == expected


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"X" * 19,
        b"X" * 21,
        _payload(year=0),
        _payload(month=13),
        _payload(year=2025, month=2, day=29),
        _payload(hour=24),
        _payload(minute=60),
        _payload(second=60),
        _payload(fraction=1_000_000_000),
        _payload(fraction=123),
        _payload(timezone_hour=15),
        _payload(timezone_minute=60),
        _payload(timezone_hour=1, timezone_minute=-30),
        _payload(timezone_hour=-1, timezone_minute=30),
        _payload(timezone_hour=14, timezone_minute=1),
        _payload(timezone_hour=-14, timezone_minute=-1),
    ],
)
def test_datetimeoffset_decoder_rejects_malformed_bytes_without_values(
    payload: bytes,
) -> None:
    with pytest.raises(ValueError) as captured:
        decode_sql_server_datetimeoffset(payload)
    assert str(captured.value) == "The SQL Server datetimeoffset payload is invalid."
    assert repr(payload) not in str(captured.value)


@pytest.mark.parametrize("payload", [bytearray(20), memoryview(bytes(20)), "X" * 20])
def test_datetimeoffset_decoder_requires_exact_bytes_type(payload: object) -> None:
    with pytest.raises(ValueError) as captured:
        decode_sql_server_datetimeoffset(payload)  # type: ignore[arg-type]
    assert str(captured.value) == "The SQL Server datetimeoffset payload is invalid."


class TrackingConnection:
    def __init__(self, events: list[str], *, registration_error: Exception | None = None) -> None:
        self.events = events
        self.registration_error = registration_error
        self.registrations: list[tuple[int, Callable[[bytes], object]]] = []
        self.closed = False

    def add_output_converter(
        self,
        sqltype: int,
        func: Callable[[bytes], object],
    ) -> None:
        self.events.append("register")
        if self.registration_error is not None:
            raise self.registration_error
        self.registrations.append((sqltype, func))

    def cursor(self) -> object:
        self.events.append("cursor")
        return object()

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        self.events.append("close")
        self.closed = True


class TrackingConnector:
    def __init__(self, *connections: TrackingConnection) -> None:
        self.connections = list(connections)

    def connect(
        self,
        _connection_string: str,
        *,
        autocommit: bool,
        timeout: int,
    ) -> TrackingConnection:
        assert autocommit is False
        assert timeout == 15
        connection = self.connections.pop(0)
        connection.events.append("connect")
        return connection


def _config() -> SQLServerConfig:
    return SQLServerConfig.from_mapping(
        {
            "SERVER": "SERVER_PLACEHOLDER",
            "DATABASE": "DATABASE_PLACEHOLDER",
            "AUTH_MODE": "integrated",
        }
    )


def test_each_new_connection_registers_once_before_its_first_cursor() -> None:
    first_events: list[str] = []
    second_events: list[str] = []
    first = TrackingConnection(first_events)
    second = TrackingConnection(second_events)
    factory = SqlServerConnectionFactory(
        _config(),
        TrackingConnector(first, second),  # type: ignore[arg-type]
    )

    opened_first = factory()
    opened_first.cursor()
    opened_second = factory()
    opened_second.cursor()

    assert first_events == ["connect", "register", "cursor"]
    assert second_events == ["connect", "register", "cursor"]
    assert len(first.registrations) == len(second.registrations) == 1
    assert first.registrations[0][0] == second.registrations[0][0] == SQL_SS_TIMESTAMPOFFSET
    assert first.registrations[0][1] is decode_sql_server_datetimeoffset
    assert second.registrations[0][1] is decode_sql_server_datetimeoffset


def test_registration_failure_is_redacted_and_closes_connection(
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[str] = []
    connection = TrackingConnection(
        events,
        registration_error=RuntimeError("SYNTHETIC_RAW_REGISTRATION_VALUE"),
    )
    factory = SqlServerConnectionFactory(
        _config(),
        TrackingConnector(connection),  # type: ignore[arg-type]
    )

    with pytest.raises(RepositoryError) as captured:
        factory()

    assert events == ["connect", "register", "close"]
    assert connection.closed
    assert "SYNTHETIC_RAW_REGISTRATION_VALUE" not in str(captured.value)
    assert caplog.records == []


class ConverterFailureCursor:
    rowcount = -1

    def __init__(self) -> None:
        self.closed = False

    def execute(self, _operation: str, *_parameters: object) -> ConverterFailureCursor:
        return self

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> Any:
        return (decode_sql_server_datetimeoffset(b"SYNTHETIC_RAW_PAYLOAD"),)

    def close(self) -> None:
        self.closed = True


class ConverterFailureConnection:
    def __init__(self) -> None:
        self.failure_cursor = ConverterFailureCursor()
        self.rollbacks = 0
        self.closed = False

    def cursor(self) -> ConverterFailureCursor:
        return self.failure_cursor

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


def test_converter_failure_is_translated_and_resources_close() -> None:
    connection = ConverterFailureConnection()
    repository = SqlServerCredentialRepository(lambda: connection)

    with pytest.raises(RepositoryError) as captured:
        repository.get_vault_metadata()

    assert "SYNTHETIC_RAW_PAYLOAD" not in str(captured.value)
    assert connection.rollbacks == 1
    assert connection.failure_cursor.closed
    assert connection.closed
