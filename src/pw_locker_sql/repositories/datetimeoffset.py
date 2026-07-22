"""Safe conversion of SQL Server ``datetimeoffset`` ODBC payloads."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from struct import Struct
from struct import error as StructError
from typing import Protocol

SQL_SS_TIMESTAMPOFFSET = -155

# SQL_SS_TIMESTAMPOFFSET_STRUCT contains six signed 16-bit calendar/time
# components, an unsigned nanosecond fraction, and two signed 16-bit offset
# components. SQL Server supplies the fraction in 100-nanosecond increments.
_TIMESTAMPOFFSET_STRUCT = Struct("<6hI2h")
_INVALID_PAYLOAD_MESSAGE = "The SQL Server datetimeoffset payload is invalid."


class OutputConverterConnection(Protocol):
    """The pyodbc connection surface needed to register an output converter."""

    def add_output_converter(
        self,
        sqltype: int,
        func: Callable[[bytes], object],
    ) -> None: ...


def decode_sql_server_datetimeoffset(payload: bytes) -> datetime:
    """Decode a ``SQL_SS_TIMESTAMPOFFSET_STRUCT`` into an aware datetime.

    Python cannot represent SQL Server's final 100-nanosecond digit. Conversion
    deterministically truncates that sub-microsecond digit toward zero.
    """

    if type(payload) is not bytes or len(payload) != _TIMESTAMPOFFSET_STRUCT.size:
        raise ValueError(_INVALID_PAYLOAD_MESSAGE)
    try:
        (
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction,
            timezone_hour,
            timezone_minute,
        ) = _TIMESTAMPOFFSET_STRUCT.unpack(payload)
        _validate_fraction(fraction)
        offset_minutes = _validated_offset_minutes(timezone_hour, timezone_minute)
        return datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction // 1_000,
            tzinfo=timezone(timedelta(minutes=offset_minutes)),
        )
    except (OverflowError, StructError, ValueError):
        raise ValueError(_INVALID_PAYLOAD_MESSAGE) from None


def register_sql_server_datetimeoffset_converter(
    connection: OutputConverterConnection,
) -> None:
    """Register the SQL Server datetimeoffset decoder on one new connection."""

    connection.add_output_converter(
        SQL_SS_TIMESTAMPOFFSET,
        decode_sql_server_datetimeoffset,
    )


def _validate_fraction(fraction: int) -> None:
    if not 0 <= fraction <= 999_999_999 or fraction % 100 != 0:
        raise ValueError(_INVALID_PAYLOAD_MESSAGE)


def _validated_offset_minutes(timezone_hour: int, timezone_minute: int) -> int:
    if not -14 <= timezone_hour <= 14 or not -59 <= timezone_minute <= 59:
        raise ValueError(_INVALID_PAYLOAD_MESSAGE)
    if (timezone_hour > 0 and timezone_minute < 0) or (
        timezone_hour < 0 and timezone_minute > 0
    ):
        raise ValueError(_INVALID_PAYLOAD_MESSAGE)
    offset_minutes = timezone_hour * 60 + timezone_minute
    if not -14 * 60 <= offset_minutes <= 14 * 60:
        raise ValueError(_INVALID_PAYLOAD_MESSAGE)
    return offset_minutes
