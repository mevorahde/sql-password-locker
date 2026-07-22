from __future__ import annotations

import os
from collections.abc import Mapping

from pw_locker_sql.runtime import ENVIRONMENT_KEY_MAP

_BLOCKED_NAMES = frozenset({name.casefold() for name in ENVIRONMENT_KEY_MAP} | {"pytest_addopts"})
_BLOCKED_PREFIXES = ("odbc_", "pw_locker_sql_", "python", "sqlserver_", "sql_")
_CREDENTIAL_MARKERS = (
    "api_key",
    "connection_string",
    "credential",
    "password",
    "secret",
    "token",
)
_SAFE_OVERRIDE_NAMES = frozenset(
    {"pythondontwritebytecode", "pythonioencoding", "stage2_sentinel"}
)


def _is_blocked(name: str) -> bool:
    normalized = name.casefold()
    return (
        normalized in _BLOCKED_NAMES
        or normalized.startswith(_BLOCKED_PREFIXES)
        or normalized == "database_url"
        or any(marker in normalized for marker in _CREDENTIAL_MARKERS)
    )


def isolated_subprocess_environment(overrides: Mapping[str, str]) -> dict[str, str]:
    """Preserve the host process environment without leaking vault or pytest opt-ins."""

    environment = os.environ.copy()
    for name in tuple(environment):
        if _is_blocked(name):
            environment.pop(name, None)
    if any(
        _is_blocked(name) and name.casefold() not in _SAFE_OVERRIDE_NAMES for name in overrides
    ):
        raise ValueError("blocked subprocess environment override")
    environment.update(overrides)
    return environment
