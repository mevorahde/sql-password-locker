from __future__ import annotations

import os
from collections.abc import Mapping

from pw_locker_sql.runtime import ENVIRONMENT_KEY_MAP

_BLOCKED_NAMES = frozenset(
    {name.casefold() for name in ENVIRONMENT_KEY_MAP} | {"pytest_addopts"}
)


def isolated_subprocess_environment(overrides: Mapping[str, str]) -> dict[str, str]:
    """Preserve the host process environment without leaking vault or pytest opt-ins."""

    environment = os.environ.copy()
    for name in tuple(environment):
        if name.casefold() in _BLOCKED_NAMES:
            environment.pop(name, None)
    if any(name.casefold() in _BLOCKED_NAMES for name in overrides):
        raise ValueError("blocked subprocess environment override")
    environment.update(overrides)
    return environment
