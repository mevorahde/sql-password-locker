"""Import-safe compatibility entry point for the SQL vault copy command."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from pw_locker_sql import cli


def main(argv: Sequence[str] | None = None) -> int:
    """Delegate ``pwsql ACCOUNT`` to ``pw-locker-sql copy ACCOUNT``."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    return cli.main(_copy_arguments(arguments))


def _copy_arguments(arguments: list[str]) -> list[str]:
    if arguments[:1] == ["--no-env-file"]:
        return ["--no-env-file", "copy", *arguments[1:]]
    if arguments[:1] == ["--env-file"]:
        if len(arguments) == 1:
            return arguments
        return ["--env-file", arguments[1], "copy", *arguments[2:]]
    if arguments and arguments[0].startswith("--env-file="):
        return [arguments[0], "copy", *arguments[1:]]
    return ["copy", *arguments]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
