"""Import-safe command-line boundary for deferred operational implementations."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

EXIT_OK = 0
EXIT_UNAVAILABLE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pw-locker-sql",
        description="SQL Server Password Locker foundation",
    )
    subparsers = parser.add_subparsers(dest="command")
    for command in ("initialize", "unlock", "list", "get", "set", "delete"):
        subparsers.add_parser(command, help=f"{command.title()} support is deferred")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        if error.code == EXIT_OK:
            return EXIT_OK
        raise
    if arguments.command is None:
        parser.print_help()
        return EXIT_OK
    print(
        "Operation unavailable until SQL and cryptographic providers are configured.",
        file=sys.stderr,
    )
    return EXIT_UNAVAILABLE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
