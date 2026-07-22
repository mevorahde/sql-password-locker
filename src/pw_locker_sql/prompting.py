"""Injectable secure terminal prompting without import-time interaction."""

from __future__ import annotations

import getpass
import sys
from typing import Protocol, TextIO

from pw_locker_sql.errors import SecurePromptError


class PromptProvider(Protocol):
    def secret(self, prompt: str) -> str: ...

    def confirm(self, prompt: str) -> bool: ...


class TerminalPromptProvider:
    """Rejects redirected input instead of allowing echoed secret fallback."""

    def __init__(self, input_stream: TextIO | None = None) -> None:
        self._input = input_stream or sys.stdin

    def secret(self, prompt: str) -> str:
        self._require_terminal()
        try:
            value = getpass.getpass(prompt, stream=sys.stderr)
        except KeyboardInterrupt:
            raise
        except (EOFError, OSError):
            raise SecurePromptError() from None
        except Exception:
            raise SecurePromptError() from None
        if not value:
            raise SecurePromptError()
        return value

    def confirm(self, prompt: str) -> bool:
        self._require_terminal()
        try:
            print(prompt, end="", file=sys.stderr, flush=True)
            response = self._input.readline()
        except KeyboardInterrupt:
            raise
        except (EOFError, OSError):
            raise SecurePromptError() from None
        except Exception:
            raise SecurePromptError() from None
        if response == "":
            raise SecurePromptError()
        return response.strip().casefold() in {"y", "yes"}

    def _require_terminal(self) -> None:
        try:
            interactive = self._input.isatty()
        except Exception:
            raise SecurePromptError() from None
        if not interactive:
            raise SecurePromptError()

    def __repr__(self) -> str:
        return "TerminalPromptProvider()"

    __str__ = __repr__
