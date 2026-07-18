"""Lazy, secret-safe clipboard boundary."""

from __future__ import annotations

import importlib
from typing import Protocol, cast

from pw_locker_sql.errors import ClipboardError


class ClipboardProvider(Protocol):
    def copy(self, value: str) -> None: ...

    def read(self) -> str: ...

    def clear(self) -> None: ...


class _PyperclipModule(Protocol):
    def copy(self, text: str) -> None: ...

    def paste(self) -> str: ...


class PyperclipClipboardProvider:
    """Loads pyperclip and accesses the clipboard only on an explicit operation."""

    def _module(self) -> _PyperclipModule:
        try:
            return cast(_PyperclipModule, importlib.import_module("pyperclip"))
        except Exception:
            raise ClipboardError() from None

    def copy(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise ClipboardError()
        try:
            self._module().copy(value)
        except ClipboardError:
            raise
        except Exception:
            raise ClipboardError() from None

    def read(self) -> str:
        try:
            value = self._module().paste()
        except ClipboardError:
            raise
        except Exception:
            raise ClipboardError() from None
        if not isinstance(value, str):
            raise ClipboardError()
        return value

    def clear(self) -> None:
        try:
            self._module().copy("")
        except ClipboardError:
            raise
        except Exception:
            raise ClipboardError() from None

    def __repr__(self) -> str:
        return "PyperclipClipboardProvider()"

    __str__ = __repr__
