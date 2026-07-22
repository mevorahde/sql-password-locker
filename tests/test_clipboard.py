from __future__ import annotations

import importlib

import pytest

from pw_locker_sql.clipboard import PyperclipClipboardProvider
from pw_locker_sql.errors import ClipboardError


class FakePyperclip:
    def __init__(self) -> None:
        self.value = ""
        self.fail = False

    def copy(self, text: str) -> None:
        if self.fail:
            raise RuntimeError("SYNTHETIC_CLIPBOARD_DIAGNOSTIC")
        self.value = text

    def paste(self) -> str:
        if self.fail:
            raise RuntimeError("SYNTHETIC_CLIPBOARD_DIAGNOSTIC")
        return self.value


def test_pyperclip_is_loaded_only_for_an_explicit_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = FakePyperclip()
    calls: list[str] = []

    def fake_import(name: str) -> FakePyperclip:
        calls.append(name)
        return module

    monkeypatch.setattr(importlib, "import_module", fake_import)
    clipboard = PyperclipClipboardProvider()
    assert calls == []
    clipboard.copy("SYNTHETIC_CLIPBOARD_VALUE")
    assert calls == ["pyperclip"]
    assert clipboard.read() == "SYNTHETIC_CLIPBOARD_VALUE"
    clipboard.clear()
    assert module.value == ""


def test_clipboard_failure_is_generic_and_secret_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    module = FakePyperclip()
    module.fail = True
    monkeypatch.setattr(importlib, "import_module", lambda _name: module)
    with pytest.raises(ClipboardError) as captured:
        PyperclipClipboardProvider().copy("SYNTHETIC_CLIPBOARD_VALUE")
    rendered = str(captured.value) + repr(captured.value)
    assert "SYNTHETIC_CLIPBOARD_VALUE" not in rendered
    assert "SYNTHETIC_CLIPBOARD_DIAGNOSTIC" not in rendered


def test_clipboard_provider_repr_contains_no_contents() -> None:
    rendered = repr(PyperclipClipboardProvider())
    assert rendered == "PyperclipClipboardProvider()"
