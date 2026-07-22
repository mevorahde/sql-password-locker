from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pw_locker_sql.gui import app
from pw_locker_sql.gui.view import TkVaultView
from tests.subprocess_environment import isolated_subprocess_environment


def test_gui_imports_have_no_side_effects(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "src"
    guard = """def guard(event, args):
    if event == "open" and str(args[0]).lower().endswith((".env", ".db", ".log")):
        raise RuntimeError("protected read blocked")
    if event == "open" and isinstance(args[1], str) and any(flag in args[1] for flag in "wax+"):
        raise RuntimeError("filesystem write blocked")
    if event in {"socket.connect", "socket.bind", "subprocess.Popen"}:
        raise RuntimeError("external side effect blocked")
"""
    script = (
        "import sys, threading;"
        f"sys.path.insert(0, {str(source)!r});"
        "threading.Thread.start=lambda self: (_ for _ in ()).throw(RuntimeError('thread blocked'));"
        f"exec({guard!r});sys.addaudithook(guard);"
        "import pw_locker_sql.gui.app;"
        "import pw_locker_sql.gui.controller;"
        "import importlib.resources;"
        "importlib.resources.files=lambda *args: "
        "(_ for _ in ()).throw(RuntimeError('asset blocked'));"
        "import pw_locker_sql.gui.icon;"
        "import pw_locker_sql.gui.operations;"
        "import pw_locker_sql.gui.presenter;"
        "import pw_locker_sql.gui.view;"
        "assert 'tkinter' not in sys.modules;"
        "assert 'dotenv' not in sys.modules;"
        "assert 'pyodbc' not in sys.modules;"
        "assert 'pyperclip' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=tmp_path,
        env=isolated_subprocess_environment(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONIOENCODING": "utf-8",
            }
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    application_artifacts = [path for path in tmp_path.iterdir() if path.name != "_norton_"]
    assert application_artifacts == []


def test_main_is_the_only_root_creation_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_tk() -> object:
        calls.append("root")
        raise RuntimeError("SYNTHETIC_NO_DISPLAY")

    monkeypatch.setitem(sys.modules, "tkinter", SimpleNamespace(Tk=fake_tk))
    assert calls == []
    assert app.main() == 70
    assert calls == ["root"]


class FakeVariable:
    def __init__(self, value: bool) -> None:
        self.value = value

    def get(self) -> bool:
        return self.value


class FakeEntry:
    def __init__(self) -> None:
        self.show = "*"

    def configure(self, *, show: str) -> None:
        self.show = show


def test_password_visibility_toggles_presentation_without_reading_values() -> None:
    view = TkVaultView.__new__(TkVaultView)
    view._create_show = FakeVariable(False)  # type: ignore[attr-defined]
    view._create_password_entry = FakeEntry()  # type: ignore[attr-defined]
    view._create_confirm_entry = FakeEntry()  # type: ignore[attr-defined]
    view._toggle_create_visibility()
    assert view._create_password_entry.show == "*"  # type: ignore[attr-defined]
    assert view._create_confirm_entry.show == "*"  # type: ignore[attr-defined]
    view._create_show.value = True  # type: ignore[attr-defined]
    view._toggle_create_visibility()
    assert view._create_password_entry.show == ""  # type: ignore[attr-defined]
    assert view._create_confirm_entry.show == ""  # type: ignore[attr-defined]

    view._unlock_show = FakeVariable(False)  # type: ignore[attr-defined]
    view._unlock_entry = FakeEntry()  # type: ignore[attr-defined]
    view._toggle_unlock_visibility()
    assert view._unlock_entry.show == "*"  # type: ignore[attr-defined]
    view._unlock_show.value = True  # type: ignore[attr-defined]
    view._toggle_unlock_visibility()
    assert view._unlock_entry.show == ""  # type: ignore[attr-defined]

    view._credential_show = FakeVariable(False)  # type: ignore[attr-defined]
    view._credential_password_entry = FakeEntry()  # type: ignore[attr-defined]
    view._credential_confirm_entry = FakeEntry()  # type: ignore[attr-defined]
    view._toggle_credential_visibility()
    assert view._credential_password_entry.show == "*"  # type: ignore[attr-defined]
    assert view._credential_confirm_entry.show == "*"  # type: ignore[attr-defined]
    view._credential_show.value = True  # type: ignore[attr-defined]
    view._toggle_credential_visibility()
    assert view._credential_password_entry.show == ""  # type: ignore[attr-defined]
    assert view._credential_confirm_entry.show == ""  # type: ignore[attr-defined]
