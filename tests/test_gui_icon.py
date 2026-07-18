from __future__ import annotations

import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from pw_locker_sql.gui import app
from pw_locker_sql.gui.icon import (
    ICO_ICON_NAME,
    PNG_ICON_NAME,
    apply_window_icon,
    icon_resource,
)

PNG_SHA256 = "14449eba94875329430ec3e464d39cf9bbc068a57c75bec893e9411943329097"
ICO_SHA256 = "0b6fe84c03e40d2f10d85cb85555d5852e74b31cd4294dec2a41e87ee334bfc5"


def test_packaged_icons_match_approved_asset_hashes() -> None:
    assert sha256(icon_resource(PNG_ICON_NAME).read_bytes()).hexdigest() == PNG_SHA256
    assert sha256(icon_resource(ICO_ICON_NAME).read_bytes()).hexdigest() == ICO_SHA256


def test_assets_are_package_relative_and_declared_as_package_data() -> None:
    assert icon_resource(PNG_ICON_NAME).name == PNG_ICON_NAME
    assert icon_resource(ICO_ICON_NAME).name == ICO_ICON_NAME
    project_root = Path(__file__).resolve().parents[1]
    metadata = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    assert '"pw_locker_sql.assets" = ["*.png", "*.ico"]' in metadata
    assert "C:\\Users\\" not in metadata
    runtime_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (project_root / "src" / "pw_locker_sql").rglob("*.py")
    )
    assert "C:\\Users\\" not in runtime_source
    assert "self-assessment-tips-chatgpt-conversation" not in runtime_source


class FakeIconRoot:
    def __init__(self, events: list[str], *, fail: bool = False) -> None:
        self.events = events
        self.fail = fail

    def iconbitmap(self, *, default: str) -> None:
        if self.fail:
            raise RuntimeError("SYNTHETIC_COSMETIC_FAILURE")
        assert default.endswith("sql-password-locker.ico")
        self.events.append("ico")

    def iconphoto(self, default: bool, image: object) -> None:
        if self.fail:
            raise RuntimeError("SYNTHETIC_COSMETIC_FAILURE")
        assert default is True
        self.events.append("png")


class FakeTkModule:
    def __init__(self, events: list[str], *, fail: bool = False) -> None:
        self.events = events
        self.fail = fail

    def PhotoImage(self, *, data: bytes) -> object:  # noqa: N802
        if self.fail:
            raise RuntimeError("SYNTHETIC_COSMETIC_FAILURE")
        assert data
        self.events.append("photo")
        return object()


def test_icon_applies_ico_and_png_and_retains_photo_reference() -> None:
    events: list[str] = []
    root = FakeIconRoot(events)
    apply_window_icon(root, FakeTkModule(events))
    assert events == ["ico", "photo", "png"]
    assert root._pw_locker_icon_photo is not None  # type: ignore[attr-defined]


def test_cosmetic_icon_failure_does_not_block_startup() -> None:
    apply_window_icon(FakeIconRoot([], fail=True), FakeTkModule([], fail=True))


def test_application_applies_icon_before_constructing_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Root:
        def mainloop(self) -> None:
            events.append("mainloop")

        def destroy(self) -> None:
            events.append("destroy")

    root = Root()
    tkinter_module = SimpleNamespace(Tk=lambda: root)
    monkeypatch.setitem(sys.modules, "tkinter", tkinter_module)

    import pw_locker_sql.gui.icon as icon_module
    import pw_locker_sql.gui.operations as operations_module
    import pw_locker_sql.gui.presenter as presenter_module
    import pw_locker_sql.gui.view as view_module

    monkeypatch.setattr(icon_module, "apply_window_icon", lambda *_args: events.append("icon"))

    class View:
        def __init__(self, _root: object) -> None:
            events.append("view")

        def bind_presenter(self, _presenter: object) -> None:
            events.append("bind")

    class Presenter:
        def __init__(self, *_args: object) -> None:
            events.append("presenter")

        def start(self) -> None:
            events.append("start")

    monkeypatch.setattr(view_module, "TkVaultView", View)
    monkeypatch.setattr(view_module, "TkScheduler", lambda _root: object())
    monkeypatch.setattr(view_module, "TkDeleteConfirmation", lambda _root: object())
    monkeypatch.setattr(operations_module, "SingleWorkerExecutor", lambda: object())
    monkeypatch.setattr(operations_module, "OperationCoordinator", lambda *_args: object())
    monkeypatch.setattr(presenter_module, "VaultGuiPresenter", Presenter)

    assert app.main() == 0
    assert events[:2] == ["icon", "view"]
    assert events[-2:] == ["start", "mainloop"]
