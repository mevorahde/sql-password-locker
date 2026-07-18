"""Lazy package-resource loading for the application window icon."""

from __future__ import annotations

from importlib.resources import as_file, files
from typing import Any

ASSET_PACKAGE = "pw_locker_sql.assets"
PNG_ICON_NAME = "sql-password-locker.png"
ICO_ICON_NAME = "sql-password-locker.ico"


def icon_resource(name: str) -> Any:
    """Resolve an icon relative to the installed assets package."""
    if name not in {PNG_ICON_NAME, ICO_ICON_NAME}:
        raise ValueError("unsupported icon resource")
    return files(ASSET_PACKAGE).joinpath(name)


def apply_window_icon(root: Any, tkinter_module: Any) -> None:
    """Best-effort icon setup; cosmetic failures never block application startup."""
    try:
        with as_file(icon_resource(ICO_ICON_NAME)) as ico_path:
            root.iconbitmap(default=str(ico_path))
    except Exception:
        pass

    try:
        image = tkinter_module.PhotoImage(data=icon_resource(PNG_ICON_NAME).read_bytes())
        root.iconphoto(True, image)
        root._pw_locker_icon_photo = image
    except Exception:
        pass
