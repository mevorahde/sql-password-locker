"""Tkinter widgets for the SQL Password Locker; no root is created on import."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pw_locker_sql.gui.presenter import VaultGuiPresenter


class TkVaultView:
    """Concrete ttk view containing no vault, cryptographic, or SQL decisions."""

    def __init__(self, root: Any) -> None:
        import tkinter as tk
        from tkinter import ttk

        self._tk = tk
        self._ttk = ttk
        self._root = root
        self._presenter: VaultGuiPresenter | None = None
        self._destroyed = False
        root.title("SQL Password Locker")
        root.minsize(760, 500)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        self._container = ttk.Frame(root, padding=16)
        self._container.grid(row=0, column=0, sticky="nsew")
        self._container.columnconfigure(0, weight=1)
        self._container.rowconfigure(0, weight=1)
        self._status = tk.StringVar(value="")
        self._frames: list[object] = []
        self._busy_widgets: list[object] = []
        self._selection_widgets: list[object] = []
        self._build_startup()
        self._build_create()
        self._build_unlock()
        self._build_main()
        ttk.Label(self._container, textvariable=self._status, anchor="w").grid(
            row=1,
            column=0,
            sticky="ew",
            pady=(12, 0),
        )

    def bind_presenter(self, presenter: VaultGuiPresenter) -> None:
        self._presenter = presenter
        self._retry.configure(command=presenter.retry)
        self._startup_close.configure(command=presenter.close)
        self._create_button.configure(command=self._submit_create)
        self._create_confirm_entry.bind("<Return>", self._create_return)
        self._unlock_button.configure(command=self._submit_unlock)
        self._unlock_entry.bind("<Return>", self._unlock_return)
        self._refresh_button.configure(command=presenter.refresh)
        self._copy_button.configure(command=presenter.copy_selected)
        self._delete_button.configure(command=presenter.delete_selected)
        self._save_button.configure(command=self._submit_save)
        self._credential_confirm_entry.bind("<Return>", self._save_return)
        self._lock_button.configure(command=presenter.lock)
        self._accounts.bind("<<ListboxSelect>>", self._selection_changed)
        self._root.protocol("WM_DELETE_WINDOW", presenter.close)
        self._root.bind_all("<KeyPress>", self._activity, add="+")
        self._root.bind_all("<ButtonPress>", self._activity, add="+")

    def show_startup(self, message: str, *, retry: bool = False) -> None:
        self._show(self._startup_frame)
        self._startup_message.set(message)
        self._retry.configure(state="normal" if retry else "disabled")

    def show_create(self) -> None:
        self._show(self._create_frame)
        self._create_password_entry.focus_set()

    def show_unlock(self) -> None:
        self._show(self._unlock_frame)
        self._unlock_entry.focus_set()

    def show_main(self) -> None:
        self._show(self._main_frame)
        self._accounts.focus_set()

    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for widget in self._busy_widgets:
            try:
                widget.configure(state=state)  # type: ignore[attr-defined]
            except Exception:
                pass
        if not busy:
            self.set_selection_enabled(bool(self._accounts.curselection()))

    def set_status(self, message: str) -> None:
        self._status.set(message)

    def set_accounts(self, accounts: tuple[str, ...]) -> None:
        self._accounts.delete(0, self._tk.END)
        for account in accounts:
            self._accounts.insert(self._tk.END, account)
        self.set_selection_enabled(False)

    def set_account_name(self, account: str) -> None:
        self._account_name.set(account)

    def set_selection_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for widget in self._selection_widgets:
            widget.configure(state=state)  # type: ignore[attr-defined]

    def clear_master_fields(self) -> None:
        self._create_password.set("")
        self._create_confirmation.set("")
        self._unlock_password.set("")

    def reset_master_visibility(self) -> None:
        self._create_show.set(False)
        self._unlock_show.set(False)
        self._toggle_create_visibility()
        self._toggle_unlock_visibility()

    def clear_credential_fields(self) -> None:
        self._credential_password.set("")
        self._credential_confirmation.set("")

    def reset_credential_visibility(self) -> None:
        self._credential_show.set(False)
        self._toggle_credential_visibility()

    def destroy(self) -> None:
        if self._destroyed:
            return
        self._destroyed = True
        self._root.destroy()

    def _build_startup(self) -> None:
        ttk = self._ttk
        frame = ttk.Frame(self._container, padding=24)
        frame.columnconfigure(0, weight=1)
        self._startup_message = self._tk.StringVar(value="Checking configuration…")
        ttk.Label(frame, textvariable=self._startup_message, anchor="center").grid(
            row=0, column=0, columnspan=2, sticky="ew", pady=(80, 20)
        )
        self._retry = ttk.Button(frame, text="Retry", state="disabled")
        self._retry.grid(row=1, column=0, padx=6)
        self._startup_close = ttk.Button(frame, text="Close")
        self._startup_close.grid(row=1, column=1, padx=6)
        self._startup_frame = frame
        self._frames.append(frame)
        self._busy_widgets.append(self._retry)

    def _build_create(self) -> None:
        ttk = self._ttk
        frame = ttk.Frame(self._container, padding=24)
        frame.columnconfigure(1, weight=1)
        self._create_password = self._tk.StringVar()
        self._create_confirmation = self._tk.StringVar()
        self._create_show = self._tk.BooleanVar(value=False)
        ttk.Label(frame, text="Create encrypted vault").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 16)
        )
        ttk.Label(frame, text="Master password").grid(row=1, column=0, sticky="w", pady=6)
        self._create_password_entry = ttk.Entry(
            frame, textvariable=self._create_password, show="*"
        )
        self._create_password_entry.grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Label(frame, text="Confirm master password").grid(
            row=2, column=0, sticky="w", pady=6
        )
        self._create_confirm_entry = ttk.Entry(
            frame, textvariable=self._create_confirmation, show="*"
        )
        self._create_confirm_entry.grid(row=2, column=1, sticky="ew", pady=6)
        self._create_show_button = ttk.Checkbutton(
            frame,
            text="Show password",
            variable=self._create_show,
            command=self._toggle_create_visibility,
        )
        self._create_show_button.grid(row=3, column=1, sticky="w", pady=6)
        self._create_button = ttk.Button(frame, text="Create Vault")
        self._create_button.grid(row=4, column=1, sticky="e", pady=(12, 0))
        self._create_frame = frame
        self._frames.append(frame)
        self._busy_widgets.extend(
            [
                self._create_password_entry,
                self._create_confirm_entry,
                self._create_show_button,
                self._create_button,
            ]
        )

    def _build_unlock(self) -> None:
        ttk = self._ttk
        frame = ttk.Frame(self._container, padding=24)
        frame.columnconfigure(1, weight=1)
        self._unlock_password = self._tk.StringVar()
        self._unlock_show = self._tk.BooleanVar(value=False)
        ttk.Label(frame, text="Unlock vault").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 16)
        )
        ttk.Label(frame, text="Master password").grid(row=1, column=0, sticky="w", pady=6)
        self._unlock_entry = ttk.Entry(frame, textvariable=self._unlock_password, show="*")
        self._unlock_entry.grid(row=1, column=1, sticky="ew", pady=6)
        self._unlock_show_button = ttk.Checkbutton(
            frame,
            text="Show password",
            variable=self._unlock_show,
            command=self._toggle_unlock_visibility,
        )
        self._unlock_show_button.grid(row=2, column=1, sticky="w", pady=6)
        self._unlock_button = ttk.Button(frame, text="Unlock")
        self._unlock_button.grid(row=3, column=1, sticky="e", pady=(12, 0))
        self._unlock_frame = frame
        self._frames.append(frame)
        self._busy_widgets.extend(
            [self._unlock_entry, self._unlock_show_button, self._unlock_button]
        )

    def _build_main(self) -> None:
        ttk = self._ttk
        frame = ttk.Frame(self._container)
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=2)
        frame.rowconfigure(1, weight=1)
        header = ttk.Frame(frame)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Encrypted credentials").grid(row=0, column=0, sticky="w")
        self._lock_button = ttk.Button(header, text="Lock")
        self._lock_button.grid(row=0, column=1, sticky="e")

        left = ttk.LabelFrame(frame, text="Accounts", padding=10)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)
        self._accounts = self._tk.Listbox(left, exportselection=False)
        self._accounts.grid(row=0, column=0, columnspan=3, sticky="nsew")
        self._refresh_button = ttk.Button(left, text="Refresh")
        self._refresh_button.grid(row=1, column=0, sticky="ew", pady=(8, 0), padx=(0, 4))
        self._copy_button = ttk.Button(left, text="Copy", state="disabled")
        self._copy_button.grid(row=1, column=1, sticky="ew", pady=(8, 0), padx=4)
        self._delete_button = ttk.Button(left, text="Delete", state="disabled")
        self._delete_button.grid(row=1, column=2, sticky="ew", pady=(8, 0), padx=(4, 0))

        right = ttk.LabelFrame(frame, text="Credential", padding=10)
        right.grid(row=1, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(1, weight=1)
        self._account_name = self._tk.StringVar()
        self._credential_password = self._tk.StringVar()
        self._credential_confirmation = self._tk.StringVar()
        self._credential_show = self._tk.BooleanVar(value=False)
        ttk.Label(right, text="Account name").grid(row=0, column=0, sticky="w", pady=6)
        self._account_entry = ttk.Entry(right, textvariable=self._account_name)
        self._account_entry.grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Label(right, text="Password").grid(row=1, column=0, sticky="w", pady=6)
        self._credential_password_entry = ttk.Entry(
            right, textvariable=self._credential_password, show="*"
        )
        self._credential_password_entry.grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Label(right, text="Confirm password").grid(row=2, column=0, sticky="w", pady=6)
        self._credential_confirm_entry = ttk.Entry(
            right, textvariable=self._credential_confirmation, show="*"
        )
        self._credential_confirm_entry.grid(row=2, column=1, sticky="ew", pady=6)
        self._credential_show_button = ttk.Checkbutton(
            right,
            text="Show password",
            variable=self._credential_show,
            command=self._toggle_credential_visibility,
        )
        self._credential_show_button.grid(row=3, column=1, sticky="w", pady=6)
        self._save_button = ttk.Button(right, text="Save Credential")
        self._save_button.grid(row=4, column=1, sticky="e", pady=(12, 0))
        self._main_frame = frame
        self._frames.append(frame)
        self._busy_widgets.extend(
            [
                self._accounts,
                self._refresh_button,
                self._copy_button,
                self._delete_button,
                self._account_entry,
                self._credential_password_entry,
                self._credential_confirm_entry,
                self._credential_show_button,
                self._save_button,
            ]
        )
        self._selection_widgets.extend([self._copy_button, self._delete_button])

    def _show(self, frame: object) -> None:
        for candidate in self._frames:
            candidate.grid_forget()  # type: ignore[attr-defined]
        frame.grid(row=0, column=0, sticky="nsew")  # type: ignore[attr-defined]

    def _toggle_create_visibility(self) -> None:
        mask = "" if self._create_show.get() else "*"
        self._create_password_entry.configure(show=mask)
        self._create_confirm_entry.configure(show=mask)

    def _toggle_unlock_visibility(self) -> None:
        self._unlock_entry.configure(show="" if self._unlock_show.get() else "*")

    def _toggle_credential_visibility(self) -> None:
        mask = "" if self._credential_show.get() else "*"
        self._credential_password_entry.configure(show=mask)
        self._credential_confirm_entry.configure(show=mask)

    def _submit_create(self) -> None:
        if self._presenter is not None:
            self._presenter.create_vault(
                self._create_password.get(), self._create_confirmation.get()
            )

    def _create_return(self, _event: object) -> str:
        if self._presenter is None:
            return "break"
        return self._presenter.create_return(
            self._create_password.get(), self._create_confirmation.get()
        )

    def _submit_unlock(self) -> None:
        if self._presenter is not None:
            self._presenter.unlock(self._unlock_password.get())

    def _unlock_return(self, _event: object) -> str:
        if self._presenter is None:
            return "break"
        return self._presenter.unlock_return(self._unlock_password.get())

    def _submit_save(self) -> None:
        if self._presenter is not None:
            self._presenter.save_credential(
                self._account_name.get(),
                self._credential_password.get(),
                self._credential_confirmation.get(),
            )

    def _save_return(self, _event: object) -> str:
        if self._presenter is None:
            return "break"
        return self._presenter.save_return(
            self._account_name.get(),
            self._credential_password.get(),
            self._credential_confirmation.get(),
        )

    def _selection_changed(self, _event: object) -> None:
        if self._presenter is None:
            return
        selection = self._accounts.curselection()
        account = self._accounts.get(selection[0]) if selection else None
        self._presenter.select_account(account)

    def _activity(self, _event: object) -> None:
        if self._presenter is not None:
            self._presenter.activity()


class TkScheduler:
    def __init__(self, root: Any) -> None:
        self._root = root

    def call_soon(self, callback: Callable[[], None]) -> object:
        return self._root.after(0, callback)

    def call_idle(self, callback: Callable[[], None]) -> object:
        return self._root.after_idle(callback)

    def call_later(self, milliseconds: int, callback: Callable[[], None]) -> object:
        return self._root.after(milliseconds, callback)

    def cancel(self, handle: object) -> None:
        self._root.after_cancel(handle)


class TkDeleteConfirmation:
    def __init__(self, parent: Any) -> None:
        self._parent = parent

    def confirm(self, account: str) -> bool:
        from tkinter import messagebox

        return bool(
            messagebox.askyesno(
                "Delete credential",
                f"Delete credential for {account}?",
                parent=self._parent,
            )
        )
