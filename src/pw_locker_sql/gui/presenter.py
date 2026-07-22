"""Headless GUI state machine over runtime, controller, and clipboard boundaries."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, TypeVar, cast

from pw_locker_sql.clipboard import ClipboardProvider
from pw_locker_sql.config import SQLServerConfig
from pw_locker_sql.domain import CredentialMetadata
from pw_locker_sql.gui.controller import ControllerResult, VaultController
from pw_locker_sql.gui.operations import OperationCoordinator, Scheduler
from pw_locker_sql.runtime import (
    ConfigurationSelection,
    OperationalRuntimeProtocol,
    RuntimeFactoryProtocol,
)
from pw_locker_sql.schema.version import CURRENT_SCHEMA_VERSION
from pw_locker_sql.services import CredentialWriteResult, VaultService

AUTO_LOCK_MILLISECONDS = 5 * 60 * 1000
CLIPBOARD_CLEAR_MILLISECONDS = 30 * 1000
T = TypeVar("T")


class Screen(str, Enum):
    STARTUP = "startup"
    CREATE = "create"
    UNLOCK = "unlock"
    MAIN = "main"
    CLOSED = "closed"


class VaultView(Protocol):
    def show_startup(self, message: str, *, retry: bool = False) -> None: ...

    def show_create(self) -> None: ...

    def show_unlock(self) -> None: ...

    def show_main(self) -> None: ...

    def set_busy(self, busy: bool) -> None: ...

    def set_status(self, message: str) -> None: ...

    def set_accounts(self, accounts: tuple[str, ...]) -> None: ...

    def set_account_name(self, account: str) -> None: ...

    def set_selection_enabled(self, enabled: bool) -> None: ...

    def clear_master_fields(self) -> None: ...

    def reset_master_visibility(self) -> None: ...

    def clear_credential_fields(self) -> None: ...

    def reset_credential_visibility(self) -> None: ...

    def destroy(self) -> None: ...


class DeleteConfirmation(Protocol):
    def confirm(self, account: str) -> bool: ...


class _PresentationFailure(Exception):
    pass


@dataclass(slots=True)
class _StartupResult:
    runtime: OperationalRuntimeProtocol
    initialized: bool


@dataclass(slots=True)
class _ClipboardLease:
    value: str = field(repr=False)
    serial: int


@dataclass(slots=True)
class _AccountResult:
    accounts: tuple[str, ...]
    write_result: CredentialWriteResult | None = None


class VaultGuiPresenter:
    """Coordinates GUI workflows without importing or manipulating Tk widgets."""

    def __init__(
        self,
        view: VaultView,
        runtime_factory: RuntimeFactoryProtocol,
        coordinator: OperationCoordinator,
        scheduler: Scheduler,
        confirmation: DeleteConfirmation,
        *,
        auto_lock_milliseconds: int = AUTO_LOCK_MILLISECONDS,
        clipboard_clear_milliseconds: int = CLIPBOARD_CLEAR_MILLISECONDS,
    ) -> None:
        if auto_lock_milliseconds < 1 or clipboard_clear_milliseconds < 1:
            raise ValueError("timeouts must be positive")
        self._view = view
        self._runtime_factory = runtime_factory
        self._coordinator = coordinator
        self._scheduler = scheduler
        self._confirmation = confirmation
        self._auto_lock_milliseconds = auto_lock_milliseconds
        self._clipboard_clear_milliseconds = clipboard_clear_milliseconds
        self._runtime: OperationalRuntimeProtocol | None = None
        self._controller: VaultController | None = None
        self._selection = ConfigurationSelection()
        self._screen = Screen.STARTUP
        self._generation = 0
        self._selected_account: str | None = None
        self._accounts: tuple[str, ...] = ()
        self._inactivity_handle: object | None = None
        self._clipboard_handle: object | None = None
        self._startup_launch_handle: object | None = None
        self._clipboard_lease: _ClipboardLease | None = None
        self._clipboard_serial = 0
        self._closed = False

    @property
    def screen(self) -> Screen:
        return self._screen

    def start(self, selection: ConfigurationSelection | None = None) -> None:
        if self._closed or self._coordinator.busy or self._startup_launch_handle is not None:
            return
        self._selection = selection or ConfigurationSelection()
        self._begin_startup(defer_until_idle=False)

    def retry(self) -> None:
        if self._closed or self._coordinator.busy or self._startup_launch_handle is not None:
            return
        self._close_runtime()
        self._begin_startup(defer_until_idle=True)

    def _begin_startup(self, *, defer_until_idle: bool) -> None:
        self._generation += 1
        generation = self._generation
        self._screen = Screen.STARTUP
        self._view.show_startup("Checking configuration…")
        self._view.set_busy(True)

        def launch() -> None:
            self._startup_launch_handle = None
            if self._current(generation):
                self._submit_startup(generation)

        if defer_until_idle:
            try:
                self._startup_launch_handle = self._scheduler.call_idle(launch)
            except Exception:
                self._startup_launch_handle = None
                self._show_startup_failure(generation)
        else:
            launch()

    def _submit_startup(self, generation: int) -> None:

        def operation() -> _StartupResult:
            config: SQLServerConfig = self._runtime_factory.load_config(self._selection)
            runtime = self._runtime_factory.compose(config)
            try:
                version = runtime.schema_manager.current_version()
                if version not in {0, CURRENT_SCHEMA_VERSION}:
                    raise _PresentationFailure()
                initialized = False
                if version == CURRENT_SCHEMA_VERSION:
                    controller = _controller_for(runtime)
                    initialized = _value(controller.is_initialized())
                return _StartupResult(runtime, initialized)
            except Exception:
                runtime.close()
                raise

        def success(result: _StartupResult) -> None:
            if not self._current(generation):
                result.runtime.close()
                return
            self._close_runtime()
            self._runtime = result.runtime
            self._controller = _controller_for(result.runtime)
            self._view.set_busy(False)
            if result.initialized:
                self._enter_unlock("Vault is locked.")
            else:
                self._enter_create()

        def failure() -> None:
            self._show_startup_failure(generation)

        self._coordinator.submit(
            operation,
            success,
            failure,
            discard=lambda result: result.runtime.close(),
        )

    def _show_startup_failure(self, generation: int) -> None:
        if not self._current(generation):
            return
        self._view.set_busy(False)
        self._screen = Screen.STARTUP
        self._view.show_startup("Unable to initialize. Try again.", retry=True)

    def create_vault(self, password: str, confirmation: str) -> None:
        if not self._ready(Screen.CREATE):
            return
        if not password or password != confirmation:
            self._clear_master()
            self._view.set_status("Master password confirmation did not match.")
            return
        runtime, controller = self._required_boundaries()
        generation = self._generation
        self._view.set_busy(True)

        def operation() -> _AccountResult:
            runtime.schema_manager.migrate()
            _ok(controller.initialize(password))
            return _AccountResult(_account_values(_value(controller.list_credentials())))

        def success(result: _AccountResult) -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._clear_master()
            self._enter_main(result.accounts, "Vault created.")

        def failure() -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._clear_master()
            self._view.set_status("Vault could not be created.")

        self._coordinator.submit(operation, success, failure)

    def create_return(self, password: str, confirmation: str) -> str:
        self.create_vault(password, confirmation)
        return "break"

    def unlock(self, password: str) -> None:
        if not self._ready(Screen.UNLOCK):
            return
        if not password:
            self._clear_master()
            self._view.set_status("Unable to unlock vault.")
            return
        runtime, controller = self._required_boundaries()
        generation = self._generation
        self._view.set_busy(True)

        def operation() -> tuple[str, ...]:
            if runtime.schema_manager.current_version() != CURRENT_SCHEMA_VERSION:
                raise _PresentationFailure()
            _ok(controller.unlock(password))
            return _account_values(_value(controller.list_credentials()))

        def success(accounts: tuple[str, ...]) -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._clear_master()
            self._enter_main(accounts, "Vault unlocked.")

        def failure() -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._clear_master()
            self._view.set_status("Unable to unlock vault.")

        self._coordinator.submit(operation, success, failure)

    def unlock_return(self, password: str) -> str:
        self.unlock(password)
        return "break"

    def select_account(self, account: str | None) -> None:
        if self._screen is not Screen.MAIN or self._closed:
            return
        if account not in self._accounts:
            self._selected_account = None
            self._view.set_selection_enabled(False)
            return
        self._selected_account = account
        self._view.set_account_name(account)
        self._view.set_selection_enabled(True)
        self.activity()

    def refresh(self, *, manual: bool = True) -> None:
        if not self._ready(Screen.MAIN):
            return
        _, controller = self._required_boundaries()
        generation = self._generation
        self._view.set_busy(True)

        def operation() -> tuple[str, ...]:
            return _account_values(_value(controller.list_credentials()))

        def success(accounts: tuple[str, ...]) -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._replace_accounts(accounts)
            if manual:
                self._view.set_status("Accounts refreshed.")
            self._arm_inactivity()

        self._submit_with_status(operation, success, "Unable to refresh accounts.", generation)

    def save_credential(self, account: str, password: str, confirmation: str) -> None:
        if not self._ready(Screen.MAIN):
            return
        if not account.strip() or not password or password != confirmation:
            self._clear_credential()
            self._view.set_status("Credential input is invalid.")
            return
        _, controller = self._required_boundaries()
        generation = self._generation
        self._view.set_busy(True)

        def operation() -> _AccountResult:
            write_result = _value(controller.set_credential(account, password))
            accounts = _account_values(_value(controller.list_credentials()))
            return _AccountResult(accounts, write_result)

        def success(result: _AccountResult) -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._clear_credential()
            self._replace_accounts(result.accounts)
            message = (
                "Credential created."
                if result.write_result is CredentialWriteResult.CREATED
                else "Credential updated."
            )
            self._view.set_status(message)
            self._arm_inactivity()

        self._submit_with_status(operation, success, "Unable to save credential.", generation)

    def save_return(self, account: str, password: str, confirmation: str) -> str:
        self.save_credential(account, password, confirmation)
        return "break"

    def copy_selected(self) -> None:
        if not self._ready(Screen.MAIN) or self._selected_account is None:
            return
        runtime, controller = self._required_boundaries()
        account = self._selected_account
        generation = self._generation
        self._view.set_busy(True)

        def operation() -> _ClipboardLease:
            plaintext = _value(controller.get_credential(account))
            runtime.clipboard.copy(plaintext)
            return _ClipboardLease(plaintext, self._clipboard_serial + 1)

        def success(lease: _ClipboardLease) -> None:
            if not self._current(generation):
                _best_effort_clear(runtime.clipboard, lease.value)
                return
            self._view.set_busy(False)
            self._install_clipboard_lease(lease)
            self._view.set_status("Password copied. Clipboard will clear in 30 seconds.")
            self._arm_inactivity()

        self._submit_with_status(
            operation,
            success,
            "Clipboard operation failed.",
            generation,
            discard=lambda lease: _best_effort_clear(runtime.clipboard, lease.value),
        )

    def delete_selected(self) -> None:
        if not self._ready(Screen.MAIN) or self._selected_account is None:
            return
        account = self._selected_account
        if not self._confirmation.confirm(account):
            self._view.set_status("Deletion cancelled.")
            return
        _, controller = self._required_boundaries()
        generation = self._generation
        self._view.set_busy(True)

        def operation() -> tuple[str, ...]:
            _ok(controller.delete_credential(account))
            return _account_values(_value(controller.list_credentials()))

        def success(accounts: tuple[str, ...]) -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._replace_accounts(accounts)
            self._view.set_status("Credential deleted.")
            self._arm_inactivity()

        self._submit_with_status(operation, success, "Unable to delete credential.", generation)

    def activity(self) -> None:
        if self._screen is Screen.MAIN and not self._closed:
            self._arm_inactivity()

    def lock(self, *, inactivity: bool = False) -> None:
        if self._closed:
            return
        if self._screen is not Screen.MAIN:
            return
        self._generation += 1
        self._cancel_startup_launch()
        self._cancel_inactivity()
        self._clear_owned_clipboard()
        self._view.set_busy(False)
        if self._controller is not None:
            try:
                self._controller.lock()
            except Exception:
                pass
        self._clear_master()
        self._clear_credential()
        message = "Vault locked due to inactivity." if inactivity else "Vault locked."
        self._enter_unlock(message)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._screen = Screen.CLOSED
        self._generation += 1
        self._cancel_startup_launch()
        self._cancel_inactivity()
        self._clear_owned_clipboard()
        self._close_runtime()
        self._coordinator.close()
        try:
            self._view.destroy()
        except Exception:
            pass

    def _submit_with_status(
        self,
        operation: Callable[[], T],
        success: Callable[[T], None],
        message: str,
        generation: int,
        discard: Callable[[T], None] | None = None,
    ) -> None:
        def failure() -> None:
            if not self._current(generation):
                return
            self._view.set_busy(False)
            self._clear_credential()
            self._view.set_status(message)
            self._arm_inactivity()

        self._coordinator.submit(operation, success, failure, discard)

    def _ready(self, screen: Screen) -> bool:
        return not self._closed and self._screen is screen and not self._coordinator.busy

    def _current(self, generation: int) -> bool:
        return not self._closed and generation == self._generation

    def _required_boundaries(self) -> tuple[OperationalRuntimeProtocol, VaultController]:
        if self._runtime is None or self._controller is None:
            raise _PresentationFailure()
        return self._runtime, self._controller

    def _enter_create(self) -> None:
        self._screen = Screen.CREATE
        self._selected_account = None
        self._clear_master()
        self._view.show_create()
        self._view.set_status("Create a new encrypted vault.")

    def _enter_unlock(self, message: str) -> None:
        self._screen = Screen.UNLOCK
        self._selected_account = None
        self._clear_master()
        self._clear_credential()
        self._view.show_unlock()
        self._view.set_status(message)

    def _enter_main(self, accounts: tuple[str, ...], message: str) -> None:
        self._screen = Screen.MAIN
        self._view.show_main()
        self._replace_accounts(accounts)
        if not accounts and message in {"Vault created.", "Vault unlocked."}:
            message = f"{message} No credentials saved."
        self._view.set_status(message)
        self._arm_inactivity()

    def _replace_accounts(self, accounts: tuple[str, ...]) -> None:
        self._accounts = tuple(sorted(accounts))
        self._selected_account = None
        self._view.set_accounts(self._accounts)
        self._view.set_account_name("")
        self._view.set_selection_enabled(False)

    def _clear_master(self) -> None:
        self._view.clear_master_fields()
        self._view.reset_master_visibility()

    def _clear_credential(self) -> None:
        self._view.clear_credential_fields()
        self._view.reset_credential_visibility()

    def _install_clipboard_lease(self, lease: _ClipboardLease) -> None:
        self._cancel_clipboard_timer()
        self._clipboard_serial += 1
        lease.serial = self._clipboard_serial
        self._clipboard_lease = lease

        def clear() -> None:
            if self._closed or lease.serial != self._clipboard_serial:
                return
            runtime = self._runtime
            if runtime is not None:
                try:
                    if runtime.clipboard.read() == lease.value:
                        runtime.clipboard.clear()
                except Exception:
                    self._view.set_status("Clipboard operation failed.")
            if self._clipboard_lease is lease:
                self._clipboard_lease = None
            self._clipboard_handle = None

        self._clipboard_handle = self._scheduler.call_later(
            self._clipboard_clear_milliseconds,
            clear,
        )

    def _clear_owned_clipboard(self) -> None:
        self._cancel_clipboard_timer()
        lease = self._clipboard_lease
        runtime = self._runtime
        self._clipboard_lease = None
        self._clipboard_serial += 1
        if lease is not None and runtime is not None:
            _best_effort_clear(runtime.clipboard, lease.value)

    def _cancel_clipboard_timer(self) -> None:
        if self._clipboard_handle is not None:
            try:
                self._scheduler.cancel(self._clipboard_handle)
            except Exception:
                pass
            self._clipboard_handle = None

    def _arm_inactivity(self) -> None:
        if self._screen is not Screen.MAIN or self._closed:
            return
        self._cancel_inactivity()
        self._inactivity_handle = self._scheduler.call_later(
            self._auto_lock_milliseconds,
            lambda: self.lock(inactivity=True),
        )

    def _cancel_inactivity(self) -> None:
        if self._inactivity_handle is not None:
            try:
                self._scheduler.cancel(self._inactivity_handle)
            except Exception:
                pass
            self._inactivity_handle = None

    def _cancel_startup_launch(self) -> None:
        if self._startup_launch_handle is not None:
            try:
                self._scheduler.cancel(self._startup_launch_handle)
            except Exception:
                pass
            self._startup_launch_handle = None

    def _close_runtime(self) -> None:
        runtime = self._runtime
        self._runtime = None
        self._controller = None
        if runtime is not None:
            try:
                runtime.close()
            except Exception:
                pass


def _controller_for(runtime: OperationalRuntimeProtocol) -> VaultController:
    return VaultController(cast(VaultService, runtime.service))


def _ok(result: ControllerResult[T]) -> None:
    if not result.ok:
        raise _PresentationFailure()


def _value(result: ControllerResult[T]) -> T:
    if not result.ok or result.value is None:
        raise _PresentationFailure()
    return result.value


def _account_values(metadata: tuple[CredentialMetadata, ...]) -> tuple[str, ...]:
    return tuple(sorted(item.credential_id.value for item in metadata))


def _best_effort_clear(clipboard: ClipboardProvider, expected: str) -> None:
    try:
        if clipboard.read() == expected:
            clipboard.clear()
    except Exception:
        pass
