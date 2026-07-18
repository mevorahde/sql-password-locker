from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Generic, TypeVar

import pytest

from pw_locker_sql.config import SQLServerConfig
from pw_locker_sql.domain import CredentialId, CredentialMetadata
from pw_locker_sql.errors import AuthenticationError, RepositoryError, VaultAlreadyInitializedError
from pw_locker_sql.gui.operations import OperationCoordinator
from pw_locker_sql.gui.presenter import Screen, VaultGuiPresenter
from pw_locker_sql.services import CredentialWriteResult

T = TypeVar("T")
NOW = datetime(2026, 4, 5, 6, 7, tzinfo=timezone.utc)
MASTER = "SYNTHETIC_MASTER_PASSWORD"
PASSWORD = "SYNTHETIC_CREDENTIAL_PASSWORD"


class FakeFuture(Generic[T]):
    def __init__(self, operation: Callable[[], T]) -> None:
        self.operation = operation
        self.callbacks: list[Callable[[FakeFuture[T]], None]] = []
        self.value: T | None = None
        self.error: Exception | None = None

    def add_done_callback(self, callback: Callable[[FakeFuture[T]], None]) -> None:
        self.callbacks.append(callback)

    def result(self) -> T:
        if self.error is not None:
            raise self.error
        assert self.value is not None
        return self.value

    def run(self) -> None:
        try:
            self.value = self.operation()
        except Exception as error:
            self.error = error
        for callback in self.callbacks:
            callback(self)


class FakeExecutor:
    def __init__(self) -> None:
        self.pending: list[FakeFuture[object]] = []
        self.shutdown_calls = 0

    def submit(self, operation: Callable[[], T]) -> FakeFuture[T]:
        future = FakeFuture(operation)
        self.pending.append(future)  # type: ignore[arg-type]
        return future

    def shutdown(self) -> None:
        self.shutdown_calls += 1

    def run_next(self) -> None:
        self.pending.pop(0).run()


class FakeScheduler:
    def __init__(self) -> None:
        self.next_handle = 1
        self.callbacks: dict[int, tuple[int, Callable[[], None]]] = {}
        self.cancelled: list[int] = []

    def call_soon(self, callback: Callable[[], None]) -> object:
        return self.call_later(0, callback)

    def call_idle(self, callback: Callable[[], None]) -> object:
        return self.call_later(-1, callback)

    def call_later(self, milliseconds: int, callback: Callable[[], None]) -> object:
        handle = self.next_handle
        self.next_handle += 1
        self.callbacks[handle] = (milliseconds, callback)
        return handle

    def cancel(self, handle: object) -> None:
        assert isinstance(handle, int)
        self.cancelled.append(handle)
        self.callbacks.pop(handle, None)

    def run_soon(self) -> None:
        while True:
            handles = [
                handle
                for handle, (delay, _callback) in self.callbacks.items()
                if delay == 0
            ]
            if not handles:
                return
            self.run(handles[0])

    def run_idle(self) -> None:
        handles = self.handles_for(-1)
        if handles:
            self.run(handles[0])

    def run(self, handle: int) -> None:
        item = self.callbacks.pop(handle, None)
        if item is not None:
            item[1]()

    def handles_for(self, milliseconds: int) -> list[int]:
        return [
            handle
            for handle, (delay, _callback) in self.callbacks.items()
            if delay == milliseconds
        ]


class FakeView:
    def __init__(self) -> None:
        self.screen = ""
        self.startup_message = ""
        self.retry = False
        self.busy: list[bool] = []
        self.status = ""
        self.status_history: list[str] = []
        self.accounts: tuple[str, ...] = ()
        self.account_name = ""
        self.selection_enabled = False
        self.master_clear_calls = 0
        self.master_reset_calls = 0
        self.credential_clear_calls = 0
        self.credential_reset_calls = 0
        self.destroy_calls = 0

    def show_startup(self, message: str, *, retry: bool = False) -> None:
        self.screen = "startup"
        self.startup_message = message
        self.retry = retry

    def show_create(self) -> None:
        self.screen = "create"

    def show_unlock(self) -> None:
        self.screen = "unlock"

    def show_main(self) -> None:
        self.screen = "main"

    def set_busy(self, busy: bool) -> None:
        self.busy.append(busy)

    def set_status(self, message: str) -> None:
        self.status = message
        self.status_history.append(message)

    def set_accounts(self, accounts: tuple[str, ...]) -> None:
        self.accounts = accounts

    def set_account_name(self, account: str) -> None:
        self.account_name = account

    def set_selection_enabled(self, enabled: bool) -> None:
        self.selection_enabled = enabled

    def clear_master_fields(self) -> None:
        self.master_clear_calls += 1

    def reset_master_visibility(self) -> None:
        self.master_reset_calls += 1

    def clear_credential_fields(self) -> None:
        self.credential_clear_calls += 1

    def reset_credential_visibility(self) -> None:
        self.credential_reset_calls += 1

    def destroy(self) -> None:
        self.destroy_calls += 1


class FakeSchema:
    def __init__(self, version: int) -> None:
        self.version = version
        self.current_calls = 0
        self.migrate_calls = 0
        self.error: Exception | None = None

    def current_version(self) -> int:
        self.current_calls += 1
        if self.error is not None:
            raise self.error
        return self.version

    def migrate(self) -> int:
        self.migrate_calls += 1
        if self.error is not None:
            raise self.error
        self.version = 1
        return 1


class FakeService:
    def __init__(self, initialized: bool) -> None:
        self.initialized = initialized
        self.unlocked = False
        self.accounts: tuple[str, ...] = ()
        self.write_result = CredentialWriteResult.CREATED
        self.value = PASSWORD
        self.errors: dict[str, Exception] = {}
        self.initialize_calls = 0
        self.unlock_calls = 0
        self.lock_calls = 0
        self.close_calls = 0
        self.set_calls: list[tuple[str, str]] = []
        self.get_calls: list[str] = []
        self.list_calls = 0
        self.delete_calls: list[str] = []

    def _raise(self, operation: str) -> None:
        if operation in self.errors:
            raise self.errors[operation]

    def is_initialized(self) -> bool:
        self._raise("initialized")
        return self.initialized

    def initialize(self, master_password: str) -> None:
        self.initialize_calls += 1
        self._raise("initialize")
        self.initialized = True
        self.unlocked = True

    def unlock(self, master_password: str) -> None:
        self.unlock_calls += 1
        self._raise("unlock")
        self.unlocked = True

    def lock(self) -> None:
        self.lock_calls += 1
        self.unlocked = False

    def set_credential(self, account: str, plaintext: str) -> CredentialWriteResult:
        self.set_calls.append((account, plaintext))
        self._raise("set")
        normalized = CredentialId(account).value
        if normalized not in self.accounts:
            self.accounts = (*self.accounts, normalized)
        return self.write_result

    def get_credential(self, account: str) -> str:
        self.get_calls.append(account)
        self._raise("get")
        return self.value

    def list_credentials(self) -> tuple[CredentialMetadata, ...]:
        self.list_calls += 1
        self._raise("list")
        return tuple(CredentialMetadata(CredentialId(item), NOW, NOW) for item in self.accounts)

    def delete_credential(self, account: str) -> None:
        self.delete_calls.append(account)
        self._raise("delete")
        normalized = CredentialId(account).value
        self.accounts = tuple(item for item in self.accounts if item != normalized)

    def close(self) -> None:
        self.close_calls += 1
        self.lock()


class FakeClipboard:
    def __init__(self) -> None:
        self.current = ""
        self.copied: list[str] = []
        self.clear_calls = 0
        self.fail = False

    def copy(self, value: str) -> None:
        if self.fail:
            raise RuntimeError("SYNTHETIC_CLIPBOARD_DIAGNOSTIC")
        self.copied.append(value)
        self.current = value

    def read(self) -> str:
        if self.fail:
            raise RuntimeError("SYNTHETIC_CLIPBOARD_DIAGNOSTIC")
        return self.current

    def clear(self) -> None:
        if self.fail:
            raise RuntimeError("SYNTHETIC_CLIPBOARD_DIAGNOSTIC")
        self.clear_calls += 1
        self.current = ""


class FakeRuntime:
    def __init__(self, *, initialized: bool, version: int) -> None:
        self.schema_manager = FakeSchema(version)
        self.service = FakeService(initialized)
        self.clipboard = FakeClipboard()
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.service.close()


class FakeFactory:
    def __init__(self, *runtimes: FakeRuntime) -> None:
        self.runtimes = list(runtimes)
        self.load_calls = 0
        self.compose_calls = 0
        self.error: Exception | None = None
        self.config = SQLServerConfig.from_mapping(
            {
                "SERVER": "SERVER_PLACEHOLDER",
                "DATABASE": "DATABASE_PLACEHOLDER",
                "AUTH_MODE": "integrated",
            }
        )

    def load_config(self, selection: object) -> SQLServerConfig:
        self.load_calls += 1
        if self.error is not None:
            raise self.error
        return self.config

    def compose(self, config: SQLServerConfig) -> FakeRuntime:
        self.compose_calls += 1
        return self.runtimes.pop(0)


class FakeConfirmation:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.accounts: list[str] = []

    def confirm(self, account: str) -> bool:
        self.accounts.append(account)
        return self.result


class Harness:
    def __init__(self, runtime: FakeRuntime, confirmation: FakeConfirmation | None = None) -> None:
        self.runtime = runtime
        self.view = FakeView()
        self.executor = FakeExecutor()
        self.scheduler = FakeScheduler()
        self.factory = FakeFactory(runtime)
        self.confirmation = confirmation or FakeConfirmation()
        self.coordinator = OperationCoordinator(self.executor, self.scheduler)  # type: ignore[arg-type]
        self.presenter = VaultGuiPresenter(
            self.view,
            self.factory,  # type: ignore[arg-type]
            self.coordinator,
            self.scheduler,
            self.confirmation,
            auto_lock_milliseconds=100,
            clipboard_clear_milliseconds=50,
        )

    def complete(self) -> None:
        self.executor.run_next()
        self.scheduler.run_soon()

    def start(self) -> None:
        self.presenter.start()
        self.complete()

    def unlock(self) -> None:
        self.start()
        self.presenter.unlock(MASTER)
        self.complete()


def test_startup_pending_create_and_unlock_routes() -> None:
    create = Harness(FakeRuntime(initialized=False, version=0))
    create.presenter.start()
    assert create.view.screen == "startup"
    assert create.view.busy[-1] is True
    create.complete()
    assert create.presenter.screen is Screen.CREATE
    assert create.view.screen == "create"

    unlock = Harness(FakeRuntime(initialized=True, version=1))
    unlock.start()
    assert unlock.presenter.screen is Screen.UNLOCK
    assert unlock.view.screen == "unlock"


def test_startup_failure_is_redacted_and_retry_does_not_duplicate() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    harness = Harness(runtime)
    harness.factory.error = RepositoryError()
    harness.presenter.start()
    harness.presenter.retry()
    assert len(harness.executor.pending) == 1
    harness.complete()
    assert harness.view.retry is True
    assert "SERVER_PLACEHOLDER" not in harness.view.startup_message
    harness.factory.error = None
    harness.factory.runtimes.append(runtime)
    harness.presenter.retry()
    harness.scheduler.run_idle()
    harness.complete()
    assert harness.presenter.screen is Screen.UNLOCK


def test_retry_renders_pending_before_one_new_attempt_and_fails_safely() -> None:
    first = FakeRuntime(initialized=True, version=1)
    first.schema_manager.error = RuntimeError("SYNTHETIC_FIRST_DRIVER_DIAGNOSTIC")
    second = FakeRuntime(initialized=True, version=1)
    second.schema_manager.error = RuntimeError("SYNTHETIC_SECOND_DRIVER_DIAGNOSTIC")
    harness = Harness(first)
    harness.presenter.start()
    harness.complete()
    assert harness.view.retry is True
    assert first.close_calls == 1

    harness.factory.runtimes.append(second)
    previous_generation = harness.presenter._generation
    harness.presenter.retry()
    assert harness.view.startup_message == "Checking configuration…"
    assert harness.view.retry is False
    assert harness.view.busy[-1] is True
    assert harness.executor.pending == []
    assert len(harness.scheduler.handles_for(-1)) == 1

    harness.presenter.retry()
    assert len(harness.scheduler.handles_for(-1)) == 1
    harness.presenter._show_startup_failure(previous_generation)
    assert harness.view.startup_message == "Checking configuration…"

    harness.scheduler.run_idle()
    assert len(harness.executor.pending) == 1
    harness.complete()
    assert harness.factory.load_calls == 2
    assert harness.factory.compose_calls == 2
    assert second.close_calls == 1
    assert harness.view.startup_message == "Unable to initialize. Try again."
    assert harness.view.retry is True
    assert harness.view.busy[-1] is False
    assert "SYNTHETIC_SECOND_DRIVER_DIAGNOSTIC" not in harness.view.startup_message

    harness.presenter.close()
    assert harness.view.destroy_calls == 1


def test_close_cancels_retry_before_the_replacement_worker_starts() -> None:
    harness = Harness(FakeRuntime(initialized=True, version=1))
    harness.factory.error = RepositoryError()
    harness.presenter.start()
    harness.complete()
    harness.presenter.retry()
    idle_handle = harness.scheduler.handles_for(-1)[0]
    harness.presenter.close()
    assert idle_handle in harness.scheduler.cancelled
    assert harness.executor.pending == []
    assert harness.view.destroy_calls == 1


def test_stale_startup_result_after_close_is_discarded_and_runtime_closed() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    harness = Harness(runtime)
    harness.presenter.start()
    harness.presenter.close()
    harness.executor.run_next()
    assert runtime.close_calls == 1
    assert harness.view.destroy_calls == 1


def test_create_success_mismatch_duplicate_and_return_behavior() -> None:
    harness = Harness(FakeRuntime(initialized=False, version=0))
    harness.start()
    assert harness.presenter.create_return(MASTER, MASTER) == "break"
    harness.presenter.create_vault(MASTER, MASTER)
    assert len(harness.executor.pending) == 1
    harness.complete()
    assert harness.presenter.screen is Screen.MAIN
    assert harness.view.status == "Vault created. No credentials saved."
    assert harness.runtime.schema_manager.migrate_calls == 1
    assert harness.view.master_clear_calls > 0
    assert harness.view.master_reset_calls > 0

    mismatch = Harness(FakeRuntime(initialized=False, version=0))
    mismatch.start()
    mismatch.presenter.create_vault(MASTER, "DIFFERENT_SYNTHETIC_PASSWORD")
    assert mismatch.executor.pending == []
    assert "confirmation" in mismatch.view.status.casefold()
    assert mismatch.view.master_clear_calls > 0


def test_create_existing_vault_failure_is_generic_and_clears_fields() -> None:
    harness = Harness(FakeRuntime(initialized=False, version=0))
    harness.start()
    harness.runtime.service.errors["initialize"] = VaultAlreadyInitializedError()
    harness.presenter.create_vault(MASTER, MASTER)
    harness.complete()
    assert harness.view.status == "Vault could not be created."
    assert harness.presenter.screen is Screen.CREATE
    assert harness.view.master_clear_calls > 0


@pytest.mark.parametrize("error", [AuthenticationError(), RuntimeError("CORRUPT_PLACEHOLDER")])
def test_unlock_failures_share_message_clear_and_reset(error: Exception) -> None:
    harness = Harness(FakeRuntime(initialized=True, version=1))
    harness.start()
    harness.runtime.service.errors["unlock"] = error
    assert harness.presenter.unlock_return(MASTER) == "break"
    harness.presenter.unlock(MASTER)
    assert len(harness.executor.pending) == 1
    harness.complete()
    assert harness.view.status == "Unable to unlock vault."
    assert harness.view.master_clear_calls > 0
    assert harness.view.master_reset_calls > 0


def test_unlock_success_sorted_accounts_and_auto_lock_armed() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("zeta", "alpha")
    harness = Harness(runtime)
    harness.unlock()
    assert harness.presenter.screen is Screen.MAIN
    assert harness.view.accounts == ("alpha", "zeta")
    assert len(harness.scheduler.handles_for(100)) == 1


def test_stale_unlock_result_after_close_is_ignored_and_session_closes() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    harness = Harness(runtime)
    harness.start()
    harness.presenter.unlock(MASTER)
    harness.presenter.close()
    harness.executor.run_next()
    assert harness.presenter.screen is Screen.CLOSED
    assert runtime.close_calls == 1
    assert harness.view.destroy_calls == 1


def test_selection_populates_only_account_name_and_never_decrypts() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    assert harness.view.account_name == "account"
    assert harness.view.selection_enabled is True
    assert runtime.service.get_calls == []


@pytest.mark.parametrize(
    ("write_result", "message"),
    [
        (CredentialWriteResult.CREATED, "Credential created."),
        (CredentialWriteResult.UPDATED, "Credential updated."),
    ],
)
def test_save_create_update_preserves_success_through_refresh(
    write_result: CredentialWriteResult,
    message: str,
) -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.write_result = write_result
    harness = Harness(runtime)
    harness.unlock()
    assert harness.presenter.save_return("Mixed ACCOUNT", PASSWORD, PASSWORD) == "break"
    harness.presenter.save_credential("Mixed ACCOUNT", PASSWORD, PASSWORD)
    assert len(harness.executor.pending) == 1
    harness.complete()
    assert harness.view.status == message
    assert harness.view.accounts == ("mixed account",)
    assert harness.view.credential_clear_calls > 0
    assert harness.view.credential_reset_calls > 0


def test_save_mismatch_and_failure_clear_sensitive_fields() -> None:
    harness = Harness(FakeRuntime(initialized=True, version=1))
    harness.unlock()
    harness.presenter.save_credential("account", PASSWORD, "DIFFERENT_SYNTHETIC_PASSWORD")
    assert harness.executor.pending == []
    assert harness.view.status == "Credential input is invalid."
    harness.runtime.service.errors["set"] = RuntimeError("SYNTHETIC_FAILURE")
    harness.presenter.save_credential("account", PASSWORD, PASSWORD)
    harness.complete()
    assert harness.view.status == "Unable to save credential."
    assert harness.view.busy[-1] is False


def test_controls_disable_during_operation_and_duplicate_action_is_ignored() -> None:
    harness = Harness(FakeRuntime(initialized=True, version=1))
    harness.unlock()
    harness.presenter.refresh()
    harness.presenter.refresh()
    assert harness.view.busy[-1] is True
    assert len(harness.executor.pending) == 1
    harness.complete()
    assert harness.view.busy[-1] is False


def test_manual_refresh_reports_status_and_empty_state() -> None:
    harness = Harness(FakeRuntime(initialized=True, version=1))
    harness.unlock()
    harness.presenter.refresh()
    harness.complete()
    assert harness.view.accounts == ()
    assert harness.view.status == "Accounts refreshed."


def test_delete_confirmation_cancellation_success_and_failure() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    confirmation = FakeConfirmation(False)
    harness = Harness(runtime, confirmation)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.delete_selected()
    assert harness.view.status == "Deletion cancelled."
    assert harness.executor.pending == []
    confirmation.result = True
    harness.presenter.delete_selected()
    harness.complete()
    assert harness.view.status == "Credential deleted."
    assert harness.view.accounts == ()


def test_missing_account_delete_failure_is_safe_and_restores_controls() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    runtime.service.errors["delete"] = RuntimeError("SYNTHETIC_MISSING_DIAGNOSTIC")
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.delete_selected()
    harness.complete()
    assert harness.view.status == "Unable to delete credential."
    assert "SYNTHETIC_MISSING_DIAGNOSTIC" not in harness.view.status
    assert harness.view.busy[-1] is False


def test_copy_is_nonblocking_conditional_and_secret_never_reaches_view() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.copy_selected()
    harness.complete()
    assert runtime.service.get_calls == ["account"]
    assert runtime.clipboard.copied == [PASSWORD]
    assert PASSWORD not in " ".join(harness.view.status_history)
    handles = harness.scheduler.handles_for(50)
    assert len(handles) == 1
    harness.scheduler.run(handles[0])
    assert runtime.clipboard.clear_calls == 1


def test_copy_preserves_newer_content_and_later_copy_invalidates_prior_timer() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.copy_selected()
    harness.complete()
    first = harness.scheduler.handles_for(50)[0]
    runtime.clipboard.current = "NEWER_USER_CLIPBOARD_PLACEHOLDER"
    harness.scheduler.run(first)
    assert runtime.clipboard.clear_calls == 0

    harness.presenter.copy_selected()
    harness.complete()
    old = harness.scheduler.handles_for(50)[0]
    harness.presenter.copy_selected()
    harness.complete()
    assert old in harness.scheduler.cancelled
    assert len(harness.scheduler.handles_for(50)) == 1


def test_clipboard_failure_is_generic_and_controls_restore() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    runtime.clipboard.fail = True
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.copy_selected()
    harness.complete()
    assert harness.view.status == "Clipboard operation failed."
    assert harness.view.busy[-1] is False
    assert "SYNTHETIC_CLIPBOARD_DIAGNOSTIC" not in harness.view.status


def test_lock_clears_session_sensitive_state_clipboard_and_is_idempotent() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.copy_selected()
    harness.complete()
    harness.presenter.lock()
    harness.presenter.lock()
    assert harness.presenter.screen is Screen.UNLOCK
    assert runtime.service.lock_calls >= 1
    assert runtime.clipboard.clear_calls == 1
    assert harness.view.credential_clear_calls > 0
    assert harness.view.master_reset_calls > 0


def test_auto_lock_has_one_timer_resets_on_activity_and_skips_locked_create() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    harness = Harness(runtime)
    harness.unlock()
    first = harness.scheduler.handles_for(100)[0]
    harness.presenter.activity()
    assert first in harness.scheduler.cancelled
    current = harness.scheduler.handles_for(100)
    assert len(current) == 1
    harness.scheduler.run(current[0])
    assert harness.presenter.screen is Screen.UNLOCK
    assert harness.view.status == "Vault locked due to inactivity."
    assert harness.scheduler.handles_for(100) == []
    harness.presenter.activity()
    assert harness.scheduler.handles_for(100) == []

    create = Harness(FakeRuntime(initialized=False, version=0))
    create.start()
    create.presenter.activity()
    assert create.scheduler.handles_for(100) == []


def test_auto_lock_conditionally_clears_owned_clipboard() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.copy_selected()
    harness.complete()
    inactivity = harness.scheduler.handles_for(100)[0]
    harness.scheduler.run(inactivity)
    assert harness.presenter.screen is Screen.UNLOCK
    assert runtime.clipboard.clear_calls == 1
    assert runtime.service.lock_calls >= 1
    assert harness.view.credential_clear_calls > 0
    assert harness.view.credential_reset_calls > 0


def test_lock_invalidates_stale_operation_result() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.refresh()
    harness.presenter.lock()
    harness.complete()
    assert harness.presenter.screen is Screen.UNLOCK
    assert harness.view.status == "Vault locked."


def test_close_cancels_timers_clears_clipboard_closes_runtime_and_executor_once() -> None:
    runtime = FakeRuntime(initialized=True, version=1)
    runtime.service.accounts = ("account",)
    harness = Harness(runtime)
    harness.unlock()
    harness.presenter.select_account("account")
    harness.presenter.copy_selected()
    harness.complete()
    harness.presenter.close()
    harness.presenter.close()
    assert harness.presenter.screen is Screen.CLOSED
    assert runtime.close_calls == 1
    assert runtime.clipboard.clear_calls == 1
    assert harness.executor.shutdown_calls == 1
    assert harness.view.destroy_calls == 1
    assert harness.scheduler.handles_for(100) == []
    assert harness.scheduler.handles_for(50) == []
