from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar

from pw_locker_sql.gui.operations import OperationCoordinator

T = TypeVar("T")


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
        self.futures: list[FakeFuture[object]] = []
        self.shutdown_calls = 0

    def submit(self, operation: Callable[[], T]) -> FakeFuture[T]:
        future = FakeFuture(operation)
        self.futures.append(future)  # type: ignore[arg-type]
        return future

    def shutdown(self) -> None:
        self.shutdown_calls += 1


class FakeScheduler:
    def __init__(self) -> None:
        self.soon: list[Callable[[], None]] = []

    def call_soon(self, callback: Callable[[], None]) -> object:
        self.soon.append(callback)
        return len(self.soon)

    def call_idle(self, callback: Callable[[], None]) -> object:
        raise AssertionError("not used by operation coordinator")

    def call_later(self, milliseconds: int, callback: Callable[[], None]) -> object:
        raise AssertionError("not used by operation coordinator")

    def cancel(self, handle: object) -> None:
        raise AssertionError("not used by operation coordinator")

    def run(self) -> None:
        while self.soon:
            self.soon.pop(0)()


def test_one_operation_at_a_time_and_callbacks_use_scheduler() -> None:
    executor = FakeExecutor()
    scheduler = FakeScheduler()
    coordinator = OperationCoordinator(executor, scheduler)  # type: ignore[arg-type]
    results: list[str] = []
    assert coordinator.submit(lambda: "first", results.append, lambda: None) is True
    assert coordinator.submit(lambda: "second", results.append, lambda: None) is False
    assert coordinator.busy is True
    executor.futures[0].run()
    assert results == []
    assert coordinator.busy is True
    scheduler.run()
    assert results == ["first"]
    assert coordinator.busy is False


def test_failure_is_marshaled_and_busy_state_recovers() -> None:
    executor = FakeExecutor()
    scheduler = FakeScheduler()
    coordinator = OperationCoordinator(executor, scheduler)  # type: ignore[arg-type]
    failures: list[str] = []

    def fail() -> str:
        raise RuntimeError("SYNTHETIC_WORKER_DIAGNOSTIC")

    assert coordinator.submit(fail, lambda _value: None, lambda: failures.append("safe"))
    executor.futures[0].run()
    assert failures == []
    scheduler.run()
    assert failures == ["safe"]
    assert coordinator.busy is False


def test_close_is_idempotent_rejects_work_and_bounds_shutdown() -> None:
    executor = FakeExecutor()
    scheduler = FakeScheduler()
    coordinator = OperationCoordinator(executor, scheduler)  # type: ignore[arg-type]
    coordinator.close()
    coordinator.close()
    assert executor.shutdown_calls == 1
    assert coordinator.submit(lambda: "value", lambda _value: None, lambda: None) is False


def test_completed_result_is_discarded_after_close_without_view_callback() -> None:
    executor = FakeExecutor()
    scheduler = FakeScheduler()
    coordinator = OperationCoordinator(executor, scheduler)  # type: ignore[arg-type]
    delivered: list[str] = []
    discarded: list[str] = []
    coordinator.submit(
        lambda: "sensitive-boundary",
        delivered.append,
        lambda: None,
        discarded.append,
    )
    coordinator.close()
    executor.futures[0].run()
    assert delivered == []
    assert discarded == ["sensitive-boundary"]
    assert scheduler.soon == []
