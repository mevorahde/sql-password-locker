"""Bounded background execution with main-loop callback marshalling."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Protocol, TypeVar

T = TypeVar("T")


class Scheduler(Protocol):
    def call_soon(self, callback: Callable[[], None]) -> object: ...

    def call_idle(self, callback: Callable[[], None]) -> object: ...

    def call_later(self, milliseconds: int, callback: Callable[[], None]) -> object: ...

    def cancel(self, handle: object) -> None: ...


class SubmittedOperation(Protocol[T]):
    def add_done_callback(self, callback: Callable[[SubmittedOperation[T]], None]) -> None: ...

    def result(self) -> T: ...


class OperationExecutor(Protocol):
    def submit(self, operation: Callable[[], T]) -> SubmittedOperation[T]: ...

    def shutdown(self) -> None: ...


class SingleWorkerExecutor:
    """One lazily started worker; shutdown never waits indefinitely."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pw-locker-sql")
        self._closed = False

    def submit(self, operation: Callable[[], T]) -> Future[T]:
        if self._closed:
            raise RuntimeError("executor is closed")
        return self._executor.submit(operation)

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)

    def __repr__(self) -> str:
        state = "closed" if self._closed else "ready"
        return f"SingleWorkerExecutor(state={state!r})"


class OperationCoordinator:
    """Allows one operation and dispatches every completion through a scheduler."""

    def __init__(self, executor: OperationExecutor, scheduler: Scheduler) -> None:
        self._executor = executor
        self._scheduler = scheduler
        self._busy = False
        self._closed = False

    @property
    def busy(self) -> bool:
        return self._busy

    def submit(
        self,
        operation: Callable[[], T],
        success: Callable[[T], None],
        failure: Callable[[], None],
        discard: Callable[[T], None] | None = None,
    ) -> bool:
        if self._closed or self._busy:
            return False
        self._busy = True
        try:
            submitted = self._executor.submit(operation)
        except Exception:
            self._busy = False
            self._schedule(failure)
            return True

        def finished(result: SubmittedOperation[T]) -> None:
            def deliver() -> None:
                if self._closed:
                    _discard_result(result, discard)
                    return
                self._busy = False
                try:
                    value = result.result()
                except Exception:
                    failure()
                else:
                    success(value)

            if self._closed:
                _discard_result(result, discard)
            else:
                self._schedule(deliver)

        submitted.add_done_callback(finished)
        return True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._executor.shutdown()

    def _schedule(self, callback: Callable[[], None]) -> None:
        try:
            self._scheduler.call_soon(callback)
        except Exception:
            pass


def _discard_result(
    result: SubmittedOperation[T],
    discard: Callable[[T], None] | None,
) -> None:
    try:
        value = result.result()
    except Exception:
        return
    if discard is not None:
        try:
            discard(value)
        except Exception:
            pass
