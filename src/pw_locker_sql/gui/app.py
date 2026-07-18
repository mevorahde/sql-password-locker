"""Explicit Tk GUI launch boundary."""

from __future__ import annotations


def main() -> int:
    """Create and run the GUI only when explicitly invoked."""
    root = None
    try:
        import tkinter as tk

        from pw_locker_sql.gui.icon import apply_window_icon
        from pw_locker_sql.gui.operations import OperationCoordinator, SingleWorkerExecutor
        from pw_locker_sql.gui.presenter import VaultGuiPresenter
        from pw_locker_sql.gui.view import TkDeleteConfirmation, TkScheduler, TkVaultView
        from pw_locker_sql.runtime import RuntimeComposition

        root = tk.Tk()
        apply_window_icon(root, tk)
        view = TkVaultView(root)
        scheduler = TkScheduler(root)
        coordinator = OperationCoordinator(SingleWorkerExecutor(), scheduler)
        presenter = VaultGuiPresenter(
            view,
            RuntimeComposition(),
            coordinator,
            scheduler,
            TkDeleteConfirmation(root),
        )
        view.bind_presenter(presenter)
        presenter.start()
        root.mainloop()
        return 0
    except Exception:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass
        return 70


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
