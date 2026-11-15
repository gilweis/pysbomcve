"""Helpers for driving asynchronous GUI scans in tests."""

import gc
from time import monotonic, sleep
import tkinter as tk

from pysbomcve.gui import SBOMCVEApp


def destroy_root(root: tk.Tk) -> None:
    """Collect destroyed widget cycles on the thread that owns the test interpreter."""
    root.destroy()
    gc.collect()


def wait_for_scan(app: SBOMCVEApp, timeout: float = 10) -> None:
    """Pump the Tk event loop until the background scan has been published."""
    deadline = monotonic() + timeout
    while app.is_scanning and monotonic() < deadline:
        app.root.update()
        sleep(0.005)
    assert not app.is_scanning, "Scan did not finish before the test timeout"


def run_scan_and_wait(app: SBOMCVEApp) -> None:
    """Start a scan and wait for completion without replacing its worker."""
    app.run_scan()
    wait_for_scan(app)
