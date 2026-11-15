"""Tests for responsive background scans and scan lifecycle handling."""

import json
from pathlib import Path
from threading import Event, get_ident
from time import monotonic, sleep
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch

import pytest

from pysbomcve.cve_parser import parse_cve_records
from pysbomcve.gui import SBOMCVEApp
from tests.gui_helpers import destroy_root, run_scan_and_wait, wait_for_scan


@pytest.fixture(name="app")
def fixture_app():
    """Create an application with valid example inputs."""
    root = tk.Tk()
    root.withdraw()
    application = SBOMCVEApp(root)
    application.load_example_files()
    yield application
    destroy_root(root)


def _controls(app: SBOMCVEApp):
    widgets = list(app.root.winfo_children())
    controls = []
    while widgets:
        widget = widgets.pop()
        widgets.extend(widget.winfo_children())
        if isinstance(widget, (ttk.Button, ttk.Entry, ttk.Radiobutton)):
            controls.append(widget)
    return controls


def test_status_bar_visible_at_default_window_size() -> None:
    """The progress text and bar must not be squeezed out by the results area."""
    root = tk.Tk()
    try:
        app = SBOMCVEApp(root)
        root.update()
        status = app._progress_bar.master  # pylint: disable=protected-access
        assert status.winfo_ismapped()
        assert status.winfo_y() + status.winfo_height() <= status.master.winfo_height()
    finally:
        destroy_root(root)


def test_scan_keeps_tk_responsive_and_reports_progress(app: SBOMCVEApp) -> None:
    """A blocked worker must not block Tk, start overlapping scans, or touch Tk."""
    entered, release, heartbeat = Event(), Event(), Event()
    worker_threads, ui_threads, formatting_threads = [], [], []
    main_thread = get_ident()
    set_content = app._set_text_content  # pylint: disable=protected-access
    format_results = SBOMCVEApp._format_results  # pylint: disable=protected-access

    def read_cves(source, *, progress):
        worker_threads.append(get_ident())
        progress("Reading CVE files: 1/100...")
        entered.set()
        assert release.wait(5), "Test worker was not released"
        return parse_cve_records(source, progress=progress)

    def publish(content):
        ui_threads.append(get_ident())
        set_content(content)

    def format_content(*args):
        formatting_threads.append(get_ident())
        return format_results(*args)

    with patch("pysbomcve.gui.parse_cve_records", side_effect=read_cves), \
            patch.object(app, "_set_text_content", side_effect=publish), \
            patch.object(SBOMCVEApp, "_format_results", side_effect=format_content):
        try:
            app.run_scan()
            assert entered.wait(1)
            assert app.is_scanning
            assert all(control.instate(["disabled"]) for control in _controls(app))
            app.root.after(0, heartbeat.set)
            deadline = monotonic() + 2
            while "1/100" not in app.status_var.get() and monotonic() < deadline:
                app.root.update()
                sleep(0.005)
            assert heartbeat.is_set()
            assert "Reading CVE files: 1/100" in app.status_var.get()
            assert "elapsed" in app.status_var.get()
            assert float(app._progress_bar["value"]) > 0  # pylint: disable=protected-access
            with patch("tkinter.messagebox.showinfo") as info:
                app.run_scan()
                app.clear_all()
            assert info.call_count == 2
            assert len(worker_threads) == 1
            assert app.sbom_path_var.get()
        finally:
            release.set()
            wait_for_scan(app)

    assert worker_threads[0] != main_thread
    assert formatting_threads == worker_threads
    assert ui_threads == [main_thread]
    assert all(not control.instate(["disabled"]) for control in _controls(app))
    assert "Scan Complete" in app.status_var.get()
    assert app.last_results is not None and len(app.last_results) == 2
    assert "Full JSON Result" in app.result_text.get("1.0", tk.END)


def test_cve_records_reused_until_changed_or_reloaded(app: SBOMCVEApp, tmp_path) -> None:
    """Changing only the SBOM reuses loaded CVEs; edits to a CVE file or Reload re-read."""
    with patch("pysbomcve.gui.parse_cve_records", wraps=parse_cve_records) as load:
        run_scan_and_wait(app)
        first = app.last_results
        sbom_copy = tmp_path / "sbom.json"
        sbom_copy.write_text(Path(app.sbom_path_var.get()).read_text("utf-8"), "utf-8")
        app.sbom_path_var.set(str(sbom_copy))
        run_scan_and_wait(app)
        assert load.call_count == 1
        assert app.last_results == first
        assert "reused" in app.status_var.get()

        app.reload_cves_and_scan()
        wait_for_scan(app)
        assert load.call_count == 2 and "reused" not in app.status_var.get()

        cve_copy = tmp_path / "cve.json"
        cve_copy.write_text(Path(app.cve_path_var.get()).read_text("utf-8"), "utf-8")
        app.cve_path_var.set(str(cve_copy))
        run_scan_and_wait(app)
        cve_copy.write_text(json.dumps([]), "utf-8")
        run_scan_and_wait(app)
        assert load.call_count == 4
        assert app.last_results == []


@pytest.mark.parametrize("target", [
    "pysbomcve.gui.parse_sbom", "pysbomcve.gui.parse_cve_records",
    "pysbomcve.gui.SBOMCVEMatcher.match", "pysbomcve.gui.SBOMCVEApp._format_results",
])
def test_scan_errors_restore_controls_and_allow_retry(app: SBOMCVEApp, target: str) -> None:
    """Failure in any worker stage is reported and leaves the prior snapshot intact."""
    run_scan_and_wait(app)
    previous_results, previous_sbom = app.last_results, app.last_sbom
    with patch(target, side_effect=ValueError("test scan failure")), \
            patch("tkinter.messagebox.showerror") as error:
        app.reload_cves_and_scan()
        wait_for_scan(app)
    error.assert_called_once_with("Scan Error", "Scan failed: test scan failure")
    assert "Scan failed" in app.status_var.get()
    assert app.last_results is previous_results and app.last_sbom is previous_sbom
    assert all(not control.instate(["disabled"]) for control in _controls(app))
    run_scan_and_wait(app)
    assert "Scan Complete" in app.status_var.get()


def test_closing_during_scan_does_not_call_tk_from_worker() -> None:
    """Cancel the polling callback on close; the daemon worker only owns Python data."""
    root = tk.Tk()
    root.withdraw()
    app = SBOMCVEApp(root)
    app.load_example_files()
    entered, release = Event(), Event()

    def read_cves(source, *, progress):
        entered.set()
        assert release.wait(5)
        return parse_cve_records(source, progress=progress)

    try:
        with patch("pysbomcve.gui.parse_cve_records", side_effect=read_cves):
            app.run_scan()
            assert entered.wait(1)
            future = app._scan_future  # pylint: disable=protected-access
            destroy_root(root)
            assert app._scan_after_id is None  # pylint: disable=protected-access
            release.set()
            assert future is not None
            _, results, content, _ = future.result(timeout=5)
            assert len(results) == 2 and "Full JSON Result" in content
    finally:
        release.set()
