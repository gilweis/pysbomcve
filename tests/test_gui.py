"""Tests for pysbomcve desktop GUI application."""

import tkinter as tk
from unittest.mock import patch
import pytest

from pysbomcve.gui import SBOMCVEApp


@pytest.fixture(name="tk_app")
def fixture_tk_app():
    """Create a headless Tk instance and SBOMCVEApp for testing."""
    root = tk.Tk()
    root.withdraw()
    app = SBOMCVEApp(root)
    yield app
    root.destroy()


def test_gui_initial_state(tk_app: SBOMCVEApp) -> None:
    """Test initial widget values and status text."""
    assert tk_app.sbom_path_var.get() == ""
    assert tk_app.cve_path_var.get() == ""
    assert "Welcome to pysbomcve" in tk_app.result_text.get("1.0", tk.END)
    assert tk_app.status_var.get() == "Ready."


def test_gui_load_example_files(tk_app: SBOMCVEApp) -> None:
    """Test loading project example files via convenience method."""
    tk_app.load_example_files()
    assert "sbom.json" in tk_app.sbom_path_var.get()
    assert "cve.json" in tk_app.cve_path_var.get()
    assert "Example files loaded" in tk_app.status_var.get()


def test_gui_run_scan_and_view_modes(tk_app: SBOMCVEApp) -> None:
    """Test running a scan from the GUI and toggling display modes."""
    tk_app.load_example_files()
    tk_app.run_scan()

    assert tk_app.last_results is not None
    assert len(tk_app.last_results) == 2
    assert "Scan Complete" in tk_app.status_var.get()

    # Verify combined display content
    content_combined = tk_app.result_text.get("1.0", tk.END)
    assert "requests @ 2.28.0" in content_combined
    assert "CVE-2023-32681" in content_combined
    assert "Full JSON Result" in content_combined

    # Toggle to JSON only
    tk_app.view_mode_var.set("json")
    tk_app._refresh_display()  # pylint: disable=protected-access
    content_json = tk_app.result_text.get("1.0", tk.END)
    assert "Full JSON Result" not in content_json
    assert '"cveId": "CVE-2023-32681"' in content_json

    # Toggle to summary only
    tk_app.view_mode_var.set("summary")
    tk_app._refresh_display()  # pylint: disable=protected-access
    content_summary = tk_app.result_text.get("1.0", tk.END)
    assert "pysbomcve Scan Report" in content_summary


def test_gui_run_scan_validation_missing_input(tk_app: SBOMCVEApp) -> None:
    """Test validation alert when input paths are missing."""
    with patch("tkinter.messagebox.showwarning") as mock_warn:
        tk_app.sbom_path_var.set("")
        tk_app.cve_path_var.set("")
        tk_app.run_scan()
        mock_warn.assert_called_once()


def test_gui_clear_all(tk_app: SBOMCVEApp) -> None:
    """Test clearing all input and text fields."""
    tk_app.load_example_files()
    tk_app.run_scan()
    tk_app.clear_all()

    assert tk_app.sbom_path_var.get() == ""
    assert tk_app.cve_path_var.get() == ""
    assert tk_app.last_results is None
    assert "Inputs cleared" in tk_app.result_text.get("1.0", tk.END)
