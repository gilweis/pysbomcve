"""Tests for pysbomcve CLI interface."""

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from pysbomcve.cli import run_cli
from pysbomcve.gui import launch_gui, main as gui_main


def test_cli_execution_with_out(tmp_path: Path) -> None:
    """Test CLI execution and saving results to file."""
    out_file = tmp_path / "results.json"
    exit_code = run_cli(
        [
            "--sbom",
            "examples/sbom.json",
            "--cve",
            "examples/cve.json",
            "--out",
            str(out_file),
            "--full",
            "--outform",
            "json",
        ]
    )
    assert exit_code == 0
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["report"] == "full" and data["generatedAt"]
    assert len(data["items"]) == 2


def test_cli_fail_on_cve() -> None:
    """Test CLI exit code 1 when --fail-on-cve is supplied."""
    exit_code = run_cli(
        [
            "--sbom",
            "examples/sbom.json",
            "--cve",
            "examples/cve.json",
            "--fail-on-cve",
        ]
    )
    assert exit_code == 1


def test_cli_missing_file() -> None:
    """Test CLI handling of non-existent files."""
    exit_code = run_cli(
        [
            "--sbom",
            "non_existent_sbom.json",
            "--cve",
            "examples/cve.json",
        ]
    )
    assert exit_code == 1


def test_gui_example_directory_entry_points(tmp_path: Path) -> None:
    """Forward the configured example directory through both GUI entry points."""
    examples_dir = tmp_path / "example files"
    with patch("pysbomcve.gui.launch_gui") as launch:
        assert run_cli(["--gui", "--examples-dir", str(examples_dir)]) == 0
        launch.assert_called_once_with(examples_dir)

    with patch("sys.argv", ["pysbomcve-gui", "--examples-dir", str(examples_dir)]):
        with patch("pysbomcve.gui.launch_gui") as launch:
            gui_main()
            launch.assert_called_once_with(examples_dir)

    with patch("sys.argv", ["pysbomcve-gui"]), patch("pysbomcve.gui.launch_gui") as launch:
        gui_main()
        launch.assert_called_once_with(None)

    with patch("pysbomcve.gui.tk.Tk") as root, patch("pysbomcve.gui.SBOMCVEApp") as app:
        launch_gui(examples_dir)
        app.assert_called_once_with(root.return_value, examples_dir)
        root.return_value.mainloop.assert_called_once()


def test_cli_examples_dir_requires_gui(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Reject the GUI-only option rather than silently ignoring it."""
    with pytest.raises(SystemExit) as exc_info:
        run_cli(["--sbom", "examples/sbom.json", "--cve", "examples/cve.json",
                 "--examples-dir", str(tmp_path)])
    assert exc_info.value.code == 2
    assert "--examples-dir requires --gui" in capsys.readouterr().err
