"""Tests for pysbomcve CLI interface."""

import json
from pathlib import Path
from pysbomcve.cli import run_cli


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
        ]
    )
    assert exit_code == 0
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert len(data) == 2


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
