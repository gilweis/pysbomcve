"""Tests for full/short JSON/HTML reports in the CLI and GUI."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tkinter as tk
from unittest.mock import patch

import pytest

from pysbomcve.cli import run_cli
from pysbomcve.gui import SBOMCVEApp
from pysbomcve.report import build_short_report, render_report
from pysbomcve.sbom_parser import parse_sbom
from tests.gui_helpers import destroy_root, run_scan_and_wait


def _sbom_and_results():
    """root->a->vuln->child, a->safe, root->b; x->child is a second root."""
    sbom = parse_sbom({
        "components": [
            {"bom-ref": cid, "name": cid, "version": "1.0"}
            for cid in ("root", "a", "b", "vuln", "child", "safe", "x")
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["a", "b"]},
            {"ref": "a", "dependsOn": ["vuln", "safe"]},
            {"ref": "vuln", "dependsOn": ["child"]},
            {"ref": "x", "dependsOn": ["child"]},
        ],
    })
    critical = {"cveId": "CVE-1", "score": 9.8, "severity": "CRITICAL", "title": "t"}
    results = [
        {"item": sbom.components["vuln"].to_dict(), "cves": [critical]},
        {"item": sbom.components["child"].to_dict(),
         "cves": [{"cveId": "CVE-2", "score": None}, dict(critical)]},
    ]
    return sbom, results


def test_short_report_lists_roots_and_children_with_cves_below() -> None:
    """Children without CVEs on or below them are omitted; CVEs are deduplicated."""
    sbom, results = _sbom_and_results()
    both = [
        {"cveId": "CVE-1", "score": 9.8, "severity": "CRITICAL"},
        {"cveId": "CVE-2", "score": None, "severity": None},
    ]
    assert build_short_report(sbom, results) == [
        {"id": "root", "name": "root", "version": "1.0", "cves": both,
         "children": [{"id": "a", "name": "a", "version": "1.0", "cves": both}]},
        {"id": "x", "name": "x", "version": "1.0", "cves": both,
         "children": [{"id": "child", "name": "child", "version": "1.0", "cves": both}]},
    ]
    assert not build_short_report(sbom, [])


def test_html_reports_escape_sbom_text() -> None:
    """HTML reports include CVE scores and escape untrusted SBOM/CVE text."""
    sbom, results = _sbom_and_results()
    sbom.components["vuln"].raw_data["name"] = "<script>x</script>"
    full = render_report(sbom, results, fmt="html")
    short = render_report(sbom, results, fmt="html", short=True)
    for page in (full, short):
        assert page.startswith("<!DOCTYPE html>")
        assert "<script>" not in page and "&lt;script&gt;" in full
    assert "CVE-1 (9.8 CRITICAL)" in short and "CVE-2 (score: N/A)" in short
    assert "<td>9.8</td>" in full
    with pytest.raises(ValueError):
        render_report(sbom, results, fmt="xml")


def test_reports_include_generation_time_and_sources() -> None:
    """JSON wraps the items with time/sources; HTML shows the time in the header."""
    sbom, results = _sbom_and_results()
    when = datetime(2026, 11, 15, 16, 5, 9, tzinfo=timezone(timedelta(hours=2)))
    data = json.loads(render_report(sbom, results, short=True, sbom_path="s.json",
                                    cve_path="cves", generated_at=when))
    assert data == {
        "generatedAt": "2026-11-15T16:05:09+02:00", "report": "short",
        "sbom": "s.json", "cve": "cves", "items": build_short_report(sbom, results),
    }
    page = render_report(sbom, results, fmt="html", generated_at=when)
    assert "Generated: 2026-11-15 16:05:09 (UTC+0200)" in page
    now = datetime.fromisoformat(json.loads(render_report(sbom, results))["generatedAt"])
    assert now.tzinfo is not None
    assert abs((datetime.now(timezone.utc) - now).total_seconds()) < 60


@pytest.mark.parametrize("extra,check", [
    ([], lambda text: json.loads(text)["report"] == "full" and "lineage_paths" in text),
    (["--short"], lambda text: all("children" in root for root in json.loads(text)["items"])),
    (["--outform", "html"], lambda text: "pysbomcve Full Report" in text),
    (["--short", "--outform", "html"], lambda text: "pysbomcve Short Report" in text),
])
def test_cli_outform_and_short(tmp_path: Path, extra, check) -> None:
    """--outform and --short select the saved report."""
    out_file = tmp_path / "report.out"
    assert run_cli(["--sbom", "examples/sbom.json", "--cve", "examples/cve.json",
                    "--out", str(out_file), *extra]) == 0
    assert check(out_file.read_text("utf-8"))


def test_gui_export_matches_cli_report(tmp_path: Path) -> None:
    """The GUI export writes the same report as the shared renderer."""
    root = tk.Tk()
    root.withdraw()
    try:
        app = SBOMCVEApp(root)
        with patch("tkinter.messagebox.showinfo") as info:
            assert app.show_export_dialog() is None
            info.assert_called_once()
            app.load_example_files()
            run_scan_and_wait(app)
            dialog = app.show_export_dialog()
            assert dialog is not None
            dialog.destroy()
            out_file = tmp_path / "short.html"
            assert app.export_report(str(out_file), short=True, fmt="html")
        assert app.last_sbom is not None and app.last_results is not None
        exported = out_file.read_text("utf-8")
        stamp = re.search(r"Generated: (\S+ \S+)", exported)
        assert stamp is not None
        assert exported == render_report(
            app.last_sbom, app.last_results, fmt="html", short=True,
            sbom_path=app.sbom_path_var.get(), cve_path=app.cve_path_var.get(),
            generated_at=datetime.strptime(stamp.group(1), "%Y-%m-%d %H:%M:%S"),
        )
    finally:
        destroy_root(root)
