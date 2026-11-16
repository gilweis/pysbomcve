"""Tests for full/short JSON/HTML reports in the CLI and GUI."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch

import pytest

from pysbomcve.cli import run_cli
from pysbomcve.gui import SBOMCVEApp
from pysbomcve.report import build_short_report, render_report, sbom_max_depth
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
    assert build_short_report(sbom, results, depth=2) == [
        {"id": "root", "name": "root", "version": "1.0", "cves": both,
         "children": [{"id": "a", "name": "a", "version": "1.0", "cves": both}]},
        {"id": "x", "name": "x", "version": "1.0", "cves": both,
         "children": [{"id": "child", "name": "child", "version": "1.0", "cves": both}]},
    ]
    assert not build_short_report(sbom, [])


def test_short_report_depth() -> None:
    """Depth 1 lists roots only; deeper levels nest children; depth must be >= 1."""
    sbom, results = _sbom_and_results()
    assert sbom_max_depth(sbom) == 4
    roots = build_short_report(sbom, results, depth=1)
    assert [root["id"] for root in roots] == ["root", "x"]
    assert all("children" not in root for root in roots)

    def ids(items):
        return [(item["id"], ids(item.get("children", []))) for item in items]

    assert ids(build_short_report(sbom, results, depth=4)) == [
        ("root", [("a", [("vuln", [("child", [])])])]),
        ("x", [("child", [])]),
    ]
    assert build_short_report(sbom, results, depth=9) == build_short_report(
        sbom, results, depth=4) == build_short_report(sbom, results)
    deepest = build_short_report(sbom, results, depth=4)[0]["children"][0]["children"][0]
    assert deepest["cves"] == build_short_report(sbom, results)[0]["cves"]
    assert "children" not in deepest["children"][0]
    with pytest.raises(ValueError):
        build_short_report(sbom, results, depth=0)
    html = render_report(sbom, results, fmt="html", short=True, depth=3)
    assert "Depth: 3 level(s)" in html and "<td>3</td>" in html and "<td>4</td>" not in html
    assert json.loads(render_report(sbom, results, fmt="json", short=True, depth=3))["depth"] == 3


def test_short_report_depth_handles_cycles() -> None:
    """Dependency cycles stop at the repeated item instead of recursing forever."""
    sbom = parse_sbom({
        "components": [{"bom-ref": cid, "name": cid} for cid in ("r", "p", "q")],
        "dependencies": [
            {"ref": "r", "dependsOn": ["p"]}, {"ref": "p", "dependsOn": ["q"]},
            {"ref": "q", "dependsOn": ["p"]},
        ],
    })
    results = [{"item": sbom.components["q"].to_dict(), "cves": [{"cveId": "CVE-q"}]}]
    report = build_short_report(sbom, results, depth=10)
    assert report[0]["children"][0]["children"][0]["id"] == "q"
    assert "children" not in report[0]["children"][0]["children"][0]


def test_html_reports_escape_sbom_text() -> None:
    """HTML reports include CVE scores and escape untrusted SBOM/CVE text."""
    sbom, results = _sbom_and_results()
    sbom.components["vuln"].raw_data["name"] = "<script>x</script>"
    full = render_report(sbom, results, fmt="html", short=False)
    short = render_report(sbom, results, fmt="html")
    for page in (full, short):
        assert page.startswith("<!DOCTYPE html>")
        assert "<script>" not in page and "&lt;script&gt;" in full
    assert "CVE-1 (9.8 CRITICAL)" in short and "CVE-2 (score: N/A)" in short
    assert "<td class=\"sev-critical\">9.8</td>" in full
    with pytest.raises(ValueError):
        render_report(sbom, results, fmt="xml")


def test_html_colors_cves_by_severity() -> None:
    """CRITICAL is dark red and bold, HIGH red, MEDIUM orange; others uncolored."""
    sbom, results = _sbom_and_results()
    results[0]["cves"] = [
        {"cveId": f"CVE-{sev}", "score": score, "severity": sev}
        for sev, score in (("CRITICAL", 9.8), ("High", 7.5), ("MEDIUM", 5.0), ("LOW", 2.0))
    ]
    short = render_report(sbom, results)
    assert '<span class="sev-critical">CVE-CRITICAL (9.8 CRITICAL)</span>' in short
    assert '<span class="sev-high">CVE-High (7.5 High)</span>' in short
    assert '<span class="sev-medium">CVE-MEDIUM (5.0 MEDIUM)</span>' in short
    assert "<span>CVE-LOW (2.0 LOW)</span>" in short
    assert "<span>CVE-2 (score: N/A)</span>" in short
    full = render_report(sbom, results, short=False)
    assert '<td class="sev-high">CVE-High</td>' in full
    assert '<td class="sev-medium">MEDIUM</td>' in full and "<td>CVE-LOW</td>" in full
    for page in (short, full):
        assert ".sev-critical{color:#991b1b;font-weight:bold}" in page
        assert ".sev-high{color:#dc2626}" in page and ".sev-medium{color:#ea580c}" in page


def test_reports_include_generation_time_and_sources() -> None:
    """JSON wraps the items with time/sources; HTML shows the time in the header."""
    sbom, results = _sbom_and_results()
    when = datetime(2026, 11, 15, 16, 5, 9, tzinfo=timezone(timedelta(hours=2)))
    data = json.loads(render_report(sbom, results, fmt="json", short=True, sbom_path="s.json",
                                    cve_path="cves", generated_at=when))
    assert data == {
        "generatedAt": "2026-11-15T16:05:09+02:00", "report": "short", "depth": 4,
        "sbom": "s.json", "cve": "cves", "items": build_short_report(sbom, results),
    }
    page = render_report(sbom, results, fmt="html", generated_at=when)
    assert "Generated: 2026-11-15 16:05:09 (UTC+0200)" in page
    now = datetime.fromisoformat(
        json.loads(render_report(sbom, results, fmt="json"))["generatedAt"])
    assert now.tzinfo is not None
    assert abs((datetime.now(timezone.utc) - now).total_seconds()) < 60


@pytest.mark.parametrize("extra,check", [
    ([], lambda text: "pysbomcve Short Report" in text and "Depth: 3 level(s)" in text),
    (["--full"], lambda text: "pysbomcve Full Report" in text),
    (["--outform", "json"], lambda text: json.loads(text)["report"] == "short"
     and json.loads(text)["depth"] == 3 and "lineage_paths" not in text),
    (["--short", "--outform", "json"],
     lambda text: all("children" in root for root in json.loads(text)["items"])),
    (["--full", "--outform", "json"],
     lambda text: json.loads(text)["report"] == "full" and "lineage_paths" in text),
])
def test_cli_outform_and_report_kind(tmp_path: Path, extra, check) -> None:
    """A short HTML report at maximum depth is the default; --full and --outform change it."""
    out_file = tmp_path / "report.out"
    assert run_cli(["--sbom", "examples/sbom.json", "--cve", "examples/cve.json",
                    "--out", str(out_file), *extra]) == 0
    assert check(out_file.read_text("utf-8"))


def test_cli_depth(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--depth sets the short report levels within 1..max depth; not allowed with --full."""
    base = ["--sbom", "examples/sbom.json", "--cve", "examples/cve.json"]
    out_file = tmp_path / "short.json"
    assert run_cli([*base, "--depth", "1", "--outform", "json", "--out", str(out_file)]) == 0
    data = json.loads(out_file.read_text("utf-8"))
    assert data["depth"] == 1 and all("children" not in root for root in data["items"])
    capsys.readouterr()
    for depth in ("0", "99"):
        with patch("pysbomcve.cli.parse_cve_records") as load:
            assert run_cli([*base, "--short", "--depth", depth]) == 1
        load.assert_not_called()
        assert "--depth must be from 1 to" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        run_cli([*base, "--full", "--depth", "2"])
    assert "--depth cannot be used with --full" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        run_cli([*base, "--full", "--short"])
    assert "not allowed with argument" in capsys.readouterr().err


def test_short_html_draws_tree_lines() -> None:
    """Items are connected by tee/elbow connectors and pipes for open ancestors."""
    sbom, results = _sbom_and_results()
    results.append({"item": sbom.components["b"].to_dict(), "cves": [{"cveId": "CVE-b"}]})
    page = render_report(sbom, results, fmt="html")

    def guides(name: str) -> list:
        row = next(line for line in page.splitlines()
                   if re.search(rf'<span class="name[^"]*">{re.escape(name)}</span>', line))
        return re.findall(r'<span class="(pipe|tee|elbow|)"></span>', row)

    assert not guides("root")
    assert '<span class="name parent">root</span>' in page
    assert '<span class="name">b</span>' in page
    assert guides("a") == ["tee"] and guides("b") == ["elbow"]
    # "a" has a later sibling "b", so its line continues past "vuln" and "child".
    assert guides("vuln") == ["pipe", "elbow"]
    assert guides("child") == ["pipe", "", "elbow"]
    assert ".tee{" in page and ".elbow{" in page


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
            assert app.last_sbom is not None
            _check_depth_controls(dialog, sbom_max_depth(app.last_sbom))
            dialog.destroy()
            out_file = tmp_path / "short.html"
            assert app.export_report(str(out_file), short=True, fmt="html", depth=1)
        assert app.last_sbom is not None and app.last_results is not None
        exported = out_file.read_text("utf-8")
        stamp = re.search(r"Generated: (\S+ \S+)", exported)
        assert stamp is not None
        assert exported == render_report(
            app.last_sbom, app.last_results, fmt="html", short=True, depth=1,
            sbom_path=app.sbom_path_var.get(), cve_path=app.cve_path_var.get(),
            generated_at=datetime.strptime(stamp.group(1), "%Y-%m-%d %H:%M:%S"),
        )
    finally:
        destroy_root(root)


def _check_depth_controls(dialog: tk.Toplevel, max_depth: int) -> None:
    """Depth is limited to 1..max, defaults to max, and is enabled only for Short."""
    widgets = list(dialog.winfo_children())
    found = []
    while widgets:
        widget = widgets.pop()
        widgets.extend(widget.winfo_children())
        found.append(widget)
    spin = next(w for w in found if isinstance(w, ttk.Spinbox))
    short, full = (next(w for w in found if isinstance(w, ttk.Radiobutton)
                        and str(w.cget("value")) == kind) for kind in ("short", "full"))
    assert float(spin.cget("from")) == 1 and float(spin.cget("to")) == max_depth
    assert spin.get() == str(max_depth)
    assert str(spin.cget("state")) != tk.DISABLED
    full.invoke()
    assert str(spin.cget("state")) == tk.DISABLED
    short.invoke()
    assert str(spin.cget("state")) == tk.NORMAL
    spin.set("0")
    export = next(w for w in found if isinstance(w, ttk.Button)
                  and w.cget("text") == "Export...")
    with patch("tkinter.messagebox.showerror") as error, \
            patch("tkinter.filedialog.asksaveasfilename") as ask:
        export.invoke()
    error.assert_called_once()
    ask.assert_not_called()
