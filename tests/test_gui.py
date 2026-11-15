"""Tests for pysbomcve desktop GUI application."""

import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Tuple
from unittest.mock import patch
import pytest

from pysbomcve.graph_view import ResultsGraphWindow, SBOMTreeWindow, _display_name
from pysbomcve.gui import SBOMCVEApp
from pysbomcve.sbom_parser import parse_sbom
from tests.gui_helpers import destroy_root, run_scan_and_wait


@pytest.fixture(name="tk_app")
def fixture_tk_app():
    """Create a headless Tk instance and SBOMCVEApp for testing."""
    root = tk.Tk()
    root.withdraw()
    app = SBOMCVEApp(root)
    yield app
    destroy_root(root)


def _graph_zoom_buttons(graph: tk.Toplevel) -> Dict[str, ttk.Button]:
    """Find the graph window's zoom controls."""
    return {
        str(widget.cget("text")): widget
        for frame in graph.winfo_children()
        for widget in frame.winfo_children()
        if isinstance(widget, ttk.Button)
    }


def _scrollable_graph(app: SBOMCVEApp) -> ResultsGraphWindow:
    """Create a graph large enough to move in both directions."""
    app.last_results = [{
        "item": {"name": "leaf"},
        "lineage_paths": [[{"name": f"ancestor-{index}"} for index in range(8)]],
        "cves": [
            {"cveId": f"CVE-2026-{index:04d}", "descriptions": ["Description."]}
            for index in range(20)
        ],
    }]
    graph = app.show_graph()
    assert graph is not None
    graph.update()
    graph.canvas.xview_moveto(0.3)
    graph.canvas.yview_moveto(0.3)
    graph.update()
    return graph


def _tree_rectangle(tree: SBOMTreeWindow, tag: str) -> int:
    """Find the rectangle of a tree component."""
    return next(
        node for node in tree.canvas.find_withtag(tag)
        if tree.canvas.type(node) == "rectangle"
    )


def _tree_edge(tree: SBOMTreeWindow, parent: str, child: str) -> int:
    """Find the arrow connecting two component cards."""
    source = tree.canvas.coords(_tree_rectangle(tree, parent))
    target = tree.canvas.coords(_tree_rectangle(tree, child))
    start_x = source[2] if target[0] > source[0] else source[0]
    end_x = target[0] if target[0] > source[0] else target[2]
    expected = [start_x, (source[1] + source[3]) / 2,
                end_x, (target[1] + target[3]) / 2]
    return next(
        node for node in tree.canvas.find_withtag("edge")
        if tree.canvas.coords(node) == pytest.approx(expected)
    )


def _dialog_details(dialog: tk.Toplevel) -> Dict[str, Any]:
    """Read the JSON displayed in an item-details dialog."""
    text = next(
        widget for frame in dialog.winfo_children() for widget in frame.winfo_children()
        if isinstance(widget, tk.Text)
    )
    return json.loads(text.get("1.0", tk.END))


def _click_tree_component(tree: SBOMTreeWindow, tag: str, timestamp: int) -> None:
    """Click a component currently in the viewport."""
    canvas = tree.canvas
    left, top = canvas.coords(_tree_rectangle(tree, tag))[:2]
    x = int(left + 15 - canvas.canvasx(0))
    y = int(top + 15 - canvas.canvasy(0))
    assert 0 <= x < canvas.winfo_width() and 0 <= y < canvas.winfo_height()
    canvas.event_generate("<Motion>", x=x, y=y)
    canvas.event_generate("<ButtonPress-1>", x=x, y=y, time=timestamp)
    canvas.event_generate("<ButtonRelease-1>", x=x, y=y, time=timestamp + 10)
    tree.update()


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


def test_gui_custom_examples_dir(tmp_path: Path) -> None:
    """Load and scan the named files from a custom example directory."""
    examples_dir = tmp_path / "example files"
    examples_dir.mkdir()
    project_examples = Path(__file__).resolve().parent.parent / "examples"
    for name in ("sbom.json", "cve.json"):
        (examples_dir / name).write_bytes((project_examples / name).read_bytes())

    root = tk.Tk()
    root.withdraw()
    try:
        app = SBOMCVEApp(root, examples_dir=examples_dir)
        app.load_example_files()
        assert app.sbom_path_var.get() == str(examples_dir / "sbom.json")
        assert app.cve_path_var.get() == str(examples_dir / "cve.json")
        run_scan_and_wait(app)
        assert app.last_results is not None
        assert len(app.last_results) == 2
    finally:
        destroy_root(root)


@pytest.mark.parametrize("missing_name", ["sbom.json", "cve.json"])
def test_gui_examples_dir_missing_file(tmp_path: Path, missing_name: str) -> None:
    """Report a missing example file without replacing either input."""
    other_name = "cve.json" if missing_name == "sbom.json" else "sbom.json"
    (tmp_path / other_name).write_text("{}", encoding="utf-8")
    root = tk.Tk()
    root.withdraw()
    try:
        app = SBOMCVEApp(root, examples_dir=tmp_path)
        app.sbom_path_var.set("previous-sbom")
        app.cve_path_var.set("previous-cve")
        with patch("tkinter.messagebox.showerror") as error:
            app.load_example_files()
        error.assert_called_once()
        assert str(tmp_path / missing_name) in error.call_args.args[1]
        assert app.sbom_path_var.get() == "previous-sbom"
        assert app.cve_path_var.get() == "previous-cve"
        assert "not found" in app.status_var.get().lower()
    finally:
        destroy_root(root)


def test_gui_selects_cve_directory_and_scans(
    tk_app: SBOMCVEApp, tmp_path: Path
) -> None:
    """Select a folder using the button and scan CVE files in all its subfolders."""
    cve_dir = tmp_path / "CVE records"
    project_examples = Path(__file__).resolve().parent.parent / "examples"
    cves = json.loads((project_examples / "cve.json").read_text(encoding="utf-8"))
    for index, cve in enumerate(cves):
        nested_dir = cve_dir / f"year-{index}" / "batch"
        nested_dir.mkdir(parents=True)
        (nested_dir / f"cve-{index}.JSON").write_text(json.dumps(cve), encoding="utf-8")
    tk_app.sbom_path_var.set(str(project_examples / "sbom.json"))
    input_frame = next(
        child for parent in tk_app.root.winfo_children()
        for child in parent.winfo_children()
        if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Input Files"
    )
    folder_button = next(
        child for child in input_frame.winfo_children()
        if isinstance(child, ttk.Button) and child.cget("text") == "Folder..."
    )
    file_button = next(
        child for child in input_frame.winfo_children()
        if isinstance(child, ttk.Button) and child.cget("text") == "File..."
    )
    with patch(
        "tkinter.filedialog.askopenfilename", return_value=str(project_examples / "cve.json")
    ):
        file_button.invoke()
    assert tk_app.cve_path_var.get() == str(project_examples / "cve.json")

    with patch("tkinter.filedialog.askdirectory", side_effect=[str(cve_dir), ""]):
        folder_button.invoke()
        assert tk_app.cve_path_var.get() == str(cve_dir)
        folder_button.invoke()
        assert tk_app.cve_path_var.get() == str(cve_dir)

    run_scan_and_wait(tk_app)
    assert tk_app.last_results is not None
    assert {item["cves"][0]["cveId"] for item in tk_app.last_results} == {
        "CVE-2023-32681", "CVE-2021-44228",
    }


def test_gui_run_scan_and_view_modes(tk_app: SBOMCVEApp) -> None:
    """Test running a scan from the GUI and toggling display modes."""
    tk_app.load_example_files()
    run_scan_and_wait(tk_app)

    assert tk_app.last_results is not None
    assert len(tk_app.last_results) == 2
    assert "Scan Complete" in tk_app.status_var.get()

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
        run_scan_and_wait(tk_app)
        mock_warn.assert_called_once()


def test_gui_clear_all(tk_app: SBOMCVEApp) -> None:
    """Test clearing all input and text fields."""
    tk_app.load_example_files()
    run_scan_and_wait(tk_app)
    tk_app.clear_all()

    assert tk_app.sbom_path_var.get() == ""
    assert tk_app.cve_path_var.get() == ""
    assert tk_app.last_results is None
    assert tk_app.last_sbom is None
    assert "Inputs cleared" in tk_app.result_text.get("1.0", tk.END)


@pytest.mark.parametrize("filename", ["sbom.json", "sbom_spdx.json"])
def test_gui_sbom_tree_button_and_scan_snapshot(
    tk_app: SBOMCVEApp, filename: str
) -> None:
    """Show all items and dependencies from either format, not changed input paths."""
    examples = Path(__file__).resolve().parent.parent / "examples"
    tk_app.sbom_path_var.set(str(examples / filename))
    tk_app.cve_path_var.set(str(examples / "cve.json"))
    run_scan_and_wait(tk_app)
    sbom = tk_app.last_sbom
    assert sbom is not None
    tk_app.sbom_path_var.set("a different input that does not exist.json")
    button = next(
        widget
        for parent in tk_app.root.winfo_children()
        for frame in parent.winfo_children()
        for widget in frame.winfo_children()
        if isinstance(widget, ttk.Button) and widget.cget("text") == "SBOM Tree..."
    )
    with patch("tkinter.messagebox.showwarning") as warning:
        button.invoke()
    warning.assert_not_called()
    tree = next(
        child for child in tk_app.root.winfo_children()
        if isinstance(child, SBOMTreeWindow)
    )
    labels = [
        tree.canvas.itemcget(node, "text")
        for node in tree.canvas.find_withtag("node")
        if tree.canvas.type(node) == "text"
    ]
    assert len(labels) == len(sbom.components)
    for c in sbom.components.values():
        assert any(label.split("\n")[0] == _display_name(c.raw_data, c.name) for label in labels)
    assert len(tree.canvas.find_withtag("edge")) == sum(
        len(component.parent_ids.intersection(sbom.components))
        for component in sbom.components.values()
    )
    assert any("CVE-2023-32681" in label for label in labels)
    assert any("payment-gateway-client" in label and "CVE-" not in label for label in labels)


@pytest.mark.parametrize("filename", ["sbom.json", "sbom_spdx.json"])
def test_gui_sbom_tree_before_scan(tk_app: SBOMCVEApp, filename: str) -> None:
    """Render the selected SBOM without CVE input, clearly marked as unscanned."""
    examples = Path(__file__).resolve().parent.parent / "examples"
    sbom_path = examples / filename
    tk_app.sbom_path_var.set(str(sbom_path))
    button = next(
        widget
        for parent in tk_app.root.winfo_children()
        for frame in parent.winfo_children()
        for widget in frame.winfo_children()
        if isinstance(widget, ttk.Button) and widget.cget("text") == "SBOM Tree..."
    )
    with patch("tkinter.messagebox.showwarning") as warning, patch(
        "tkinter.messagebox.showinfo"
    ) as info:
        button.invoke()
    warning.assert_called_once()
    assert "not" in warning.call_args.args[1].lower()
    assert "scan" in warning.call_args.args[1].lower()
    info.assert_not_called()
    tree = next(
        child for child in tk_app.root.winfo_children()
        if isinstance(child, SBOMTreeWindow)
    )
    labels = [
        tree.canvas.itemcget(node, "text")
        for node in tree.canvas.find_withtag("node")
        if tree.canvas.type(node) == "text"
    ]
    parsed = parse_sbom(sbom_path)
    assert len(labels) == len(parsed.components)
    assert {label.split("\n")[0] for label in labels} == {
        _display_name(c.raw_data, c.name) for c in parsed.components.values()
    }
    assert all("CVE-" not in label for label in labels)
    assert any(
        "not been run" in str(widget.cget("text")).lower()
        for widget in tree.winfo_children() if isinstance(widget, ttk.Label)
    )
    assert tk_app.last_sbom is None
    assert tk_app.last_results is None

    dialog = tree.show_item_details("component-0")
    details = _dialog_details(dialog)
    assert details["item"] == next(iter(parsed.components.values())).to_dict()
    assert details["cves"] is None
    assert "not scanned" in details["scan_status"].lower()

    tk_app.cve_path_var.set(str(examples / "cve.json"))
    run_scan_and_wait(tk_app)
    with patch("tkinter.messagebox.showwarning") as warning:
        scanned_tree = tk_app.show_sbom_tree()
    warning.assert_not_called()
    assert scanned_tree is not None
    assert any(
        "CVE-2023-32681" in scanned_tree.canvas.itemcget(node, "text")
        for node in scanned_tree.canvas.find_all()
        if scanned_tree.canvas.type(node) == "text"
    )


def test_gui_sbom_tree_preview_uses_current_selection(tk_app: SBOMCVEApp) -> None:
    """A new preview reads the currently selected file instead of an earlier preview."""
    examples = Path(__file__).resolve().parent.parent / "examples"
    with patch("tkinter.messagebox.showwarning") as warning:
        tk_app.sbom_path_var.set(str(examples / "sbom.json"))
        first = tk_app.show_sbom_tree()
        tk_app.sbom_path_var.set(str(examples / "sbom_spdx.json"))
        second = tk_app.show_sbom_tree()
    assert warning.call_count == 2
    assert first is not None and second is not None
    first_labels = [
        first.canvas.itemcget(node, "text") for node in first.canvas.find_all()
        if first.canvas.type(node) == "text"
    ]
    second_labels = [
        second.canvas.itemcget(node, "text") for node in second.canvas.find_all()
        if second.canvas.type(node) == "text"
    ]
    assert any("log4j-core" in label for label in first_labels)
    assert not any("log4j-core" in label for label in second_labels)
    assert any("requests" in label for label in second_labels)


@pytest.mark.parametrize("contents", ["{invalid json", "[]", "{}", '{"components": null}'])
def test_gui_sbom_tree_before_scan_reports_bad_input(
    tk_app: SBOMCVEApp, tmp_path: Path, contents: str
) -> None:
    """Malformed or unreadable SBOMs produce an error, never an empty tree."""
    sbom_path = tmp_path / "invalid.json"
    sbom_path.write_text(contents, encoding="utf-8")
    tk_app.sbom_path_var.set(str(sbom_path))
    with patch("tkinter.messagebox.showerror") as error, patch(
        "tkinter.messagebox.showwarning"
    ) as warning, patch("tkinter.messagebox.showinfo"):
        assert tk_app.show_sbom_tree() is None
    error.assert_called_once()
    warning.assert_not_called()
    assert not any(isinstance(child, SBOMTreeWindow) for child in tk_app.root.winfo_children())


def test_gui_sbom_tree_missing_input(tk_app: SBOMCVEApp, tmp_path: Path) -> None:
    """Prompt for an SBOM, and report a missing file before opening a tree."""
    with patch("tkinter.messagebox.showwarning") as warning, patch(
        "tkinter.messagebox.showinfo"
    ):
        assert tk_app.show_sbom_tree() is None
    warning.assert_called_once()
    assert "SBOM" in warning.call_args.args[1]
    for path in (tmp_path / "missing.json", tmp_path):
        tk_app.sbom_path_var.set(str(path))
        with patch("tkinter.messagebox.showerror") as error, patch(
            "tkinter.messagebox.showinfo"
        ):
            assert tk_app.show_sbom_tree() is None
        error.assert_called_once()
        assert str(path) in error.call_args.args[1]


def test_gui_sbom_tree_allows_no_matches(tk_app: SBOMCVEApp) -> None:
    """A completed scan with no findings is not an unscanned preview."""
    tk_app.last_sbom = parse_sbom({"components": [{"name": "unaffected"}]})
    tk_app.last_results = []
    with patch("tkinter.messagebox.showwarning") as warning:
        tree = tk_app.show_sbom_tree()
    warning.assert_not_called()
    assert tree is not None
    assert any(
        tree.canvas.itemcget(node, "text") == "unaffected"
        for node in tree.canvas.find_all() if tree.canvas.type(node) == "text"
    )
    tk_app.last_sbom = parse_sbom({"components": []})
    empty_tree = tk_app.show_sbom_tree()
    assert empty_tree is not None
    assert any(
        empty_tree.canvas.itemcget(node, "text") == "No components in this SBOM."
        for node in empty_tree.canvas.find_all() if empty_tree.canvas.type(node) == "text"
    )
    tk_app.clear_all()
    with patch("tkinter.messagebox.showwarning"):
        assert tk_app.show_sbom_tree() is None


def test_gui_sbom_tree_shared_dependencies_cycles_and_highlights(
    tk_app: SBOMCVEApp, tmp_path: Path
) -> None:
    """Preserve every edge and highlight only the affected version with all CVE IDs."""
    data = {
        "components": [
            {"bom-ref": "root", "name": "root"},
            {"bom-ref": "parent", "name": "parent"},
            {"bom-ref": "old", "name": "requests", "version": "2.28.0",
             "properties": [{"name": "extra", "value": "complete details"}]},
            {"bom-ref": "new", "name": "requests", "version": "2.32.0"},
            {"bom-ref": "cycle-a", "name": "cycle-a"},
            {"bom-ref": "cycle-b", "name": "cycle-b"},
            {"bom-ref": "orphan", "name": "orphan"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["parent", "old", "new"]},
            {"ref": "parent", "dependsOn": ["old"]},
            {"ref": "cycle-a", "dependsOn": ["cycle-b"]},
            {"ref": "cycle-b", "dependsOn": ["cycle-a"]},
        ],
    }
    (tmp_path / "sbom.json").write_text(json.dumps(data), encoding="utf-8")
    examples = Path(__file__).resolve().parent.parent / "examples"
    cves = json.loads((examples / "cve.json").read_text(encoding="utf-8"))
    cves.append(json.loads(json.dumps(cves[0])))
    cves[-1]["cveMetadata"]["cveId"] = "CVE-2026-9999"
    (tmp_path / "cves.json").write_text(json.dumps(cves), encoding="utf-8")
    tk_app.sbom_path_var.set(str(tmp_path / "sbom.json"))
    tk_app.cve_path_var.set(str(tmp_path / "cves.json"))
    run_scan_and_wait(tk_app)
    tree = tk_app.show_sbom_tree()
    assert tree is not None
    assert tk_app.last_results is not None
    assert len(tk_app.last_results) == 1
    labels = {}
    colors = {}
    for index, component in enumerate(data["components"]):
        nodes = tree.canvas.find_withtag(f"component-{index}")
        text = next(node for node in nodes if tree.canvas.type(node) == "text")
        rectangle = next(node for node in nodes if tree.canvas.type(node) == "rectangle")
        labels[component["bom-ref"]] = tree.canvas.itemcget(text, "text")
        colors[component["bom-ref"]] = tree.canvas.itemcget(rectangle, "fill")
    assert len(tree.canvas.find_withtag("node")) == 2 * len(data["components"])
    assert len(tree.canvas.find_withtag("edge")) == 6
    assert "CVE-2023-32681" in labels["old"] and "CVE-2026-9999" in labels["old"]
    assert "CVE-" not in labels["new"]
    assert colors["old"] != colors["new"]
    assert len({color for cid, color in colors.items() if cid != "old"}) == 1
    dialog = tree.show_item_details("component-2")
    text = next(
        widget for frame in dialog.winfo_children() for widget in frame.winfo_children()
        if isinstance(widget, tk.Text)
    )
    details = json.loads(text.get("1.0", tk.END))
    assert details["item"] == data["components"][2]
    assert details["cves"] == tk_app.last_results[0]["cves"]
    assert all("rawRecord" in cve for cve in details["cves"])
    assert text.cget("state") == tk.DISABLED
    dialog.destroy()
    dialog = tree.show_item_details("component-3")
    assert _dialog_details(dialog) == {
        "item": data["components"][3], "cves": []
    }


def test_gui_sbom_tree_click_double_click_and_drag_after_zoom(tk_app: SBOMCVEApp) -> None:
    """Single-click selects, double-click opens full details, and dragging does neither."""
    tk_app.load_example_files()
    run_scan_and_wait(tk_app)
    tree = tk_app.show_sbom_tree()
    assert tree is not None
    tree.update()
    _graph_zoom_buttons(tree)["Zoom in"].invoke()
    tree.canvas.xview_moveto(0)
    tree.canvas.yview_moveto(0)
    tree.update()
    canvas = tree.canvas
    tag = "component-2"
    rectangle = _tree_rectangle(tree, tag)
    left, top = canvas.coords(rectangle)[:2]
    x, y = int(left + 15 - canvas.canvasx(0)), int(top + 15 - canvas.canvasy(0))
    original_outline = canvas.itemcget(rectangle, "outline")
    with patch.object(tree, "show_item_details", wraps=tree.show_item_details) as details:
        _click_tree_component(tree, tag, 1000)
        details.assert_not_called()
        assert canvas.itemcget(rectangle, "outline") != original_outline
        _click_tree_component(tree, tag, 1100)
        details.assert_called_once_with(tag)
        dialog = next(child for child in tree.winfo_children() if isinstance(child, tk.Toplevel))
        item_details = _dialog_details(dialog)
        assert item_details["item"]["name"] == "requests"
        assert tk_app.last_results is not None
        assert item_details["cves"] == next(
            result["cves"] for result in tk_app.last_results
            if result["item"]["name"] == "requests"
        )
        assert "rawRecord" in item_details["cves"][0]
        dialog.destroy()
        details.reset_mock()
        canvas.event_generate("<ButtonPress-1>", x=x, y=y, time=2000)
        canvas.event_generate("<B1-Motion>", x=x + 15, y=y + 15, time=2010)
        canvas.event_generate("<B1-Motion>", x=x, y=y, time=2020)
        canvas.event_generate("<ButtonRelease-1>", x=x, y=y, time=2030)
        tree.update()
        details.assert_not_called()
        _click_tree_component(tree, tag, 2100)
        details.assert_not_called()


def test_gui_unscanned_tree_click_and_double_click(tk_app: SBOMCVEApp) -> None:
    """Selection and item details work in the unscanned preview too."""
    examples = Path(__file__).resolve().parent.parent / "examples"
    tk_app.sbom_path_var.set(str(examples / "sbom.json"))
    with patch("tkinter.messagebox.showwarning"):
        tree = tk_app.show_sbom_tree()
    assert tree is not None
    tree.update()
    rectangle = _tree_rectangle(tree, "component-0")
    original = tree.canvas.itemcget(rectangle, "outline")
    with patch.object(tree, "show_item_details", wraps=tree.show_item_details) as details:
        _click_tree_component(tree, "component-0", 1000)
        details.assert_not_called()
        assert tree.canvas.itemcget(rectangle, "outline") != original
        _click_tree_component(tree, "component-0", 1100)
        details.assert_called_once_with("component-0")
    dialog = next(child for child in tree.winfo_children() if isinstance(child, tk.Toplevel))
    item_details = _dialog_details(dialog)
    assert item_details["item"]["name"] == "ecommerce-platform"
    assert item_details["cves"] is None
    assert "not scanned" in item_details["scan_status"].lower()


def test_gui_sbom_tree_highlights_all_paths_and_preserves_cve_colors(
    tk_app: SBOMCVEApp,
) -> None:
    """Highlight all ancestors, descendants, and connecting paths but not siblings."""
    ids = ["root", "left", "right", "target", "child", "grandchild", "sibling", "other"]
    tk_app.last_sbom = parse_sbom({
        "components": [{"bom-ref": cid, "name": cid} for cid in ids],
        "dependencies": [
            {"ref": "root", "dependsOn": ["left", "right", "sibling"]},
            {"ref": "left", "dependsOn": ["target"]},
            {"ref": "right", "dependsOn": ["target"]},
            {"ref": "target", "dependsOn": ["child"]},
            {"ref": "child", "dependsOn": ["grandchild"]},
        ],
    })
    tk_app.last_results = [{
        "item": tk_app.last_sbom.components["target"].to_dict(),
        "cves": [{"cveId": "CVE-2026-0001"}],
    }]
    tree = tk_app.show_sbom_tree()
    assert tree is not None
    tree.update()
    canvas = tree.canvas
    tags = {cid: f"component-{index}" for index, cid in enumerate(ids)}
    rectangles = {cid: _tree_rectangle(tree, tag) for cid, tag in tags.items()}
    fills = {cid: canvas.itemcget(node, "fill") for cid, node in rectangles.items()}
    original = canvas.itemcget(rectangles["target"], "outline")
    original_edge = canvas.itemcget(_tree_edge(tree, tags["root"], tags["left"]), "fill")
    _click_tree_component(tree, tags["target"], 1000)
    outlines = {cid: canvas.itemcget(node, "outline") for cid, node in rectangles.items()}
    assert outlines["target"] != original
    assert outlines["root"] == outlines["left"] == outlines["right"] != original
    assert outlines["child"] == outlines["grandchild"] != original
    assert len({outlines["target"], outlines["root"], outlines["child"]}) == 3
    assert outlines["sibling"] == outlines["other"] == original
    assert fills == {cid: canvas.itemcget(node, "fill") for cid, node in rectangles.items()}
    for parent, child in (("root", "left"), ("root", "right"),
                          ("left", "target"), ("right", "target")):
        assert canvas.itemcget(_tree_edge(tree, tags[parent], tags[child]), "fill") \
            == outlines["root"]
    for parent, child in (("target", "child"), ("child", "grandchild")):
        assert canvas.itemcget(_tree_edge(tree, tags[parent], tags[child]), "fill") \
            == outlines["child"]
    assert canvas.itemcget(_tree_edge(tree, tags["root"], tags["sibling"]), "fill") \
        == original_edge

    _graph_zoom_buttons(tree)["Zoom in"].invoke()
    tree.update()
    for cid, tag in tags.items():
        assert canvas.itemcget(_tree_rectangle(tree, tag), "outline") == outlines[cid]
    assert canvas.itemcget(_tree_edge(tree, tags["right"], tags["target"]), "fill") \
        == outlines["root"]
    canvas.xview_moveto(0)
    canvas.yview_moveto(0)
    tree.update()
    _click_tree_component(tree, tags["root"], 2500)
    assert canvas.itemcget(_tree_rectangle(tree, tags["sibling"]), "outline") \
        == canvas.itemcget(_tree_rectangle(tree, tags["target"]), "outline")
    assert canvas.itemcget(_tree_rectangle(tree, tags["other"]), "outline") == original
    canvas.event_generate("<Motion>", x=5, y=5)
    canvas.event_generate("<ButtonPress-1>", x=5, y=5, time=4000)
    canvas.event_generate("<ButtonRelease-1>", x=5, y=5, time=4010)
    tree.update()
    assert all(
        canvas.itemcget(_tree_rectangle(tree, tag), "outline") == original
        for tag in tags.values()
    )


def test_gui_sbom_tree_highlights_cycles_in_both_directions(tk_app: SBOMCVEApp) -> None:
    """A cycle is traversed safely and marked as both ancestor and descendant."""
    tk_app.last_sbom = parse_sbom({
        "components": [
            {"bom-ref": cid, "name": cid}
            for cid in ("root", "selected", "cycle", "other")
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["selected"]},
            {"ref": "selected", "dependsOn": ["cycle"]},
            {"ref": "cycle", "dependsOn": ["selected"]},
        ],
    })
    tk_app.last_results = []
    tree = tk_app.show_sbom_tree()
    assert tree is not None
    tree.update()
    _click_tree_component(tree, "component-1", 1000)
    canvas = tree.canvas
    outlines = [
        canvas.itemcget(_tree_rectangle(tree, f"component-{index}"), "outline")
        for index in range(4)
    ]
    assert len(set(outlines)) == 4
    for parent, child in (("component-1", "component-2"), ("component-2", "component-1")):
        assert canvas.itemcget(_tree_edge(tree, parent, child), "fill") == outlines[2]
    assert canvas.itemcget(_tree_edge(tree, "component-0", "component-1"), "fill") \
        == outlines[0]


def test_gui_graph_before_scan_and_empty_results(tk_app: SBOMCVEApp) -> None:
    """Require a scan, but allow viewing a completed scan with no findings."""
    with patch("tkinter.messagebox.showinfo") as mock_info:
        assert tk_app.show_graph() is None
        mock_info.assert_called_once()
    tk_app.last_results = []
    graph = tk_app.show_graph()
    assert graph is not None
    labels = [
        graph.canvas.itemcget(node, "text")
        for node in graph.canvas.find_all()
        if graph.canvas.type(node) == "text"
    ]
    assert "No affected items in these scan results." in labels


def test_gui_graph_connects_all_paths_and_cves(tk_app: SBOMCVEApp) -> None:
    """Keep branching paths separate and connect each CVE to its affected item."""
    tk_app.last_results = [
        {
            "item": {"name": "leaf", "versionInfo": "1.0"},
            "lineage_paths": [
                [{"name": "parent-a"}, {"name": "shared-root"}],
                [{"name": "parent-b"}, {"name": "shared-root"}],
            ],
            "cves": [
                {"cveId": "CVE-2026-0001", "descriptions": ["First description."]},
                {"cveId": "CVE-2026-0002", "descriptions": ["Second description."]},
            ],
        },
        {
            "item": {"name": "root-item"},
            "lineage_paths": [],
            "cves": [{"cveId": "CVE-2026-0003", "descriptions": []}],
        },
    ]
    graph = tk_app.show_graph()
    assert graph is not None
    labels = [
        graph.canvas.itemcget(node, "text")
        for node in graph.canvas.find_all()
        if graph.canvas.type(node) == "text"
    ]
    assert "leaf\n1.0" in labels
    assert "root-item" in labels
    assert "parent-a" in labels and "parent-b" in labels
    assert labels.count("shared-root") == 2
    assert "CVE-2026-0001 (score: N/A)\n\nFirst description." in labels
    assert "CVE-2026-0002 (score: N/A)\n\nSecond description." in labels
    assert "No recorded ancestors." in labels
    assert len(graph.canvas.find_withtag("edge")) == 7

    def node_bounds(tag: str) -> List[float]:
        rectangle = next(
            node for node in graph.canvas.find_withtag(tag)
            if graph.canvas.type(node) == "rectangle"
        )
        return graph.canvas.coords(rectangle)

    expected_edges = [
        ("affected-0", "cve-0-0"),
        ("affected-0", "cve-0-1"),
        ("affected-0", "ancestor-0-0-0"),
        ("ancestor-0-0-0", "ancestor-0-0-1"),
        ("affected-0", "ancestor-0-1-0"),
        ("ancestor-0-1-0", "ancestor-0-1-1"),
        ("affected-1", "cve-1-0"),
    ]
    edges = [graph.canvas.coords(node) for node in graph.canvas.find_withtag("edge")]
    for source_tag, target_tag in expected_edges:
        source = node_bounds(source_tag)
        target = node_bounds(target_tag)
        start_x = source[2] if target[0] > source[0] else source[0]
        end_x = target[0] if target[0] > source[0] else target[2]
        assert [start_x, (source[1] + source[3]) / 2,
                end_x, (target[1] + target[3]) / 2] in edges


def test_gui_graph_zoom_resizes_nodes_and_text(tk_app: SBOMCVEApp) -> None:
    """Zoom controls resize cards and text, preserve connections, and reset."""
    tk_app.last_results = [{
        "item": {"name": "leaf", "version": "1.0"},
        "lineage_paths": [[{"name": "parent"}]],
        "cves": [{
            "cveId": "CVE-2026-1234",
            "descriptions": ["A description that wraps across multiple lines. " * 30],
        }],
    }]
    graph = tk_app.show_graph()
    assert graph is not None
    graph.update()
    buttons = _graph_zoom_buttons(graph)

    def card_metrics(tag: str) -> Tuple[List[float], int]:
        items = graph.canvas.find_withtag(tag)
        rectangle = next(item for item in items if graph.canvas.type(item) == "rectangle")
        text = next(item for item in items if graph.canvas.type(item) == "text")
        coords = graph.canvas.coords(rectangle)
        text_box = graph.canvas.bbox(text)
        assert text_box is not None
        assert coords[0] <= text_box[0] and text_box[2] <= coords[2]
        assert coords[1] <= text_box[1] and text_box[3] <= coords[3]
        font = graph.canvas.itemcget(text, "font")
        size = int(graph.tk.call("font", "actual", font, "-size"))
        return coords, size

    def assert_connected(source_tag: str, target_tag: str) -> None:
        source, _ = card_metrics(source_tag)
        target, _ = card_metrics(target_tag)
        start_x = source[2] if target[0] > source[0] else source[0]
        end_x = target[0] if target[0] > source[0] else target[2]
        expected = [start_x, (source[1] + source[3]) / 2,
                    end_x, (target[1] + target[3]) / 2]
        assert any(
            graph.canvas.coords(item) == pytest.approx(expected)
            for item in graph.canvas.find_withtag("edge")
        )

    original, original_font = card_metrics("cve-0-0")
    original_region = [float(value) for value in graph.canvas.cget("scrollregion").split()]
    buttons["Zoom in"].invoke()
    graph.update()
    enlarged, enlarged_font = card_metrics("cve-0-0")
    enlarged_region = [float(value) for value in graph.canvas.cget("scrollregion").split()]
    assert enlarged[2] - enlarged[0] > original[2] - original[0]
    assert enlarged_font > original_font
    assert enlarged_region[2] > original_region[2]
    assert enlarged_region[3] > original_region[3]

    assert_connected("affected-0", "cve-0-0")
    assert_connected("affected-0", "ancestor-0-0-0")

    buttons["Zoom out"].invoke()
    buttons["Zoom out"].invoke()
    graph.update()
    reduced, reduced_font = card_metrics("cve-0-0")
    assert reduced[2] - reduced[0] < original[2] - original[0]
    assert reduced_font < original_font
    buttons["Reset zoom"].invoke()
    graph.update()
    restored, restored_font = card_metrics("cve-0-0")
    assert restored == pytest.approx(original)
    assert restored_font == original_font


def test_gui_graph_zoom_keeps_view_and_stops_at_limits(tk_app: SBOMCVEApp) -> None:
    """Keep the viewport centered and prevent invalid zoom levels."""
    tk_app.last_results = [{
        "item": {"name": "leaf"},
        "lineage_paths": [[{"name": f"ancestor-{index}"} for index in range(8)]],
        "cves": [
            {"cveId": f"CVE-2026-{index:04d}", "descriptions": ["Description."]}
            for index in range(15)
        ],
    }]
    graph = tk_app.show_graph()
    assert graph is not None
    graph.update()
    buttons = _graph_zoom_buttons(graph)
    graph.canvas.xview_moveto(0.3)
    graph.canvas.yview_moveto(0.2)
    graph.update()

    def center() -> Tuple[float, float]:
        return (
            graph.canvas.canvasx(graph.canvas.winfo_width() / 2),
            graph.canvas.canvasy(graph.canvas.winfo_height() / 2),
        )

    original_center = center()
    buttons["Zoom in"].invoke()
    graph.update()
    assert center() == pytest.approx(
        (original_center[0] * 1.2, original_center[1] * 1.2), abs=3
    )

    for _ in range(20):
        buttons["Zoom out"].invoke()
    smallest = graph.canvas.coords(graph.canvas.find_withtag("affected-0")[0])
    buttons["Zoom out"].invoke()
    assert graph.canvas.coords(graph.canvas.find_withtag("affected-0")[0]) == smallest
    for _ in range(20):
        buttons["Zoom in"].invoke()
    largest = graph.canvas.coords(graph.canvas.find_withtag("affected-0")[0])
    buttons["Zoom in"].invoke()
    assert graph.canvas.coords(graph.canvas.find_withtag("affected-0")[0]) == largest
    assert largest[0] > smallest[0] > 0


def test_gui_graph_mouse_drag_pans_and_wheel_still_scrolls(tk_app: SBOMCVEApp) -> None:
    """Dragging pans both axes while existing wheel scrolling remains available."""
    graph = _scrollable_graph(tk_app)
    canvas = graph.canvas
    before = canvas.canvasx(0), canvas.canvasy(0)
    canvas.event_generate("<ButtonPress-1>", x=400, y=300)
    canvas.event_generate("<B1-Motion>", x=460, y=340)
    canvas.event_generate("<ButtonRelease-1>", x=460, y=340)
    graph.update()
    assert (canvas.canvasx(0), canvas.canvasy(0)) == pytest.approx(
        (before[0] - 60, before[1] - 40), abs=2
    )

    before = canvas.canvasx(0), canvas.canvasy(0)
    canvas.event_generate("<MouseWheel>", x=400, y=300, delta=-120)
    graph.update()
    assert canvas.canvasy(0) > before[1]
    assert canvas.canvasx(0) == before[0]
    before = canvas.canvasx(0), canvas.canvasy(0)
    canvas.event_generate("<Shift-MouseWheel>", x=400, y=300, delta=-120)
    graph.update()
    assert canvas.canvasx(0) > before[0]
    assert canvas.canvasy(0) == before[1]


def test_gui_graph_ctrl_wheel_zooms_at_pointer(tk_app: SBOMCVEApp) -> None:
    """Ctrl+wheel zooms around the mouse pointer in both directions."""
    graph = _scrollable_graph(tk_app)
    canvas = graph.canvas
    x, y = 400, 300
    before = canvas.canvasx(x), canvas.canvasy(y)
    original = canvas.coords(canvas.find_withtag("affected-0")[0])
    canvas.event_generate("<Control-MouseWheel>", x=x, y=y, delta=120)
    graph.update()
    enlarged = canvas.coords(canvas.find_withtag("affected-0")[0])
    assert enlarged[0] > original[0]
    assert (canvas.canvasx(x), canvas.canvasy(y)) == pytest.approx(
        (before[0] * 1.2, before[1] * 1.2), abs=3
    )
    canvas.event_generate("<Control-MouseWheel>", x=x, y=y, delta=-120)
    graph.update()
    assert canvas.coords(canvas.find_withtag("affected-0")[0]) == pytest.approx(original)
    assert (canvas.canvasx(x), canvas.canvasy(y)) == pytest.approx(before, abs=3)

    canvas.event_generate("<Control-Button-4>", x=x, y=y)
    graph.update()
    assert canvas.coords(canvas.find_withtag("affected-0")[0])[0] > original[0]
    canvas.event_generate("<Control-Button-5>", x=x, y=y)
    graph.update()
    assert canvas.coords(canvas.find_withtag("affected-0")[0]) == pytest.approx(original)


def test_gui_graph_scrollbars_reach_large_results(tk_app: SBOMCVEApp) -> None:
    """Scroll to deep ancestry and CVEs beyond the initial graph viewport."""
    tk_app.last_results = [{
        "item": {"name": "leaf"},
        "lineage_paths": [[{"name": f"ancestor-{depth}"} for depth in range(8)]],
        "cves": [
            {"cveId": f"CVE-2026-{index:04d}",
             "descriptions": ["Long description with all details.\n" * 25]}
            for index in range(10)
        ],
    }]
    graph = tk_app.show_graph()
    assert graph is not None
    graph.update()
    _graph_zoom_buttons(graph)["Zoom in"].invoke()
    graph.update()
    region = [float(value) for value in graph.canvas.cget("scrollregion").split()]
    assert region[2] > graph.canvas.winfo_width()
    assert region[3] > graph.canvas.winfo_height()
    scrollbars = [
        child for child in graph.canvas.master.winfo_children()
        if child.winfo_class() == "TScrollbar"
    ]
    assert len(scrollbars) == 2
    for scrollbar in scrollbars:
        graph.tk.call(scrollbar.cget("command"), "moveto", "1")
    assert graph.canvas.xview()[0] > 0
    assert graph.canvas.yview()[0] > 0
    assert graph.canvas.xview()[1] == 1
    assert graph.canvas.yview()[1] == 1


def test_gui_graph_double_click_opens_full_cve_details(tk_app: SBOMCVEApp) -> None:
    """Double-click the actual CVE card, then inspect its complete details dialog."""
    cve = {
        "cveId": "CVE-2026-1234",
        "descriptions": ["Visible CVE description."],
        "score": 9.8,
        "references": ["https://example.org/advisory"],
        "rawRecord": {"longLine": "detail " * 500, "entries": list(range(200))},
    }
    tk_app.last_results = [{"item": {"name": "leaf"}, "cves": [cve],
                            "lineage_paths": []}]
    graph = tk_app.show_graph()
    assert graph is not None
    graph.update()
    _graph_zoom_buttons(graph)["Zoom in"].invoke()
    graph.canvas.xview_moveto(0)
    graph.canvas.yview_moveto(0)
    graph.update()
    rectangle = next(
        item for item in graph.canvas.find_withtag("cve-0-0")
        if graph.canvas.type(item) == "rectangle"
    )
    x, y = graph.canvas.coords(rectangle)[:2]
    x = int(x + 5 - graph.canvas.canvasx(0))
    y = int(y + 5 - graph.canvas.canvasy(0))
    with patch.object(graph, "show_cve_details") as show_details:
        graph.canvas.event_generate("<Motion>", x=x, y=y)
        for timestamp in (1000, 1100):
            graph.canvas.event_generate(
                "<ButtonPress-1>", x=x, y=y, time=timestamp
            )
            graph.canvas.event_generate(
                "<ButtonRelease-1>", x=x, y=y, time=timestamp + 10
            )
        graph.update()
        show_details.assert_called_once_with(cve)

    dialog = graph.show_cve_details(cve)
    dialog.update()
    frame = dialog.winfo_children()[0]
    text = next(child for child in frame.winfo_children() if isinstance(child, tk.Text))
    assert json.loads(text.get("1.0", tk.END)) == cve
    assert text.cget("state") == tk.DISABLED
    scrollbars = [
        child for child in frame.winfo_children() if child.winfo_class() == "TScrollbar"
    ]
    assert len(scrollbars) == 2
    for scrollbar in sorted(
        scrollbars, key=lambda bar: bar.cget("orient") != tk.HORIZONTAL
    ):
        dialog.tk.call(scrollbar.cget("command"), "moveto", "1")
        dialog.update_idletasks()
        if scrollbar.cget("orient") == tk.HORIZONTAL:
            assert text.xview()[0] > 0
        else:
            assert text.yview()[0] > 0
