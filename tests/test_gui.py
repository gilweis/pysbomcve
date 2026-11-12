"""Tests for pysbomcve desktop GUI application."""

import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Tuple
from unittest.mock import patch
import pytest

from pysbomcve.graph_view import ResultsGraphWindow
from pysbomcve.gui import SBOMCVEApp


@pytest.fixture(name="tk_app")
def fixture_tk_app():
    """Create a headless Tk instance and SBOMCVEApp for testing."""
    root = tk.Tk()
    root.withdraw()
    app = SBOMCVEApp(root)
    yield app
    root.destroy()


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
        app.run_scan()
        assert app.last_results is not None
        assert len(app.last_results) == 2
    finally:
        root.destroy()


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
        root.destroy()


def test_gui_selects_cve_directory_and_scans(
    tk_app: SBOMCVEApp, tmp_path: Path
) -> None:
    """Select a folder using the button and scan all its CVE files."""
    cve_dir = tmp_path / "CVE records"
    cve_dir.mkdir()
    project_examples = Path(__file__).resolve().parent.parent / "examples"
    cves = json.loads((project_examples / "cve.json").read_text(encoding="utf-8"))
    for index, cve in enumerate(cves):
        (cve_dir / f"cve-{index}.json").write_text(json.dumps(cve), encoding="utf-8")
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

    tk_app.run_scan()
    assert tk_app.last_results is not None
    assert {item["cves"][0]["cveId"] for item in tk_app.last_results} == {
        "CVE-2023-32681", "CVE-2021-44228",
    }


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
    assert "CVE-2026-0001\n\nFirst description." in labels
    assert "CVE-2026-0002\n\nSecond description." in labels
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
