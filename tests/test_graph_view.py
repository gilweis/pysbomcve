"""Tests for the SBOM tree window's CVE path filter."""

import json
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional, Set
from unittest.mock import patch

import pytest

from pysbomcve.graph_view import ResultsGraphWindow, SBOMTreeWindow
from pysbomcve.sbom_parser import parse_sbom
from tests.gui_helpers import destroy_root

IDS = ["root", "a", "b", "vuln", "child", "safe", "x"]


@pytest.fixture(name="root")
def fixture_root():
    """Create a hidden Tk root."""
    tk_root = tk.Tk()
    tk_root.withdraw()
    yield tk_root
    destroy_root(tk_root)


def _tree(
    root: tk.Tk, vulnerable: Optional[List[str]] = None, scanned: bool = True
) -> SBOMTreeWindow:
    """Build root->a->vuln->child, a->safe, root->b, and x->child."""
    sbom = parse_sbom({
        "components": [{"bom-ref": cid, "name": cid} for cid in IDS],
        "dependencies": [
            {"ref": "root", "dependsOn": ["a", "b"]},
            {"ref": "a", "dependsOn": ["vuln", "safe"]},
            {"ref": "vuln", "dependsOn": ["child"]},
            {"ref": "x", "dependsOn": ["child"]},
        ],
    })
    results: Optional[List[Dict[str, Any]]] = None
    if scanned:
        results = [
            {"item": sbom.components[cid].to_dict(), "cves": [{"cveId": f"CVE-{cid}"}]}
            for cid in (vulnerable if vulnerable is not None else ["vuln"])
        ]
    tree = SBOMTreeWindow(root, sbom, results)
    tree.update()
    return tree


def _shown(tree: SBOMTreeWindow) -> Set[str]:
    """Return the IDs of components drawn on the canvas."""
    return {
        IDS[int(tag.split("-")[1])]
        for node in tree.canvas.find_withtag("node")
        for tag in tree.canvas.gettags(node) if tag.startswith("component-")
    }


def _links(tree: SBOMTreeWindow) -> Set[tuple]:
    """Return the drawn arrows as (parent, child) IDs."""
    links = set()
    for edge in tree.canvas.find_withtag("edge"):
        for tag in tree.canvas.gettags(edge):
            if tag.startswith("link-"):
                parts = tag.split("-")
                links.add((IDS[int(parts[2])], IDS[int(parts[4])]))
    return links


def _checkbox(tree: SBOMTreeWindow) -> ttk.Checkbutton:
    return next(
        widget for widget in tree.winfo_children()
        if isinstance(widget, ttk.Checkbutton)
    )


def test_cve_paths_only_filters_and_restores(root: tk.Tk) -> None:
    """Keep only items and arrows on root-to-leaf paths through a vulnerable item."""
    tree = _tree(root)
    assert _shown(tree) == set(IDS)
    _checkbox(tree).invoke()
    tree.update()
    assert tree.cve_paths_only_var.get()
    assert _shown(tree) == {"root", "a", "vuln", "child"}
    assert _links(tree) == {("root", "a"), ("a", "vuln"), ("vuln", "child")}

    tree.set_cve_paths_only(False)
    assert _shown(tree) == set(IDS)
    assert ("x", "child") in _links(tree)


def test_cve_paths_only_highlights_visible_paths_and_clears_hidden_selection(
    root: tk.Tk,
) -> None:
    """Highlighting follows only shown arrows; hidden selections are cleared."""
    tree = _tree(root)
    tree._select_component("component-5")  # pylint: disable=protected-access
    tree.set_cve_paths_only(True)
    assert tree._selected_tag is None  # pylint: disable=protected-access

    tree._select_component("component-4")  # pylint: disable=protected-access
    canvas = tree.canvas
    outlines = {
        cid: canvas.itemcget(
            next(n for n in canvas.find_withtag(f"component-{IDS.index(cid)}")
                 if canvas.type(n) == "rectangle"), "outline")
        for cid in _shown(tree)
    }
    assert outlines["root"] == outlines["a"] == outlines["vuln"] != outlines["child"]


def test_cve_paths_only_without_matches_or_scan(root: tk.Tk) -> None:
    """Explain an empty filtered tree and disable the filter before scanning."""
    tree = _tree(root, vulnerable=[])
    tree.set_cve_paths_only(True)
    assert not _shown(tree)
    texts = [tree.canvas.itemcget(item, "text") for item in tree.canvas.find_all()]
    assert "No items with matched CVEs in this scan." in texts

    preview = _tree(root, scanned=False)
    assert str(_checkbox(preview).cget("state")) == tk.DISABLED
    preview.set_cve_paths_only(True)
    assert not preview.cve_paths_only_var.get()
    assert _shown(preview) == set(IDS)


def test_tree_statistics(root: tk.Tk) -> None:
    """Report structure and vulnerable-item counts, following the score filter."""
    tree = _tree(root, vulnerable=["vuln", "safe"])
    stats = tree.statistics()
    assert stats == {
        "items": 7, "dependencies": 6, "roots": 2, "max_depth": 4,
        "items_with_cves": 2, "unique_cves": 2,
    }
    label = tree._stats_label.cget("text")  # pylint: disable=protected-access
    assert "Items: 7" in label and "Max depth: 4" in label
    assert "Items with CVEs: 2 (28.6%)" in label
    _apply_range(tree, "5", "10")
    assert tree.statistics()["items_with_cves"] == 0
    tree.set_cve_paths_only(True)
    assert "Displayed items: 0" in tree._stats_label.cget("text")  # pylint: disable=protected-access

    preview = _tree(root, scanned=False)
    assert preview.statistics()["items_with_cves"] is None
    assert "Items with CVEs: not scanned" in preview._stats_label.cget("text")  # pylint: disable=protected-access

    cyclic = SBOMTreeWindow(root, parse_sbom({
        "components": [{"bom-ref": cid, "name": cid} for cid in ("r", "p", "q")],
        "dependencies": [
            {"ref": "r", "dependsOn": ["p"]}, {"ref": "p", "dependsOn": ["q"]},
            {"ref": "q", "dependsOn": ["p"]},
        ],
    }), [])
    assert cyclic.max_depth() == 3


def test_group_shown_with_name_in_both_graphs(root: tk.Tk) -> None:
    """Show 'group/name' for grouped items and the plain name otherwise."""
    sbom = parse_sbom({
        "components": [
            {"bom-ref": "app", "name": "app"},
            {"bom-ref": "b", "group": "@angular", "name": "build", "version": "19.2.0"},
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["b"]}],
    })
    results = [{
        "item": sbom.components["b"].to_dict(), "cves": [{"cveId": "CVE-x"}],
        "lineage_paths": [[sbom.components["app"].to_dict()]],
    }]
    for window in (SBOMTreeWindow(root, sbom, results), ResultsGraphWindow(root, results)):
        text = _canvas_text(window)
        assert "@angular/build\n19.2.0" in text
        assert "app" in text and "/app" not in text


def test_cve_scores_shown_in_both_graphs(root: tk.Tk) -> None:
    """Show score and severity next to each CVE ID, or N/A when unscored."""
    sbom = parse_sbom({"components": [{"bom-ref": "pkg", "name": "pkg"}]})
    cves = [
        {"cveId": "CVE-2026-0001", "score": 9.8, "severity": "CRITICAL"},
        {"cveId": "CVE-2026-0002", "score": None, "severity": None},
    ]
    results = [{"item": sbom.components["pkg"].to_dict(), "cves": cves}]
    expected = ("CVE-2026-0001 (9.8 CRITICAL)", "CVE-2026-0002 (score: N/A)")
    for window in (SBOMTreeWindow(root, sbom, results), ResultsGraphWindow(root, results)):
        text = "\n".join(
            window.canvas.itemcget(item, "text") for item in window.canvas.find_all()
            if window.canvas.type(item) == "text"
        )
        assert all(label in text for label in expected)


def _score_button(window: ResultsGraphWindow, name: str) -> ttk.Button:
    return next(
        widget for frame in window.winfo_children() for widget in frame.winfo_children()
        if isinstance(widget, ttk.Button) and widget.cget("text") == name
    )


def _score_data():
    sbom = parse_sbom({
        "components": [{"bom-ref": cid, "name": cid} for cid in ("root", "a", "b")],
        "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}],
    })
    results = [
        {
            "item": sbom.components["a"].to_dict(),
            "cves": [
                {"cveId": "CVE-unscored", "score": None},
                {"cveId": "CVE-low", "score": 0.0},
                {"cveId": "CVE-middle", "score": 7.0},
                {"cveId": "CVE-high", "score": 10.0},
            ],
            "lineage_paths": [[{"name": "root"}]],
        },
        {
            "item": sbom.components["b"].to_dict(),
            "cves": [{"cveId": "CVE-other", "score": 2.0}],
            "lineage_paths": [[{"name": "root"}]],
        },
    ]
    return sbom, results


def _canvas_text(window: ResultsGraphWindow) -> str:
    return "\n".join(
        window.canvas.itemcget(item, "text")
        for item in window.canvas.find_all() if window.canvas.type(item) == "text"
    )


def _apply_range(window: ResultsGraphWindow, low: str, high: str) -> None:
    window.score_min_var.set(low)
    window.score_max_var.set(high)
    _score_button(window, "Apply").invoke()
    window.update()


def test_results_score_filter_preserves_binding_and_restores(root: tk.Tk) -> None:
    """Filter CVEs and findings while keeping original card detail bindings."""
    _, results = _score_data()
    graph = ResultsGraphWindow(root, results)
    graph.update()
    _apply_range(graph, "7", "10")
    text = _canvas_text(graph)
    assert "CVE-middle" in text and "CVE-high" in text
    assert all(cve not in text for cve in ("CVE-unscored", "CVE-low", "CVE-other"))
    assert not graph.canvas.find_withtag("affected-1")

    rectangle = next(
        item for item in graph.canvas.find_withtag("cve-0-2")
        if graph.canvas.type(item) == "rectangle"
    )
    x, y = graph.canvas.coords(rectangle)[:2]
    x, y = int(x + 5 - graph.canvas.canvasx(0)), int(y + 5 - graph.canvas.canvasy(0))
    with patch.object(graph, "show_cve_details") as show_details:
        graph.canvas.event_generate("<Motion>", x=x, y=y)
        for timestamp in (1000, 1100):
            graph.canvas.event_generate("<ButtonPress-1>", x=x, y=y, time=timestamp)
            graph.canvas.event_generate("<ButtonRelease-1>", x=x, y=y, time=timestamp + 10)
        graph.update()
        show_details.assert_called_once_with(results[0]["cves"][2])

    _apply_range(graph, "0", "0")
    assert "CVE-low" in _canvas_text(graph)
    assert "CVE-middle" not in _canvas_text(graph)
    _apply_range(graph, "0", "10")
    assert "CVE-high" in _canvas_text(graph)
    assert "CVE-unscored" not in _canvas_text(graph)
    _score_button(graph, "Zoom in").invoke()
    assert "CVE-high" in _canvas_text(graph) and "CVE-unscored" not in _canvas_text(graph)
    _apply_range(graph, "9", "9")
    assert "No CVEs match the score filter." in _canvas_text(graph)
    _score_button(graph, "Clear").invoke()
    assert all(cve in _canvas_text(graph) for cve in ("CVE-unscored", "CVE-other"))
    assert graph.score_min_var.get() == graph.score_max_var.get() == ""


def test_tree_score_filter_combines_with_paths_and_preserves_details(root: tk.Tk) -> None:
    """Filter labels and colors, then restrict paths to CVEs in the range."""
    sbom, results = _score_data()
    tree = SBOMTreeWindow(root, sbom, results)
    tree.update()
    _apply_range(tree, "7", "")
    assert "CVE-middle" in _canvas_text(tree) and "CVE-high" in _canvas_text(tree)
    assert "CVE-other" not in _canvas_text(tree) and "CVE-unscored" not in _canvas_text(tree)
    assert tree.canvas.find_withtag("component-2")
    rect = next(
        item for item in tree.canvas.find_withtag("component-2")
        if tree.canvas.type(item) == "rectangle"
    )
    assert tree.canvas.itemcget(rect, "fill") == "#e4efff"
    dialog = tree.show_item_details("component-1")
    text = next(
        widget for frame in dialog.winfo_children() for widget in frame.winfo_children()
        if isinstance(widget, tk.Text)
    )
    assert json.loads(text.get("1.0", tk.END))["cves"] == results[0]["cves"]

    tree._select_component("component-2")  # pylint: disable=protected-access
    _checkbox(tree).invoke()
    assert tree._selected_tag is None  # pylint: disable=protected-access
    assert tree.canvas.find_withtag("component-0")
    assert tree.canvas.find_withtag("component-1")
    assert not tree.canvas.find_withtag("component-2")
    _apply_range(tree, "", "2")
    assert tree.canvas.find_withtag("component-2")
    assert "CVE-low" in _canvas_text(tree) and "CVE-other" in _canvas_text(tree)
    assert "CVE-middle" not in _canvas_text(tree)
    _score_button(tree, "Zoom in").invoke()
    assert "CVE-other" in _canvas_text(tree) and "CVE-middle" not in _canvas_text(tree)
    _apply_range(tree, "9", "9")
    assert "No items have CVEs matching the score filter." in _canvas_text(tree)
    _score_button(tree, "Clear").invoke()
    assert "CVE-unscored" in _canvas_text(tree)
    assert tree.canvas.find_withtag("component-2")


@pytest.mark.parametrize("low,high", [
    ("abc", "9"), ("9", "2"), ("-1", "5"), ("0", "11"), ("nan", "10"), ("0", "inf"),
])
def test_score_filter_rejects_invalid_ranges(root: tk.Tk, low: str, high: str) -> None:
    """Invalid input reports an error without replacing the applied filter."""
    _, results = _score_data()
    graph = ResultsGraphWindow(root, results)
    _apply_range(graph, "7", "10")
    with patch("pysbomcve.graph_view.messagebox.showerror") as error:
        _apply_range(graph, low, high)
    error.assert_called_once()
    assert "CVE-middle" in _canvas_text(graph)
    assert "CVE-low" not in _canvas_text(graph)


def test_score_filter_disabled_for_preview(root: tk.Tk) -> None:
    """A pre-scan preview cannot be filtered by unknown CVE scores."""
    tree = _tree(root, scanned=False)
    assert str(_score_button(tree, "Apply").cget("state")) == tk.DISABLED
    assert str(_score_button(tree, "Clear").cget("state")) == tk.DISABLED
    entries = [
        widget for frame in tree.winfo_children() for widget in frame.winfo_children()
        if isinstance(widget, ttk.Entry)
    ]
    assert len(entries) == 2 and all(str(entry.cget("state")) == tk.DISABLED for entry in entries)
