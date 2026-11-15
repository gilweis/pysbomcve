"""Scrollable graphical results and CVE detail windows."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional, Set, Tuple

from pysbomcve.report import sbom_max_depth
from pysbomcve.sbom_parser import ParsedSBOM

_DEFAULT_COLOR = "#64748b"
_SELECTED_COLOR = "#7c3aed"
_ANCESTOR_COLOR = "#15803d"
_DESCENDANT_COLOR = "#c2410c"
_BOTH_COLOR = "#0e7490"


def _display_name(item: Dict[str, Any], name: Optional[str] = None) -> str:
    """Return 'group/name' when the SBOM item has a group, otherwise the name."""
    name = name or item.get("name") or "Unnamed item"
    group = item.get("group")
    return f"{group}/{name}" if group else str(name)


def _cve_label(cve: Dict[str, Any]) -> str:
    """Format a CVE ID with its CVSS score and severity, when known."""
    cve_id = cve.get("cveId", "Unknown CVE")
    score, severity = cve.get("score"), cve.get("severity")
    if score is None:
        return f"{cve_id} (score: N/A)"
    return f"{cve_id} ({score} {severity})" if severity else f"{cve_id} ({score})"


# pylint: disable=too-many-instance-attributes
class ResultsGraphWindow(tk.Toplevel):
    """Display affected components, their ancestor paths, and matching CVEs."""

    window_title = "pysbomcve - Graphical Results"
    instructions = (
        "CVEs: yellow | Affected items: red | SBOM ancestors: blue. "
        "Double-click a CVE for full details."
    )
    score_filter_available = True

    def __init__(self, parent: tk.Misc, results: List[Dict[str, Any]]) -> None:
        """Create an independent view of the supplied scan results."""
        super().__init__(parent)
        self.title(self.window_title)
        self.geometry("1200x750")
        self.minsize(750, 450)
        self._results = results
        self._zoom_percent = 100
        self._score_range: Optional[Tuple[float, float]] = None

        ttk.Label(
            self,
            text=self.instructions,
            padding=10,
        ).pack(fill=tk.X)
        controls = ttk.Frame(self, padding=(10, 0, 10, 8))
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="Zoom:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            controls, text="Zoom out",
            command=lambda: self._set_zoom(self._zoom_percent - 20),
        ).pack(side=tk.LEFT)
        self._zoom_label = ttk.Label(controls, text="100%", width=6, anchor=tk.CENTER)
        self._zoom_label.pack(side=tk.LEFT)
        ttk.Button(
            controls, text="Zoom in",
            command=lambda: self._set_zoom(self._zoom_percent + 20),
        ).pack(side=tk.LEFT)
        ttk.Button(
            controls, text="Reset zoom", command=lambda: self._set_zoom(100)
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Label(controls, text="Drag to pan | Ctrl+wheel to zoom").pack(
            side=tk.LEFT, padx=(12, 0)
        )

        self.score_min_var = tk.StringVar(self)
        self.score_max_var = tk.StringVar(self)
        self._score_filter_label = self._create_score_controls()

        frame = ttk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True)
        self.canvas = tk.Canvas(frame, background="white", highlightthickness=0)
        vertical = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.canvas.yview)
        horizontal = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.canvas.grid(row=0, column=0, sticky=tk.NSEW)
        vertical.grid(row=0, column=1, sticky=tk.NS)
        horizontal.grid(row=1, column=0, sticky=tk.EW)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.canvas.bind("<MouseWheel>", self._scroll)
        self.canvas.bind(
            "<Shift-MouseWheel>", lambda event: self._scroll(event, horizontal=True)
        )
        self.canvas.bind("<Button-4>", lambda _event: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind("<Button-5>", lambda _event: self.canvas.yview_scroll(1, "units"))
        self.canvas.bind("<Control-MouseWheel>", self._mouse_zoom)
        self.canvas.bind("<Control-Button-4>", lambda event: self._mouse_zoom(event, 1))
        self.canvas.bind("<Control-Button-5>", lambda event: self._mouse_zoom(event, -1))
        self.canvas.bind("<ButtonPress-1>", self._pan_start)
        self.canvas.bind("<B1-Motion>", self._pan_drag)
        self.canvas.bind("<ButtonRelease-1>", self._pan_end)

        self._bind_node_events()
        self._render_graph()

    def _create_score_controls(self) -> ttk.Label:
        controls = ttk.Frame(self, padding=(10, 0, 10, 8))
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="CVSS score range (0-10):").pack(side=tk.LEFT)
        state = tk.NORMAL if self.score_filter_available else tk.DISABLED
        ttk.Entry(controls, textvariable=self.score_min_var, width=6, state=state).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        ttk.Label(controls, text="to").pack(side=tk.LEFT, padx=4)
        ttk.Entry(controls, textvariable=self.score_max_var, width=6, state=state).pack(
            side=tk.LEFT
        )
        ttk.Button(controls, text="Apply", command=self._apply_score_filter,
                   state=state).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="Clear", command=self._clear_score_filter,
                   state=state).pack(side=tk.LEFT, padx=(4, 0))
        label = ttk.Label(controls, text="No score filter")
        label.pack(side=tk.LEFT, padx=(12, 0))
        return label

    def _apply_score_filter(self) -> None:
        """Validate and apply an inclusive score range without changing the scan."""
        minimum, maximum = self.score_min_var.get().strip(), self.score_max_var.get().strip()
        if not minimum and not maximum:
            self._clear_score_filter()
            return
        try:
            low = float(minimum) if minimum else 0.0
            high = float(maximum) if maximum else 10.0
        except ValueError:
            messagebox.showerror(
                "Invalid score range", "Enter scores from 0 to 10.", parent=self
            )
            return
        if not 0 <= low <= high <= 10:
            messagebox.showerror(
                "Invalid score range",
                "Enter scores from 0 to 10, with the minimum no greater than the maximum.",
                parent=self,
            )
            return
        self._score_range = (low, high)
        self._score_filter_label.configure(text=f"Applied: {low:g} to {high:g}; unscored hidden")
        self._render_graph()

    def _clear_score_filter(self) -> None:
        """Restore all CVEs, including those without scores."""
        self.score_min_var.set("")
        self.score_max_var.set("")
        self._score_range = None
        self._score_filter_label.configure(text="No score filter")
        self._render_graph()

    def _matches_score(self, cve: Dict[str, Any]) -> bool:
        if self._score_range is None:
            return True
        score = cve.get("score")
        return (
            isinstance(score, (int, float))
            and self._score_range[0] <= score <= self._score_range[1]
        )

    def _bind_node_events(self) -> None:
        """Bind CVE tags once; the bindings also apply to redrawn nodes."""
        for index, finding in enumerate(self._results):
            for cve_index, cve in enumerate(finding.get("cves", [])):
                tag = f"cve-{index}-{cve_index}"
                self.canvas.tag_bind(
                    tag, "<Double-Button-1>",
                    lambda _event, record=cve: self.show_cve_details(record),
                )
                self.canvas.tag_bind(
                    tag, "<Enter>", lambda _event: self.canvas.configure(cursor="hand2")
                )
                self.canvas.tag_bind(
                    tag, "<Leave>", lambda _event: self.canvas.configure(cursor="")
                )

    def _render_graph(self) -> None:
        """Redraw at the current zoom so wrapped text fits its cards."""
        self.canvas.delete(tk.ALL)
        scale = self._zoom_percent / 100
        for x, label in (
            (30, "Matching CVEs"),
            (500, "Affected items"),
            (800, "Ancestor paths: immediate parent -> root"),
        ):
            self.canvas.create_text(
                x * scale, 20 * scale, text=label, anchor=tk.NW,
                font=("Segoe UI", max(1, round(11 * scale)), "bold"),
            )
        y = 60.0
        shown = False
        for index, finding in enumerate(self._results):
            if self._score_range is not None and not any(
                self._matches_score(cve) for cve in finding.get("cves", [])
            ):
                continue
            shown = True
            y = self._draw_finding(finding, index, y)
        if not shown:
            self.canvas.create_text(
                30 * scale, y * scale,
                text=("No CVEs match the score filter." if self._score_range is not None
                      else "No affected items in these scan results."), anchor=tk.NW,
                font=("Segoe UI", max(1, round(10 * scale))),
            )
        self.canvas.tag_lower("edge")
        bounds = self.canvas.bbox(tk.ALL)
        if bounds:
            self.canvas.configure(
                scrollregion=(0, 0, bounds[2] + 30 * scale, bounds[3] + 30 * scale)
            )

    def _set_zoom(
        self, percent: int, anchor: Optional[Tuple[int, int]] = None
    ) -> None:
        """Zoom around the mouse anchor, or the viewport center for buttons."""
        percent = max(40, min(300, percent))
        if percent == self._zoom_percent:
            return
        old_scale = self._zoom_percent / 100
        width, height = self.canvas.winfo_width(), self.canvas.winfo_height()
        focus_x, focus_y = anchor if anchor is not None else (width / 2, height / 2)
        graph_x = self.canvas.canvasx(focus_x) / old_scale
        graph_y = self.canvas.canvasy(focus_y) / old_scale
        self._zoom_percent = percent
        self._zoom_label.configure(text=f"{percent}%")
        self._render_graph()
        scale = percent / 100
        region = [float(value) for value in self.canvas.cget("scrollregion").split()]
        self.canvas.xview_moveto((graph_x * scale - focus_x) / region[2])
        self.canvas.yview_moveto((graph_y * scale - focus_y) / region[3])

    def _mouse_zoom(self, event: tk.Event, steps: Optional[int] = None) -> str:
        """Handle Ctrl+wheel zoom on Windows, macOS, and X11."""
        if steps is None:
            if not event.delta:
                return "break"
            steps = max(1, abs(event.delta) // 120)
            if event.delta < 0:
                steps = -steps
        self._set_zoom(self._zoom_percent + 20 * steps, (event.x, event.y))
        return "break"

    def _pan_start(self, event: tk.Event) -> None:
        """Mark the start of a mouse drag."""
        self.canvas.scan_mark(event.x, event.y)
        self.canvas.configure(cursor="fleur")

    def _pan_drag(self, event: tk.Event) -> None:
        """Move the canvas by the distance dragged."""
        self.canvas.scan_dragto(event.x, event.y, gain=1)
        self.canvas.configure(cursor="fleur")

    def _pan_end(self, _event: tk.Event) -> None:
        """Restore the clickable node cursor when the drag ends."""
        over_node = any(
            tag.startswith(("cve-", "component-"))
            for tag in self.canvas.gettags(tk.CURRENT)
        )
        self.canvas.configure(cursor="hand2" if over_node else "")

    def _scroll(self, event: tk.Event, horizontal: bool = False) -> str:
        """Scroll the graph without changing scroll behavior in other windows."""
        if event.delta:
            units = max(1, abs(event.delta) // 120)
            units *= -1 if event.delta > 0 else 1
            if horizontal:
                self.canvas.xview_scroll(units, "units")
            else:
                self.canvas.yview_scroll(units, "units")
        return "break"

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _draw_node(
        self, x: float, y: float, width: int, label: str, color: str, tag: str
    ) -> Tuple[float, float, float, float]:
        """Draw a card sized to its complete, wrapped text."""
        scale = self._zoom_percent / 100
        text = self.canvas.create_text(
            (x + 12) * scale, (y + 12) * scale, text=label,
            width=(width - 24) * scale, anchor=tk.NW,
            font=("Segoe UI", max(1, round(10 * scale))), tags=(tag, "node"),
        )
        bounds = self.canvas.bbox(text)
        height = max(64, bounds[3] / scale - y + 12) if bounds else 64
        rectangle = self.canvas.create_rectangle(
            x * scale, y * scale, (x + width) * scale, (y + height) * scale,
            fill=color, outline=_DEFAULT_COLOR, width=max(1, scale), tags=(tag, "node"),
        )
        self.canvas.tag_lower(rectangle, text)
        return x, y, x + width, y + height

    def _connect_nodes(
        self,
        source: Tuple[float, float, float, float],
        target: Tuple[float, float, float, float],
    ) -> int:
        """Connect facing card edges with an arrow."""
        if target[0] > source[0]:
            start_x, end_x = source[2], target[0]
        else:
            start_x, end_x = source[0], target[2]
        scale = self._zoom_percent / 100
        return self.canvas.create_line(
            start_x * scale, (source[1] + source[3]) / 2 * scale,
            end_x * scale, (target[1] + target[3]) / 2 * scale,
            arrow=tk.LAST, fill=_DEFAULT_COLOR, width=max(1, 2 * scale),
            arrowshape=(8 * scale, 10 * scale, 3 * scale), tags="edge",
        )

    # pylint: disable=too-many-locals
    def _draw_finding(self, finding: Dict[str, Any], index: int, y: float) -> float:
        """Lay out one affected item with separate rows for each ancestor path."""
        cve_nodes = []
        cve_y = y
        for cve_index, cve in enumerate(finding.get("cves", [])):
            if not self._matches_score(cve):
                continue
            tag = f"cve-{index}-{cve_index}"
            description = "\n\n".join(cve.get("descriptions", []))
            label = f"{_cve_label(cve)}\n\n"
            label += description or "No description provided."
            bounds = self._draw_node(30, cve_y, 400, label, "#fff4cc", tag)
            cve_nodes.append(bounds)
            cve_y = bounds[3] + 20

        parent_nodes = []
        ancestor_y = y
        for path_index, path in enumerate(finding.get("lineage_paths", [])):
            previous = None
            row_bottom = ancestor_y
            for depth, ancestor in enumerate(path):
                tag = f"ancestor-{index}-{path_index}-{depth}"
                bounds = self._draw_node(
                    800 + depth * 280, ancestor_y, 230,
                    self._item_label(ancestor), "#e4efff", tag,
                )
                if previous is None:
                    parent_nodes.append(bounds)
                else:
                    self._connect_nodes(previous, bounds)
                previous = bounds
                row_bottom = max(row_bottom, bounds[3])
            ancestor_y = row_bottom + 20
        if not parent_nodes:
            scale = self._zoom_percent / 100
            self.canvas.create_text(
                800 * scale, (y + 20) * scale, text="No recorded ancestors.",
                anchor=tk.NW, font=("Segoe UI", max(1, round(10 * scale))),
            )

        item_tag = f"affected-{index}"
        item = self._draw_node(
            500, y, 230, self._item_label(finding.get("item", {})), "#fde2e2", item_tag
        )
        bottom = max(cve_y, ancestor_y, item[3])
        offset = (bottom - item[3]) / 2
        self.canvas.move(item_tag, 0, offset * self._zoom_percent / 100)
        item = item[0], item[1] + offset, item[2], item[3] + offset
        for node in cve_nodes + parent_nodes:
            self._connect_nodes(item, node)
        return bottom + 40

    @staticmethod
    def _item_label(item: Dict[str, Any]) -> str:
        """Include the group and version to distinguish same-named SBOM components."""
        name = _display_name(item)
        version = item.get("version") or item.get("versionInfo")
        return f"{name}\n{version}" if version else str(name)

    def show_cve_details(self, cve: Dict[str, Any]) -> tk.Toplevel:
        """Open the complete CVE, including its raw record, in a read-only dialog."""
        return self._show_details(
            f"CVE full details - {cve.get('cveId', 'Unknown CVE')}", cve
        )

    def _show_details(self, title: str, data: Dict[str, Any]) -> tk.Toplevel:
        """Display complete JSON data in a scrollable, read-only dialog."""
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("850x600")
        dialog.minsize(500, 300)
        dialog.transient(self)
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        text = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 10))
        vertical = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        horizontal = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        text.grid(row=0, column=0, sticky=tk.NSEW)
        vertical.grid(row=0, column=1, sticky=tk.NS)
        horizontal.grid(row=1, column=0, sticky=tk.EW)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text.insert("1.0", json.dumps(data, indent=2, ensure_ascii=False))
        text.configure(state=tk.DISABLED)
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(0, 10))
        return dialog


class SBOMTreeWindow(ResultsGraphWindow):
    """Display every SBOM component and dependency, with CVEs if scanned."""

    window_title = "pysbomcve - SBOM Tree"
    instructions = (
        "Displayed CVEs: red | No displayed CVEs: blue (filters may hide matches). "
        "Click an item to highlight its paths; double-click for full details."
    )

    def __init__(
        self, parent: tk.Misc, sbom: ParsedSBOM,
        results: Optional[List[Dict[str, Any]]],
    ) -> None:
        self._sbom = sbom
        self._scan_completed = results is not None
        self.score_filter_available = self._scan_completed
        if results is None:
            self.instructions = (
                "WARNING: CVE scan has not been run. Blue items have not been "
                "checked for vulnerabilities. Click to highlight paths; "
                "double-click for full details."
            )
            findings: List[Dict[str, Any]] = []
        else:
            findings = results
        # Matcher results retain the original component dictionaries from this snapshot.
        self._cves_by_item = {id(finding["item"]): finding["cves"] for finding in findings}
        self._component_tags = {
            f"component-{index}": component
            for index, component in enumerate(sbom.components.values())
        }
        self._tags_by_id = {
            component.component_id: tag for tag, component in self._component_tags.items()
        }
        self._children: Dict[str, List[str]] = {cid: [] for cid in sbom.components}
        for cid, component in sbom.components.items():
            for parent_id in sorted(component.parent_ids):
                if parent_id in self._children:
                    self._children[parent_id].append(cid)
        self._selected_tag: Optional[str] = None
        self._last_click_tag: Optional[str] = None
        self._drag_origin = (0, 0)
        self._dragged = False
        self._cve_paths_only = False
        self._shown_edges: Optional[Set[Tuple[str, str]]] = None
        self._stats_label: Optional[ttk.Label] = None
        self._visible_count = len(sbom.components)
        super().__init__(parent, findings)
        self._stats_label = ttk.Label(
            self, padding=(10, 0, 10, 8), font=("TkDefaultFont", 9, "bold")
        )
        self._stats_label.pack(fill=tk.X, before=self.canvas.master)
        self._update_statistics()
        self.cve_paths_only_var = tk.BooleanVar(self, value=False)
        ttk.Checkbutton(
            self,
            text="Show only paths with CVEs",
            variable=self.cve_paths_only_var,
            command=lambda: self.set_cve_paths_only(self.cve_paths_only_var.get()),
            state=tk.NORMAL if self._scan_completed else tk.DISABLED,
            padding=(10, 0, 10, 8),
        ).pack(anchor=tk.W, before=self.canvas.master)
        ttk.Label(
            self,
            text=(
                "Outlines/arrows: selected purple | ancestors green | descendants orange | "
                "both teal | click background to clear."
            ),
            padding=(10, 0, 10, 8),
        ).pack(fill=tk.X, before=self.canvas.master)
        if not self._scan_completed:
            self.title(f"{self.window_title} (CVE scan not run)")

    def _bind_node_events(self) -> None:
        for tag in self._component_tags:
            self.canvas.tag_bind(
                tag, "<Enter>", lambda _event: self.canvas.configure(cursor="hand2")
            )
            self.canvas.tag_bind(
                tag, "<Leave>", lambda _event: self.canvas.configure(cursor="")
            )
        self.canvas.bind("<Double-ButtonRelease-1>", self._double_click)

    def max_depth(self) -> int:
        """Return the number of levels in the longest acyclic dependency chain."""
        return sbom_max_depth(self._sbom)

    def statistics(self) -> Dict[str, Any]:
        """Summarize the SBOM structure and, after a scan, its vulnerable items."""
        components = self._sbom.components.values()
        cve_lists = [self._cves_by_item.get(id(c.raw_data), []) for c in components]
        stats: Dict[str, Any] = {
            "items": len(self._sbom.components),
            "dependencies": sum(len(children) for children in self._children.values()),
            "roots": sum(
                1 for c in components
                if c.component_id in self._sbom.root_ids
                or not c.parent_ids & self._sbom.components.keys()
            ),
            "max_depth": self.max_depth(),
            "items_with_cves": None,
            "unique_cves": None,
        }
        if self._scan_completed:
            shown = [[cve for cve in cves if self._matches_score(cve)] for cves in cve_lists]
            stats["items_with_cves"] = sum(1 for cves in shown if cves)
            stats["unique_cves"] = len(
                {cve.get("cveId") for cves in shown for cve in cves}
            )
        return stats

    def _update_statistics(self) -> None:
        if self._stats_label is None:
            return
        stats = self.statistics()
        parts = [
            f"Items: {stats['items']}",
            f"Dependencies: {stats['dependencies']}",
            f"Root items: {stats['roots']}",
            f"Max depth: {stats['max_depth']}",
        ]
        if stats["items_with_cves"] is None:
            parts.append("Items with CVEs: not scanned")
        else:
            in_range = " in score range" if self._score_range is not None else ""
            percent = 100 * stats["items_with_cves"] / stats["items"] if stats["items"] else 0
            parts.append(
                f"Items with CVEs{in_range}: {stats['items_with_cves']} ({percent:.1f}%)"
            )
            parts.append(f"Unique CVEs{in_range}: {stats['unique_cves']}")
        if self._visible_count != stats["items"]:
            parts.append(f"Displayed items: {self._visible_count}")
        self._stats_label.configure(text="Statistics: " + " | ".join(parts))

    def set_cve_paths_only(self, enabled: bool) -> None:
        """Show either the full tree or only paths passing through a vulnerable item."""
        self._cve_paths_only = enabled and self._scan_completed
        self.cve_paths_only_var.set(self._cve_paths_only)
        self._render_graph()

    def _visible_graph(self) -> Tuple[List[str], Set[Tuple[str, str]]]:
        """Return the components and edges on a root-to-leaf path containing a CVE."""
        self._shown_edges = None
        all_edges = {
            (parent_id, cid)
            for parent_id, child_ids in self._children.items() for cid in child_ids
        }
        if not self._cve_paths_only:
            return list(self._sbom.components), all_edges
        vulnerable = {
            cid for cid, component in self._sbom.components.items()
            if any(
                self._matches_score(cve)
                for cve in self._cves_by_item.get(id(component.raw_data), [])
            )
        }
        upstream, downstream = set(vulnerable), set(vulnerable)
        for cid in vulnerable:
            upstream |= self._trace_paths(cid, upward=True)[0]
            downstream |= self._trace_paths(cid, upward=False)[0]
        # An edge is on such a path if a CVE lies below its child or above its parent.
        edges = {
            (parent_id, cid) for parent_id, cid in all_edges
            if cid in upstream or parent_id in downstream
        }
        self._shown_edges = edges
        visible = upstream | downstream
        return [cid for cid in self._sbom.components if cid in visible], edges

    def _render_graph(self) -> None:
        """Lay out each component once, preserving shared and cyclic dependencies."""
        self.canvas.delete(tk.ALL)
        visible, edges = self._visible_graph()
        self._visible_count = len(visible)
        self._update_statistics()
        children = {
            parent_id: [cid for cid in self._children[parent_id] if (parent_id, cid) in edges]
            for parent_id in visible
        }
        roots = [
            cid for cid in visible
            if cid in self._sbom.root_ids or not any(
                (parent_id, cid) in edges
                for parent_id in self._sbom.components[cid].parent_ids
            )
        ]
        if self._selected_tag is not None and \
                self._component_tags[self._selected_tag].component_id not in visible:
            self._selected_tag = None
            self._last_click_tag = None
        bounds_by_id: Dict[str, Tuple[float, float, float, float]] = {}
        y = 30.0
        for start in roots + visible:
            stack = [(start, 0)]
            while stack:
                cid, depth = stack.pop()
                if cid in bounds_by_id:
                    continue
                bounds_by_id[cid] = self._draw_component(
                    cid, self._tags_by_id[cid], depth, y
                )
                y = bounds_by_id[cid][3] + 25
                stack.extend((child, depth + 1) for child in reversed(children[cid]))

        for parent_id in visible:
            for cid in children[parent_id]:
                edge = self._connect_nodes(bounds_by_id[parent_id], bounds_by_id[cid])
                self.canvas.addtag_withtag(
                    f"link-{self._tags_by_id[parent_id]}-{self._tags_by_id[cid]}", edge
                )
        if not bounds_by_id:
            self.canvas.create_text(
                30, 30, anchor=tk.NW,
                text=(
                    "No items have CVEs matching the score filter."
                    if self._cve_paths_only and self._score_range is not None
                    else "No items with matched CVEs in this scan."
                    if self._cve_paths_only else "No components in this SBOM."
                ),
            )
        self.canvas.tag_lower("edge")
        self._highlight_selection()
        scale = self._zoom_percent / 100
        bounds = self.canvas.bbox(tk.ALL)
        if bounds:
            self.canvas.configure(
                scrollregion=(0, 0, bounds[2] + 30 * scale, bounds[3] + 30 * scale)
            )

    def _draw_component(
        self, component_id: str, tag: str, depth: int, y: float
    ) -> Tuple[float, float, float, float]:
        """Label a component with every matched CVE ID and highlight matches."""
        component = self._sbom.components[component_id]
        cves = [
            cve for cve in self._cves_by_item.get(id(component.raw_data), [])
            if self._matches_score(cve)
        ]
        label = _display_name(component.raw_data, component.name)
        if component.version:
            label += f"\n{component.version}"
        if cves:
            label += "\n" + "\n".join(_cve_label(cve) for cve in cves)
        return self._draw_node(
            30 + depth * 330, y, 270, label,
            "#fde2e2" if cves else "#e4efff", tag,
        )

    def _trace_paths(
        self, start: str, upward: bool
    ) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Find all reachable components and directed edges, including cycles."""
        visited = {start}
        edges: Set[Tuple[str, str]] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            neighbors = (
                self._sbom.components[current].parent_ids
                if upward else self._children[current]
            )
            for neighbor in neighbors:
                edge = (neighbor, current) if upward else (current, neighbor)
                if neighbor not in self._sbom.components or (
                    self._shown_edges is not None and edge not in self._shown_edges
                ):
                    continue
                edges.add(edge)
                if neighbor not in visited:
                    visited.add(neighbor)
                    stack.append(neighbor)
        visited.remove(start)
        return visited, edges

    @staticmethod
    def _path_color(upward: bool, downward: bool) -> str:
        if upward and downward:
            return _BOTH_COLOR
        if upward:
            return _ANCESTOR_COLOR
        if downward:
            return _DESCENDANT_COLOR
        return _DEFAULT_COLOR

    def _highlight_selection(self) -> None:
        """Highlight the selected item and all paths above and below it."""
        selected_id = None
        ancestors: Set[str] = set()
        descendants: Set[str] = set()
        up_edges: Set[Tuple[str, str]] = set()
        down_edges: Set[Tuple[str, str]] = set()
        if self._selected_tag is not None:
            selected_id = self._component_tags[self._selected_tag].component_id
            ancestors, up_edges = self._trace_paths(selected_id, upward=True)
            descendants, down_edges = self._trace_paths(selected_id, upward=False)
        self._highlight_components(selected_id, ancestors, descendants)
        self._highlight_edges(up_edges, down_edges)

    def _highlight_components(
        self, selected_id: Optional[str], ancestors: Set[str], descendants: Set[str]
    ) -> None:
        scale = self._zoom_percent / 100
        for tag, component in self._component_tags.items():
            cid = component.component_id
            color = (
                _SELECTED_COLOR if cid == selected_id
                else self._path_color(cid in ancestors, cid in descendants)
            )
            width = 4 if cid == selected_id else 3 if color != _DEFAULT_COLOR else 1
            for node in self.canvas.find_withtag(tag):
                if self.canvas.type(node) == "rectangle":
                    self.canvas.itemconfigure(node, outline=color, width=max(1, width * scale))

    def _highlight_edges(
        self, up_edges: Set[Tuple[str, str]], down_edges: Set[Tuple[str, str]]
    ) -> None:
        tags = self._tags_by_id
        scale = self._zoom_percent / 100
        for parent_id, child_ids in self._children.items():
            for cid in child_ids:
                edge = (parent_id, cid)
                color = self._path_color(edge in up_edges, edge in down_edges)
                width = 2 if color == _DEFAULT_COLOR else 3
                self.canvas.itemconfigure(
                    f"link-{tags[parent_id]}-{tags[cid]}",
                    fill=color, width=max(1, width * scale),
                )

    def _current_component_tag(self) -> Optional[str]:
        return next(
            (tag for tag in self.canvas.gettags(tk.CURRENT) if tag in self._component_tags),
            None,
        )

    def _select_component(self, tag: Optional[str]) -> None:
        if tag != self._selected_tag:
            self._selected_tag = tag
            self._highlight_selection()

    def _was_dragged(self, event: tk.Event) -> bool:
        return self._dragged or max(
            abs(event.x - self._drag_origin[0]), abs(event.y - self._drag_origin[1])
        ) > 4

    def _pan_start(self, event: tk.Event) -> None:
        self._drag_origin = (event.x, event.y)
        self._dragged = False
        super()._pan_start(event)

    def _pan_drag(self, event: tk.Event) -> None:
        if max(
            abs(event.x - self._drag_origin[0]), abs(event.y - self._drag_origin[1])
        ) > 4:
            self._dragged = True
        super()._pan_drag(event)

    def _pan_end(self, event: tk.Event) -> None:
        super()._pan_end(event)
        if self._was_dragged(event):
            self._last_click_tag = None
            return
        self._last_click_tag = self._current_component_tag()
        self._select_component(self._last_click_tag)

    def _double_click(self, event: tk.Event) -> None:
        super()._pan_end(event)
        if self._was_dragged(event):
            self._last_click_tag = None
            return
        tag = self._current_component_tag()
        if tag is not None and tag == self._last_click_tag:
            self._last_click_tag = None
            self.show_item_details(tag)
        else:
            self._last_click_tag = tag
            self._select_component(tag)

    def show_item_details(self, tag: str) -> tk.Toplevel:
        """Show the item and its CVE records, or indicate it has not been scanned."""
        component = self._component_tags[tag]
        details: Dict[str, Any] = {}
        if not self._scan_completed:
            details["scan_status"] = "Not scanned for CVEs"
        details["item"] = component.to_dict()
        details["cves"] = (
            self._cves_by_item.get(id(component.raw_data), [])
            if self._scan_completed else None
        )
        return self._show_details(
            f"SBOM item full details - {_display_name(component.raw_data, component.name)}", details
        )
