"""Scrollable graphical results and CVE detail windows."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional, Tuple


class ResultsGraphWindow(tk.Toplevel):
    """Display affected components, their ancestor paths, and matching CVEs."""

    def __init__(self, parent: tk.Misc, results: List[Dict[str, Any]]) -> None:
        """Create an independent view of the supplied scan results."""
        super().__init__(parent)
        self.title("pysbomcve - Graphical Results")
        self.geometry("1200x750")
        self.minsize(750, 450)
        self._results = results
        self._zoom_percent = 100

        ttk.Label(
            self,
            text="CVEs: yellow | Affected items: red | SBOM ancestors: blue. "
            "Double-click a CVE for full details.",
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

        self._bind_cve_events()
        self._render_graph()

    def _bind_cve_events(self) -> None:
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
        for index, finding in enumerate(self._results):
            y = self._draw_finding(finding, index, y)
        if not self._results:
            self.canvas.create_text(
                30 * scale, y * scale,
                text="No affected items in these scan results.", anchor=tk.NW,
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
        """Restore the CVE cursor when the drag ends."""
        over_cve = any(tag.startswith("cve-") for tag in self.canvas.gettags(tk.CURRENT))
        self.canvas.configure(cursor="hand2" if over_cve else "")

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
            fill=color, outline="#64748b", width=max(1, scale), tags=(tag, "node"),
        )
        self.canvas.tag_lower(rectangle, text)
        return x, y, x + width, y + height

    def _connect_nodes(
        self,
        source: Tuple[float, float, float, float],
        target: Tuple[float, float, float, float],
    ) -> None:
        """Connect facing card edges with an arrow."""
        if target[0] > source[0]:
            start_x, end_x = source[2], target[0]
        else:
            start_x, end_x = source[0], target[2]
        scale = self._zoom_percent / 100
        self.canvas.create_line(
            start_x * scale, (source[1] + source[3]) / 2 * scale,
            end_x * scale, (target[1] + target[3]) / 2 * scale,
            arrow=tk.LAST, fill="#64748b", width=max(1, 2 * scale),
            arrowshape=(8 * scale, 10 * scale, 3 * scale), tags="edge",
        )

    # pylint: disable=too-many-locals
    def _draw_finding(self, finding: Dict[str, Any], index: int, y: float) -> float:
        """Lay out one affected item with separate rows for each ancestor path."""
        cve_nodes = []
        cve_y = y
        for cve_index, cve in enumerate(finding.get("cves", [])):
            tag = f"cve-{index}-{cve_index}"
            description = "\n\n".join(cve.get("descriptions", []))
            label = f"{cve.get('cveId', 'Unknown CVE')}\n\n"
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
        """Include the version to distinguish same-named SBOM components."""
        name = item.get("name") or "Unnamed item"
        version = item.get("version") or item.get("versionInfo")
        return f"{name}\n{version}" if version else str(name)

    def show_cve_details(self, cve: Dict[str, Any]) -> tk.Toplevel:
        """Open the complete CVE, including its raw record, in a read-only dialog."""
        dialog = tk.Toplevel(self)
        dialog.title(f"CVE full details - {cve.get('cveId', 'Unknown CVE')}")
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
        text.insert("1.0", json.dumps(cve, indent=2, ensure_ascii=False))
        text.configure(state=tk.DISABLED)
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(0, 10))
        return dialog
