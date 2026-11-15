"""Desktop Graphical User Interface (GUI) for pysbomcve.

This module provides a Tkinter-based desktop application that allows users to
select an SBOM file and a CVE file or directory, execute vulnerability matching,
and view the results in a scrollable text box.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future
import json
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from time import monotonic
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Tuple, Union

from pysbomcve.cli import _add_examples_dir_argument, _format_item_summary
from pysbomcve.cve_parser import CVERecord, parse_cve_records
from pysbomcve.graph_view import ResultsGraphWindow, SBOMTreeWindow
from pysbomcve.matcher import SBOMCVEMatcher
from pysbomcve.report import render_report
from pysbomcve.sbom_parser import ParsedSBOM, parse_sbom

_ScanResult = Tuple[ParsedSBOM, List[Dict[str, Any]], str, List[CVERecord]]
# Resolved CVE path plus (mtime, size) for files; folders are only reloaded on request.
_CVEKey = Tuple[str, Optional[Tuple[int, int]]]


# pylint: disable=too-many-instance-attributes
class SBOMCVEApp:
    """Desktop GUI application for matching SBOM components against CVE records."""

    def __init__(
        self, root: tk.Tk, examples_dir: Optional[Union[str, Path]] = None
    ) -> None:
        """Initialize the desktop GUI window and components.

        Args:
            root: Root Tkinter window.
            examples_dir: Folder containing sbom.json and cve.json, or None
                to use the project's examples folder.
        """
        self.root: tk.Tk = root
        self.root.title("pysbomcve - SBOM & CVE Vulnerability Matcher")
        self.root.geometry("950x700")
        self.root.minsize(750, 500)
        self.examples_dir: Path = (
            Path(examples_dir).expanduser().resolve()
            if examples_dir is not None
            else Path(__file__).resolve().parent.parent / "examples"
        )

        # State variables
        self.sbom_path_var: tk.StringVar = tk.StringVar()
        self.cve_path_var: tk.StringVar = tk.StringVar()
        self.view_mode_var: tk.StringVar = tk.StringVar(value="combined")
        self.status_var: tk.StringVar = tk.StringVar(value="Ready.")
        self.result_text: tk.Text = tk.Text()
        self.last_results: Optional[List[Dict[str, Any]]] = None
        self.last_sbom: Optional[ParsedSBOM] = None
        self._scan_future: Optional[Future[_ScanResult]] = None
        self._scan_progress: Queue[str] = Queue()
        self._scan_after_id: Optional[str] = None
        self._scan_started = 0.0
        self._scan_message = ""
        self._cve_cache: Optional[Tuple[_CVEKey, List[CVERecord]]] = None
        self._pending_cve_key: Optional[_CVEKey] = None
        self._using_cached_cves = False

        self._configure_styles()
        self._build_ui()
        self.root.bind("<Destroy>", self._on_destroy, add="+")

    @property
    def is_scanning(self) -> bool:
        """Whether a scan is running or its results are being prepared."""
        return self._scan_future is not None

    def _configure_styles(self) -> None:
        """Configure ttk styles for the application."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 9))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

    def _build_ui(self) -> None:
        """Construct all UI frames and widgets."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        self._main_frame = main_frame

        self._create_header_frame(main_frame)
        self._create_file_selection_frame(main_frame)
        self._create_actions_frame(main_frame)
        # Pack the status bar before the expanding results so it is never squeezed out.
        self._progress_bar = self._create_status_bar(main_frame)
        self._create_results_frame(main_frame)

    def _create_header_frame(self, parent: ttk.Frame) -> None:
        """Create header label with instructions."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_lbl = ttk.Label(
            header_frame,
            text="SBOM & CVE Vulnerability Matcher",
            style="Header.TLabel",
        )
        title_lbl.pack(anchor=tk.W)

        subtitle_lbl = ttk.Label(
            header_frame,
            text=(
                "Select a CycloneDX or SPDX SBOM file and a CVE JSON file or folder "
                "to find vulnerable packages with full tree lineage to root."
            ),
        )
        subtitle_lbl.pack(anchor=tk.W)

    def _create_file_selection_frame(self, parent: ttk.Frame) -> None:
        """Create file selection input rows."""
        frame = ttk.LabelFrame(parent, text="Input Files", padding="10")
        frame.pack(fill=tk.X, pady=(0, 10))

        # SBOM row
        ttk.Label(frame, text="SBOM File (CycloneDX / SPDX JSON):").grid(
            row=0, column=0, sticky=tk.W, pady=4
        )
        sbom_entry = ttk.Entry(frame, textvariable=self.sbom_path_var, width=65)
        sbom_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=4)
        ttk.Button(frame, text="Browse...", command=self.browse_sbom).grid(
            row=0, column=2, padx=2, pady=4
        )

        # CVE row
        ttk.Label(frame, text="CVE File or Folder (CVE JSON 5.0):").grid(
            row=1, column=0, sticky=tk.W, pady=4
        )
        cve_entry = ttk.Entry(frame, textvariable=self.cve_path_var, width=65)
        cve_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=4)
        ttk.Button(frame, text="File...", command=self.browse_cve).grid(
            row=1, column=2, padx=2, pady=4
        )
        ttk.Button(frame, text="Folder...", command=self.browse_cve_directory).grid(
            row=1, column=3, padx=2, pady=4
        )
        ttk.Label(frame, text="Folder scans include JSON files in all subfolders.").grid(
            row=2, column=1, columnspan=3, sticky=tk.W
        )

        frame.columnconfigure(1, weight=1)

    def _create_actions_frame(self, parent: ttk.Frame) -> None:
        """Create control action buttons and view toggle radio buttons."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=(0, 8))

        # Action Buttons
        scan_btn = ttk.Button(
            frame,
            text="  Scan Vulnerabilities  ",
            style="Accent.TButton",
            command=self.run_scan,
        )
        scan_btn.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            frame,
            text="Reload CVEs + Scan",
            command=self.reload_cves_and_scan,
        ).pack(side=tk.LEFT, padx=5)

        example_btn = ttk.Button(
            frame,
            text="Load Example Files",
            command=self.load_example_files,
        )
        example_btn.pack(side=tk.LEFT, padx=5)

        save_btn = ttk.Button(
            frame,
            text="Save Results...",
            command=self.save_results,
        )
        save_btn.pack(side=tk.LEFT, padx=5)

        clear_btn = ttk.Button(
            frame,
            text="Clear",
            command=self.clear_all,
        )
        clear_btn.pack(side=tk.LEFT, padx=5)

        options_frame = ttk.Frame(parent)
        options_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(
            options_frame,
            text="Graphical Results...",
            command=self.show_graph,
        ).pack(side=tk.LEFT)
        ttk.Button(
            options_frame,
            text="SBOM Tree...",
            command=self.show_sbom_tree,
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            options_frame,
            text="Export Report...",
            command=self.show_export_dialog,
        ).pack(side=tk.LEFT, padx=5)

        # View Mode radio buttons
        view_frame = ttk.Frame(options_frame)
        view_frame.pack(side=tk.RIGHT)
        ttk.Label(view_frame, text="Display:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Radiobutton(
            view_frame,
            text="Combined",
            variable=self.view_mode_var,
            value="combined",
            command=self._refresh_display,
        ).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(
            view_frame,
            text="Summary Only",
            variable=self.view_mode_var,
            value="summary",
            command=self._refresh_display,
        ).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(
            view_frame,
            text="JSON Only",
            variable=self.view_mode_var,
            value="json",
            command=self._refresh_display,
        ).pack(side=tk.LEFT, padx=2)

    def _create_results_frame(self, parent: ttk.Frame) -> None:
        """Create scrollable text box with horizontal and vertical scrollbars."""
        frame = ttk.LabelFrame(parent, text="Scan Results", padding="5")
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Text widget configured with no word wrapping for clean table/tree alignment
        self.result_text = tk.Text(
            frame,
            wrap=tk.NONE,
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )

        # Vertical and Horizontal Scrollbars
        v_scrollbar = ttk.Scrollbar(
            frame, orient=tk.VERTICAL, command=self.result_text.yview
        )
        h_scrollbar = ttk.Scrollbar(
            frame, orient=tk.HORIZONTAL, command=self.result_text.xview
        )

        self.result_text.configure(
            xscrollcommand=h_scrollbar.set,
            yscrollcommand=v_scrollbar.set,
        )

        # Grid geometry to bind text box with both scrollbars
        self.result_text.grid(row=0, column=0, sticky=tk.NSEW)
        v_scrollbar.grid(row=0, column=1, sticky=tk.NS)
        h_scrollbar.grid(row=1, column=0, sticky=tk.EW)

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._set_text_content(
            "Welcome to pysbomcve!\n\n"
            "1. Select an SBOM JSON file (CycloneDX or SPDX).\n"
            "2. Select a CVE JSON 5.0 file or folder.\n"
            "3. Click 'Scan Vulnerabilities' (or 'Load Example Files' to test immediately).\n"
        )

    def _create_status_bar(self, parent: ttk.Frame) -> ttk.Progressbar:
        """Create the scan activity indicator and status label."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, side=tk.BOTTOM)
        progress_bar = ttk.Progressbar(frame, mode="indeterminate", length=100)
        progress_bar.pack(side=tk.RIGHT, padx=(8, 0))
        status_bar = ttk.Label(
            frame,
            textvariable=self.status_var,
            style="Status.TLabel",
            relief=tk.SUNKEN,
            padding="4",
        )
        status_bar.pack(fill=tk.X, expand=True, side=tk.LEFT)
        return progress_bar

    def browse_sbom(self) -> None:
        """Open file dialog to choose an SBOM file."""
        file_path = filedialog.askopenfilename(
            title="Select SBOM JSON File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if file_path:
            self.sbom_path_var.set(file_path)

    def browse_cve(self) -> None:
        """Open file dialog to choose a CVE JSON file."""
        file_path = filedialog.askopenfilename(
            title="Select CVE JSON File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if file_path:
            self.cve_path_var.set(file_path)

    def browse_cve_directory(self) -> None:
        """Open a folder dialog to choose a directory of CVE JSON files."""
        folder_path = filedialog.askdirectory(
            title="Select CVE Records Folder", parent=self.root, mustexist=True
        )
        if folder_path:
            self.cve_path_var.set(folder_path)

    def load_example_files(self) -> None:
        """Fill input paths from the configured examples directory."""
        example_sbom = self.examples_dir / "sbom.json"
        example_cve = self.examples_dir / "cve.json"
        missing = [str(path) for path in (example_sbom, example_cve) if not path.is_file()]
        if missing:
            self.status_var.set("Example files not found.")
            messagebox.showerror(
                "Example Files Error", "Example files not found:\n" + "\n".join(missing)
            )
            return

        self.sbom_path_var.set(str(example_sbom))
        self.cve_path_var.set(str(example_cve))
        self.status_var.set("Example files loaded. Click 'Scan Vulnerabilities' to run.")

    def run_scan(self) -> None:
        """Validate inputs and start a scan without blocking Tk's event loop."""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "A scan is already running.")
            return
        sbom_path = self.sbom_path_var.get().strip()
        cve_path = self.cve_path_var.get().strip()

        if not sbom_path:
            messagebox.showwarning("Missing Input", "Please select an SBOM JSON file.")
            return

        if not cve_path:
            messagebox.showwarning("Missing Input", "Please select a CVE JSON file or folder.")
            return

        if not Path(sbom_path).exists():
            messagebox.showerror("File Error", f"SBOM file does not exist:\n{sbom_path}")
            return

        if not Path(cve_path).exists():
            messagebox.showerror("File Error", f"CVE file or folder does not exist:\n{cve_path}")
            return

        self._scan_started = monotonic()
        self._scan_message = "Loading SBOM..."
        self.status_var.set(self._scan_message)
        self._scan_progress = Queue()
        cve_key = self._cve_key(cve_path)
        cached = (
            self._cve_cache[1]
            if self._cve_cache is not None and self._cve_cache[0] == cve_key else None
        )
        self._pending_cve_key = cve_key
        self._using_cached_cves = cached is not None
        future: Future[_ScanResult] = Future()
        self._scan_future = future
        self._set_scan_busy(True)
        self._scan_after_id = self.root.after(100, self._poll_scan)
        Thread(
            target=self._scan_worker,
            args=(
                sbom_path, cve_path, self.view_mode_var.get(),
                self._scan_progress, future, cached,
            ),
            daemon=True,
        ).start()

    def reload_cves_and_scan(self) -> None:
        """Discard previously loaded CVE records and scan with freshly read files."""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "A scan is already running.")
            return
        self._cve_cache = None
        self.run_scan()

    @staticmethod
    def _cve_key(cve_path: str) -> _CVEKey:
        path = Path(cve_path).resolve()
        if path.is_file():
            stat = path.stat()
            return str(path), (stat.st_mtime_ns, stat.st_size)
        return str(path), None

    @staticmethod
    def _scan_worker(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        sbom_path: str, cve_path: str, mode: str,
        updates: Queue[str], future: Future[_ScanResult],
        cached_cves: Optional[List[CVERecord]] = None,
    ) -> None:
        """Only handle Python data here; all Tk operations stay on the main thread."""
        last_update = 0.0

        def report(message: str) -> None:
            nonlocal last_update
            now = monotonic()
            if now - last_update >= 0.1:
                updates.put(message)
                last_update = now

        try:
            parsed_sbom = parse_sbom(sbom_path)
            if cached_cves is None:
                cves = parse_cve_records(cve_path, progress=report)
            else:
                cves = cached_cves
                updates.put(f"Reusing {len(cves):,} CVE records already loaded...")
            results = SBOMCVEMatcher().match(parsed_sbom, cves, progress=report)
            updates.put("Preparing results...")
            content = SBOMCVEApp._format_results(results, mode, sbom_path, cve_path)
            future.set_result((parsed_sbom, results, content, cves))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            future.set_exception(exc)

    def _set_scan_busy(self, busy: bool) -> None:
        widgets = list(self._main_frame.winfo_children())
        while widgets:
            widget = widgets.pop()
            widgets.extend(widget.winfo_children())
            if isinstance(widget, (ttk.Button, ttk.Entry, ttk.Radiobutton)):
                widget.state(["disabled"] if busy else ["!disabled"])
        self.root.configure(cursor="watch" if busy else "")
        if busy:
            self._progress_bar.start(50)
        else:
            self._progress_bar.stop()

    def _poll_scan(self) -> None:
        """Consume worker messages and publish completed results on the Tk thread."""
        self._scan_after_id = None
        future = self._scan_future
        if future is None:
            return
        try:
            while True:
                self._scan_message = self._scan_progress.get_nowait()
        except Empty:
            pass
        elapsed = monotonic() - self._scan_started
        self.status_var.set(f"{self._scan_message} ({elapsed:.1f}s elapsed)")
        if not future.done():
            self._scan_after_id = self.root.after(100, self._poll_scan)
            return
        self._scan_future = None
        self._set_scan_busy(False)
        error = future.exception()
        if error is not None:
            err_msg = f"Scan failed: {error}"
            self.status_var.set(err_msg)
            messagebox.showerror("Scan Error", err_msg)
            return
        try:
            parsed_sbom, results, content, cves = future.result()
            self.last_results = results
            self.last_sbom = parsed_sbom
            if self._pending_cve_key is not None:
                self._cve_cache = (self._pending_cve_key, cves)
            self._set_text_content(content)
            total_vulns = sum(len(item.get("cves", [])) for item in results)
            status_msg = (
                f"Scan Complete: {len(results)} vulnerable component(s) found, "
                f"{total_vulns} matching CVE(s). ({elapsed:.1f}s"
                + (f"; reused {len(cves):,} loaded CVE records" if self._using_cached_cves
                   else "")
                + ")"
            )
            self.status_var.set(status_msg)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            err_msg = f"Scan failed: {exc}"
            self.status_var.set(err_msg)
            messagebox.showerror("Scan Error", err_msg)

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget == self.root and self._scan_after_id is not None:
            self.root.after_cancel(self._scan_after_id)
            self._scan_after_id = None

    def show_graph(self) -> Optional[ResultsGraphWindow]:
        """Open a separate graphical window for the latest scan results."""
        if self.last_results is None:
            messagebox.showinfo("No Scan Results", "Run a scan before opening the graph.")
            return None
        return ResultsGraphWindow(self.root, self.last_results)

    def show_sbom_tree(self) -> Optional[SBOMTreeWindow]:
        """Open the scanned SBOM, or preview the selected SBOM before scanning."""
        if self.last_sbom is not None and self.last_results is not None:
            return SBOMTreeWindow(self.root, self.last_sbom, self.last_results)

        sbom_path = self.sbom_path_var.get().strip()
        if not sbom_path:
            messagebox.showwarning("Missing Input", "Please select an SBOM JSON file.")
            return None

        try:
            parsed_sbom = parse_sbom(sbom_path)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            messagebox.showerror("SBOM Error", f"Failed to load SBOM:\n{sbom_path}\n\n{exc}")
            return None

        messagebox.showwarning(
            "CVE Scan Not Run",
            "This SBOM has not been scanned for CVEs. The tree cannot indicate "
            "whether its components are vulnerable until you run a scan.",
        )
        return SBOMTreeWindow(self.root, parsed_sbom, None)

    @staticmethod
    def _format_summary_text(
        results: List[Dict[str, Any]], sbom_path: str, cve_path: str
    ) -> str:
        """Generate human-readable summary report string."""
        total_vulns = sum(len(item.get("cves", [])) for item in results)
        lines: List[str] = [
            "=" * 70,
            "                      pysbomcve Scan Report",
            "=" * 70,
            f"SBOM: {sbom_path}",
            f"CVE : {cve_path}",
            f"Total vulnerable items found: {len(results)}",
            f"Total matching CVEs         : {total_vulns}",
            "=" * 70,
            "",
        ]

        if not results:
            lines.append("No vulnerable items were matched in this SBOM.")
            return "\n".join(lines)

        for item_dict in results:
            lines.append(_format_item_summary(item_dict))
            lines.append("-" * 70)

        return "\n".join(lines)

    def _refresh_display(self) -> None:
        """Update results text box according to current view mode."""
        if self.last_results is None:
            return

        content = self._format_results(
            self.last_results, self.view_mode_var.get(),
            self.sbom_path_var.get(), self.cve_path_var.get(),
        )
        self._set_text_content(content)

    @staticmethod
    def _format_results(
        results: List[Dict[str, Any]], mode: str, sbom_path: str, cve_path: str
    ) -> str:
        if mode == "summary":
            return SBOMCVEApp._format_summary_text(results, sbom_path, cve_path)
        if mode == "json":
            return json.dumps(results, indent=2)
        summary = SBOMCVEApp._format_summary_text(results, sbom_path, cve_path)
        json_str = json.dumps(results, indent=2)
        return f"{summary}\n\n--- Full JSON Result ---\n{json_str}"

    def _set_text_content(self, content: str) -> None:
        """Set text in the result box while maintaining read-only status."""
        self.result_text.configure(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, content)
        self.result_text.configure(state=tk.DISABLED)

    def save_results(self) -> None:
        """Save scan results to a user-selected JSON file."""
        if not self.last_results:
            messagebox.showinfo("Nothing to Save", "No scan results available to save.")
            return

        out_path = filedialog.asksaveasfilename(
            title="Save Scan Results",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not out_path:
            return

        try:
            with open(out_path, "w", encoding="utf-8") as file_handle:
                json.dump(self.last_results, file_handle, indent=2)
            self.status_var.set(f"Results successfully saved to: {out_path}")
            messagebox.showinfo("Saved", f"Results successfully saved to:\n{out_path}")
        except OSError as exc:
            messagebox.showerror("Save Error", f"Failed to save results: {exc}")

    def show_export_dialog(self) -> Optional[tk.Toplevel]:
        """Ask for full or short report and JSON or HTML format, then export."""
        if self.last_results is None or self.last_sbom is None:
            messagebox.showinfo("No Scan Results", "Run a scan before exporting a report.")
            return None
        dialog = tk.Toplevel(self.root)
        dialog.title("Export Report")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)
        report_var = tk.StringVar(dialog, value="full")
        format_var = tk.StringVar(dialog, value="json")
        ttk.Label(frame, text="Report:").grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(frame, text="Full (all vulnerable items and CVE details)",
                        variable=report_var, value="full").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(
            frame, text="Short (roots and items below them, with CVE IDs and scores)",
            variable=report_var, value="short",
        ).grid(row=1, column=1, sticky=tk.W)
        ttk.Label(frame, text="Format:").grid(row=2, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Radiobutton(frame, text="JSON", variable=format_var, value="json").grid(
            row=2, column=1, sticky=tk.W, pady=(8, 0))
        ttk.Radiobutton(frame, text="HTML", variable=format_var, value="html").grid(
            row=3, column=1, sticky=tk.W)

        def export() -> None:
            fmt, short = format_var.get(), report_var.get() == "short"
            out_path = filedialog.asksaveasfilename(
                parent=dialog,
                title="Export Report",
                defaultextension=f".{fmt}",
                initialfile=f"pysbomcve_{'short' if short else 'full'}_report.{fmt}",
                filetypes=[(f"{fmt.upper()} Files", f"*.{fmt}"), ("All Files", "*.*")],
            )
            if out_path and self.export_report(out_path, short=short, fmt=fmt):
                dialog.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=2, sticky=tk.E, pady=(12, 0))
        ttk.Button(buttons, text="Export...", command=export).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=(6, 0))
        return dialog

    def export_report(self, out_path: str, *, short: bool, fmt: str) -> bool:
        """Write the last scan as the same full/short JSON/HTML report as the CLI."""
        if self.last_results is None or self.last_sbom is None:
            messagebox.showinfo("No Scan Results", "Run a scan before exporting a report.")
            return False
        report = render_report(
            self.last_sbom, self.last_results, fmt=fmt, short=short,
            sbom_path=self.sbom_path_var.get(), cve_path=self.cve_path_var.get(),
        )
        try:
            with open(out_path, "w", encoding="utf-8") as file_handle:
                file_handle.write(report)
        except OSError as exc:
            messagebox.showerror("Export Error", f"Failed to export report: {exc}")
            return False
        self.status_var.set(f"Report exported to: {out_path}")
        messagebox.showinfo("Exported", f"Report exported to:\n{out_path}")
        return True

    def clear_all(self) -> None:
        """Clear all inputs, results, and reset application status."""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "Wait for the scan before clearing inputs.")
            return
        self.sbom_path_var.set("")
        self.cve_path_var.set("")
        self.last_results = None
        self.last_sbom = None
        self._set_text_content("Inputs cleared. Select new files to start a scan.")
        self.status_var.set("Ready.")


def launch_gui(examples_dir: Optional[Union[str, Path]] = None) -> None:
    """Launch the Desktop GUI application with an optional examples directory."""
    root = tk.Tk()
    SBOMCVEApp(root, examples_dir)
    root.mainloop()


def main() -> None:
    """Entry point for GUI execution."""
    parser = argparse.ArgumentParser(description="Launch the pysbomcve desktop GUI.")
    _add_examples_dir_argument(parser)
    args = parser.parse_args()
    launch_gui(args.examples_dir)


if __name__ == "__main__":
    main()
