"""Desktop Graphical User Interface (GUI) for pysbomcve.

This module provides a Tkinter-based desktop application that allows users to
select SBOM and CVE JSON files, execute vulnerability matching, and view the
results in a scrollable text box with vertical and horizontal scrollbars.
"""

from __future__ import annotations

import json
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from pysbomcve.cli import _format_item_summary
from pysbomcve.matcher import match_sbom_cve


# pylint: disable=too-many-instance-attributes
class SBOMCVEApp:
    """Desktop GUI application for matching SBOM components against CVE records."""

    def __init__(self, root: tk.Tk) -> None:
        """Initialize the desktop GUI window and components.

        Args:
            root: Root Tkinter window.
        """
        self.root: tk.Tk = root
        self.root.title("pysbomcve - SBOM & CVE Vulnerability Matcher")
        self.root.geometry("950x700")
        self.root.minsize(750, 500)

        # State variables
        self.sbom_path_var: tk.StringVar = tk.StringVar()
        self.cve_path_var: tk.StringVar = tk.StringVar()
        self.view_mode_var: tk.StringVar = tk.StringVar(value="combined")
        self.status_var: tk.StringVar = tk.StringVar(value="Ready.")
        self.result_text: tk.Text = tk.Text()
        self.last_results: Optional[List[Dict[str, Any]]] = None

        self._configure_styles()
        self._build_ui()

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

        self._create_header_frame(main_frame)
        self._create_file_selection_frame(main_frame)
        self._create_actions_frame(main_frame)
        self._create_results_frame(main_frame)
        self._create_status_bar(main_frame)

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
                "Select a CycloneDX or SPDX SBOM file and a CVE JSON 5.0 record file "
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
        ttk.Label(frame, text="CVE File (CVE JSON 5.0):").grid(
            row=1, column=0, sticky=tk.W, pady=4
        )
        cve_entry = ttk.Entry(frame, textvariable=self.cve_path_var, width=65)
        cve_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=4)
        ttk.Button(frame, text="Browse...", command=self.browse_cve).grid(
            row=1, column=2, padx=2, pady=4
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

        # View Mode radio buttons
        view_frame = ttk.Frame(frame)
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
            "2. Select a CVE JSON 5.0 file.\n"
            "3. Click 'Scan Vulnerabilities' (or 'Load Example Files' to test immediately).\n"
        )

    def _create_status_bar(self, parent: ttk.Frame) -> None:
        """Create bottom status label."""
        status_bar = ttk.Label(
            parent,
            textvariable=self.status_var,
            style="Status.TLabel",
            relief=tk.SUNKEN,
            padding="4",
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

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

    def load_example_files(self) -> None:
        """Convenience method to fill file paths with project example files."""
        base_dir = Path(__file__).resolve().parent.parent
        example_sbom = base_dir / "examples" / "sbom.json"
        example_cve = base_dir / "examples" / "cve.json"

        if example_sbom.exists():
            self.sbom_path_var.set(str(example_sbom))
        if example_cve.exists():
            self.cve_path_var.set(str(example_cve))

        self.status_var.set("Example files loaded. Click 'Scan Vulnerabilities' to run.")

    def run_scan(self) -> None:
        """Execute vulnerability matching on the selected files."""
        sbom_path = self.sbom_path_var.get().strip()
        cve_path = self.cve_path_var.get().strip()

        if not sbom_path:
            messagebox.showwarning("Missing Input", "Please select an SBOM JSON file.")
            return

        if not cve_path:
            messagebox.showwarning("Missing Input", "Please select a CVE JSON file.")
            return

        if not Path(sbom_path).exists():
            messagebox.showerror("File Error", f"SBOM file does not exist:\n{sbom_path}")
            return

        if not Path(cve_path).exists():
            messagebox.showerror("File Error", f"CVE file does not exist:\n{cve_path}")
            return

        self.status_var.set("Scanning components and matching CVEs...")
        self.root.update_idletasks()

        try:
            results = match_sbom_cve(sbom_path, cve_path)
            self.last_results = results

            total_vulns = sum(len(item.get("cves", [])) for item in results)
            status_msg = (
                f"Scan Complete: {len(results)} vulnerable component(s) found, "
                f"{total_vulns} matching CVE(s)."
            )
            self.status_var.set(status_msg)
            self._refresh_display()

        except Exception as exc:  # pylint: disable=broad-exception-caught
            err_msg = f"Scan failed: {exc}"
            self.status_var.set(err_msg)
            messagebox.showerror("Scan Error", err_msg)

    def _format_summary_text(self, results: List[Dict[str, Any]]) -> str:
        """Generate human-readable summary report string."""
        total_vulns = sum(len(item.get("cves", [])) for item in results)
        lines: List[str] = [
            "=" * 70,
            "                      pysbomcve Scan Report",
            "=" * 70,
            f"SBOM: {self.sbom_path_var.get()}",
            f"CVE : {self.cve_path_var.get()}",
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

        mode = self.view_mode_var.get()
        if mode == "summary":
            content = self._format_summary_text(self.last_results)
        elif mode == "json":
            content = json.dumps(self.last_results, indent=2)
        else:  # combined
            summary = self._format_summary_text(self.last_results)
            json_str = json.dumps(self.last_results, indent=2)
            content = f"{summary}\n\n--- Full JSON Result ---\n{json_str}"

        self._set_text_content(content)

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

    def clear_all(self) -> None:
        """Clear all inputs, results, and reset application status."""
        self.sbom_path_var.set("")
        self.cve_path_var.set("")
        self.last_results = None
        self._set_text_content("Inputs cleared. Select new files to start a scan.")
        self.status_var.set("Ready.")


def launch_gui() -> None:
    """Launch the Desktop GUI application."""
    root = tk.Tk()
    SBOMCVEApp(root)
    root.mainloop()


def main() -> None:
    """Entry point for GUI execution."""
    launch_gui()


if __name__ == "__main__":
    main()
