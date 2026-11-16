"""Command-line interface for pysbomcve.

This module provides a console tool to match SBOMs against CVE JSON 5.0 records,
printing human-readable and JSON results to stdout and saving results to a file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pysbomcve.cve_parser import parse_cve_records
from pysbomcve.matcher import SBOMCVEMatcher
from pysbomcve.report import REPORT_FORMATS, render_report, sbom_max_depth
from pysbomcve.sbom_parser import parse_sbom


def _format_cve_lines(cves: List[Dict[str, Any]]) -> List[str]:
    """Format matching CVE bullet points."""
    lines: List[str] = [f"    Matched CVEs ({len(cves)}):"]
    for cve in cves:
        cve_id = cve.get("cveId", "Unknown")
        sev = cve.get("severity", "N/A")
        score = cve.get("score", "N/A")
        title = cve.get("title", "")
        lines.append(f"      * {cve_id} [Severity: {sev}, Score: {score}]")
        if title:
            lines.append(f"        Title: {title}")
    return lines


def _format_path_lines(
    paths: List[List[Dict[str, Any]]], comp_name: str, comp_ver: str
) -> List[str]:
    """Format ancestor path lines."""
    lines: List[str] = ["    Lineage to Root:"]
    if not paths:
        lines.append("      (Direct root component)")
        return lines

    for idx, path in enumerate(paths, 1):
        chain_parts = [f"{comp_name} ({comp_ver})"]
        for parent in path:
            p_name = parent.get("name", "unknown")
            p_ver = parent.get("version") or parent.get("versionInfo") or ""
            chain_parts.append(f"{p_name} ({p_ver})" if p_ver else p_name)
        lines.append(f"      Path {idx}: {' -> '.join(chain_parts)}")
    return lines


def _format_item_summary(item_dict: Dict[str, Any]) -> str:
    """Format a summary string for a single vulnerable SBOM component.

    Args:
        item_dict: Matching component dictionary containing 'item', 'cves', and 'lineage_paths'.

    Returns:
        Formatted multi-line summary string.
    """
    comp = item_dict.get("item", {})
    comp_name = comp.get("name", "unknown")
    comp_ver = comp.get("version") or comp.get("versionInfo") or "unknown"

    lines: List[str] = [f"[-] Component: {comp_name} @ {comp_ver}"]
    if comp.get("purl"):
        lines.append(f"    PURL: {comp['purl']}")

    lines.extend(_format_cve_lines(item_dict.get("cves", [])))
    lines.extend(_format_path_lines(item_dict.get("lineage_paths", []), comp_name, comp_ver))

    return "\n".join(lines)


def _add_examples_dir_argument(parser: argparse.ArgumentParser) -> None:
    """Add the example directory option shared by the GUI entry points."""
    parser.add_argument(
        "--examples-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="Folder containing sbom.json and cve.json for the GUI examples button.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for pysbomcve CLI.

    Returns:
        Configured argparse.ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="pysbomcve",
        description="Match CycloneDX and SPDX SBOM components against CVE JSON 5.0 records.",
    )
    parser.add_argument(
        "--sbom",
        default=None,
        help="Path to the SBOM JSON file (CycloneDX or SPDX format).",
    )
    parser.add_argument(
        "--cve",
        default=None,
        help="Path to the CVE JSON 5.0 file, list file, or directory (searched recursively).",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the desktop graphical user interface (GUI).",
    )
    _add_examples_dir_argument(parser)
    parser.add_argument(
        "--out",
        "-o",
        dest="out",
        default=None,
        help="Path to the output file where the report will be saved.",
    )
    parser.add_argument(
        "--outform",
        choices=REPORT_FORMATS,
        default="html",
        help="Report format for --out and the printed report: html (default) or json.",
    )
    report_kind = parser.add_mutually_exclusive_group()
    report_kind.add_argument(
        "--full",
        action="store_true",
        help=(
            "Full report: every vulnerable item with its complete CVE records and "
            "paths to the root, instead of the default short report."
        ),
    )
    report_kind.add_argument(
        "--short",
        action="store_true",
        help=(
            "Short report (the default): the SBOM tree levels selected by --depth, "
            "each item with all CVE IDs and scores in it or below it; items without "
            "CVEs are omitted."
        ),
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Tree levels in the short report, from 1 (roots only) to the SBOM's "
            "maximum depth (default: the maximum depth). Not allowed with --full."
        ),
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation level for output formatting (default: 2).",
    )
    parser.add_argument(
        "--fail-on-cve",
        action="store_true",
        help="Exit with return code 1 if one or more vulnerable items are found.",
    )
    return parser


def _validate_input_paths(sbom_path: Path, cve_path: Path) -> Optional[str]:
    """Validate that input files exist on disk."""
    if not sbom_path.exists():
        return f"Error: SBOM file not found: {sbom_path}\n"
    if not cve_path.exists():
        return f"Error: CVE source not found: {cve_path}\n"
    return None


class _DepthError(ValueError):
    """The requested short-report depth is outside the SBOM's levels."""


def _scan_and_render(
    parsed_args: argparse.Namespace, sbom_path: Path, cve_path: Path
) -> Tuple[List[Dict[str, Any]], str]:
    """Match the inputs and render the report selected by --outform and --full."""
    parsed_sbom = parse_sbom(sbom_path)
    depth = parsed_args.depth
    if depth is not None:
        # Check before the potentially slow CVE loading.
        max_depth = max(sbom_max_depth(parsed_sbom), 1)
        if not 1 <= depth <= max_depth:
            raise _DepthError(
                f"--depth must be from 1 to {max_depth} (the SBOM's maximum depth)"
            )
    results = SBOMCVEMatcher().match(parsed_sbom, parse_cve_records(cve_path))
    report = render_report(
        parsed_sbom, results, fmt=parsed_args.outform, short=not parsed_args.full,
        sbom_path=str(sbom_path), cve_path=str(cve_path), indent=parsed_args.indent,
        depth=depth,
    )
    return results, report


def _check_cli_args(parser: argparse.ArgumentParser, parsed_args: argparse.Namespace) -> None:
    """Reject option combinations that only apply to other modes (exits on error)."""
    if parsed_args.examples_dir is not None:
        parser.error("--examples-dir requires --gui")
    if parsed_args.depth is not None and parsed_args.full:
        parser.error("--depth cannot be used with --full")
    if not parsed_args.sbom or not parsed_args.cve:
        parser.error("the following arguments are required: --sbom, --cve (or use --gui)")


def run_cli(args: Optional[List[str]] = None) -> int:
    """Execute the CLI logic.

    Args:
        args: Optional list of argument strings. Uses sys.argv[1:] if None.

    Returns:
        Exit code (0 for success, 1 on vulnerability when --fail-on-cve set or error).
    """
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.gui:
        # pylint: disable=import-outside-toplevel
        from pysbomcve.gui import launch_gui

        launch_gui(parsed_args.examples_dir)
        return 0

    _check_cli_args(parser, parsed_args)
    sbom_path = Path(parsed_args.sbom)
    cve_path = Path(parsed_args.cve)

    path_error = _validate_input_paths(sbom_path, cve_path)
    if path_error:
        sys.stderr.write(path_error)
        return 1

    try:
        results, report = _scan_and_render(parsed_args, sbom_path, cve_path)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        sys.stderr.write(
            f"{'Error' if isinstance(exc, _DepthError) else 'Error during matching'}: {exc}\n"
        )
        return 1

    total_vulns = sum(len(item.get("cves", [])) for item in results)

    # Print human-readable summary
    print("=" * 70)
    print("                      pysbomcve Scan Report")
    print("=" * 70)
    print(f"SBOM: {sbom_path}")
    print(f"CVE : {cve_path}")
    print(f"Total vulnerable items found: {len(results)}")
    print(f"Total matching CVEs         : {total_vulns}")
    print("=" * 70)

    if results:
        print("\nVulnerable Components:")
        for item in results:
            print(_format_item_summary(item))
            print("-" * 70)
    else:
        print("\nNo vulnerabilities matched against the provided SBOM components.")

    # Print the selected report to console
    kind = "Full" if parsed_args.full else "Short"
    print(f"\n--- {kind} {parsed_args.outform.upper()} Report ---")
    print(report)

    # Save to output file if requested
    if parsed_args.out:
        out_path = Path(parsed_args.out)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as out_file:
                out_file.write(report)
            print(f"\n[+] Results successfully saved to: {out_path.resolve()}")
        except OSError as exc:
            sys.stderr.write(f"Error writing output to {out_path}: {exc}\n")
            return 1

    if parsed_args.fail_on_cve and results:
        return 1

    return 0


def main() -> None:
    """Main CLI entry point function."""
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
