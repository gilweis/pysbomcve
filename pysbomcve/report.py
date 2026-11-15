"""Full and short scan reports in JSON or HTML, shared by the CLI and GUI.

The full report is the complete list of matcher findings. The short report lists
only SBOM roots and the items directly below them, each with every CVE found in
that item or anywhere below it; items with no CVEs on or below them are omitted.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime
from html import escape
import json
from typing import Any, Dict, Iterable, List, Optional

from pysbomcve.sbom_parser import ParsedSBOM

REPORT_FORMATS = ("json", "html")


def _cve_summary(cves: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate CVEs by ID, ordered by descending score (unscored last), then ID."""
    unique: Dict[str, Dict[str, Any]] = {}
    for cve in cves:
        cve_id = str(cve.get("cveId", "Unknown CVE"))
        unique.setdefault(cve_id, {
            "cveId": cve_id, "score": cve.get("score"), "severity": cve.get("severity"),
        })
    return sorted(
        unique.values(),
        key=lambda c: (c["score"] is None, -(c["score"] or 0), c["cveId"]),
    )


def _cve_label(cve: Dict[str, Any]) -> str:
    score, severity = cve.get("score"), cve.get("severity")
    if score is None:
        return f"{cve['cveId']} (score: N/A)"
    return f"{cve['cveId']} ({score} {severity})" if severity else f"{cve['cveId']} ({score})"


def _item_name(item: Dict[str, Any]) -> str:
    name = item.get("name") or "Unnamed item"
    group = item.get("group")
    return f"{group}/{name}" if group else str(name)


def build_short_report(
    sbom: ParsedSBOM, results: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Summarize CVEs at the SBOM roots and the items directly below them.

    Args:
        sbom: The parsed SBOM the results were produced from.
        results: Matcher findings for the same SBOM snapshot.

    Returns:
        One entry per root with CVEs on or below it, each listing its children
        with CVEs on or below them.
    """
    ids_by_item = {id(c.raw_data): cid for cid, c in sbom.components.items()}
    own: Dict[str, List[Dict[str, Any]]] = {}
    for finding in results:
        cid = ids_by_item.get(id(finding["item"]))
        if cid is not None:
            own.setdefault(cid, []).extend(finding.get("cves", []))
    children: Dict[str, List[str]] = {cid: [] for cid in sbom.components}
    for cid, component in sbom.components.items():
        for parent_id in component.parent_ids:
            if parent_id in children:
                children[parent_id].append(cid)

    def cves_at_or_below(start: str) -> List[Dict[str, Any]]:
        seen, queue, found = {start}, deque([start]), []
        while queue:
            cid = queue.popleft()
            found.extend(own.get(cid, []))
            for child in children[cid]:
                if child not in seen:
                    seen.add(child)
                    queue.append(child)
        return _cve_summary(found)

    def entry(cid: str, cves: List[Dict[str, Any]]) -> Dict[str, Any]:
        component = sbom.components[cid]
        return {
            "id": cid, "name": _item_name(component.raw_data),
            "version": component.version, "cves": cves,
        }

    report = []
    for cid, component in sbom.components.items():
        is_root = cid in sbom.root_ids or not component.parent_ids & sbom.components.keys()
        if not is_root:
            continue
        cves = cves_at_or_below(cid)
        if not cves:
            continue
        below = [(child, cves_at_or_below(child)) for child in children[cid]]
        report.append({
            **entry(cid, cves),
            "children": [entry(child, child_cves) for child, child_cves in below if child_cves],
        })
    return report


_STYLE = (
    "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1e293b}"
    "table{border-collapse:collapse;margin:8px 0 20px;width:100%}"
    "th,td{border:1px solid #cbd5e1;padding:6px 8px;text-align:left;vertical-align:top}"
    "th{background:#f1f5f9}.meta{color:#475569}h2{margin-top:28px}"
)


def _html_page(title: str, meta: Dict[str, str], body: List[str]) -> str:
    return "\n".join([
        "<!DOCTYPE html>", "<html lang=\"en\">", "<head>", "<meta charset=\"utf-8\">",
        f"<title>{escape(title)}</title>", f"<style>{_STYLE}</style>", "</head>", "<body>",
        f"<h1>{escape(title)}</h1>",
        f"<p class=\"meta\">Generated: {escape(meta['generated'])}<br>"
        f"SBOM: {escape(meta['sbom'])}<br>CVE: {escape(meta['cve'])}</p>",
        *body, "</body>", "</html>", "",
    ])


def _full_html(results: List[Dict[str, Any]], meta: Dict[str, str]) -> str:
    total = sum(len(f.get("cves", [])) for f in results)
    body = [f"<p>Vulnerable items: {len(results)} | Matching CVEs: {total}</p>"]
    if not results:
        body.append("<p>No vulnerabilities matched the SBOM components.</p>")
    for finding in results:
        item = finding.get("item", {})
        version = item.get("version") or item.get("versionInfo") or ""
        body.append(f"<h2>{escape(_item_name(item))} {escape(str(version))}</h2>")
        if item.get("purl"):
            body.append(f"<p>PURL: {escape(str(item['purl']))}</p>")
        body.append("<table><tr><th>CVE</th><th>Score</th><th>Severity</th><th>Title</th></tr>")
        for cve in finding.get("cves", []):
            score = cve.get("score")
            body.append(
                f"<tr><td>{escape(str(cve.get('cveId', '')))}</td>"
                f"<td>{'N/A' if score is None else escape(str(score))}</td>"
                f"<td>{escape(str(cve.get('severity') or ''))}</td>"
                f"<td>{escape(str(cve.get('title') or ''))}</td></tr>"
            )
        body.append("</table>")
        paths = finding.get("lineage_paths") or []
        body.append("<p>Path to root:</p><ul>")
        if not paths:
            body.append("<li>(Root item)</li>")
        for path in paths:
            chain = [_item_name(item)] + [_item_name(parent) for parent in path]
            body.append(f"<li>{escape(' -> '.join(chain))}</li>")
        body.append("</ul>")
    return _html_page("pysbomcve Full Report", meta, body)


def _short_html(short: List[Dict[str, Any]], meta: Dict[str, str]) -> str:
    def cve_cell(cves: List[Dict[str, Any]]) -> str:
        return "<br>".join(escape(_cve_label(cve)) for cve in cves)

    body = []
    if not short:
        body.append("<p>No SBOM items have CVEs on or below them.</p>")
    for root in short:
        body.append(
            f"<h2>Root: {escape(root['name'])} {escape(root['version'] or '')}</h2>"
            f"<p>All CVEs in this root ({len(root['cves'])}):<br>{cve_cell(root['cves'])}</p>"
            "<table><tr><th>Item below root</th><th>Version</th>"
            "<th>CVEs in this item and below</th></tr>"
        )
        for child in root["children"]:
            body.append(
                f"<tr><td>{escape(child['name'])}</td><td>{escape(child['version'] or '')}</td>"
                f"<td>{cve_cell(child['cves'])}</td></tr>"
            )
        body.append("</table>")
    return _html_page("pysbomcve Short Report", meta, body)


# pylint: disable=too-many-arguments
def render_report(
    sbom: ParsedSBOM,
    results: List[Dict[str, Any]],
    *,
    fmt: str = "json",
    short: bool = False,
    sbom_path: str = "",
    cve_path: str = "",
    indent: Optional[int] = 2,
    generated_at: Optional[datetime] = None,
) -> str:
    """Render the full or short report as JSON or HTML text.

    JSON reports are an object with ``generatedAt`` (ISO 8601 with UTC offset),
    ``report`` ("full" or "short"), ``sbom``, ``cve``, and ``items``: the vulnerable
    items for a full report, or the roots for a short report.

    Args:
        sbom: The parsed SBOM the results were produced from.
        results: Matcher findings for the same SBOM snapshot.
        fmt: "json" or "html".
        short: Produce the short root/child CVE summary instead of all findings.
        sbom_path: SBOM source recorded in the report.
        cve_path: CVE source recorded in the report.
        indent: JSON indentation.
        generated_at: Report time; defaults to the current local time.

    Returns:
        The report text.
    """
    if fmt not in REPORT_FORMATS:
        raise ValueError(f"Unsupported report format: {fmt}")
    stamp = (generated_at or datetime.now()).astimezone()
    items = build_short_report(sbom, results) if short else results
    if fmt == "json":
        return json.dumps({
            "generatedAt": stamp.isoformat(timespec="seconds"),
            "report": "short" if short else "full",
            "sbom": sbom_path, "cve": cve_path, "items": items,
        }, indent=indent)
    meta = {
        "generated": f"{stamp:%Y-%m-%d %H:%M:%S} (UTC{stamp:%z})",
        "sbom": sbom_path, "cve": cve_path,
    }
    return _short_html(items, meta) if short else _full_html(items, meta)
