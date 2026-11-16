"""Full and short scan reports in JSON or HTML, shared by the CLI and GUI.

The full report is the complete list of matcher findings. The short report (the
default) lists the SBOM tree down to a chosen depth (by default the whole tree),
each item with every CVE found in it or anywhere below it; items with no CVEs on
or below them are omitted.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime
from html import escape
import json
from typing import Any, Dict, Iterable, List, Optional, Set

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


_SEVERITY_CLASSES = {"CRITICAL": "sev-critical", "HIGH": "sev-high", "MEDIUM": "sev-medium"}


def _severity_attr(cve: Dict[str, Any]) -> str:
    """Return an HTML class attribute coloring CRITICAL, HIGH, and MEDIUM CVEs."""
    css = _SEVERITY_CLASSES.get(str(cve.get("severity") or "").strip().upper())
    return f" class=\"{css}\"" if css else ""


def _item_name(item: Dict[str, Any]) -> str:
    name = item.get("name") or "Unnamed item"
    group = item.get("group")
    return f"{group}/{name}" if group else str(name)


def _children_map(sbom: ParsedSBOM) -> Dict[str, List[str]]:
    children: Dict[str, List[str]] = {cid: [] for cid in sbom.components}
    for cid, component in sbom.components.items():
        for parent_id in sorted(component.parent_ids):
            if parent_id in children:
                children[parent_id].append(cid)
    return children


def _root_ids(sbom: ParsedSBOM) -> List[str]:
    return [
        cid for cid, component in sbom.components.items()
        if cid in sbom.root_ids or not component.parent_ids & sbom.components.keys()
    ]


def sbom_max_depth(sbom: ParsedSBOM) -> int:
    """Return the number of levels in the longest dependency chain, not following cycles."""
    children = _children_map(sbom)
    depth: Dict[str, int] = {}
    on_stack: Set[str] = set()
    starts = [cid for cid in sbom.components if cid in sbom.root_ids]
    for start in starts + list(sbom.components):
        if start in depth:
            continue
        on_stack.add(start)
        stack = [(start, iter(children[start]))]
        while stack:
            cid, pending = stack[-1]
            child = next(pending, None)
            if child is None:
                stack.pop()
                on_stack.discard(cid)
                # Edges back into the current chain form cycles and are not followed.
                depth[cid] = 1 + max(
                    (depth[c] for c in children[cid] if c in depth), default=0
                )
            elif child not in depth and child not in on_stack:
                on_stack.add(child)
                stack.append((child, iter(children[child])))
    return max(depth.values(), default=0)


def build_short_report(
    sbom: ParsedSBOM, results: List[Dict[str, Any]], depth: Optional[int] = None
) -> List[Dict[str, Any]]:
    """Summarize CVEs for the top ``depth`` levels of the SBOM tree.

    Level 1 is the roots, level 2 the items directly below them, and so on. Each
    listed item shows every CVE found in it or anywhere below it; items with no
    CVEs on or below them are omitted. Items above the last level that have such
    items below them list them in ``children``.

    Args:
        sbom: The parsed SBOM the results were produced from.
        results: Matcher findings for the same SBOM snapshot.
        depth: Number of tree levels to include (at least 1); None (default)
            includes the whole tree. Values beyond the tree's depth also do.

    Returns:
        One entry per root with CVEs on or below it.
    """
    if depth is None:
        depth = max(sbom_max_depth(sbom), 1)
    if depth < 1:
        raise ValueError("Short report depth must be at least 1.")
    ids_by_item = {id(c.raw_data): cid for cid, c in sbom.components.items()}
    own: Dict[str, List[Dict[str, Any]]] = {}
    for finding in results:
        cid = ids_by_item.get(id(finding["item"]))
        if cid is not None:
            own.setdefault(cid, []).extend(finding.get("cves", []))
    children = _children_map(sbom)
    below_cache: Dict[str, List[Dict[str, Any]]] = {}

    def cves_at_or_below(start: str) -> List[Dict[str, Any]]:
        if start not in below_cache:
            seen, queue, found = {start}, deque([start]), []
            while queue:
                cid = queue.popleft()
                found.extend(own.get(cid, []))
                for child in children[cid]:
                    if child not in seen:
                        seen.add(child)
                        queue.append(child)
            below_cache[start] = _cve_summary(found)
        return below_cache[start]

    def entry(cid: str, level: int, path: Set[str]) -> Optional[Dict[str, Any]]:
        cves = cves_at_or_below(cid)
        if not cves:
            return None
        component = sbom.components[cid]
        item: Dict[str, Any] = {
            "id": cid, "name": _item_name(component.raw_data),
            "version": component.version, "cves": cves,
        }
        if level < depth:
            # Skip edges back to an item already on this path (dependency cycles).
            nested = (entry(child, level + 1, path | {child})
                      for child in children[cid] if child not in path)
            listed = [child for child in nested if child is not None]
            if listed:
                item["children"] = listed
        return item

    report = (entry(cid, 1, {cid}) for cid in _root_ids(sbom))
    return [root for root in report if root is not None]


_TREE_LINE = "linear-gradient(#64748b,#64748b)"
_STYLE = (
    "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1e293b}"
    "table{border-collapse:collapse;margin:8px 0 20px;width:100%}"
    "th,td{border:1px solid #cbd5e1;padding:6px 8px;text-align:left;vertical-align:top}"
    "th{background:#f1f5f9}.meta{color:#475569}h2{margin-top:28px}"
    ".sev-critical{color:#991b1b;font-weight:bold}.sev-high{color:#dc2626}"
    ".sev-medium{color:#ea580c}"
    # Tree guides: cells stretch to the row height and hide horizontal borders so
    # the vertical lines join across rows, like a file explorer tree.
    "td.tree{height:1px;padding:0 8px 0 0;border-top-style:hidden;border-bottom-style:hidden}"
    ".node{display:flex;height:100%;min-height:30px}"
    ".node>span{flex:none;width:22px}"
    ".node>.name{flex:1;width:auto;padding:6px 0 6px 4px;white-space:nowrap}"
    # A parent's line runs down from below its name to its children's connectors.
    f".node>.parent{{background:{_TREE_LINE} no-repeat 10px 100%/2px calc(100% - 26px)}}"
    f".pipe{{background:{_TREE_LINE} no-repeat 10px 0/2px 100%}}"
    f".tee{{background:{_TREE_LINE} no-repeat 10px 0/2px 100%,"
    f"{_TREE_LINE} no-repeat 10px 15px/12px 2px}}"
    f".elbow{{background:{_TREE_LINE} no-repeat 10px 0/2px 17px,"
    f"{_TREE_LINE} no-repeat 10px 15px/12px 2px}}"
)


def _html_page(title: str, meta: Dict[str, str], body: List[str]) -> str:
    return "\n".join([
        "<!DOCTYPE html>", "<html lang=\"en\">", "<head>", "<meta charset=\"utf-8\">",
        f"<title>{escape(title)}</title>", f"<style>{_STYLE}</style>", "</head>", "<body>",
        f"<h1>{escape(title)}</h1>",
        f"<p class=\"meta\">Generated: {escape(meta['generated'])}<br>"
        + (f"Depth: {escape(meta['depth'])}<br>" if "depth" in meta else "")
        + f"SBOM: {escape(meta['sbom'])}<br>CVE: {escape(meta['cve'])}</p>",
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
            sev = _severity_attr(cve)
            body.append(
                f"<tr><td{sev}>{escape(str(cve.get('cveId', '')))}</td>"
                f"<td{sev}>{'N/A' if score is None else escape(str(score))}</td>"
                f"<td{sev}>{escape(str(cve.get('severity') or ''))}</td>"
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
        return "<br>".join(
            f"<span{_severity_attr(cve)}>{escape(_cve_label(cve))}</span>" for cve in cves
        )

    def row(item: Dict[str, Any], level: int, guides: List[str]) -> str:
        spans = "".join(f"<span class=\"{guide}\"></span>" for guide in guides)
        name_class = "name parent" if item.get("children") else "name"
        return (
            f"<tr><td>{level}</td><td class=\"tree\"><div class=\"node\">{spans}"
            f"<span class=\"{name_class}\">{escape(item['name'])}</span></div></td>"
            f"<td>{escape(item['version'] or '')}</td><td>{cve_cell(item['cves'])}</td></tr>"
        )

    def rows(items: List[Dict[str, Any]], level: int, open_above: List[bool]) -> List[str]:
        lines = []
        for position, item in enumerate(items):
            last = position == len(items) - 1
            # A vertical line continues for each ancestor that has later siblings.
            guides = ["pipe" if is_open else "" for is_open in open_above]
            lines.append(row(item, level, guides + ["elbow" if last else "tee"]))
            lines.extend(rows(item.get("children", []), level + 1, open_above + [not last]))
        return lines

    body = []
    if not short:
        body.append("<p>No SBOM items have CVEs on or below them.</p>")
    for root in short:
        body.append(
            f"<h2>Root: {escape(root['name'])} {escape(root['version'] or '')}</h2>"
            "<table><tr><th>Level</th><th>Item</th><th>Version</th>"
            "<th>CVEs in this item and below</th></tr>"
        )
        body.append(row(root, 1, []))
        body.extend(rows(root.get("children", []), 2, []))
        body.append("</table>")
    return _html_page("pysbomcve Short Report", meta, body)


# pylint: disable=too-many-arguments
def render_report(
    sbom: ParsedSBOM,
    results: List[Dict[str, Any]],
    *,
    fmt: str = "html",
    short: bool = True,
    sbom_path: str = "",
    cve_path: str = "",
    indent: Optional[int] = 2,
    generated_at: Optional[datetime] = None,
    depth: Optional[int] = None,
) -> str:
    """Render the full or short report as JSON or HTML text.

    JSON reports are an object with ``generatedAt`` (ISO 8601 with UTC offset),
    ``report`` ("full" or "short"), ``sbom``, ``cve``, and ``items``: the vulnerable
    items for a full report, or the roots for a short report. Short reports also
    record ``depth``.

    Args:
        sbom: The parsed SBOM the results were produced from.
        results: Matcher findings for the same SBOM snapshot.
        fmt: "html" (default) or "json".
        short: Produce the short tree CVE summary (default) instead of all findings.
        sbom_path: SBOM source recorded in the report.
        cve_path: CVE source recorded in the report.
        indent: JSON indentation.
        generated_at: Report time; defaults to the current local time.
        depth: Tree levels in a short report (1 = roots only, 2 = roots and
            the items directly below them); None (default) means the SBOM's
            maximum depth.

    Returns:
        The report text.
    """
    if fmt not in REPORT_FORMATS:
        raise ValueError(f"Unsupported report format: {fmt}")
    stamp = (generated_at or datetime.now()).astimezone()
    if short and depth is None:
        depth = max(sbom_max_depth(sbom), 1)
    items = build_short_report(sbom, results, depth) if short else results
    if fmt == "json":
        header: Dict[str, Any] = {
            "generatedAt": stamp.isoformat(timespec="seconds"),
            "report": "short" if short else "full",
        }
        if short:
            header["depth"] = depth
        return json.dumps({
            **header, "sbom": sbom_path, "cve": cve_path, "items": items,
        }, indent=indent)
    meta = {
        "generated": f"{stamp:%Y-%m-%d %H:%M:%S} (UTC{stamp:%z})",
        "sbom": sbom_path, "cve": cve_path,
    }
    if short:
        meta["depth"] = f"{depth} level(s)"
    return _short_html(items, meta) if short else _full_html(items, meta)
