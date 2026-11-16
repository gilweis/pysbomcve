# pysbomcve

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Code Quality: Pylint 10/10](https://img.shields.io/badge/Pylint-10.00%2F10-brightgreen.svg)](https://pylint.org/)

**pysbomcve** is a Python library and command-line tool that matches CVE vulnerabilities against software components in a Software Bill of Materials (SBOM). It automatically traces and includes the complete lineage of upper ancestor items in the dependency tree all the way to the root of the SBOM.

---

## Features

- **SBOM Formats Supported**:
  - **CycloneDX JSON** (v1.4, v1.5, v1.6)
  - **SPDX JSON** (v2.2, v2.3)
- **CVE Format Supported**:
  - **CVE JSON 5.0 / 5.1** (Official [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) schema)
  - Supports single CVE files, bundled CVE lists, and directories of CVE records (searched recursively, including subfolders)
- **Lineage Tracing to Root**:
  - For every vulnerable component identified, the output includes all upper items in the SBOM tree from its immediate parent up to the root application.
- **Accurate Version & Product Matching**:
  - Evaluates SemVer, PEP 440, version ranges (`lessThan`, `lessThanOrEqual`), exact versions, wildcards (`*`), and explicit unaffected overrides.
  - Matches across package names, products, vendors, PURLs, and CPEs. For npm
    scoped packages (`@scope/name`, from the SBOM group or PURL namespace), a bare
    CVE product or CPE product name only matches when the CVE vendor is absent or
    corresponds to the scope, so `@angular/build` does not match SUSE's `build`;
    a CVE package name of `@scope/name` always matches. Other groups, such as Maven
    namespaces, are not treated as vendors.
  - Product names match only when they equal the item or PURL name exactly
    (ignoring case and `_`/`-`): CVE product `log4j` does not match `log4j-core`,
    and product `Controller` does not match `abort-controller`.
- **GUI-Ready Architecture**:
  - Clean separation between core matching algorithms, parsers, and presentation logic, making it trivial to integrate with future desktop GUIs (Tkinter, PyQt) or web frontends.
- **Strict Quality**:
  - Full type annotations and docstrings.
  - 100% test coverage for core matching logic.
  - Passes Pylint with a **10.00 / 10** rating.

---

## Installation

### Prerequisites

- Python 3.8 or higher
- `packaging >= 20.0`

### Install from Source

```bash
git clone https://github.com/gilweis/pysbomcve.git
cd pysbomcve
pip install -r requirements.txt
pip install -e .
```

---

## Command-Line Usage

The console application provides named parameters using standard `argparse` conventions:

```bash
python -m pysbomcve --sbom <path-to-sbom.json> --cve <path-to-cve.json> [--out <path-to-results.json>]
```

### CLI Parameters

| Parameter | Shorthand | Required | Description |
|-----------|-----------|----------|-------------|
| `--sbom` | | CLI mode | Path to the SBOM JSON file (CycloneDX or SPDX format). |
| `--cve` | | CLI mode | Path to the CVE JSON 5.0 file, directory, or array file. |
| `--gui` | | No | Launch the desktop GUI instead of CLI matching. |
| `--examples-dir` | | No | Folder for the GUI's example files; requires `--gui`. |
| `--out` | `-o` | No | Path to the output file to save the report. |
| `--outform` | | No | Report format: `html` (default) or `json`. Used for `--out` and the printed report. |
| `--full` | | No | Full report: every vulnerable item with its complete CVE records and paths to the root. Without it, the short report is produced. |
| `--short` | | No | Short report (the default): the SBOM tree down to `--depth` levels, each item listing every CVE ID and score found in that item or anywhere below it. Items with no CVEs on or below them are omitted. Cannot be combined with `--full`. |
| `--depth` | | No | Number of tree levels in the short report, from `1` (roots only) to the SBOM's maximum depth. Default: the maximum depth (the whole tree). Not allowed with `--full`. |
| `--indent` | | No | JSON indentation level for console/file output (default: `2`). |
| `--fail-on-cve` | | No | Exits with status code `1` if any vulnerabilities are found (useful in CI/CD). |

### Example CLI Command

Run using the provided real-world examples:

```bash
# Short HTML report of the whole tree (the default)
python -m pysbomcve --sbom examples/sbom.json --cve examples/cve.json -o report.html
# Short JSON report with two tree levels
python -m pysbomcve --sbom examples/sbom.json --cve examples/cve.json --depth 2 --outform json -o report.json
# Full JSON report
python -m pysbomcve --sbom examples/sbom.json --cve examples/cve.json --full --outform json -o results.json
```

Every report records when it was generated (local time with UTC offset), shown
at the top of HTML reports. The short HTML report draws the SBOM tree with solid
connector lines, like a file explorer.

Reports show every CVSS version a CVE record has (4.0, 3.1, 3.0, 2.0), e.g.
`CVE-2014-0160 (CVSS 3.1: 7.5 HIGH | CVSS 2.0: 5.0 MEDIUM)`; when several metrics
give the same version (e.g. from the CNA and an ADP), the highest is shown. In
HTML reports, each CVE ID is colored by its highest score's severity and each
version by its own severity: CRITICAL dark red and bold, HIGH red, MEDIUM orange;
LOW and unscored CVEs use the normal text color. Scores without a severity get
their version's official rating: CVSS 3.x/4.0 9.0-10.0 CRITICAL, 7.0-8.9 HIGH,
4.0-6.9 MEDIUM, 0.1-3.9 LOW; CVSS 2.0 (which has no CRITICAL) 7.0-10.0 HIGH,
4.0-6.9 MEDIUM, 0.0-3.9 LOW. JSON reports are an object:
`{"generatedAt": "2026-11-15T16:05:09+02:00", "report": "full" | "short", "sbom": ..., "cve": ..., "items": [...]}`.
For a full report, `items` is the list of vulnerable items with their complete CVE
records and paths to the root. A short report also records `depth`, and `items`
is a list of roots, each with `id`, `name` (`group/name` when the item has a
group), `version`, `cves` (`cveId`, `score` and `severity` of the highest score,
`scores` by CVSS version, deduplicated and sorted by descending score), and, when
items with CVEs are listed below it, `children` with the same fields. Full-report
CVE records also include `scores`, keyed by version (`"4.0"`, `"3.1"`, `"3.0"`,
`"2.0"`), each with `score`, `severity`, and `vector`.
An item shared by several parents appears under each of them; dependency cycles
stop at the repeated item.

---

## Desktop GUI

The project includes a ready‑to‑use desktop GUI built with **Tkinter**.  
Run the GUI with the `--gui` flag (or the dedicated entry point `pysbomcve-gui`).

```bash
python -m pysbomcve --gui
# or
pysbomcve-gui
```

To configure the **Load Example Files** button, supply a folder containing
`sbom.json` and `cve.json`:

```bash
python -m pysbomcve --gui --examples-dir "C:\path\to\examples"
# or
pysbomcve-gui --examples-dir "C:\path\to\examples"
```

Without this option, the GUI uses the `examples` folder next to the package.
Relative paths are resolved from the working directory. Missing example files
are reported without changing the existing input paths.

The GUI lets you:

- Select an SBOM JSON file and either a CVE JSON file or a folder of CVE records.
  Directory scans read every `.json` file in the selected folder and all its subfolders;
  files that are not valid CVE JSON are skipped.
- Scan for vulnerable components without blocking the GUI. An animated activity
  bar and elapsed-time status show SBOM loading, CVE file/record counts, indexing,
  component matching, and result preparation. Scan/input actions are temporarily
  disabled to prevent overlapping scans or changing inputs mid-scan. Failures
  are reported and leave the previous successful results available.
- Loaded CVE records are kept in memory and reused by later scans of the same CVE
  path, so changing only the SBOM does not re-read the CVE files. A single CVE file
  is re-read automatically if it changes; after changing files in a CVE folder,
  click **Reload CVEs + Scan**.
- View results in three modes: **Combined** (summary + raw JSON), **Summary**, and **JSON**.
- Click **Export Report...** after scanning to save the same report as the CLI:
  choose **Short** (the default) or **Full** and **JSON** or **HTML**, then pick the
  file. For a short report, set **Depth** from 1 (roots only) to the scanned SBOM's
  maximum depth; the default is the maximum depth.
- Click **CVEs SBOM...** after scanning to open a separate graph window.
  Each affected item connects to its matching CVEs and to every ancestor path
  (immediate parent through root), with named nodes for each SBOM item.
- CVE cards show the CVE ID, every CVSS version's score and severity, and the
  descriptions. In both graphs, CVE text uses the same colors as the HTML report:
  the CVE ID by its highest severity, and each `CVSS <version>: <score> <severity>`
  line by its own severity (CRITICAL dark red and bold, HIGH red, MEDIUM orange).
  Double-click a card to open its complete details, including the raw CVE record,
  in a read-only dialog.
- Both graphs have an optional inclusive **CVSS score range** filter. Enter a
  minimum and/or maximum from 0 to 10 and click **Apply**; a blank bound means
  0 or 10, respectively. CVEs without scores are hidden while filtering. Click
  **Clear** to show all CVEs again. Filtering changes only the graph view, not
  scan results or full item details.
- Choose the **CVSS version** used for the score filter: **Highest (any)** (the
  default, the highest score of any version) or 4.0, 3.1, 3.0, or 2.0. With a
  specific version, CVEs that have no score for it are hidden while a score range
  is applied. All versions' scores are always shown.
- Click **SBOM Tree...** to view every SBOM item, including items with no matched
  CVEs. Before a scan, select an SBOM file and open the tree without a CVE input.
  A warning and a banner indicate that the items have not been checked for CVEs;
  item details show `null` for CVEs rather than implying there are no matches.
  Arrows show dependencies; shared dependencies and cycles
  are retained without duplicating items. Each item shows its name (as
  `group/name` when the SBOM item has a group, in both graphs) and version.
  Items with displayed CVEs are red and list each CVE with all its CVSS scores; other items
  are blue, including items whose CVEs are hidden by the score filter.
  Single-click an item to highlight all its ancestor and descendant paths. Outlines
  and arrows show the selected item in purple, ancestors in green, descendants in
  orange, and items in both directions (cycles) in teal. Click the background to
  clear the selection. Double-click an item to see its complete SBOM data and all
  complete matched CVE records in a scrollable, read-only dialog. Dragging pans
  without opening details; highlighting remains visible when zooming.
  After a scan, check **Show only paths with CVEs** to hide everything except items
  on a root-to-leaf path through a vulnerable item: the vulnerable items, all their
  ancestors and all their descendants, plus only the arrows on those paths. The
  option uses the score-filtered CVEs, and both filters are disabled in the
  pre-scan preview.
  A statistics line shows the number of items, dependencies, root items, maximum
  depth (levels in the longest dependency chain, not following cycles), items with
  CVEs (count and percentage), and unique CVEs. CVE counts follow the score filter,
  show "not scanned" in the preview, and the number of displayed items is added
  while filtering hides items.
  The tree uses the last successful scan's snapshot, even if input paths change.
- Use horizontal and vertical scrollbars for large graphs and CVE details.
  In the graph, the mouse wheel scrolls vertically; Shift+wheel scrolls horizontally.
- Use **Zoom in**, **Zoom out**, and **Reset zoom** in the graph window to resize
  the graph and its labels. Drag with the left mouse button to pan, or use
  Ctrl+mouse wheel to zoom around the pointer.
- Save the results to a file or clear the view.

The underlying parsing and matching logic is the same as the CLI. The GUI retains
the parsed SBOM alongside the results to display the complete dependency tree.
Matching indexes CVE package names, product names, and CPE products to avoid
comparing every component with every CVE. Candidate CVEs still pass through the
same product/vendor and version checks, preserving result order and full details.
`parse_cve_records()` and `SBOMCVEMatcher.match()` accept an optional
`progress=callback` keyword; the callback receives human-readable status messages.

## Python Module API Usage

You can import and use `pysbomcve` directly in your Python code, backend services, or future GUI applications:

```python
from pysbomcve import match_sbom_cve

# Match using file paths
results = match_sbom_cve(
    sbom="examples/sbom.json",
    cve="examples/cve.json"
)

# Or match using in-memory dictionaries
# results = match_sbom_cve(sbom=my_sbom_dict, cve=my_cve_dict)

for finding in results:
    item = finding["item"]
    cves = finding["cves"]
    upper_items = finding["upper_items"]
    lineage_paths = finding["lineage_paths"]

    print(f"Component: {item['name']} ({item['version']})")
    print(f"  Vulnerabilities: {[c['cveId'] for c in cves]}")
    print(f"  Upper items count: {len(upper_items)}")
    for path in lineage_paths:
        print("  Path to root:", " -> ".join(p['name'] for p in path))
```

### Future GUI Integration

Because `match_sbom_cve` accepts file paths or raw dictionaries and returns pure Python dictionaries/JSON-serializable data, building a graphical interface is straightforward:

```python
# Conceptual GUI callback
def on_scan_clicked(sbom_path: str, cve_path: str, result_textbox):
    findings = match_sbom_cve(sbom_path, cve_path)
    result_textbox.clear()
    if not findings:
        result_textbox.insert("No vulnerabilities detected.")
        return

    for item in findings:
        comp_name = item["item"]["name"]
        comp_ver = item["item"]["version"]
        cve_ids = ", ".join(c["cveId"] for c in item["cves"])
        parents = " -> ".join(p.get("name") for p in item["upper_items"])
        result_textbox.insert(f"[{comp_name} @ {comp_ver}] : {cve_ids}\n  Lineage: {parents}\n\n")
```

---

## Example Folder

The `examples/` directory contains real-world test data ready for execution:

1. **`examples/sbom.json`**:
   - Standard CycloneDX JSON SBOM representing an e-commerce platform with a 3-tier dependency graph:
     - Root: `ecommerce-platform` (1.0.0)
     - Intermediate Service: `payment-gateway-client` (3.2.0)
       - Leaf: `requests` (2.28.0) — **Vulnerable to CVE-2023-32681**
     - Intermediate Service: `event-audit-service` (1.1.0)
       - Leaf: `log4j-core` (2.14.1) — **Vulnerable to CVE-2021-44228**
     - Safe Library: `cryptography` (41.0.5)

2. **`examples/sbom_spdx.json`**:
   - Standard SPDX 2.3 JSON SBOM with package definitions and relationship graphs.

3. **`examples/cve.json`**:
   - Real CVE JSON 5.0 records sourced from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5):
     - `CVE-2023-32681` (Requests Proxy-Authorization leak)
     - `CVE-2021-44228` (Log4j2 JNDI RCE)

---

## Example Result

### Console Summary Output

```text
======================================================================
                      pysbomcve Scan Report
======================================================================
SBOM: examples/sbom.json
CVE : examples/cve.json
Total vulnerable items found: 2
Total matching CVEs         : 2
======================================================================

Vulnerable Components:
[-] Component: requests @ 2.28.0
    PURL: pkg:pypi/requests@2.28.0
    Matched CVEs (1):
      * CVE-2023-32681 [Severity: MEDIUM, Score: 6.1]
        Title: Unintended leak of Proxy-Authorization header in requests
    Lineage to Root:
      Path 1: requests (2.28.0) -> payment-gateway-client (3.2.0) -> ecommerce-platform (1.0.0)
----------------------------------------------------------------------
[-] Component: log4j-core @ 2.14.1
    PURL: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    Matched CVEs (1):
      * CVE-2021-44228 [Severity: CRITICAL, Score: 10.0]
        Title: Remote code execution in Log4j2 JNDI lookup feature
    Lineage to Root:
      Path 1: log4j-core (2.14.1) -> event-audit-service (1.1.0) -> ecommerce-platform (1.0.0)
----------------------------------------------------------------------
```

### Result JSON Structure

Each matched item in the returned list contains:
1. `item`: The full information of the component from the SBOM.
2. `cves`: All matching CVE records and extracted metadata (score, severity, descriptions, references, problem types, raw record).
3. `upper_items`: All upper items in the SBOM tree from immediate parent to root.
4. `lineage_paths`: Ordered paths from parent to root.

```json
[
  {
    "item": {
      "type": "library",
      "bom-ref": "pkg:pypi/requests@2.28.0",
      "name": "requests",
      "version": "2.28.0",
      "description": "Python HTTP for Humans",
      "purl": "pkg:pypi/requests@2.28.0",
      "cpe": "cpe:2.3:a:psf:requests:2.28.0:*:*:*:*:*:*:*"
    },
    "cves": [
      {
        "cveId": "CVE-2023-32681",
        "state": "PUBLISHED",
        "title": "Unintended leak of Proxy-Authorization header in requests",
        "severity": "MEDIUM",
        "score": 6.1,
        "descriptions": [
          "Requests releases prior to 2.31.0 may leak Proxy-Authorization headers to destination servers during HTTPS redirects."
        ],
        "problemTypes": [
          "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        ],
        "references": [
          "https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56",
          "https://github.com/psf/requests/releases/tag/v2.31.0"
        ],
        "affected": [ ... ],
        "rawRecord": { ... }
      }
    ],
    "upper_items": [
      {
        "type": "library",
        "bom-ref": "pkg:pypi/payment-gateway-client@3.2.0",
        "name": "payment-gateway-client",
        "version": "3.2.0"
      },
      {
        "type": "application",
        "bom-ref": "pkg:generic/ecommerce-platform@1.0.0",
        "name": "ecommerce-platform",
        "version": "1.0.0"
      }
    ],
    "lineage_paths": [
      [
        {
          "type": "library",
          "bom-ref": "pkg:pypi/payment-gateway-client@3.2.0",
          "name": "payment-gateway-client",
          "version": "3.2.0"
        },
        {
          "type": "application",
          "bom-ref": "pkg:generic/ecommerce-platform@1.0.0",
          "name": "ecommerce-platform",
          "version": "1.0.0"
        }
      ]
    ]
  }
]
```

---

## Running Tests and Linting

### Unit Tests

Run the test suite using `pytest`:

```bash
pytest
```

### Code Quality (Pylint)

Check code quality with `pylint`:

```bash
pylint pysbomcve tests
```

Expected result:
```text
------------------------------------
Your code has been rated at 10.00/10
```

---

## License

This project is licensed under the [MIT License](LICENSE).
