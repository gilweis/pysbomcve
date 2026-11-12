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
  - Supports single CVE files, bundled CVE lists, and .directories of CVE records
- **Lineage Tracing to Root**:
  - For every vulnerable component identified, the output includes all upper items in the SBOM tree from its immediate parent up to the root application.
- **Accurate Version & Product Matching**:
  - Evaluates SemVer, PEP 440, version ranges (`lessThan`, `lessThanOrEqual`), exact versions, wildcards (`*`), and explicit unaffected overrides.
  - Matches across package names, products, vendors, PURLs, and CPEs.
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
| `--out` | `-o` | No | Path to the output JSON file to save the scan results. |
| `--indent` | | No | JSON indentation level for console/file output (default: `2`). |
| `--fail-on-cve` | | No | Exits with status code `1` if any vulnerabilities are found (useful in CI/CD). |

### Example CLI Command

Run using the provided real-world examples:

```bash
python -m pysbomcve --sbom examples/sbom.json --cve examples/cve.json -o results.json
```

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
  Directory scans read JSON files directly in the selected folder, not subfolders.
- Scan for vulnerable components.
- View results in three modes: **Combined** (summary + raw JSON), **Summary**, and **JSON**.
- Click **Graphical Results...** after scanning to open a separate graph window.
  Each affected item connects to its matching CVEs and to every ancestor path
  (immediate parent through root), with named nodes for each SBOM item.
- CVE cards show the CVE ID and descriptions. Double-click a card to open its
  complete details, including the raw CVE record, in a read-only dialog.
- Use horizontal and vertical scrollbars for large graphs and CVE details.
  In the graph, the mouse wheel scrolls vertically; Shift+wheel scrolls horizontally.
- Use **Zoom in**, **Zoom out**, and **Reset zoom** in the graph window to resize
  the graph and its labels. Drag with the left mouse button to pan, or use
  Ctrl+mouse wheel to zoom around the pointer.
- Save the results to a file or clear the view.

The underlying matching logic is the same as the CLI; the GUI simply calls `match_sbom_cve` and formats the output for display.

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
