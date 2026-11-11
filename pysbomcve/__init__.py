"""pysbomcve: Match CVE JSON 5.0 vulnerabilities against CycloneDX and SPDX SBOMs.

This package provides tools and programmatic APIs to find vulnerable components
within an SBOM, extracting matching CVE records and tracing dependency ancestry
all the way to the root of the SBOM graph.
"""

from pysbomcve.cve_parser import CVEAffectedProduct, CVERecord, parse_cve_records
from pysbomcve.gui import SBOMCVEApp, launch_gui
from pysbomcve.matcher import SBOMCVEMatcher, match_sbom_cve
from pysbomcve.sbom_parser import ParsedSBOM, SBOMComponent, parse_sbom
from pysbomcve.version_utils import is_version_vulnerable

__version__ = "0.1.0"
__all__ = [
    "match_sbom_cve",
    "SBOMCVEMatcher",
    "parse_sbom",
    "ParsedSBOM",
    "SBOMComponent",
    "parse_cve_records",
    "CVERecord",
    "CVEAffectedProduct",
    "is_version_vulnerable",
    "SBOMCVEApp",
    "launch_gui",
]
