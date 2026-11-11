"""Vulnerability matching engine between SBOM components and CVE records.

This module coordinates matching between SBOM items (CycloneDX or SPDX) and CVE JSON 5.0
records, returning vulnerable components along with matching CVE details and their
complete lineage of upper items up to the SBOM root.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import unquote

from pysbomcve.cve_parser import CVEAffectedProduct, CVERecord, parse_cve_records
from pysbomcve.sbom_parser import ParsedSBOM, SBOMComponent, parse_sbom
from pysbomcve.version_utils import is_version_vulnerable


def normalize_identifier(identifier: Optional[str]) -> str:
    """Normalize a package or product name for resilient comparison.

    Converts to lowercase, converts underscores to dashes, and strips non-alphanumeric
    leading/trailing characters.

    Args:
        identifier: The raw string identifier.

    Returns:
        Cleaned identifier string.
    """
    if not identifier:
        return ""
    cleaned = identifier.lower().replace("_", "-").strip()
    cleaned = re.sub(r"[^\w\-\./:]+", "", cleaned)
    return cleaned


def extract_purl_name(purl: Optional[str]) -> Optional[str]:
    """Extract package name from a Package URL (purl).

    Example:
        'pkg:pypi/requests@2.28.0' -> 'requests'
        'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' -> 'log4j-core'

    Args:
        purl: The purl string.

    Returns:
        Extracted package name or None.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    # Strip query parameters and subpath
    purl_base = purl.split("?")[0].split("#")[0]
    # Strip version
    purl_no_version = purl_base.split("@")[0]
    # Extract name part after last slash
    parts = purl_no_version.split("/")
    if parts:
        raw_name = parts[-1]
        return unquote(raw_name)
    return None


def extract_cpe_vendor_product(cpe: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Extract vendor and product from a CPE 2.3 or 2.2 URI.

    Example:
        'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*' -> ('apache', 'log4j')

    Args:
        cpe: CPE string.

    Returns:
        Tuple of (vendor, product) or (None, None).
    """
    if not cpe:
        return None, None
    parts = cpe.split(":")
    if len(parts) >= 5:
        # CPE 2.3 format: cpe:2.3:part:vendor:product:...
        vendor = parts[3] if parts[3] not in ("*", "-", "") else None
        product = parts[4] if parts[4] not in ("*", "-", "") else None
        return vendor, product
    return None, None


def _token_match(target: str, candidate: str) -> bool:
    """Check if target tokens match or appear in candidate tokens.

    Args:
        target: First normalized identifier.
        candidate: Second normalized identifier.

    Returns:
        True if significant overlap occurs.
    """
    if not target or not candidate:
        return False
    if target == candidate:
        return True

    target_tokens = set(re.findall(r"[a-z0-9]+", target))
    candidate_tokens = set(re.findall(r"[a-z0-9]+", candidate))

    if not target_tokens or not candidate_tokens:
        return False

    # Check if target is a subset or candidate is a subset
    if target_tokens.issubset(candidate_tokens) or candidate_tokens.issubset(target_tokens):
        return True

    return False


def _matches_package_or_product(
    comp_name_norm: str,
    purl_name_norm: str,
    comp_group: Optional[str],
    affected: CVEAffectedProduct,
) -> bool:
    """Check if component name or purl matches package_name or product in CVE."""
    # Check direct package_name match if given in CVE
    if affected.package_name:
        aff_pkg_norm = normalize_identifier(affected.package_name)
        if aff_pkg_norm in (comp_name_norm, purl_name_norm):
            return True
        if ":" in aff_pkg_norm and aff_pkg_norm.split(":")[-1] in (
            comp_name_norm,
            purl_name_norm,
        ):
            return True

    # Check product name match
    if affected.product:
        aff_prod_norm = normalize_identifier(affected.product)
        if aff_prod_norm in (comp_name_norm, purl_name_norm):
            return True
        if _token_match(aff_prod_norm, comp_name_norm):
            if not affected.vendor or not comp_group:
                return True
            aff_vend_norm = normalize_identifier(affected.vendor)
            comp_grp_norm = normalize_identifier(comp_group)
            if _token_match(aff_vend_norm, comp_grp_norm):
                return True

    return False


def _matches_cpe(
    comp_cpe: Optional[str],
    comp_name_norm: str,
    purl_name_norm: str,
    affected_cpes: List[str],
) -> bool:
    """Check if component matches any CPE listed in the affected entry."""
    for aff_cpe in affected_cpes:
        _, aff_prod = extract_cpe_vendor_product(aff_cpe)
        if aff_prod and normalize_identifier(aff_prod) in (comp_name_norm, purl_name_norm):
            return True
        if comp_cpe:
            _, comp_prod = extract_cpe_vendor_product(comp_cpe)
            if (
                aff_prod
                and comp_prod
                and normalize_identifier(aff_prod) == normalize_identifier(comp_prod)
            ):
                return True
    return False


def does_product_match(
    component: SBOMComponent, affected: CVEAffectedProduct
) -> bool:
    """Check if an SBOM component matches an affected product entry in a CVE.

    Compares package names, products, vendors, PURLs, and CPEs.

    Args:
        component: SBOMComponent from the parsed SBOM.
        affected: CVEAffectedProduct from the CVE record.

    Returns:
        True if the component represents the affected product, False otherwise.
    """
    comp_name_norm = normalize_identifier(component.name)
    purl_name = extract_purl_name(component.purl)
    purl_name_norm = normalize_identifier(purl_name) if purl_name else ""

    if _matches_package_or_product(
        comp_name_norm, purl_name_norm, component.group, affected
    ):
        return True

    if affected.cpes and _matches_cpe(
        component.cpe, comp_name_norm, purl_name_norm, affected.cpes
    ):
        return True

    return False


class SBOMCVEMatcher:
    """Matches SBOM components against CVE records."""

    def __init__(self) -> None:
        """Initialize the SBOMCVEMatcher."""

    def match_component(
        self, comp: SBOMComponent, cve_records: List[CVERecord]
    ) -> List[Dict[str, Any]]:
        """Find all CVEs matching a single SBOM component.

        Args:
            comp: The SBOMComponent to check.
            cve_records: List of candidate CVERecord instances.

        Returns:
            List of matching CVE dictionaries.
        """
        matching_cves: List[Dict[str, Any]] = []
        for cve in cve_records:
            is_cve_match = False
            for aff in cve.affected:
                if does_product_match(comp, aff) and is_version_vulnerable(
                    comp.version, aff.versions
                ):
                    is_cve_match = True
                    break
            if is_cve_match:
                matching_cves.append(cve.to_dict())
        return matching_cves

    def match(
        self, parsed_sbom: ParsedSBOM, cve_records: List[CVERecord]
    ) -> List[Dict[str, Any]]:
        """Find all SBOM components that have one or more matching CVEs.

        For each matching component, gathers:
        - The full component information from the SBOM.
        - All matching CVE details.
        - The complete list and paths of upper items in the tree up to the SBOM root.

        Args:
            parsed_sbom: ParsedSBOM instance containing components and dependency graph.
            cve_records: List of parsed CVERecord instances.

        Returns:
            List of matching item dictionaries.
        """
        results: List[Dict[str, Any]] = []

        for cid, comp in parsed_sbom.components.items():
            matching_cves = self.match_component(comp, cve_records)
            if matching_cves:
                upper_items = parsed_sbom.get_upper_items(cid)
                lineage_paths = parsed_sbom.get_lineage_paths(cid)

                results.append(
                    {
                        "item": comp.to_dict(),
                        "cves": matching_cves,
                        "upper_items": upper_items,
                        "lineage_paths": lineage_paths,
                    }
                )

        return results


def match_sbom_cve(
    sbom: Union[str, Path, Dict[str, Any]],
    cve: Union[str, Path, Dict[str, Any], List[Any]],
) -> List[Dict[str, Any]]:
    """Convenience function to match an SBOM against CVE records.

    Parses the SBOM and CVE inputs and performs matching.

    Args:
        sbom: File path or dictionary of CycloneDX or SPDX SBOM.
        cve: File path, directory path, dictionary, or list of CVE JSON 5.0 records.

    Returns:
        List of vulnerable component dictionaries with CVE info and upper items.
    """
    parsed_sbom = parse_sbom(sbom)
    cve_records = parse_cve_records(cve)
    matcher = SBOMCVEMatcher()
    return matcher.match(parsed_sbom, cve_records)
