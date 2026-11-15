"""Vulnerability matching engine between SBOM components and CVE records.

This module coordinates matching between SBOM items (CycloneDX or SPDX) and CVE JSON 5.0
records, returning vulnerable components along with matching CVE details and their
complete lineage of upper items up to the SBOM root.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union
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


def extract_purl_namespace(purl: Optional[str]) -> Optional[str]:
    """Extract the namespace (group/scope) from a Package URL (purl).

    Example:
        'pkg:npm/%40angular/build@19.0.0' -> '@angular'
        'pkg:pypi/requests@2.28.0' -> None
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    parts = purl.split("?")[0].split("#")[0].split("/")
    if len(parts) < 3:
        return None
    return unquote("/".join(parts[1:-1])) or None


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


def npm_scope(component: SBOMComponent) -> Optional[str]:
    """Return an npm-style ``@scope`` from the group or PURL namespace, if any.

    Scopes are part of an npm package's identity: ``@angular/build`` and ``build``
    are different packages. Other namespaces, such as Maven groups, are not scopes.
    """
    for namespace in (component.group, extract_purl_namespace(component.purl)):
        if namespace and namespace.startswith("@"):
            return namespace
    return None


def _scope_identified(vendor: Optional[str], scope: Optional[str]) -> bool:
    """Whether a bare product name can refer to a scoped package.

    A product name alone does not identify a scoped package, so a known vendor
    must correspond to the scope (e.g. vendor "angular" for ``@angular``).
    """
    if not scope or not vendor:
        return True
    return _token_match(normalize_identifier(vendor), normalize_identifier(scope))


def _matches_package_or_product(
    comp_name_norm: str,
    purl_name_norm: str,
    affected: CVEAffectedProduct,
    scope: Optional[str] = None,
) -> bool:
    """Check if component name or purl matches package_name or product in CVE."""
    # Check direct package_name match if given in CVE
    if affected.package_name:
        aff_pkg_norm = normalize_identifier(affected.package_name)
        names = (comp_name_norm, purl_name_norm)
        if scope:
            names += (normalize_identifier(f"{scope}/{comp_name_norm}"),)
        if aff_pkg_norm in names:
            return True
        if ":" in aff_pkg_norm and aff_pkg_norm.split(":")[-1] in names:
            return True

    # Product names must equal the item or PURL name exactly (after normalization).
    if affected.product and _scope_identified(affected.vendor, scope):
        aff_prod_norm = normalize_identifier(affected.product)
        if aff_prod_norm in (comp_name_norm, purl_name_norm):
            return True

    return False


def _matches_cpe(
    comp_cpe: Optional[str],
    comp_name_norm: str,
    purl_name_norm: str,
    affected_cpes: List[str],
    scope: Optional[str] = None,
) -> bool:
    """Check if component matches any CPE listed in the affected entry."""
    for aff_cpe in affected_cpes:
        aff_vendor, aff_prod = extract_cpe_vendor_product(aff_cpe)
        if (
            aff_prod
            and normalize_identifier(aff_prod) in (comp_name_norm, purl_name_norm)
            and _scope_identified(aff_vendor, scope)
        ):
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

    Compares package names, products, vendors, PURLs, and CPEs. For npm scoped
    packages, a bare product name only matches when the CVE vendor (if any)
    corresponds to the scope; ``@scope/name`` package names always match.

    Args:
        component: SBOMComponent from the parsed SBOM.
        affected: CVEAffectedProduct from the CVE record.

    Returns:
        True if the component represents the affected product, False otherwise.
    """
    comp_name_norm = normalize_identifier(component.name)
    purl_name = extract_purl_name(component.purl)
    purl_name_norm = normalize_identifier(purl_name) if purl_name else ""
    scope = npm_scope(component)

    if _matches_package_or_product(
        comp_name_norm, purl_name_norm, affected, scope
    ):
        return True

    if affected.cpes and _matches_cpe(
        component.cpe, comp_name_norm, purl_name_norm, affected.cpes, scope
    ):
        return True

    return False


class _CVEIndex:
    """Select candidates by exact package, product, and CPE names."""

    # pylint: disable=too-few-public-methods
    def __init__(
        self, records: List[CVERecord], progress: Optional[Callable[[str], None]]
    ) -> None:
        self._names: Dict[str, Set[int]] = {}
        for index, record in enumerate(records):
            for affected in record.affected:
                self._add_name(affected.package_name, index)
                self._add_name(affected.product, index)
                if affected.package_name and ":" in affected.package_name:
                    self._add_name(normalize_identifier(affected.package_name).split(":")[-1],
                                   index)
                for cpe in affected.cpes:
                    self._add_name(extract_cpe_vendor_product(cpe)[1], index)
            if progress and ((index + 1) % 1000 == 0 or index + 1 == len(records)):
                progress(f"Indexing CVEs: {index + 1:,}/{len(records):,} records...")

    def _add_name(self, name: Optional[str], index: int) -> None:
        if name is not None:
            self._names.setdefault(normalize_identifier(name), set()).add(index)

    def candidates(self, component: SBOMComponent) -> List[int]:
        """Return candidate positions in the original CVE order."""
        name = normalize_identifier(component.name)
        candidates: Set[int] = set()
        scope = npm_scope(component)
        for key in (
            name, normalize_identifier(extract_purl_name(component.purl)),
            normalize_identifier(extract_cpe_vendor_product(component.cpe)[1]),
            normalize_identifier(f"{scope}/{name}") if scope else "",
        ):
            candidates.update(self._names.get(key, ()))
        return sorted(candidates)


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
        self, parsed_sbom: ParsedSBOM, cve_records: List[CVERecord],
        *, progress: Optional[Callable[[str], None]] = None,
    ) -> List[Dict[str, Any]]:
        """Find all SBOM components that have one or more matching CVEs.

        For each matching component, gathers:
        - The full component information from the SBOM.
        - All matching CVE details.
        - The complete list and paths of upper items in the tree up to the SBOM root.

        Args:
            parsed_sbom: ParsedSBOM instance containing components and dependency graph.
            cve_records: List of parsed CVERecord instances.
            progress: Optional callback receiving indexing and component progress.

        Returns:
            List of matching item dictionaries.
        """
        results: List[Dict[str, Any]] = []
        if progress:
            progress(f"Indexing {len(cve_records):,} CVE records...")
        index = _CVEIndex(cve_records, progress)
        total = len(parsed_sbom.components)
        for completed, (cid, comp) in enumerate(parsed_sbom.components.items(), 1):
            if progress:
                progress(f"Matching components: {completed:,}/{total:,}...")
            candidates = [cve_records[position] for position in index.candidates(comp)]
            matching_cves = self.match_component(comp, candidates)
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
