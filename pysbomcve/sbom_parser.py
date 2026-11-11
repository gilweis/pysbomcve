"""SBOM parser supporting CycloneDX and SPDX JSON formats.

This module provides classes and functions to parse Software Bill of Materials (SBOM)
files in CycloneDX JSON and SPDX JSON formats, building a component graph and
computing dependency lineage chains from any item up to the root of the SBOM.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union


# pylint: disable=too-many-instance-attributes
class SBOMComponent:
    """Represents a component or package within an SBOM.

    Attributes:
        component_id: Unique identifier for the component (e.g. bom-ref, SPDXID).
        name: Name of the component.
        version: Version string of the component.
        group: Vendor, group, or namespace of the component.
        purl: Package URL (purl) identifier if available.
        cpe: Common Platform Enumeration (CPE) string if available.
        raw_data: Complete dictionary containing all original SBOM information.
        parent_ids: Set of unique identifiers for direct parent components.
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        component_id: str,
        name: str,
        version: str,
        group: Optional[str] = None,
        purl: Optional[str] = None,
        cpe: Optional[str] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize an SBOM component.

        Args:
            component_id: Unique identifier for the component.
            name: Component name.
            version: Component version string.
            group: Optional vendor or group namespace.
            purl: Optional Package URL string.
            cpe: Optional Common Platform Enumeration string.
            raw_data: Optional complete raw component dictionary from the SBOM.
        """
        self.component_id: str = component_id
        self.name: str = name
        self.version: str = version
        self.group: Optional[str] = group
        self.purl: Optional[str] = purl
        self.cpe: Optional[str] = cpe
        if raw_data is not None:
            self.raw_data: Dict[str, Any] = raw_data
        else:
            self.raw_data = {
                "name": self.name,
                "version": self.version,
                "id": self.component_id,
            }
            if self.group:
                self.raw_data["group"] = self.group
            if self.purl:
                self.raw_data["purl"] = self.purl
            if self.cpe:
                self.raw_data["cpe"] = self.cpe
        self.parent_ids: Set[str] = set()

    def to_dict(self) -> Dict[str, Any]:
        """Return the complete component information as a dictionary.

        Returns:
            Dictionary containing the full component data from the SBOM.
        """
        return self.raw_data

    def __repr__(self) -> str:
        """Return developer-friendly string representation."""
        return (
            f"SBOMComponent(id={self.component_id!r}, name={self.name!r}, "
            f"version={self.version!r})"
        )


class ParsedSBOM:
    """Holds parsed SBOM components, root elements, and dependency graph.

    Attributes:
        format_type: Format name ('cyclonedx' or 'spdx').
        root_ids: Set of IDs representing root application(s) or top-level elements.
        components: Mapping of component ID to SBOMComponent.
    """

    def __init__(self, format_type: str) -> None:
        """Initialize a ParsedSBOM instance.

        Args:
            format_type: Format of the SBOM ('cyclonedx' or 'spdx').
        """
        self.format_type: str = format_type
        self.root_ids: Set[str] = set()
        self.components: Dict[str, SBOMComponent] = {}

    def add_component(self, comp: SBOMComponent, is_root: bool = False) -> None:
        """Register a component in the SBOM graph.

        Args:
            comp: The SBOMComponent instance to add.
            is_root: Whether this component represents a root of the SBOM.
        """
        self.components[comp.component_id] = comp
        if is_root:
            self.root_ids.add(comp.component_id)

    def add_dependency(self, parent_id: str, child_id: str) -> None:
        """Register a parent-child dependency relationship.

        Args:
            parent_id: ID of the parent/enclosing component.
            child_id: ID of the depended-upon/child component.
        """
        if child_id in self.components and parent_id != child_id:
            self.components[child_id].parent_ids.add(parent_id)

    def get_lineage_paths(self, component_id: str) -> List[List[Dict[str, Any]]]:
        """Compute all dependency paths from the component's parent up to the root.

        Uses depth-first search with cycle prevention.

        Args:
            component_id: The ID of the component whose ancestry to trace.

        Returns:
            List of paths, where each path is a list of component dictionaries
            ordered from immediate parent up to the root component.
        """
        if component_id not in self.components:
            return []

        paths: List[List[str]] = []

        def _dfs(current_id: str, current_path: List[str], visited: Set[str]) -> None:
            comp = self.components.get(current_id)
            if not comp or not comp.parent_ids:
                if current_path:
                    paths.append(list(current_path))
                return

            reached_any_parent = False
            for parent_id in sorted(comp.parent_ids):
                if parent_id in visited or parent_id not in self.components:
                    continue
                reached_any_parent = True
                _dfs(
                    parent_id,
                    current_path + [parent_id],
                    visited | {parent_id},
                )

            if not reached_any_parent and current_path:
                paths.append(list(current_path))

        _dfs(component_id, [], {component_id})

        result_paths: List[List[Dict[str, Any]]] = []
        for path in paths:
            path_dicts = [
                self.components[pid].to_dict()
                for pid in path
                if pid in self.components
            ]
            if path_dicts:
                result_paths.append(path_dicts)

        return result_paths

    def get_upper_items(self, component_id: str) -> List[Dict[str, Any]]:
        """Return a deduplicated list of all upper items in the SBOM tree up to root.

        The list is ordered from closest ancestors (parents) to farthest (roots).

        Args:
            component_id: The ID of the component whose upper items are requested.

        Returns:
            List of component dictionaries for all upper items up to root.
        """
        if component_id not in self.components:
            return []

        upper_items: List[Dict[str, Any]] = []
        visited: Set[str] = {component_id}
        queue: List[str] = sorted(self.components[component_id].parent_ids)

        while queue:
            parent_id = queue.pop(0)
            if parent_id in visited or parent_id not in self.components:
                continue
            visited.add(parent_id)
            upper_items.append(self.components[parent_id].to_dict())
            for grand_parent_id in sorted(self.components[parent_id].parent_ids):
                if grand_parent_id not in visited:
                    queue.append(grand_parent_id)

        return upper_items


def _extract_cpe_from_ext_refs(external_refs: List[Dict[str, Any]]) -> Optional[str]:
    """Extract CPE string from SPDX external references list.

    Args:
        external_refs: List of external reference dictionaries.

    Returns:
        CPE string if found, otherwise None.
    """
    for ref in external_refs:
        ref_type = str(ref.get("referenceType", "")).lower()
        if "cpe" in ref_type:
            locator = ref.get("referenceLocator")
            if locator:
                return str(locator)
    return None


def _extract_purl_from_ext_refs(external_refs: List[Dict[str, Any]]) -> Optional[str]:
    """Extract PURL string from SPDX external references list.

    Args:
        external_refs: List of external reference dictionaries.

    Returns:
        PURL string if found, otherwise None.
    """
    for ref in external_refs:
        ref_type = str(ref.get("referenceType", "")).lower()
        if ref_type == "purl":
            locator = ref.get("referenceLocator")
            if locator:
                return str(locator)
    return None


def _extract_cyclonedx_root(metadata: Dict[str, Any]) -> Optional[SBOMComponent]:
    """Extract root component from CycloneDX metadata."""
    root_comp_data = metadata.get("component")
    if not root_comp_data or not isinstance(root_comp_data, dict):
        return None
    root_name = root_comp_data.get("name", "root")
    root_ver = root_comp_data.get("version", "")
    root_id = (
        root_comp_data.get("bom-ref")
        or root_comp_data.get("ref")
        or f"{root_name}@{root_ver}"
    )
    return SBOMComponent(
        component_id=root_id,
        name=root_name,
        version=root_ver,
        group=root_comp_data.get("group"),
        purl=root_comp_data.get("purl"),
        cpe=root_comp_data.get("cpe"),
        raw_data=root_comp_data,
    )


def _add_cyclonedx_component_tree(
    parsed: ParsedSBOM, cdata: Dict[str, Any], enclosing_id: Optional[str] = None
) -> str:
    """Recursively register CycloneDX component and child components."""
    c_name = cdata.get("name", "")
    c_ver = cdata.get("version", "")
    cid = cdata.get("bom-ref") or cdata.get("ref") or f"{c_name}@{c_ver}"

    comp = SBOMComponent(
        component_id=cid,
        name=c_name,
        version=c_ver,
        group=cdata.get("group"),
        purl=cdata.get("purl"),
        cpe=cdata.get("cpe"),
        raw_data=cdata,
    )
    parsed.add_component(comp)

    if enclosing_id:
        parsed.add_dependency(enclosing_id, cid)

    for sub_comp in cdata.get("components", []):
        if isinstance(sub_comp, dict):
            _add_cyclonedx_component_tree(parsed, sub_comp, enclosing_id=cid)

    return cid


def _apply_cyclonedx_dependencies(
    parsed: ParsedSBOM, dependencies: List[Any], root_id: Optional[str]
) -> None:
    """Apply dependency relationships in CycloneDX graph."""
    for dep in dependencies:
        if isinstance(dep, dict) and dep.get("ref"):
            parent_ref = str(dep["ref"])
            for child_ref in dep.get("dependsOn", []):
                parsed.add_dependency(parent_ref, str(child_ref))

    if root_id:
        for cid, comp in parsed.components.items():
            if cid != root_id and not comp.parent_ids:
                parsed.add_dependency(root_id, cid)


def _parse_cyclonedx(data: Dict[str, Any]) -> ParsedSBOM:
    """Parse CycloneDX JSON SBOM data.

    Args:
        data: CycloneDX JSON data dictionary.

    Returns:
        A ParsedSBOM instance populated with components and dependencies.
    """
    parsed = ParsedSBOM(format_type="cyclonedx")

    root_comp = _extract_cyclonedx_root(data.get("metadata", {}))
    root_id: Optional[str] = None
    if root_comp:
        root_id = root_comp.component_id
        parsed.add_component(root_comp, is_root=True)

    for cdata in data.get("components", []):
        if isinstance(cdata, dict):
            _add_cyclonedx_component_tree(parsed, cdata)

    _apply_cyclonedx_dependencies(parsed, data.get("dependencies", []), root_id)
    return parsed


def _extract_spdx_package(pkg: Dict[str, Any]) -> Optional[SBOMComponent]:
    """Extract an SBOMComponent from an SPDX package dictionary."""
    spdx_id = pkg.get("SPDXID", "")
    if not spdx_id:
        return None

    pkg_name = pkg.get("name", "")
    pkg_ver = pkg.get("versionInfo", "")
    ext_refs = pkg.get("externalRefs", [])

    cpe = _extract_cpe_from_ext_refs(ext_refs)
    purl = _extract_purl_from_ext_refs(ext_refs)
    originator = pkg.get("originator") or pkg.get("supplier")

    return SBOMComponent(
        component_id=spdx_id,
        name=pkg_name,
        version=pkg_ver,
        group=str(originator) if originator else None,
        purl=purl,
        cpe=cpe,
        raw_data=pkg,
    )


def _apply_spdx_relationships(
    parsed: ParsedSBOM, relationships: List[Any], doc_spdx_id: Optional[str]
) -> None:
    """Apply SPDX relationships to the parsed dependency graph."""
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        elem_id = rel.get("spdxElementId", "")
        rel_type = rel.get("relationshipType", "").upper()
        related_id = rel.get("relatedSpdxElement", "")

        if rel_type in ("DEPENDS_ON", "CONTAINS"):
            parsed.add_dependency(elem_id, related_id)
        elif rel_type in ("DEPENDENCY_OF", "CONTAINED_BY"):
            parsed.add_dependency(related_id, elem_id)
        elif rel_type == "DESCRIBES" and elem_id in ("SPDXRef-DOCUMENT", doc_spdx_id):
            parsed.root_ids.add(related_id)


def _parse_spdx(data: Dict[str, Any]) -> ParsedSBOM:
    """Parse SPDX JSON SBOM data.

    Args:
        data: SPDX JSON data dictionary.

    Returns:
        A ParsedSBOM instance populated with packages and relationships.
    """
    parsed = ParsedSBOM(format_type="spdx")

    for desc_id in data.get("documentDescribes", []):
        parsed.root_ids.add(str(desc_id))

    for pkg in data.get("packages", []):
        if isinstance(pkg, dict):
            comp = _extract_spdx_package(pkg)
            if comp:
                parsed.add_component(comp, is_root=comp.component_id in parsed.root_ids)

    if not parsed.root_ids and parsed.components:
        first_id = next(iter(parsed.components.keys()))
        parsed.root_ids.add(first_id)

    _apply_spdx_relationships(parsed, data.get("relationships", []), data.get("SPDXID"))

    if parsed.root_ids:
        primary_root = next(iter(parsed.root_ids))
        for cid, comp in parsed.components.items():
            if cid not in parsed.root_ids and not comp.parent_ids:
                parsed.add_dependency(primary_root, cid)

    return parsed


def parse_sbom(sbom_source: Union[str, Path, Dict[str, Any]]) -> ParsedSBOM:
    """Parse an SBOM from a file path or dictionary.

    Automatically detects CycloneDX JSON or SPDX JSON.

    Args:
        sbom_source: File path (str or Path) or dictionary representing the SBOM.

    Returns:
        ParsedSBOM instance.

    Raises:
        ValueError: If SBOM format is neither CycloneDX nor SPDX, or JSON is invalid.
        FileNotFoundError: If the specified file does not exist.
    """
    data: Dict[str, Any]
    if isinstance(sbom_source, (str, Path)):
        file_path = Path(sbom_source)
        if not file_path.exists():
            raise FileNotFoundError(f"SBOM file not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
    elif isinstance(sbom_source, dict):
        data = sbom_source
    else:
        raise ValueError(f"Invalid SBOM source type: {type(sbom_source).__name__}")

    # Format detection
    bom_format = str(data.get("bomFormat", "")).lower()
    spdx_version = str(data.get("spdxVersion", "")).upper()

    if bom_format == "cyclonedx" or "bomFormat" in data:
        return _parse_cyclonedx(data)

    if spdx_version.startswith("SPDX") or "spdxVersion" in data:
        return _parse_spdx(data)

    # Heuristic detection
    if "components" in data:
        return _parse_cyclonedx(data)
    if "packages" in data:
        return _parse_spdx(data)

    raise ValueError(
        "Unrecognized SBOM format. Expected CycloneDX JSON or SPDX JSON."
    )
