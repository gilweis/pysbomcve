"""CVE JSON 5.0 parser module.

This module parses CVE JSON 5.0 and 5.1 records, extracting metadata, descriptions,
CVSS metrics, affected products, and version constraints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


# pylint: disable=too-few-public-methods
class CVEAffectedProduct:
    """Represents an affected product entry in a CVE JSON 5.0 record.

    Attributes:
        vendor: Vendor or organization name.
        product: Product name.
        package_name: Package name (e.g. in PyPI, Maven, npm).
        cpes: List of CPE identifiers.
        versions: List of version constraint dictionaries.
        raw_data: Original affected dictionary from the CVE.
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        package_name: Optional[str] = None,
        cpes: Optional[List[str]] = None,
        versions: Optional[List[Dict[str, Any]]] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize an affected product entry.

        Args:
            vendor: Vendor or maintainer name.
            product: Product name.
            package_name: Package name if specified.
            cpes: List of Common Platform Enumeration (CPE) strings.
            versions: List of version constraint specifications.
            raw_data: Complete raw dictionary of the affected entry.
        """
        self.vendor: Optional[str] = vendor
        self.product: Optional[str] = product
        self.package_name: Optional[str] = package_name
        self.cpes: List[str] = cpes or []
        self.versions: List[Dict[str, Any]] = versions or []
        self.raw_data: Dict[str, Any] = raw_data or {}

    def to_dict(self) -> Dict[str, Any]:
        """Return the raw affected dictionary."""
        return self.raw_data

    def __repr__(self) -> str:
        """Return developer-friendly string representation."""
        return (
            f"CVEAffectedProduct(product={self.product!r}, "
            f"vendor={self.vendor!r}, package_name={self.package_name!r})"
        )


# pylint: disable=too-many-instance-attributes
class CVERecord:
    """Represents a parsed CVE JSON 5.0 record.

    Attributes:
        cve_id: The CVE identifier (e.g., 'CVE-2023-32681').
        state: State of the CVE (e.g. 'PUBLISHED').
        title: Short title or summary.
        descriptions: English or primary text descriptions.
        metrics: CVSS metrics list.
        cvss_score: Highest extracted CVSS base score.
        cvss_severity: Severity level (e.g. 'CRITICAL', 'HIGH', 'MEDIUM').
        problem_types: List of CWE IDs or problem type descriptions.
        references: List of reference URLs.
        affected: List of CVEAffectedProduct objects.
        raw_data: Full original CVE JSON 5.0 record.
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        cve_id: str,
        state: str = "PUBLISHED",
        title: str = "",
        descriptions: Optional[List[str]] = None,
        metrics: Optional[List[Dict[str, Any]]] = None,
        cvss_score: Optional[float] = None,
        cvss_severity: Optional[str] = None,
        problem_types: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
        affected: Optional[List[CVEAffectedProduct]] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize a CVE record.

        Args:
            cve_id: CVE identifier string.
            state: Record state (default 'PUBLISHED').
            title: Title or summary string.
            descriptions: List of description text strings.
            metrics: List of metrics dictionaries.
            cvss_score: Highest CVSS base score.
            cvss_severity: Severity rating string.
            problem_types: List of CWE IDs or problem descriptions.
            references: List of reference URLs.
            affected: List of affected product objects.
            raw_data: Complete raw dictionary of the CVE record.
        """
        self.cve_id: str = cve_id
        self.state: str = state
        self.title: str = title
        self.descriptions: List[str] = descriptions or []
        self.metrics: List[Dict[str, Any]] = metrics or []
        self.cvss_score: Optional[float] = cvss_score
        self.cvss_severity: Optional[str] = cvss_severity
        self.problem_types: List[str] = problem_types or []
        self.references: List[str] = references or []
        self.affected: List[CVEAffectedProduct] = affected or []
        self.raw_data: Dict[str, Any] = raw_data or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert the CVE record to a dictionary.

        Returns:
            Dictionary containing structured CVE details and the raw record.
        """
        return {
            "cveId": self.cve_id,
            "state": self.state,
            "title": self.title,
            "descriptions": self.descriptions,
            "severity": self.cvss_severity,
            "score": self.cvss_score,
            "problemTypes": self.problem_types,
            "references": self.references,
            "metrics": self.metrics,
            "affected": [aff.raw_data for aff in self.affected],
            "rawRecord": self.raw_data,
        }

    def __repr__(self) -> str:
        """Return developer-friendly string representation."""
        return (
            f"CVERecord(id={self.cve_id!r}, severity={self.cvss_severity!r}, "
            f"score={self.cvss_score})"
        )


def _extract_descriptions(cna: Dict[str, Any]) -> List[str]:
    """Extract English descriptions from CNA container.

    Args:
        cna: CNA container dictionary.

    Returns:
        List of description strings.
    """
    desc_list = cna.get("descriptions", [])
    results: List[str] = []
    if isinstance(desc_list, list):
        for desc in desc_list:
            if isinstance(desc, dict):
                val = desc.get("value")
                if val:
                    results.append(str(val))
    return results


def _parse_metric_item(
    metric: Dict[str, Any]
) -> tuple[Optional[float], Optional[str]]:
    """Extract score and severity from a single metric entry."""
    other_type = metric.get("other", {}).get("type")
    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0", "other"):
        cvss_obj = metric.get(key)
        if not isinstance(cvss_obj, dict):
            continue
        score_val = cvss_obj.get("baseScore")
        sev_val = cvss_obj.get("baseSeverity") or other_type
        if score_val is not None:
            try:
                score = float(score_val)
                sev = str(sev_val).upper() if sev_val else None
                return score, sev
            except (ValueError, TypeError):
                continue
    return None, None


def _extract_cvss(metrics_list: List[Dict[str, Any]]) -> tuple[Optional[float], Optional[str]]:
    """Extract highest CVSS score and severity from metrics.

    Args:
        metrics_list: List of metric entries from CVE record.

    Returns:
        Tuple of (cvss_score, cvss_severity).
    """
    max_score: Optional[float] = None
    severity: Optional[str] = None

    for metric in metrics_list:
        if isinstance(metric, dict):
            score, sev = _parse_metric_item(metric)
            if score is not None and (max_score is None or score > max_score):
                max_score = score
                severity = sev

    return max_score, severity


def _extract_problem_types(cna: Dict[str, Any]) -> List[str]:
    """Extract CWE IDs and problem descriptions from CNA container.

    Args:
        cna: CNA container dictionary.

    Returns:
        List of problem type strings.
    """
    problems: List[str] = []
    for pt in cna.get("problemTypes", []):
        if not isinstance(pt, dict):
            continue
        for desc in pt.get("descriptions", []):
            if isinstance(desc, dict):
                cwe_id = desc.get("cweId")
                cwe_desc = desc.get("description")
                if cwe_id and cwe_desc:
                    problems.append(f"{cwe_id}: {cwe_desc}")
                elif cwe_id:
                    problems.append(str(cwe_id))
                elif cwe_desc:
                    problems.append(str(cwe_desc))
    return problems


def _extract_references(cna: Dict[str, Any]) -> List[str]:
    """Extract reference URLs from CNA container.

    Args:
        cna: CNA container dictionary.

    Returns:
        List of reference URL strings.
    """
    refs: List[str] = []
    for ref in cna.get("references", []):
        if isinstance(ref, dict):
            url = ref.get("url")
            if url:
                refs.append(str(url))
        elif isinstance(ref, str):
            refs.append(ref)
    return refs


def _extract_affected_products(
    affected_list: List[Dict[str, Any]]
) -> List[CVEAffectedProduct]:
    """Parse list of affected items into CVEAffectedProduct instances.

    Args:
        affected_list: List of affected dictionaries.

    Returns:
        List of CVEAffectedProduct objects.
    """
    results: List[CVEAffectedProduct] = []
    for item in affected_list:
        if not isinstance(item, dict):
            continue
        cpes = [str(c) for c in item.get("cpes", []) if c]
        versions = [v for v in item.get("versions", []) if isinstance(v, dict)]
        results.append(
            CVEAffectedProduct(
                vendor=item.get("vendor"),
                product=item.get("product"),
                package_name=item.get("packageName"),
                cpes=cpes,
                versions=versions,
                raw_data=item,
            )
        )
    return results


def _gather_metrics(containers: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Gather metrics from CNA and any ADP containers."""
    cna = containers.get("cna", {})
    all_metrics: List[Dict[str, Any]] = []
    if isinstance(cna.get("metrics"), list):
        all_metrics.extend(cna["metrics"])

    adp_list = containers.get("adp", [])
    if isinstance(adp_list, list):
        for adp in adp_list:
            if isinstance(adp, dict) and isinstance(adp.get("metrics"), list):
                all_metrics.extend(adp["metrics"])
    return all_metrics


def _gather_affected(containers: Dict[str, Any]) -> List[CVEAffectedProduct]:
    """Gather affected products from CNA and any ADP containers."""
    cna = containers.get("cna", {})
    raw_affected: List[Dict[str, Any]] = []
    if isinstance(cna.get("affected"), list):
        raw_affected.extend(cna["affected"])

    adp_list = containers.get("adp", [])
    if isinstance(adp_list, list):
        for adp in adp_list:
            if isinstance(adp, dict) and isinstance(adp.get("affected"), list):
                raw_affected.extend(adp["affected"])
    return _extract_affected_products(raw_affected)


def parse_single_cve_dict(data: Dict[str, Any]) -> Optional[CVERecord]:
    """Parse a single CVE JSON 5.0 dictionary.

    Args:
        data: Dictionary representing a CVE JSON 5.0 record.

    Returns:
        CVERecord if valid, otherwise None.
    """
    metadata = data.get("cveMetadata", {})
    cve_id = metadata.get("cveId")
    if not cve_id:
        return None

    state = str(metadata.get("state", "PUBLISHED")).upper()
    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    all_metrics = _gather_metrics(containers)
    score, severity = _extract_cvss(all_metrics)

    return CVERecord(
        cve_id=cve_id,
        state=state,
        title=str(cna.get("title", "")),
        descriptions=_extract_descriptions(cna),
        metrics=all_metrics,
        cvss_score=score,
        cvss_severity=severity,
        problem_types=_extract_problem_types(cna),
        references=_extract_references(cna),
        affected=_gather_affected(containers),
        raw_data=data,
    )


def _parse_cve_directory(dir_path: Path) -> List[CVERecord]:
    """Parse all JSON CVE files inside a directory."""
    records: List[CVERecord] = []
    for json_file in sorted(dir_path.glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as file_handle:
                file_data = json.load(file_handle)
            records.extend(parse_cve_records(file_data))
        except (json.JSONDecodeError, ValueError):
            continue
    return records


def parse_cve_records(
    cve_source: Union[str, Path, Dict[str, Any], List[Any]]
) -> List[CVERecord]:
    """Parse one or more CVE JSON 5.0 records from files, directories, or dicts.

    Supports:
    - Path to a single CVE JSON 5.0 file.
    - Path to a directory of CVE JSON files.
    - Dictionary representing a CVE JSON 5.0 record.
    - Dictionary with 'cves' or 'cveRecords' list.
    - List of CVE records.

    Args:
        cve_source: Source containing CVE data.

    Returns:
        List of parsed CVERecord instances.

    Raises:
        FileNotFoundError: If the specified file or directory does not exist.
        ValueError: If the source format cannot be parsed.
    """
    if isinstance(cve_source, (str, Path)):
        source_path = Path(cve_source)
        if not source_path.exists():
            raise FileNotFoundError(f"CVE source not found: {source_path}")
        if source_path.is_dir():
            return _parse_cve_directory(source_path)
        with open(source_path, "r", encoding="utf-8") as file_handle:
            loaded_data = json.load(file_handle)
        return parse_cve_records(loaded_data)

    if isinstance(cve_source, list):
        records: List[CVERecord] = []
        for item in cve_source:
            if isinstance(item, dict):
                rec = parse_single_cve_dict(item)
                if rec:
                    records.append(rec)
        return records

    if isinstance(cve_source, dict):
        for wrap_key in ("cves", "cveRecords", "records", "vulnerabilities"):
            if isinstance(cve_source.get(wrap_key), list):
                return parse_cve_records(cve_source[wrap_key])
        rec = parse_single_cve_dict(cve_source)
        return [rec] if rec else []

    raise ValueError(f"Unsupported CVE source type: {type(cve_source).__name__}")
