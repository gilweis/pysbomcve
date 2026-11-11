"""Version parsing and comparison utilities for SBOM and CVE matching.

This module provides functions to parse, normalize, and compare software version
strings according to PEP 440, Semantic Versioning, and CVE JSON 5.0 version specifications.
"""

from __future__ import annotations

import re
from typing import Any, Tuple, Union
from packaging import version as pkg_version


def normalize_version_string(ver_str: str) -> str:
    """Normalize a raw version string for reliable comparison.

    Strips whitespace, surrounding quotes, and common leading prefixes such as
    'v', 'V', 'ver-', 'version-', or 'release-'.

    Args:
        ver_str: Raw version string (e.g. 'v2.14.1', '  1.0.0  ').

    Returns:
        Cleaned version string.
    """
    if not ver_str:
        return ""
    cleaned = str(ver_str).strip().strip("'\"")
    cleaned = re.sub(r"^(?:release[-_]|version[-_]|ver[-_]|[vV])", "", cleaned)
    return cleaned.strip()


def parse_version_safe(ver_str: str) -> Union[pkg_version.Version, Tuple[Any, ...]]:
    """Safely parse a version string into a comparable object.

    First attempts to use `packaging.version.parse`. If the string is not a valid
    PEP 440 version (e.g., custom enterprise tags like '1.2.3.Final'), it falls
    back to extracting numeric chunks and strings as a comparable tuple.

    Args:
        ver_str: The version string to parse.

    Returns:
        A comparable packaging.version.Version object or a tuple of segment values.
    """
    cleaned = normalize_version_string(ver_str)
    try:
        return pkg_version.parse(cleaned)
    except pkg_version.InvalidVersion:
        # Fallback: tokenize digits and alphanumeric words
        tokens = re.findall(r"(\d+|[a-zA-Z]+)", cleaned)
        normalized_tokens: list[Union[int, str]] = []
        for token in tokens:
            if token.isdigit():
                normalized_tokens.append(int(token))
            else:
                normalized_tokens.append(token.lower())
        return tuple(normalized_tokens)


def _compare_parsed(
    ver_a: Union[pkg_version.Version, Tuple[Any, ...]],
    ver_b: Union[pkg_version.Version, Tuple[Any, ...]],
) -> int:
    """Compare two parsed versions.

    Args:
        ver_a: First parsed version.
        ver_b: Second parsed version.

    Returns:
        -1 if ver_a < ver_b, 0 if ver_a == ver_b, 1 if ver_a > ver_b.
    """
    if type(ver_a) is type(ver_b):
        if ver_a < ver_b:
            return -1
        if ver_a > ver_b:
            return 1
        return 0

    # Cross-type comparison (one is packaging.version.Version, other is tuple)
    str_a = str(ver_a)
    str_b = str(ver_b)
    if str_a < str_b:
        return -1
    if str_a > str_b:
        return 1
    return 0


def compare_versions(target_ver: str, spec_ver: str) -> int:
    """Compare two version strings.

    Args:
        target_ver: Target version string.
        spec_ver: Specification version string to compare against.

    Returns:
        -1 if target_ver < spec_ver, 0 if equal, 1 if target_ver > spec_ver.
    """
    parsed_target = parse_version_safe(target_ver)
    parsed_spec = parse_version_safe(spec_ver)
    return _compare_parsed(parsed_target, parsed_spec)


def _evaluate_operator_expr(target_ver: str, expr: str) -> bool:
    """Evaluate a single version expression with operators such as '>= 2.3.0'.

    Args:
        target_ver: Component version string.
        expr: Expression with optional operator prefix (e.g. '>= 1.0', '< 2.0').

    Returns:
        True if target_ver satisfies expr, False otherwise.
    """
    cleaned_expr = expr.strip()
    match = re.match(r"^(<=|>=|<|>|==|!=|=)?\s*(.+)$", cleaned_expr)
    if not match:
        return False

    op, ver_val = match.groups()
    op = "==" if op in ("=", None) else op

    cmp_res = compare_versions(target_ver, ver_val)
    cmp_map = {
        "<": cmp_res < 0,
        "<=": cmp_res <= 0,
        ">": cmp_res > 0,
        ">=": cmp_res >= 0,
        "==": cmp_res == 0,
        "!=": cmp_res != 0,
    }
    return cmp_map.get(op, False)


def _check_upper_bounds(
    target_version: str, less_than: Any, less_than_equal: Any
) -> bool | None:
    """Check lessThan and lessThanOrEqual bounds.

    Returns:
        True/False if upper bound condition matched/failed, None if no bounds defined.
    """
    if less_than:
        lt_cleaned = normalize_version_string(str(less_than))
        return compare_versions(target_version, lt_cleaned) < 0
    if less_than_equal:
        lte_cleaned = normalize_version_string(str(less_than_equal))
        return compare_versions(target_version, lte_cleaned) <= 0
    return None


def _satisfies_lower_and_operators(
    target_version: str, raw_ver: str, has_bounds: bool
) -> bool | None:
    """Evaluate operator-prefixed strings and lower bounds.

    Returns:
        True if matched without bounds, False if failed, None if further bounds needed.
    """
    if any(raw_ver.startswith(p) for p in (">=", "<=", ">", "<")):
        sub_exprs = [sub.strip() for sub in raw_ver.split(",") if sub.strip()]
        if not all(_evaluate_operator_expr(target_version, sub) for sub in sub_exprs):
            return False
        if not has_bounds:
            return True

    has_lower = bool(
        raw_ver
        and raw_ver not in ("0", "*", "all", "unspecified", "unknown")
        and not any(raw_ver.startswith(p) for p in (">=", "<=", ">", "<"))
    )
    if has_lower and compare_versions(target_version, raw_ver) < 0:
        return False
    return None


def matches_version_spec(target_version: str, version_spec: dict[str, Any]) -> bool:
    """Check if target_version matches a CVE JSON 5.0 version specification.

    Handles CVE JSON 5.0 version fields:
    - version: starting version, exact version, wildcard ('*'), or operator string.
    - lessThan: exclusive upper bound.
    - lessThanOrEqual: inclusive upper bound.
    - status: 'affected', 'unaffected', or 'unknown'.

    Args:
        target_version: The version string of the SBOM item.
        version_spec: A version entry dictionary from CVE JSON 5.0 affected.versions.

    Returns:
        True if target_version matches this version entry, False otherwise.
    """
    status = str(version_spec.get("status", "affected")).lower()
    if not target_version or status not in ("affected", "unknown"):
        return False

    raw_ver = str(version_spec.get("version", "")).strip()
    less_than = version_spec.get("lessThan")
    less_than_equal = version_spec.get("lessThanOrEqual")
    has_bounds = bool(less_than or less_than_equal)

    # Universal wildcards
    if raw_ver in ("*", "all") and not has_bounds:
        return True

    # Operator prefixes and lower bound checks
    lower_res = _satisfies_lower_and_operators(target_version, raw_ver, has_bounds)
    if lower_res is not None:
        return lower_res

    # Upper bounds check (lessThan / lessThanOrEqual)
    upper_result = _check_upper_bounds(target_version, less_than, less_than_equal)
    if upper_result is not None:
        return upper_result

    # Exact equality fallback
    return compare_versions(target_version, raw_ver) == 0 if raw_ver else False


def is_version_vulnerable(
    target_version: str, versions_list: list[dict[str, Any]]
) -> bool:
    """Determine whether target_version is vulnerable across a list of version entries.

    Explicit 'unaffected' rules override 'affected' rules when they match the version.

    Args:
        target_version: The version string of the SBOM item.
        versions_list: List of version entry dictionaries from CVE JSON 5.0.

    Returns:
        True if the target version is affected and not explicitly marked unaffected.
    """
    if not target_version or not versions_list:
        return False

    # Check explicit unaffected rules first
    for spec in versions_list:
        status = str(spec.get("status", "")).lower()
        if status == "unaffected":
            # Test if target version falls inside unaffected specification
            spec_copy = dict(spec)
            spec_copy["status"] = "affected"
            if matches_version_spec(target_version, spec_copy):
                return False

    # Check affected rules
    for spec in versions_list:
        status = str(spec.get("status", "affected")).lower()
        if status in ("affected", "unknown"):
            if matches_version_spec(target_version, spec):
                return True

    return False
