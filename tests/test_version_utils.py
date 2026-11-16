"""Tests for pysbomcve version comparison and normalization utilities."""

from pysbomcve.version_utils import (
    compare_versions,
    is_version_vulnerable,
    matches_version_spec,
    normalize_version_string,
    parse_version_safe,
)


def test_normalize_version_string() -> None:
    """Test cleaning version strings with various prefixes and whitespace."""
    assert normalize_version_string("  v1.2.3  ") == "1.2.3"
    assert normalize_version_string("V2.0.0") == "2.0.0"
    assert normalize_version_string("release-3.1.4") == "3.1.4"
    assert normalize_version_string("ver-0.9.1") == "0.9.1"
    assert normalize_version_string("") == ""


def test_parse_version_safe() -> None:
    """Test safe parsing with both standard and non-standard versions."""
    v_std = parse_version_safe("2.14.1")
    assert str(v_std) == "2.14.1"

    v_beta = parse_version_safe("2.0-beta9")
    assert "2.0b9" in str(v_beta)

    # Custom non-PEP 440 version tag fallback
    v_custom = parse_version_safe("1.2.3.Final")
    assert isinstance(v_custom, tuple)
    assert v_custom == ((1, 1), (1, 2), (1, 3), (0, "final"))


def test_compare_versions_mixing_words_and_numbers() -> None:
    """Non-PEP 440 versions with words where others have numbers must not raise."""
    assert compare_versions("r123", "1.0.x") < 0
    assert compare_versions("1.0.x", "r123") > 0
    assert compare_versions("1.0.x", "1.0.5") < 0
    assert compare_versions("1.2.x", "1.2.x") == 0
    assert is_version_vulnerable(
        "abc123", [{"version": "0", "lessThan": "5.x", "status": "affected"}]
    ) in (True, False)


def test_compare_versions() -> None:
    """Test version ordering logic."""
    assert compare_versions("2.14.1", "2.15.0") < 0
    assert compare_versions("2.15.0", "2.14.1") > 0
    assert compare_versions("2.3.0", "2.3.0") == 0
    assert compare_versions("2.0-beta9", "2.14.1") < 0


def test_matches_version_spec_exact_and_wildcard() -> None:
    """Test exact equality and wildcard matching."""
    spec_exact = {"version": "2.15.0", "status": "affected"}
    assert matches_version_spec("2.15.0", spec_exact) is True
    assert matches_version_spec("2.14.1", spec_exact) is False

    spec_star = {"version": "*", "status": "affected"}
    assert matches_version_spec("3.4.5", spec_star) is True


def test_matches_version_spec_less_than() -> None:
    """Test range evaluation with lower bound and lessThan."""
    spec = {
        "version": "2.3.0",
        "lessThan": "2.31.0",
        "status": "affected",
    }
    assert matches_version_spec("2.28.0", spec) is True
    assert matches_version_spec("2.3.0", spec) is True
    assert matches_version_spec("2.31.0", spec) is False
    assert matches_version_spec("2.32.0", spec) is False
    assert matches_version_spec("2.2.0", spec) is False


def test_matches_version_spec_less_than_or_equal() -> None:
    """Test range evaluation with lessThanOrEqual."""
    spec = {
        "version": "1.0.0",
        "lessThanOrEqual": "1.5.0",
        "status": "affected",
    }
    assert matches_version_spec("1.5.0", spec) is True
    assert matches_version_spec("1.5.1", spec) is False
    assert matches_version_spec("1.2.0", spec) is True


def test_matches_version_spec_operator_in_version_field() -> None:
    """Test operator strings embedded in the version attribute."""
    spec = {"version": ">= 2.3.0, < 2.31.0", "status": "affected"}
    assert matches_version_spec("2.28.0", spec) is True
    assert matches_version_spec("2.31.0", spec) is False
    assert matches_version_spec("2.0.0", spec) is False


def test_is_version_vulnerable_with_unaffected_override() -> None:
    """Test that explicit unaffected rules override affected ranges."""
    versions = [
        {"version": "1.0.0", "lessThan": "2.0.0", "status": "affected"},
        {"version": "1.5.0", "status": "unaffected"},
    ]
    assert is_version_vulnerable("1.2.0", versions) is True
    assert is_version_vulnerable("1.5.0", versions) is False
    assert is_version_vulnerable("2.1.0", versions) is False
