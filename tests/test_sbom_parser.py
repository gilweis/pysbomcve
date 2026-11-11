"""Tests for pysbomcve CycloneDX and SPDX SBOM parsing and tree ancestry."""

import pytest
from pysbomcve.sbom_parser import ParsedSBOM, SBOMComponent, parse_sbom


def test_cyclonedx_parsing_and_ancestry() -> None:
    """Test CycloneDX JSON parsing with hierarchy and upper item tracing."""
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "name": "root-app",
                "version": "1.0.0",
                "bom-ref": "ref-root",
            }
        },
        "components": [
            {
                "name": "mid-layer",
                "version": "2.0.0",
                "bom-ref": "ref-mid",
            },
            {
                "name": "leaf-lib",
                "version": "3.0.0",
                "bom-ref": "ref-leaf",
            },
        ],
        "dependencies": [
            {
                "ref": "ref-root",
                "dependsOn": ["ref-mid"],
            },
            {
                "ref": "ref-mid",
                "dependsOn": ["ref-leaf"],
            },
        ],
    }

    parsed = parse_sbom(data)
    assert parsed.format_type == "cyclonedx"
    assert "ref-root" in parsed.root_ids
    assert len(parsed.components) == 3

    # Test upper items from leaf to root
    upper = parsed.get_upper_items("ref-leaf")
    assert len(upper) == 2
    assert upper[0]["name"] == "mid-layer"
    assert upper[1]["name"] == "root-app"

    # Test paths
    paths = parsed.get_lineage_paths("ref-leaf")
    assert len(paths) == 1
    assert [c["name"] for c in paths[0]] == ["mid-layer", "root-app"]


def test_spdx_parsing_and_ancestry() -> None:
    """Test SPDX JSON parsing with relationship-based lineage."""
    data = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "spdx-demo",
        "documentDescribes": ["SPDXRef-Root"],
        "packages": [
            {"SPDXID": "SPDXRef-Root", "name": "root-pkg", "versionInfo": "1.0"},
            {"SPDXID": "SPDXRef-Mid", "name": "mid-pkg", "versionInfo": "2.0"},
            {"SPDXID": "SPDXRef-Child", "name": "child-pkg", "versionInfo": "3.0"},
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-Root",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-Mid",
            },
            {
                "spdxElementId": "SPDXRef-Mid",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-Child",
            },
        ],
    }

    parsed = parse_sbom(data)
    assert parsed.format_type == "spdx"
    assert "SPDXRef-Root" in parsed.root_ids

    upper = parsed.get_upper_items("SPDXRef-Child")
    assert len(upper) == 2
    assert upper[0]["name"] == "mid-pkg"
    assert upper[1]["name"] == "root-pkg"


def test_circular_dependency_handling() -> None:
    """Ensure circular dependencies do not trigger infinite loops."""
    parsed = ParsedSBOM(format_type="cyclonedx")
    c1 = SBOMComponent(component_id="A", name="A", version="1")
    c2 = SBOMComponent(component_id="B", name="B", version="1")
    parsed.add_component(c1)
    parsed.add_component(c2)
    parsed.add_dependency("A", "B")
    parsed.add_dependency("B", "A")

    upper = parsed.get_upper_items("A")
    assert len(upper) == 1
    assert upper[0]["name"] == "B"

    paths = parsed.get_lineage_paths("A")
    assert len(paths) == 1


def test_parse_sbom_invalid_format() -> None:
    """Test raising ValueError on unrecognized SBOM format."""
    with pytest.raises(ValueError, match="Unrecognized SBOM format"):
        parse_sbom({"invalidKey": "noFormat"})
