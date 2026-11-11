"""Tests for pysbomcve matching engine between SBOM and CVEs."""

from pysbomcve.matcher import match_sbom_cve


def test_match_sbom_cve_with_examples() -> None:
    """Test full matching pipeline on example files."""
    results = match_sbom_cve("examples/sbom.json", "examples/cve.json")

    assert len(results) == 2

    # Verify requests finding
    requests_find = next(
        (r for r in results if r["item"]["name"] == "requests"), None
    )
    assert requests_find is not None
    assert requests_find["cves"][0]["cveId"] == "CVE-2023-32681"
    assert len(requests_find["upper_items"]) == 2
    assert requests_find["upper_items"][0]["name"] == "payment-gateway-client"
    assert requests_find["upper_items"][1]["name"] == "ecommerce-platform"

    # Verify log4j-core finding
    log4j_find = next(
        (r for r in results if r["item"]["name"] == "log4j-core"), None
    )
    assert log4j_find is not None
    assert log4j_find["cves"][0]["cveId"] == "CVE-2021-44228"
    assert len(log4j_find["upper_items"]) == 2
    assert log4j_find["upper_items"][0]["name"] == "event-audit-service"
    assert log4j_find["upper_items"][1]["name"] == "ecommerce-platform"


def test_match_sbom_cve_spdx() -> None:
    """Test matching with SPDX SBOM format."""
    results = match_sbom_cve("examples/sbom_spdx.json", "examples/cve.json")
    assert len(results) == 1
    item = results[0]
    assert item["item"]["name"] == "requests"
    assert item["cves"][0]["cveId"] == "CVE-2023-32681"
    assert len(item["upper_items"]) == 2
    assert item["upper_items"][0]["name"] == "payment-gateway-client"
    assert item["upper_items"][1]["name"] == "ecommerce-platform"


def test_no_match_scenario() -> None:
    """Test scenario where no component matches the CVE."""
    safe_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "name": "safe-lib",
                "version": "1.0.0",
                "bom-ref": "pkg:pypi/safe-lib@1.0.0",
            }
        ],
    }
    cve_data = {
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": "CVE-2024-9999"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "product": "other-lib",
                        "versions": [{"version": "1.0.0", "status": "affected"}],
                    }
                ]
            }
        },
    }

    results = match_sbom_cve(safe_sbom, cve_data)
    assert len(results) == 0
