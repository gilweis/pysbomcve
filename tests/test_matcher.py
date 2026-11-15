"""Tests for pysbomcve matching engine between SBOM and CVEs."""

from unittest.mock import patch

from pysbomcve.cve_parser import CVEAffectedProduct, CVERecord
from pysbomcve.matcher import SBOMCVEMatcher, does_product_match, match_sbom_cve
from pysbomcve.sbom_parser import ParsedSBOM, SBOMComponent


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


def test_product_names_must_match_exactly() -> None:
    """Partial product names (Aviatrix 'Controller', 'log4j') never match other names."""
    aviatrix = CVEAffectedProduct(vendor="Aviatrix", product="Controller")
    assert not does_product_match(SBOMComponent("a", "abort-controller", "3.0.0"), aviatrix)
    assert does_product_match(SBOMComponent("c", "controller", "1"), aviatrix)
    assert does_product_match(SBOMComponent("u", "Log4J_Core", "1"),
                              CVEAffectedProduct(product="log4j-core"))
    assert not does_product_match(SBOMComponent("l", "log4j-core", "2.14.1"),
                                  CVEAffectedProduct(product="log4j"))
    assert not does_product_match(SBOMComponent("j", "log4j", "2.14.1"),
                                  CVEAffectedProduct(product="log4j-core"))


def test_scoped_package_requires_vendor_matching_scope() -> None:
    """A same-named product from another vendor (SUSE 'build') must not match @angular/build."""
    suse = CVEAffectedProduct(vendor="SUSE", product="build")
    suse_cpe = CVEAffectedProduct(cpes=["cpe:2.3:a:suse:build:*:*:*:*:*:*:*:*"])
    purl = "pkg:npm/%40angular/build@19.2.0"
    for component in (
        SBOMComponent("a", "build", "19.2.0", group="@angular", purl=purl),
        SBOMComponent("b", "build", "19.2.0", purl=purl),
    ):
        assert not does_product_match(component, suse)
        assert not does_product_match(component, suse_cpe)
        assert does_product_match(component, CVEAffectedProduct(vendor="angular", product="build"))
        assert does_product_match(component, CVEAffectedProduct(product="build"))
        assert does_product_match(component, CVEAffectedProduct(package_name="@angular/build"))
        assert does_product_match(
            component, CVEAffectedProduct(vendor="SUSE", package_name="npm:@angular/build")
        )
    assert does_product_match(SBOMComponent("c", "build", "1"), suse)


def test_unscoped_group_does_not_restrict_vendor() -> None:
    """Groups such as Maven namespaces are not vendors; cross-named vendors still match."""
    spring = SBOMComponent(
        "s", "spring-webmvc", "5.3.0", group="org.springframework",
        purl="pkg:maven/org.springframework/spring-webmvc@5.3.0",
    )
    assert does_product_match(spring, CVEAffectedProduct(vendor="VMware", product="spring-webmvc"))
    assert does_product_match(spring, CVEAffectedProduct(
        cpes=["cpe:2.3:a:vmware:spring-webmvc:*:*:*:*:*:*:*:*"]
    ))
    # SPDX originators are stored as groups and are not scopes either.
    assert does_product_match(
        SBOMComponent("o", "build", "1", group="Organization: Example"),
        CVEAffectedProduct(vendor="SUSE", product="build"),
    )


def test_index_preserves_exhaustive_matching_rules_and_order() -> None:
    """Keep token subsets, vendors, PURL/CPE aliases, unusual names and duplicates."""
    sbom = ParsedSBOM("cyclonedx")
    for index, (name, group, purl, cpe) in enumerate([
        ("Alpha_Beta", "vendor", None, None),
        ("beta-alpha-extra", "other", None, None),
        ("renamed", None, "pkg:maven/org/artifact@1.0", None),
        ("different", None, None, "cpe:2.3:a:vendor:cpe-only:1.0"),
        ("", None, None, None),
        ("Café", None, None, None),
        ("1.2", None, None, None),
        ("encoded", None, "pkg:npm/%40scope%2Fname@1.0", None),
        ("build", "@scoped", None, None),
    ]):
        sbom.add_component(SBOMComponent(str(index), name, "1.0", group, purl, cpe))
    sbom.add_dependency("0", "2")
    records = [
        CVERecord(f"CVE-{index}", affected=[CVEAffectedProduct(
            product=product, package_name=package, vendor=vendor, cpes=cpes,
            versions=[{"version": "1.0", "status": "affected"}],
        )])
        for index, (product, package, vendor, cpes) in enumerate([
            ("alpha", None, "vendor", []),
            ("alpha-beta-extra", None, "wrong", []),
            ("unrelated", "org:artifact", None, []),
            (None, None, None, ["cpe:2.3:a:vendor:cpe-only:*"]),
            ("!!!", None, None, []),
            (None, "org:", None, []),
            ("CAFÉ", None, None, []),
            ("1", None, None, []),
            ("alpha-beta-extra-more", None, None, []),
            (None, "@scope/name", None, []),
            (None, "@scoped/build", None, []),
            ("build", None, "other", []),
        ])
    ]
    records.append(CVERecord("CVE-multi", affected=[
        CVEAffectedProduct(product="unrelated"),
        CVEAffectedProduct(product="alpha", versions=[{"version": "*"}]),
    ]))
    records.extend([records[0], CVERecord("CVE-safe", affected=[
        CVEAffectedProduct(product="alpha", versions=[{"version": "2.0"}]),
    ])])
    matcher = SBOMCVEMatcher()
    expected = []
    for cid, component in sbom.components.items():
        matches = matcher.match_component(component, records)
        if matches:
            expected.append({
                "item": component.to_dict(), "cves": matches,
                "upper_items": sbom.get_upper_items(cid),
                "lineage_paths": sbom.get_lineage_paths(cid),
            })
    progress = []
    actual = matcher.match(sbom, records, progress=progress.append)
    assert actual == expected
    assert actual[0]["item"] is sbom.components["0"].raw_data
    assert progress[0].startswith("Indexing")
    assert progress[-1] == "Matching components: 9/9..."
    scoped_ids = {cve["cveId"] for f in actual if f["item"]["name"] == "build" for cve in f["cves"]}
    assert "CVE-10" in scoped_ids and "CVE-11" not in scoped_ids


def test_index_avoids_exhaustive_comparisons_with_shared_product_tokens() -> None:
    """Common tokens must not cause every component to test every CVE."""
    sbom = ParsedSBOM("cyclonedx")
    for index in range(30):
        sbom.add_component(SBOMComponent(str(index), f"lib-item-{index}", "1.0"))
    records = [
        CVERecord(f"CVE-{index}", affected=[CVEAffectedProduct(
            product=f"lib-item-{index}", versions=[{"version": "1.0"}],
        )])
        for index in range(1000)
    ]
    with patch("pysbomcve.matcher.does_product_match", wraps=does_product_match) as check:
        results = SBOMCVEMatcher().match(sbom, records)
    assert len(results) == 30
    assert check.call_count < len(sbom.components) * len(records) // 100
