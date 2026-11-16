"""Tests for pysbomcve CVE JSON 5.0 parsing."""

import json
from pathlib import Path
import pytest
from pysbomcve.cve_parser import parse_cve_records


def test_parse_single_cve_dict() -> None:
    """Test parsing a single CVE JSON 5.0 record dictionary."""
    record_dict = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "state": "PUBLISHED",
        },
        "containers": {
            "cna": {
                "title": "Sample Vulnerability",
                "descriptions": [
                    {"lang": "en", "value": "A test vulnerability description."}
                ],
                "affected": [
                    {
                        "vendor": "TestVendor",
                        "product": "test-pkg",
                        "versions": [
                            {"version": "1.0", "lessThan": "2.0", "status": "affected"}
                        ],
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": 8.5,
                            "baseSeverity": "HIGH",
                        }
                    }
                ],
            }
        },
    }

    records = parse_cve_records(record_dict)
    assert len(records) == 1
    rec = records[0]
    assert rec.cve_id == "CVE-2024-0001"
    assert rec.title == "Sample Vulnerability"
    assert rec.cvss_score == 8.5
    assert rec.cvss_severity == "HIGH"
    assert len(rec.affected) == 1
    assert rec.affected[0].product == "test-pkg"


@pytest.mark.parametrize("metric,score,severity", [
    ({"cvssV2_0": {"version": "2.0", "baseScore": 10.0}}, 10.0, "HIGH"),
    ({"cvssV2_0": {"version": "2.0", "baseScore": 6.9}}, 6.9, "MEDIUM"),
    ({"cvssV2_0": {"version": "2.0", "baseScore": 0}}, 0.0, "LOW"),
    ({"cvssV3_1": {"baseScore": 9.0}}, 9.0, "CRITICAL"),
    ({"cvssV3_1": {"baseScore": 7.5}}, 7.5, "HIGH"),
    ({"cvssV3_1": {"baseScore": 6.9}}, 6.9, "MEDIUM"),
    ({"cvssV3_1": {"baseScore": 0.1}}, 0.1, "LOW"),
    ({"cvssV3_1": {"baseScore": 0}}, 0.0, "NONE"),
    ({"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "high"}}, 9.8, "HIGH"),
])
def test_missing_severity_is_derived_from_score(metric, score, severity) -> None:
    """Metrics without baseSeverity get their CVSS version's rating for the score."""
    record = parse_cve_records({
        "cveMetadata": {"cveId": "CVE-2024-0002"},
        "containers": {"cna": {"metrics": [metric]}},
    })[0]
    assert (record.cvss_score, record.cvss_severity) == (score, severity)


def test_scores_for_every_cvss_version() -> None:
    """Keep the highest score per CVSS version across the CNA and ADP containers."""
    record = parse_cve_records({
        "cveMetadata": {"cveId": "CVE-2024-0003"},
        "containers": {
            "cna": {"metrics": [
                {"cvssV2_0": {"baseScore": 10.0, "vectorString": "AV:N/AC:L"}},
                {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                 "cvssV3_0": {"baseScore": 7.0}},
            ]},
            "adp": [{"metrics": [
                {"cvssV3_1": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}},
                {"cvssV4_0": {"baseScore": 6.0, "baseSeverity": "MEDIUM"}},
            ]}],
        },
    })[0]
    assert record.cvss_scores == {
        "4.0": {"score": 6.0, "severity": "MEDIUM", "vector": None},
        "3.1": {"score": 9.1, "severity": "CRITICAL", "vector": None},
        "3.0": {"score": 7.0, "severity": "HIGH", "vector": None},
        "2.0": {"score": 10.0, "severity": "HIGH", "vector": "AV:N/AC:L"},
    }
    assert list(record.cvss_scores) == ["4.0", "3.1", "3.0", "2.0"]
    assert (record.cvss_score, record.cvss_severity) == (10.0, "HIGH")
    assert record.to_dict()["scores"] == record.cvss_scores


def test_parse_cve_directory(tmp_path: Path) -> None:
    """Test parsing a directory containing multiple CVE JSON files."""
    file1 = tmp_path / "cve1.json"
    file2 = tmp_path / "cve2.json"

    file1.write_text(
        json.dumps(
            {
                "dataType": "CVE_RECORD",
                "cveMetadata": {"cveId": "CVE-2024-1111"},
                "containers": {"cna": {"title": "CVE 1"}},
            }
        ),
        encoding="utf-8",
    )
    file2.write_text(
        json.dumps(
            {
                "dataType": "CVE_RECORD",
                "cveMetadata": {"cveId": "CVE-2024-2222"},
                "containers": {"cna": {"title": "CVE 2"}},
            }
        ),
        encoding="utf-8",
    )

    records = parse_cve_records(tmp_path)
    assert len(records) == 2
    ids = {r.cve_id for r in records}
    assert ids == {"CVE-2024-1111", "CVE-2024-2222"}


def test_parse_cve_file_not_found() -> None:
    """Test FileNotFoundError when pointing to a non-existent file."""
    with pytest.raises(FileNotFoundError):
        parse_cve_records("non_existent_cve_path.json")


def test_directory_loading_reports_progress_and_skipped_files(tmp_path: Path) -> None:
    """Count all nested files, including malformed JSON, without losing valid CVEs."""
    nested = tmp_path / "year" / "batch"
    nested.mkdir(parents=True)
    (nested / "valid.JSON").write_text(json.dumps({
        "cveMetadata": {"cveId": "CVE-2026-1111"},
    }), encoding="utf-8")
    (tmp_path / "invalid.json").write_text("{bad json", encoding="utf-8")
    progress = []
    records = parse_cve_records(tmp_path, progress=progress.append)
    assert [record.cve_id for record in records] == ["CVE-2026-1111"]
    assert progress[0].startswith("Discovering")
    assert progress[-1] == "Reading CVE files: 2/2; 1 records loaded, 1 files skipped..."
