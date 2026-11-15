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
