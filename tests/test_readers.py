"""Unit tests for the file/stdin reader adapters."""

from __future__ import annotations

import io
import sys
from pathlib import Path

from ioc_extractor.io.readers import read_file, read_stdin


def test_read_file_reads_utf8_content(tmp_path: Path) -> None:
    p = tmp_path / "sample.txt"
    p.write_text("hello 1.2.3.4", encoding="utf-8")
    assert read_file(p) == "hello 1.2.3.4"


def test_read_file_tolerates_invalid_utf8_bytes(tmp_path: Path) -> None:
    p = tmp_path / "binary.bin"
    p.write_bytes(b"valid text \xff\xfe more text")
    # Should not raise, even though the bytes aren't valid UTF-8.
    content = read_file(p)
    assert "valid text" in content


def test_read_stdin_reads_all_input() -> None:
    old_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("piped report text 8.8.8.8")
        assert read_stdin() == "piped report text 8.8.8.8"
    finally:
        sys.stdin = old_stdin
