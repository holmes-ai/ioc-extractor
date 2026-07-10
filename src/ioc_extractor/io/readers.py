"""Adapters that read raw text from various sources.

Kept separate from core logic so the extraction engine never depends on
the filesystem or stdin directly (testability, and clean-architecture
boundaries between domain and I/O).
"""

from __future__ import annotations

import sys
from pathlib import Path


def read_file(path: Path) -> str:
    """Read a UTF-8 text file, tolerating decode errors from binary noise."""
    return path.read_text(encoding="utf-8", errors="replace")


def read_stdin() -> str:
    """Read all of stdin as text."""
    return sys.stdin.read()
