"""Example: use ioc_extractor as a library rather than the CLI.

Run with:  python examples/extract_example.py
"""

from __future__ import annotations

from pathlib import Path

from ioc_extractor import extract
from ioc_extractor.io.writers import to_json

SAMPLE = Path(__file__).parent / "sample_report.txt"


def main() -> None:
    text = SAMPLE.read_text(encoding="utf-8")
    result = extract(text, source=str(SAMPLE))

    print(f"Found {len(result.iocs)} indicators in {result.source}")
    print("By type:", result.summary())
    print()
    print(to_json(result))


if __name__ == "__main__":
    main()
