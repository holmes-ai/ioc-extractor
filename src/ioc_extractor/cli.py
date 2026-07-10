"""Command-line interface for ioc-extractor.

This module is the composition root: it is the only place that wires
together the I/O adapters and the pure core extraction logic.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ioc_extractor import __version__
from ioc_extractor.core.extractor import extract
from ioc_extractor.io.readers import read_file, read_stdin
from ioc_extractor.io.writers import to_csv, to_json, to_stix_bundle

_WRITERS = {"json": to_json, "csv": to_csv, "stix": to_stix_bundle}


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ioc-extractor",
        description="Extract Indicators of Compromise (IOCs) from text.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="Path to a file to scan. Omit to read from stdin.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=sorted(_WRITERS),
        default="json",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write output to this file instead of stdout.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        text = read_file(args.input) if args.input else read_stdin()
    except OSError as exc:
        print(f"ioc-extractor: error: could not read input: {exc}", file=sys.stderr)
        return 1

    source = str(args.input) if args.input else "<stdin>"
    result = extract(text, source=source)
    rendered = _WRITERS[args.format](result)

    if args.output:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"ioc-extractor: error: could not write output: {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(rendered + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
