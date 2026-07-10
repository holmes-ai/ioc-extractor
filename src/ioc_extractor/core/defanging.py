"""Utilities to detect and reverse ("refang") defanged indicator notation.

Analysts commonly defang IOCs in reports (e.g. ``hxxp://evil[.]com``) so that
tooling and email clients don't treat them as live links. This module
normalizes such notation back to a canonical form for consistent matching
and deduplication, while recording that defanging was present.
"""

from __future__ import annotations

import re

_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\[\.\]|\(dot\)|\s\.\s"), "."),
    (re.compile(r"\[at\]|\(at\)"), "@"),
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r":\\\/\\\/|\[:\]\/\/"), "://"),
)

_DEFANG_MARKERS: tuple[str, ...] = ("[.]", "(dot)", "hxxp", "[at]", "(at)", "[:]//")


def is_defanged(raw: str) -> bool:
    """Return True if the raw match contains recognizable defanging markers."""
    lowered = raw.lower()
    return any(marker in lowered for marker in _DEFANG_MARKERS)


def refang(raw: str) -> str:
    """Return the canonical (refanged) form of a possibly-defanged indicator."""
    result = raw
    for pattern, replacement in _REPLACEMENTS:
        result = pattern.sub(replacement, result)
    return result
