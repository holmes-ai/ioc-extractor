"""The extraction engine: pure function(s) turning text into IOCs.

No file I/O happens here — see :mod:`ioc_extractor.io` for adapters that
read source text and write results. This keeps the domain logic unit
testable without touching a filesystem.
"""

from __future__ import annotations

import bisect

from ioc_extractor.core.defanging import is_defanged, refang
from ioc_extractor.core.models import IOC, ExtractionResult, IOCType
from ioc_extractor.core.patterns import PATTERNS
from ioc_extractor.core.validators import validate

_CONTEXT_WINDOW = 40

# Order matters: more specific types are matched first so that, when we
# de-duplicate overlapping spans, the most precise classification wins
# (e.g. a URL match should "claim" the domain embedded inside it).
_TYPE_PRIORITY: tuple[IOCType, ...] = (
    IOCType.URL,
    IOCType.EMAIL,
    IOCType.SHA512,
    IOCType.SHA256,
    IOCType.SHA1,
    IOCType.MD5,
    IOCType.CVE,
    IOCType.BTC_ADDRESS,
    IOCType.IPV6,
    IOCType.IPV4,
    IOCType.DOMAIN,
    IOCType.FILE_PATH,
)


class _ClaimedSpans:
    """Tracks non-overlapping (start, end) spans with O(log n) queries.

    The naive approach — a plain list checked with a linear scan on every
    candidate match — is O(n) per lookup and O(n^2) overall for documents
    with many indicators (a 6,000-IOC document took ~4.5s; see
    ``docs/architecture.md`` for the measured before/after). Because
    claimed spans are always non-overlapping by construction, a new
    candidate can only conflict with its immediate left/right neighbor in
    sorted order, so a binary search is sufficient.
    """

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []

    def overlaps(self, start: int, end: int) -> bool:
        idx = bisect.bisect_left(self._starts, start)
        if idx > 0 and self._ends[idx - 1] > start:
            return True
        return idx < len(self._starts) and self._starts[idx] < end

    def add(self, start: int, end: int) -> None:
        idx = bisect.bisect_left(self._starts, start)
        self._starts.insert(idx, start)
        self._ends.insert(idx, end)


def extract(text: str, *, source: str = "<memory>") -> ExtractionResult:
    """Extract all recognized IOCs from `text`.

    Args:
        text: Raw text to scan (e.g. a threat report, log excerpt, or email).
        source: A label identifying where `text` came from, stored on the
            result for traceability.

    Returns:
        An :class:`ExtractionResult` containing every validated, deduplicated
        IOC found, in first-seen order.
    """
    claimed = _ClaimedSpans()
    found: list[IOC] = []

    for ioc_type in _TYPE_PRIORITY:
        pattern = PATTERNS[ioc_type]
        for m in pattern.finditer(text):
            start, end = m.span()
            if claimed.overlaps(start, end):
                continue

            raw = m.group(0)
            normalized = refang(raw).strip().rstrip(".,;:)")
            if ioc_type is IOCType.CVE:
                normalized = normalized.upper()

            if not validate(normalized, ioc_type):
                continue

            claimed.add(start, end)
            found.append(
                IOC(
                    value=normalized,
                    ioc_type=ioc_type,
                    raw=raw,
                    was_defanged=is_defanged(raw),
                    context=_context(text, start, end),
                )
            )

    deduped = _deduplicate(found)
    return ExtractionResult(source=source, iocs=deduped)


def _context(text: str, start: int, end: int) -> str:
    lo = max(0, start - _CONTEXT_WINDOW)
    hi = min(len(text), end + _CONTEXT_WINDOW)
    return text[lo:hi].replace("\n", " ").strip()


def _deduplicate(iocs: list[IOC]) -> list[IOC]:
    seen: set[tuple[str, IOCType]] = set()
    result: list[IOC] = []
    for ioc in iocs:
        key = (ioc.value.lower(), ioc.ioc_type)
        if key in seen:
            continue
        seen.add(key)
        result.append(ioc)
    return result
