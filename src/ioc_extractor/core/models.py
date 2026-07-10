"""Domain models for extracted Indicators of Compromise.

These are pure data structures with no I/O or external dependencies,
per the clean-architecture separation used across this project.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique


@unique
class IOCType(StrEnum):
    """Enumerates every indicator category this extractor recognizes."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    CVE = "cve"
    BTC_ADDRESS = "btc_address"
    FILE_PATH = "file_path"


@dataclass(frozen=True, slots=True)
class IOC:
    """A single normalized indicator of compromise.

    Attributes:
        value: The normalized (refanged) indicator value.
        ioc_type: The classified :class:`IOCType`.
        raw: The original substring exactly as it appeared in the source text.
        was_defanged: Whether the raw match used defanged notation (e.g. ``hxxp``).
        context: A short window of surrounding text, useful for triage.
    """

    value: str
    ioc_type: IOCType
    raw: str
    was_defanged: bool = False
    context: str = ""


@dataclass(slots=True)
class ExtractionResult:
    """Aggregate result of running the extractor over a document."""

    source: str
    iocs: list[IOC] = field(default_factory=list)

    def by_type(self, ioc_type: IOCType | str) -> list[IOC]:
        """Return only the IOCs matching the requested type.

        Accepts either an :class:`IOCType` member or its plain string value
        (e.g. ``"domain"``), since :class:`IOCType` is a ``StrEnum`` and
        callers commonly pass either interchangeably.
        """
        return [i for i in self.iocs if i.ioc_type == ioc_type]

    def unique_values(self) -> set[str]:
        """Return the set of distinct normalized indicator values."""
        return {i.value for i in self.iocs}

    def summary(self) -> dict[str, int]:
        """Return a count of indicators grouped by type name."""
        counts: dict[str, int] = {}
        for ioc in self.iocs:
            counts[ioc.ioc_type.value] = counts.get(ioc.ioc_type.value, 0) + 1
        return counts
