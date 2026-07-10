"""Regex pattern registry.

Each entry maps an :class:`~ioc_extractor.core.models.IOCType` to a compiled
regular expression. Patterns are intentionally conservative (favoring
precision) and are validated further in :mod:`ioc_extractor.core.validators`.
"""

from __future__ import annotations

import re

from ioc_extractor.core.models import IOCType

_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

PATTERNS: dict[IOCType, re.Pattern[str]] = {
    IOCType.IPV4: re.compile(rf"\b(?:{_IPV4_OCTET}\[?\.\]?){{3}}{_IPV4_OCTET}\b"),
    IOCType.IPV6: re.compile(
        r"(?<![A-Za-z0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Za-z0-9:])"
    ),
    IOCType.EMAIL: re.compile(
        r"\b[A-Za-z0-9._%+\-]+\s?(?:@|\[at\]|\(at\))\s?"
        r"(?:[A-Za-z0-9-]+\s?(?:\.|\[\.\]|\(dot\))\s?)+[A-Za-z]{2,}\b"
    ),
    IOCType.URL: re.compile(
        r"\b(?:hxxps?|https?)(?::\/\/|:\\\/\\\/|\[:\]\/\/)[^\s\"'<>\)]+",
        re.IGNORECASE,
    ),
    IOCType.DOMAIN: re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\s?"
        r"(?:\.|\[\.\]|\(dot\))\s?){1,}"
        r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|site|"
        r"gov|edu|co|me|tv|cc|link|click|shop|live|world|icu|vip|work)\b",
        re.IGNORECASE,
    ),
    IOCType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    IOCType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IOCType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    IOCType.SHA512: re.compile(r"\b[a-fA-F0-9]{128}\b"),
    IOCType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    IOCType.BTC_ADDRESS: re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90})\b"),
    IOCType.FILE_PATH: re.compile(
        r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+"
        r"|(?<![A-Za-z0-9_.])\/(?:[^\/\0\s]+\/)+[^\/\0\s]+"
    ),
}
