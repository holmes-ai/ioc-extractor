"""Unit tests for raw regex pattern behavior."""

from __future__ import annotations

from ioc_extractor.core.models import IOCType
from ioc_extractor.core.patterns import PATTERNS


def test_ipv4_pattern_matches_plain_address() -> None:
    assert PATTERNS[IOCType.IPV4].search("Connect to 192.168.1.10 now")


def test_ipv4_pattern_matches_defanged_address() -> None:
    assert PATTERNS[IOCType.IPV4].search("C2 at 8[.]8[.]8[.]8")


def test_md5_pattern_requires_exact_length() -> None:
    text32 = "a" * 32
    text31 = "a" * 31
    assert PATTERNS[IOCType.MD5].search(text32)
    assert not PATTERNS[IOCType.MD5].fullmatch(text31)


def test_cve_pattern_matches_standard_form() -> None:
    assert PATTERNS[IOCType.CVE].search("Exploits CVE-2024-12345 were seen")


def test_url_pattern_matches_defanged_scheme() -> None:
    assert PATTERNS[IOCType.URL].search("hxxps://evil[.]example/payload")
