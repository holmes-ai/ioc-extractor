"""Secondary validation to filter false positives from regex matches.

Regexes are good at finding *candidates*; this module applies stricter,
semantically-aware checks (e.g. rejecting version strings that look like
IPv4 addresses, or hashes that are just long hex-looking identifiers with
no other corroborating context).
"""

from __future__ import annotations

import ipaddress

from ioc_extractor.core.models import IOCType

# Domains that are common false-positive sources (version numbers, file
# extensions parsed as TLD-like suffixes, etc.) that regexes cannot filter.
_NON_ROUTABLE_IPV4_PREFIXES: tuple[str, ...] = ("0.", "255.255.255.255")

_MIN_DOMAIN_LABELS = 2
_MAX_DNS_LABEL_LENGTH = 63
_CVE_PART_COUNT = 3
_CVE_YEAR_DIGITS = 4


def validate(value: str, ioc_type: IOCType) -> bool:
    """Return True if `value` is a plausible, well-formed IOC of `ioc_type`."""
    match ioc_type:
        case IOCType.IPV4:
            return _valid_ipv4(value)
        case IOCType.IPV6:
            return _valid_ipv6(value)
        case IOCType.DOMAIN:
            return _valid_domain(value)
        case IOCType.CVE:
            return _valid_cve(value)
        case IOCType.FILE_PATH:
            return _valid_file_path(value)
        case _:
            return True


def _valid_ipv4(value: str) -> bool:
    if value.startswith(_NON_ROUTABLE_IPV4_PREFIXES):
        return False
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _valid_domain(value: str) -> bool:
    labels = value.rstrip(".").split(".")
    if len(labels) < _MIN_DOMAIN_LABELS:
        return False
    # Reject things like "v1.2" (all-numeric labels, common in version strings).
    if all(label.isdigit() for label in labels):
        return False
    return all(0 < len(label) <= _MAX_DNS_LABEL_LENGTH for label in labels)


def _valid_cve(value: str) -> bool:
    parts = value.upper().split("-")
    return len(parts) == _CVE_PART_COUNT and parts[0] == "CVE" and len(parts[1]) == _CVE_YEAR_DIGITS


def _valid_file_path(value: str) -> bool:
    """Reject matches that are structurally path-shaped but semantically not.

    The regex already anchors POSIX paths to a true root (not preceded by
    an alphanumeric character) and Windows paths to a drive letter, which
    eliminates the bulk of false positives (dates, ratios, "and/or"). This
    is a defense-in-depth check for the remaining edge case: every segment
    being purely numeric.
    """
    segments = [s for s in value.replace("\\", "/").split("/") if s]
    if not segments:
        return False
    return not all(segment.isdigit() for segment in segments)
