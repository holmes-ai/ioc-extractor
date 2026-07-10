"""Unit tests for false-positive filtering validators."""

from __future__ import annotations

from ioc_extractor.core.models import IOCType
from ioc_extractor.core.validators import validate


def test_valid_ipv4_accepted() -> None:
    assert validate("192.168.1.1", IOCType.IPV4)


def test_ipv4_out_of_range_rejected() -> None:
    assert not validate("999.999.999.999", IOCType.IPV4)


def test_ipv4_non_routable_prefix_rejected() -> None:
    assert not validate("0.1.2.3", IOCType.IPV4)


def test_domain_single_label_rejected() -> None:
    assert not validate("localhost", IOCType.DOMAIN)


def test_domain_all_numeric_labels_rejected() -> None:
    assert not validate("1.2", IOCType.DOMAIN)


def test_domain_valid_accepted() -> None:
    assert validate("evil.example.com", IOCType.DOMAIN)


def test_cve_well_formed_accepted() -> None:
    assert validate("CVE-2024-12345", IOCType.CVE)


def test_cve_malformed_rejected() -> None:
    assert not validate("CVE-24-123", IOCType.CVE)


def test_ipv6_valid_compressed_form_accepted() -> None:
    assert validate("2001:db8::1", IOCType.IPV6)


def test_ipv6_malformed_rejected() -> None:
    assert not validate("not:a:real:address:at:all:nope:too:many", IOCType.IPV6)


def test_file_path_all_numeric_segments_rejected() -> None:
    assert not validate("12/2023", IOCType.FILE_PATH)


def test_file_path_valid_accepted() -> None:
    assert validate("/etc/passwd", IOCType.FILE_PATH)


def test_file_path_no_segments_rejected() -> None:
    assert not validate("///", IOCType.FILE_PATH)
