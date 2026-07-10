"""Integration tests for the end-to-end extraction pipeline."""

from __future__ import annotations

import time

from ioc_extractor.core.extractor import extract
from ioc_extractor.core.models import IOCType

_LARGE_DOC_IOC_COUNT = 6000
_LARGE_DOC_EXPECTED_TOTAL_IOCS = _LARGE_DOC_IOC_COUNT * 2
_LARGE_DOC_MAX_SECONDS = 2.0

SAMPLE_REPORT = """
Threat actor infrastructure observed:
- C2 server: 8[.]8[.]8[.]8
- Phishing domain: evil-corp[.]xyz
- Payload delivery: hxxps://evil-corp[.]xyz/drop/payload.exe
- Contact: attacker[at]protonmail[.]com
- Dropped file MD5: 44d88612fea8a8f36de82e1278abb02f
- SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Related vulnerability: CVE-2023-4863
- Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
"""


def test_extract_finds_expected_types() -> None:
    result = extract(SAMPLE_REPORT, source="unit-test")
    found_types = {ioc.ioc_type for ioc in result.iocs}
    assert IOCType.IPV4 in found_types
    assert IOCType.DOMAIN in found_types
    assert IOCType.URL in found_types
    assert IOCType.EMAIL in found_types
    assert IOCType.MD5 in found_types
    assert IOCType.CVE in found_types
    assert IOCType.BTC_ADDRESS in found_types


def test_extract_refangs_defanged_ip() -> None:
    result = extract(SAMPLE_REPORT, source="unit-test")
    ipv4_values = {ioc.value for ioc in result.by_type(IOCType.IPV4)}
    assert "8.8.8.8" in ipv4_values


def test_extract_marks_defanged_flag() -> None:
    result = extract(SAMPLE_REPORT, source="unit-test")
    ip_ioc = next(i for i in result.iocs if i.ioc_type is IOCType.IPV4)
    assert ip_ioc.was_defanged is True


def test_extract_deduplicates_repeated_indicators() -> None:
    text = "Bad IP 1.2.3.4 seen twice: 1.2.3.4 again."
    result = extract(text, source="unit-test")
    assert len(result.by_type(IOCType.IPV4)) == 1


def test_extract_url_claims_embedded_domain_span() -> None:
    text = "Payload at hxxps://evil-corp[.]xyz/drop/payload.exe was served."
    result = extract(text, source="unit-test")
    # The domain inside the URL should not ALSO be reported standalone.
    assert len(result.by_type(IOCType.URL)) == 1
    domain_values = {i.value for i in result.by_type(IOCType.DOMAIN)}
    assert "evil-corp.xyz" not in domain_values


def test_by_type_accepts_plain_string_as_documented_in_readme() -> None:
    """Regression test: by_type() must accept both IOCType and plain str.

    Previously used `is` identity comparison, which silently returned an
    empty list for `by_type("domain")` even though the README documents
    exactly that usage. Value equality (`==`) is required since IOCType
    is a StrEnum.
    """
    result = extract("C2 at evil.example.com", source="unit-test")
    assert result.by_type("domain") == result.by_type(IOCType.DOMAIN)
    assert len(result.by_type("domain")) == 1


def test_unique_values_returns_distinct_normalized_values() -> None:
    text = "Bad IP 1.2.3.4 seen twice: 1.2.3.4 again, plus 5.6.7.8."
    result = extract(text, source="unit-test")
    assert result.unique_values() == {"1.2.3.4", "5.6.7.8"}


def test_extract_normalizes_cve_to_canonical_uppercase() -> None:
    result = extract("vuln cve-2023-4863 seen", source="unit-test")
    values = {i.value for i in result.by_type(IOCType.CVE)}
    assert values == {"CVE-2023-4863"}


def test_extract_ipv6_compressed_notation() -> None:
    """Regression test: the IPv6 regex previously required the fully
    expanded 8-group form and missed '::' zero-compression, which is how
    the majority of real-world IPv6 addresses (loopback, link-local,
    etc.) are actually written."""
    text = "Beacon observed from 2001:db8::1 and from ::1 locally."
    result = extract(text, source="unit-test")
    values = {i.value for i in result.by_type(IOCType.IPV6)}
    assert "2001:db8::1" in values
    assert "::1" in values


def test_extract_file_path_rejects_ordinary_slashed_text() -> None:
    """Regression test: the old FILE_PATH regex matched dates, ratios,
    and phrases like 'and/or' because it lacked both a root anchor and
    any validator. Confirmed false positives before the fix: '/4', '/10/2026',
    '/false', '/or', '/B', '/50'."""
    text = (
        "The ratio is 3/4 and the date was 07/10/2026. "
        "true/false and/or option A/B. CPU usage 50/50 split."
    )
    result = extract(text, source="unit-test")
    assert result.by_type(IOCType.FILE_PATH) == []


def test_extract_file_path_still_matches_real_paths() -> None:
    text = "Dropped payload at /tmp/evil.sh and persisted via /etc/cron.d/x"
    result = extract(text, source="unit-test")
    values = {i.value for i in result.by_type(IOCType.FILE_PATH)}
    assert "/tmp/evil.sh" in values
    assert "/etc/cron.d/x" in values


def test_extract_handles_large_document_without_quadratic_blowup() -> None:
    """Regression test for the O(n^2) span-overlap check.

    Before the fix (linear scan over a growing list of claimed spans),
    this took ~4.5s for 6,000 IOCs and scaled quadratically. The
    bisect-based interval tracker keeps this well under a second.
    """
    lines = [
        f"C2 server at 10.0.{i // 256}.{i % 256} contacted evil{i}.example.com"
        for i in range(_LARGE_DOC_IOC_COUNT)
    ]
    text = "\n".join(lines)

    start = time.perf_counter()
    result = extract(text, source="unit-test")
    elapsed = time.perf_counter() - start

    assert len(result.iocs) == _LARGE_DOC_EXPECTED_TOTAL_IOCS
    assert (
        elapsed < _LARGE_DOC_MAX_SECONDS
    ), f"extraction took {elapsed:.2f}s, expected sub-quadratic scaling"


def test_extract_empty_text_returns_no_iocs() -> None:
    result = extract("", source="unit-test")
    assert result.iocs == []


def test_extract_rejects_non_routable_ipv4_candidate_end_to_end() -> None:
    """Exercises the extractor's validator-rejection path: the regex matches
    '0.1.2.3' as IPv4-shaped, but the validator rejects the non-routable
    0.x/8 prefix, so it must not appear in the final result."""
    result = extract("Traffic from 0.1.2.3 was logged.", source="unit-test")
    assert result.by_type(IOCType.IPV4) == []


def test_summary_counts_are_correct() -> None:
    result = extract(SAMPLE_REPORT, source="unit-test")
    summary = result.summary()
    assert summary["ipv4"] == 1
    assert sum(summary.values()) == len(result.iocs)
