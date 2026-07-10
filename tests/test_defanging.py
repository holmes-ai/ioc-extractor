"""Unit tests for defang detection and refanging."""

from __future__ import annotations

from ioc_extractor.core.defanging import is_defanged, refang


def test_is_defanged_detects_bracketed_dot() -> None:
    assert is_defanged("evil[.]com")


def test_is_defanged_false_for_clean_domain() -> None:
    assert not is_defanged("evil.com")


def test_refang_bracketed_dot() -> None:
    assert refang("evil[.]com") == "evil.com"


def test_refang_hxxp_scheme() -> None:
    assert refang("hxxps://evil[.]com/path") == "https://evil.com/path"


def test_refang_at_bracket_email() -> None:
    assert refang("user[at]example[.]com") == "user@example.com"


def test_refang_is_idempotent_on_clean_input() -> None:
    clean = "clean.example.com"
    assert refang(clean) == clean
