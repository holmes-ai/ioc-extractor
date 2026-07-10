# Architecture

## Goals

1. **Precision over recall creep.** Regex candidate generation is cheap;
   the validators layer exists specifically to reject the false-positive
   classes that plague naive IOC regexes (version strings matching IPv4,
   malformed CVE-like tokens, non-routable addresses).
2. **Zero I/O in the domain layer.** `core/` never touches a filesystem,
   network socket, or stdin/stdout. This is what makes 28 unit tests run
   in under 200ms with no fixtures beyond in-memory strings.
3. **Extensibility without modification.** Adding a new IOC type means
   adding one entry to `patterns.py`, optionally one validator branch, and
   one line in the priority tuple in `extractor.py` — the rest of the
   pipeline (defanging, dedup, output writers) requires no changes.

## Component breakdown

### `core/models.py`
Pure dataclasses: `IOCType` (a `StrEnum`), `IOC` (frozen, one indicator),
`ExtractionResult` (aggregate root with `by_type()`, `summary()`,
`unique_values()` convenience methods). No behavior beyond simple
aggregation — these are anemic by design, matching the functional style
of the rest of the core.

### `core/patterns.py`
A `dict[IOCType, re.Pattern]` registry. Patterns are written to tolerate
common analyst defanging notation (`[.]`, `(dot)`, `hxxp`, `[at]`) so that
matching happens *before* normalization — this avoids a chicken-and-egg
problem where you'd need to know the IOC type to refang it, but need to
refang it to classify the type.

### `core/defanging.py`
Two pure functions: `is_defanged(raw) -> bool` and `refang(raw) -> str`.
Applied to every match after pattern extraction, independent of IOC type.

### `core/validators.py`
`validate(value, ioc_type) -> bool`. Uses Python's `ipaddress` module for
IP validation (rejecting non-routable ranges we don't want as noise),
label-count/length checks for domains, and structural checks for CVEs.
Hash types have no additional validation beyond length (already encoded
in the regex) since entropy-based hash validation has a poor cost/benefit
ratio for this tool's scope.

### `core/extractor.py`
The orchestrator. Key design decision: **type priority ordering**. Since
a URL's text span fully contains a domain, and both patterns can match
the same substring, we process patterns in a fixed priority order (URL
and EMAIL before DOMAIN, longer hashes before shorter ones) and track
claimed character spans so a lower-priority pattern cannot re-claim text
already attributed to a higher-priority, more specific match. This is
implemented with simple interval overlap checks — no external interval
tree library needed at this scale.

### `io/readers.py` / `io/writers.py`
Adapters. Readers: file path → str, stdin → str. Writers: `ExtractionResult`
→ JSON / CSV / a minimal dependency-free STIX 2.1 bundle (indicator
objects only, sufficient for SIEM/TIP ingestion pipelines that just need
`pattern` + `labels`).

### `cli.py`
The composition root — the only module that imports both `io` and `core`
and wires them together. `argparse`-based, testable via `main(argv)`
returning an exit code rather than calling `sys.exit()` directly, so
tests can assert on the return value without catching `SystemExit`.

## Data flow

```
text ──► extract() ──► for each IOCType in priority order:
                          regex.finditer(text)
                            ├─ skip if span overlaps a claimed span
                            ├─ refang(raw) → normalized value
                            ├─ validate(normalized, type) → keep/discard
                            └─ record IOC + claim span
                        ──► deduplicate by (value.lower(), type)
                        ──► ExtractionResult
```

## Testing strategy

- `test_patterns.py` — regex-level unit tests (does the pattern match at all)
- `test_defanging.py` — refang/detection correctness in isolation
- `test_validators.py` — false-positive rejection in isolation
- `test_extractor.py` — end-to-end pipeline behavior (dedup, span-claiming,
  defanged-flag propagation)
- `test_writers_and_cli.py` — output format correctness and CLI wiring

This layering means a regex bug and a pipeline-orchestration bug fail in
different, specifically-named tests — there's no single monolithic
"does it work" test to debug from scratch.
