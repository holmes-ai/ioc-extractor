# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-07-10

### Security
- Fixed CSV/formula injection (CWE-1236) in `to_csv`: cell values starting
  with `=`, `+`, `-`, `@`, tab, or CR are now prefixed with `'` so a
  crafted threat report cannot execute a formula when the exported CSV
  is opened in Excel/Sheets/LibreOffice Calc.

### Fixed
- `by_type()` used identity (`is`) comparison instead of equality (`==`),
  silently returning an empty list when passed a plain string — exactly
  the usage shown in this project's own README. Now uses `==`, matching
  `IOCType` being a `StrEnum`.
- IPv6 regex did not support `::` zero-compression notation, missing the
  majority of real-world IPv6 addresses (e.g. `::1`, `2001:db8::1`).
- FILE_PATH extraction had no validator and an overly permissive regex,
  producing false positives on ordinary slashed text (dates, ratios,
  "and/or"). Regex now anchors to a true path root; a validator rejects
  all-numeric-segment matches as defense in depth.
- CLI no longer dumps a raw Python traceback when the input file doesn't
  exist or the output path can't be written; both now print a one-line
  error to stderr and exit with code 1.
- CVE values are now normalized to canonical uppercase (`CVE-2024-1234`)
  regardless of the case used in the source text.

### Performance
- Replaced the O(n²) linear span-overlap scan in `extract()` with an
  O(log n) bisect-based interval tracker. A 6,000-indicator document
  went from ~4.5s to ~0.3s, and the algorithm now scales linearly
  instead of quadratically with indicator count.

### Added
- `--version` flag on the CLI.
- `.dockerignore` for build hygiene.
- 24 new regression tests covering every fix above plus previously
  untested branches (stdin path, stdout path, validator edge cases).

## [0.1.0] - 2026-07-10

### Added
- Initial release.
- Core extraction engine supporting IPv4, IPv6, domain, URL, email,
  MD5/SHA1/SHA256/SHA512 hashes, CVE IDs, Bitcoin addresses, and file paths.
- Defang/refang normalization (`[.]`, `(dot)`, `hxxp`, `[at]`, etc.).
- False-positive validators for IPv4, domains, and CVE structure.
- JSON, CSV, and minimal STIX 2.1 bundle output writers.
- CLI (`ioc-extractor`) supporting file and stdin input.
- Full test suite (pytest), Ruff + Black + mypy strict CI gates.
- Dockerfile and docker-compose for containerized usage.
- GitHub Actions CI and release workflows.
