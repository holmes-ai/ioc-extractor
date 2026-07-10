# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's [private vulnerability reporting](../../security/advisories/new)
feature on this repository, or email **security@example.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal input file/string is ideal, given this
  tool's job is parsing untrusted text)
- Your assessment of severity, if you have one

You should expect an initial response within **5 business days**. We will
work with you to understand and validate the issue, and to agree on a
disclosure timeline before any public announcement.

## Scope notes

This project's core function is parsing **untrusted, potentially
adversarial text** (threat reports may themselves be crafted to attack
tooling that parses them). Reports of:

- ReDoS (catastrophic regex backtracking) on crafted input
- Path traversal or unsafe file handling in the CLI/I/O layer
- Any code path that would cause this tool to execute, fetch, or write
  outside the requested output location

are all in scope and taken seriously, even without a working exploit.

This tool performs no network requests and executes no extracted content
by design; reports assuming otherwise should first confirm that behavior
against the current `main` branch.
