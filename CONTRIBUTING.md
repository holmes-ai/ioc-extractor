# Contributing

Thanks for considering a contribution to IOC Extractor.

## Getting set up

```bash
git clone https://github.com/yourname/ioc-extractor.git
cd ioc-extractor
pip install -e ".[dev]"
pre-commit install
```

## Development loop

```bash
ruff check src tests       # lint
black src tests            # format
mypy src                   # type check
pytest                     # tests + coverage
```

All four must pass cleanly before opening a PR — CI enforces the same
gates.

## Adding a new IOC type

1. Add the enum member to `IOCType` in `core/models.py`.
2. Add a regex to the `PATTERNS` dict in `core/patterns.py`. Prefer
   precision over recall — a missed indicator is safer than a flood of
   false positives that erode analyst trust in the tool.
3. If the type needs extra validation beyond "did the regex match" (see
   how `DOMAIN`, `IPV4`, and `CVE` do this), add a branch to
   `core/validators.py`.
4. Add the type to the `_TYPE_PRIORITY` tuple in `core/extractor.py`,
   ordering it relative to existing types by specificity (more specific
   patterns — ones that can "contain" others, like URL containing
   DOMAIN — go earlier).
5. Add tests: at minimum a pattern-level test (`test_patterns.py`), a
   validator test if applicable (`test_validators.py`), and an
   end-to-end case in `test_extractor.py`.
6. Update the type table in `README.md`.

## Commit style

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add support for extracting SWIFT/BIC codes
fix: correct off-by-one in domain label length check
docs: clarify STIX writer scope in architecture.md
test: add regression test for overlapping URL/domain spans
chore: bump ruff to 0.6.10
```

## Pull requests

- Keep PRs focused — one logical change per PR.
- Include or update tests for any behavior change.
- Update `README.md` / `docs/architecture.md` if the change affects
  public API or design.
- Describe *why*, not just *what*, in the PR description.

## Code of conduct

Be respectful, assume good faith, and keep discussion focused on the
technical merits of a change. Harassment or personal attacks will result
in removal from the project's spaces.

## What this project will not accept

In line with the project's defensive-only scope, PRs adding offensive
capability (exploit code, credential harvesting, persistence mechanisms,
active scanning/exploitation against third-party systems) will be
declined regardless of technical quality.
