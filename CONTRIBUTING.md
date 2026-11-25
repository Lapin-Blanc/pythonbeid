# Contributing

Contributions are welcome. Please open an issue first for significant changes.

## Setup

```bash
python -m venv .venv
. .venv/bin/activate            # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pre-commit install
```

On Linux, install `pcscd` and `libpcsclite-dev` first.

## Checks

```bash
pytest                 # simulated card, coverage must stay at or above 95 %
pytest --hardware      # real card tests (they never print card data)
ruff check pythonbeid tests
black pythonbeid tests
mypy
```

The CI runs the same checks on Linux, Windows and macOS for every supported
Python version.

## Conventions

- Code, comments, docstrings (Google style) and commit messages in English.
- Type hints everywhere; `mypy --strict` must pass.
- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
  `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `ci:`.
- Work on a branch and open a pull request against `master`.
- **Never commit data read from a real card.** Tests use the synthetic
  builders in `tests/builders.py` and the simulated card in
  `tests/fake_card.py`.

## Releasing

1. Update the version in `pyproject.toml` and add a section to `CHANGELOG.md`.
2. Merge to `master`, then push a `vX.Y.Z` tag.
3. The *Publish to PyPI* workflow runs the CI, publishes with Trusted
   Publishing and creates the GitHub release from the changelog.
