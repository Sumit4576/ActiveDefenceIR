# Contributing to ActiveDefenceIR

## Workflow

1. Fork the repository, or create a branch from `main` named `feat/<topic>`, `fix/<topic>`, or `docs/<topic>`.
2. Make focused commits with imperative messages, for example `Add SSH honeypot log parser`.
3. Run the checks locally before you push:
   ```bash
   pip install -r requirements-dev.txt
   black . && flake8 . && pytest
   cd frontend && npm run lint && npm run build
   ```
4. Open a pull request against `main`. Describe what changed and why, and link the related issue.
5. CI must pass, and at least one maintainer must approve before merge. Squash-merge is preferred.

## Code style

- **Python:** formatted with [black](https://black.readthedocs.io/) (line length 120) and linted with flake8 (config in `.flake8`). Add type hints to new public functions.
- **TypeScript/React:** linted with oxlint (`frontend/.oxlintrc.json`). The production build runs `tsc` in strict mode, so it must type-check.
- **Tests:** add or update tests in `tests/` for any behavior change.
- **Secrets:** never commit API keys, `.env` files, logs, or model `.pkl` files.

## Issue labels

| Label | Meaning |
|---|---|
| `bug` | Something is broken |
| `enhancement` | New feature or improvement |
| `documentation` | Docs only |
| `security` | Security-relevant issue (report sensitive ones privately to the maintainers) |
| `good first issue` | Suitable for newcomers |
| `help wanted` | Maintainers would welcome a PR |
| `module:1` … `module:4`, `frontend` | Affected component |
