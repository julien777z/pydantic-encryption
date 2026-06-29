---
alwaysApply: true
---

# Poetry Rules

If dependencies are changed in `pyproject.toml`, run:

```bash
poetry lock
```

## Dependency Paths

Never use a full path URL (for example, `file:///Users/...`) in any `pyproject.toml` dependency. That only works on a local machine and fails in server environments. If you think you need a full path URL, the root issue is something else.

## Testing

Run tests with:

```bash
poetry run tests .
```

When updating existing tests or adding new tests, run the tests to verify they pass.

## CLI Scripts

When adding scripts to `scripts/`, use [Rich](https://rich.readthedocs.io/) for CLI output (console messages, progress bars, tables, etc.).
Never hard-code available projects, APIs, or services in Poetry scripts when the repository already has a shared discovery layer. Reuse the shared helper module instead.

## Procfiles

- Never add a Procfile entry that runs a raw `python` command.
- Procfile entries must use the service name, include a `PORT=...`, and run via Poetry (for example: `web: PORT=8080 poetry run python -m app`).
