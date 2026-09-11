# Contributing

Thanks for looking. This project has one invariant above everything else:

> **External content is data, never authority** — and a check that silently does not run is worse
> than no check, because the operator believes it ran.

## Development setup

```bash
git clone https://github.com/sscodeai/aiitg.git
cd aiitg
uv venv .venv && uv pip install -e ".[dev]"
# or: python3.11 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

## The gates (all three must pass before a PR)

```bash
make test        # pytest
make lint        # ruff, line-length 120
make typecheck   # mypy on src
```

CI runs exactly these on Python 3.11 and 3.12 for every push to `main`/`dev` and every pull request.

## Conventions

- **English only** in code, comments, commit messages, README and docs. Japanese is allowed only in
  `README.ja.md` (user-facing translation).
- **Conventional commits**: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`, `refactor:` — with a
  scope where it helps (`fix(hooks): …`).
- **Split commits by function**, not one big commit per PR.
- **Fixtures are generated in code** (`tests/fixtures/builders.py`), never committed as binaries: a
  malicious `.docx` in git is unreviewable, a builder function is diffable.
- **Test counts are enforced.** `tests/test_readme_badge.py` fails if the README badge or the
  `make test # N tests` comment disagrees with the number of collected tests, so bump them in the same
  commit that adds or removes tests.
- **A new detector or format needs**: a builder in `tests/fixtures/builders.py`, a detector test, and
  a format test — plus a note in the README tables.

## Design rules worth keeping

1. **Fail closed on decisions, fail open on availability.** If a document cannot be scanned, deny it.
   If the gateway itself is unavailable, do not break the user's tool.
2. **Never a silent substitution.** A `quarantine` decision rewrites what the model reads; the
   response must say so (`additionalContext`, audit line).
3. **One place per external contract.** Claude Code hook field names live in
   `aiitg/hooks/claude_code.py` (`DOCUMENTED_FIELDS` + `render_outcome`), and
   `tests/m3/test_hooks.py::TestEventContract` asserts the emitted field set matches the documented
   set per event.
4. **Evidence is coordinate-level.** Every finding carries a location that a human can open.

## Pull requests

- Branch from `dev`, keep `main` as the release line.
- Describe the threat model you are changing, not just the diff: what can reach the model before and
  after your change.
- If your change touches a promise in the README, update the README in the same PR.
