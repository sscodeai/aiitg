# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-11

Zero-touch adoption: enforcement for tools that never call the MCP server.

### Added

- **Claude Code hook adapter** (`aiitg hook pretooluse` / `aiitg hook posttooluse`): scans a
  `Read` target before it enters the model's context and maps the policy decision onto the hook
  contract — clean files pass, `dangerous` files are denied with the rule id, trust label and the
  exact evidence location, `quarantine` rewrites the read onto a sanitized `.txt` substitute and says
  so in `additionalContext`, `human_approval` becomes the native `ask` prompt (optionally mirrored
  into the approval queue).
- `aiitg hook-config`: prints the `.claude/settings.json` snippet with an absolute, shell-quoted
  executable path. It never writes user configuration.
- `aiitg hook doctor`: self-check for a setup that cannot enforce anything — executable on PATH,
  `PreToolUse` hook actually wired in a settings file, quarantine/cache directories writable,
  fail-closed default, enforced-format count. Exits 1 when the gateway is not on the path.
  A hook command that cannot start is a *non-blocking* error in Claude Code, so without this check a
  broken setup looks identical to a working one.
- `(path, mtime_ns, size)` decision cache plus a namespace covering build, sanitizer mode, detector
  set and policy rules: a repeat read of an unchanged document costs ~90 ms instead of ~450 ms, and
  an upgrade or `--mode` change can never reuse an old verdict.
- `docs/plan-zero-touch-adoption.md`: the design, the measured findings that shaped it, the as-built
  notes and the known gaps.

### Security

- The adapter guards the **entire** decision and response-mapping path: any exception or malformed
  payload becomes an explicit `deny` with exit code 2 when `fail_closed`, because a non-blocking exit
  would let the raw document through.
- Enforced extensions are `parseable ∪ {.doc, .rtf, .odt, .ppt, .docm, .xlsb}`: formats aiitg cannot
  parse are denied rather than treated as clean.
- A structurally damaged cache entry is a **miss**, never a verdict, so corruption cannot flip a
  clean document to `deny`.
- `PostToolUse` findings are recorded (`POL-TOOL-001`) and reported through `additionalContext`; that
  event runs after the tool, so it never emits a permission verdict.

### Fixed

- `PostToolUse` payloads carried `permissionDecision`, a field that event does not honour — the
  warning could be dropped or the payload rejected as schema-invalid. Field sets are now per event
  and asserted by `TestEventContract`.
- `aiitg hook posttooluse` no longer accepts `--mode`, `--cache-dir`, `--quarantine-dir`,
  `--max-file-bytes` or `--queue`, which could never be applied on that event.
- `tests/m2/test_mcp.py` located the MCP server at a hardcoded `.venv/bin/aiitg-mcp`, so the smoke
  test could not run in CI.

### Added (project hygiene)

- `SECURITY.md` with an in-scope / out-of-scope threat model, `CONTRIBUTING.md`, this changelog,
  project URLs in `pyproject.toml`, and a GitHub Actions workflow (lint, typecheck, tests on Python
  3.11 and 3.12).

## [0.1.0] — prior work

Initial line, not released here: format-agnostic document model (`docx`, `xlsx`, `xls`, `pdf`,
`html`, `pptx`), 7 concealment detectors, coordinate-level evidence reports, sanitizer, trust labels,
rule-based policy engine, append-only audit log, human-approval queue and an MCP server. See the
README for the capability tables.
