# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-10-09

Code-context coverage: the gate now reads source files and agent rule files, not just documents.

### Added

- **`text` parser** (`src/aiitg/parsers/text_parser.py`): one paragraph per line with a 1-based line
  number for source, config and prose files, carrying the language's comment-syntax family. The format
  registry gained `FormatHandler.basenames` so extensionless rule files (`.cursorrules`) resolve by
  name, and extension keys are normalised (a dotted registration can no longer create an unreachable
  handler).
- **DET-008 `comment_directive`** (`src/aiitg/detectors/text/comment_directive.py`): detects an unsafe
  instruction written as an ordinary comment or in a rule file — the inference-time context-injection
  channel of [arXiv:2610.05139](https://arxiv.org/abs/2610.05139). A hit needs a directive frame
  (marker / addressed / imperative / authority / safety-negation) **and** an insecure objective from
  the paper's ten weakness classes; descriptive prose, prohibitions and fix-notes are not reported.
- **Defusing on quarantine** (`defuse_comment_line`): the sanitized substitute replaces the directive
  with an inert comment, keeping the language's syntax and the line's indentation, so "quarantine" is
  not a no-op for code files. The removal is recorded in `SanitizeResult.removed`.
- **Hook enforcement** for source/config extensions and agent rule files (`AGENTS.md`, `CLAUDE.md`,
  `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `copilot-instructions.md`); `aiitg hook doctor` reports
  the enforced set.
- **Trust labeling**: a HIGH/CRITICAL comment directive caps the score below the `dangerous` threshold
  (an instruction the model would follow may never read as `safe`), earning its own content-dimension
  weight.
- **Documentation**: `docs/comment-directive-coverage.md` (design, measurements, boundaries);
  README/README.ja sections for the new surface.
- **Tests** (+98): the paper's attack corpus (32 payloads, two verbatim), a 46-comment benign corpus
  across five comment syntax families, parser/registry, defusing, hook enforcement and CLI e2e.

### Fixed

- The hook's block message said the file's "hidden content" never reached the model; a comment
  directive is visible to a human reader too, so the wording is now format-agnostic.

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
