# Zero-Touch Adoption — Design Plan (M3)

Status: design only. No source or test file was modified to produce this document.
Baseline verified on branch `main` at `e35b50e` (`git rev-parse HEAD`): `make test` = **105 passed**,
`make lint` (ruff, line-length 120) clean, `make typecheck` (mypy, `src` only) clean, Python 3.11+
(`pyproject.toml: requires-python = ">=3.11"`), venv at `.venv` (uv).

Goal: let tools that never call `aiitg-mcp` and never import `aiitg` still get input-trust
enforcement, by intercepting untrusted content **before it enters model context** and reusing the
existing M2 decision/approval/audit machinery.

---

## 1. Current architecture map

### 1.1 What was actually read

Read in full (all paths relative to repo root):

- `src/aiitg/core/document.py`, `core/detector.py`, `core/registry.py`, `core/evidence.py`,
  `core/errors.py`
- `src/aiitg/pipeline.py`, `policy.py`, `trust_label.py`, `sanitize.py`, `approval.py`, `audit.py`
- `src/aiitg/mcp_server.py`, `src/aiitg/cli/app.py`, `src/aiitg/cli/main.py`, `src/aiitg/__init__.py`
- `src/aiitg/parsers/base.py`, `parsers/__init__.py`, `parsers/html_parser.py`
- `src/aiitg/detectors/__init__.py`
- `tests/conftest.py`, `tests/fixtures/builders.py`, `tests/m2/test_mcp.py` (head),
  `tests/e2e/test_cli_e2e.py` (head)
- `Makefile`, `pyproject.toml`, `README.md` (architecture, pipeline, roadmap sections)

Grepped (symbol/line locations, not full read): `src/aiitg/detectors/*/*.py` for `id` / `name` /
`supported_kinds` / `default_severity`; `src/aiitg/cli/app.py` for `@app.command` line numbers;
`src/aiitg/parsers/*.py` for `register_parser` calls.

Not read: reporter implementations (`reporters/json_reporter.py`, `reporters/rich_reporter.py`),
individual non-HTML parsers, most detector bodies, most test bodies.

External contract facts used for Mechanism A were read from the live Claude Code hooks reference
(`https://code.claude.com/docs/en/hooks.md`, section "PreToolUse" and "PostToolUse"), not from memory.

### 1.2 Modules and symbols that matter

| Layer | Symbol | File:line | Role |
|---|---|---|---|
| IR | `TextRun`, `TextParagraph`, `Sheet`, `PdfPage`, `ParsedDocument` | `src/aiitg/core/document.py:16,30,40,52,63` | Format-agnostic document model; `ParsedDocument.all_text` at `:77` |
| Parsing | `FormatHandler`, `FormatRegistry`, `default_format_registry()` | `src/aiitg/core/registry.py:22,29,78` | Extension-first dispatch (`detect` `:42`), then parse (`:59`) |
| Parsing | `register_parser`, `ALL_HANDLERS` | `src/aiitg/parsers/base.py:20`, `src/aiitg/parsers/__init__.py:17` | 6 handlers: docx, xlsx, xls, pdf, html, pptx |
| Detection | `Detector`, `DetectorRegistry`, `run_scan`, `default_detector_registry()` | `src/aiitg/core/detector.py:14,67,129,153` | Chain runner; per-detector exceptions become report warnings (`:117-123`) |
| Detection | `ALL_DETECTORS` | `src/aiitg/detectors/__init__.py:19` | DET-001 zero_width, DET-002 hidden_style, DET-003 tiny_font, DET-004 hidden_sheet, DET-005 ooxml_nodes, DET-006 annotations, DET-007 document_meta |
| Evidence | `Severity`, `Location`, `Evidence`, `ScanReport` | `src/aiitg/core/evidence.py:15,52,81,103` | `ScanReport.summary` `:125`, `risk_score` `:133`, `trust_label`/`decision` fields `:115-116`, `to_dict` `:159` |
| Sanitize | `INVISIBLE_RE`, `BIDI_RE`, `SanitizeResult`, `Sanitizer`, `sanitize_paragraph` | `src/aiitg/sanitize.py:25,28,32,67,44` | strip/redact modes; works on `ParsedDocument` + evidence coordinates |
| Trust | `TrustLabelValue`, `TrustLabel`, `compute_trust_label` | `src/aiitg/trust_label.py:47,54,130` | safe/caution/dangerous + dimension scores; conservative caps `:167-176` |
| Policy | `DecisionAction`, `Decision`, `PolicyRule`, `PolicyEngine`, `default_policy` | `src/aiitg/policy.py:31,39,69,119,143` | First-match rules: POL-001 block dangerous, POL-002 quarantine any evidence, POL-003 human_approval caution, fallback allow |
| Pipeline | `PipelineResult`, `process_file` | `src/aiitg/pipeline.py:34,56` | The single reuse point: scan → sanitize → label → default policy |
| Approval | `ApprovalQueue.request/pending/approve/reject` | `src/aiitg/approval.py:24,31,57,66,69` | JSONL queue, pending entries carry report/decision/sanitized preview |
| Audit | `AuditLog.record/read/count` | `src/aiitg/audit.py:20,27,52,68` | Append-only JSONL: file, kind, risk, summary, label, decision |
| MCP | `scan_file`, `sanitize_file`, `trust_file`, `policy_file`, `serve` | `src/aiitg/mcp_server.py:35,53,64,71,93` | Explicit-call surface today; FastMCP tools return strings |
| Library | `scan_file`, `process_file` exports | `src/aiitg/__init__.py:38`, `:19` | Public API; must stay backward compatible |
| CLI | `scan`, `sanitize`, `trust`, `policy`, `audit`, `approvals`, `list-detectors`, `version` | `src/aiitg/cli/app.py:58,96,119,146,189,215,261,271` | Typer app; exit codes 0/1/2/3 documented in `README.md` |
| Entry points | `aiitg`, `aiitg-mcp` | `pyproject.toml` `[project.scripts]` | Console scripts |

### 1.3 Behaviors the design must respect (verified in code)

- Unsupported format → `FormatRegistry.parse` raises `ScanError(kind="unsupported_format")`
  (`src/aiitg/core/registry.py:59-68`).
- `process_file` on a parse error builds a `DANGEROUS` label and evaluates `default_policy()`;
  POL-001 therefore yields `block`. The label and decision are embedded into the report
  (`src/aiitg/pipeline.py:76-103`).
- `process_file` on an unsupported format returns a `DANGEROUS` label but **`decision=None`**
  (the `fmt is None` branch, `src/aiitg/pipeline.py:85-100`). Any integrator must treat
  `decision is None` as deny, not as allow.
- `default_policy()` is constructed fresh per call in `process_file` and in the MCP
  `policy_file` tool (`src/aiitg/mcp_server.py:71-83`); there is no shared policy singleton.
- `AuditLog.record` and `ApprovalQueue.request` both take a `ScanReport` + `Decision`, so any new
  mechanism can log/enqueue without touching either module.

---

## 2. Mechanism A — Claude Code `PreToolUse` / `PostToolUse` hook

### 2.1 Why a hook can work at all

Claude Code fires `PreToolUse` after tool parameters are formed and before the tool call is
processed, and matches on tool names including the built-ins `Read`, `WebFetch`, `Bash`, `Grep`,
`Glob`. The hook receives `tool_name`, `tool_input`, and `tool_use_id` on stdin and can return,
inside `hookSpecificOutput`:

- `permissionDecision`: `allow` | `deny` | `ask` | `defer` (precedence across hooks: deny > defer > ask > allow)
- `permissionDecisionReason`: for `deny` this text is shown to Claude
- `updatedInput`: replaces the entire tool input object before execution
- `additionalContext`: injected into Claude's context next to the tool result

Exit code 2 is a blocking error for `PreToolUse` and routes like `deny`. Hooks can be declared in
`.claude/settings.json` with a `matcher` and `timeout`. `PostToolUse` additionally supports
`updatedToolOutput`, which replaces the tool result before it is sent to Claude.
Important documented limitation: `PreToolUse` does **not** fire for files referenced with `@` in the
prompt (Claude Code inserts those while building the prompt).

For `Read`, `tool_input.file_path` is always absolute (Claude Code expands `~`/relative paths first).
`WebFetch` input is only `{url, prompt}`; the fetched body is not available in `PreToolUse`, so
WebFetch content inspection must happen in `PostToolUse` where `tool_response` is present.

### 2.2 Integration point and files to change

New code (additive; no existing signature changes):

- `src/aiitg/hooks/__init__.py` — exports `HookConfig`, `HookOutcome`, `handle_pretooluse`,
  `handle_posttooluse`.
- `src/aiitg/hooks/claude_code.py` — the hook logic: parse stdin JSON → classify → call
  `process_file` → map to a Claude Code hook response.
- `src/aiitg/cli/app.py` — add a `hook` command group (`aiitg hook pretooluse`,
  `aiitg hook posttooluse`) and a `hook-config` command that **prints** (never auto-writes) the
  `.claude/settings.json` fragment.
- Optional convenience: `aiitg hooks install --project` writes nothing without `--write`; default
  prints the snippet. This avoids mutating user config from an enforcement tool.

Backward compatibility: nothing in `aiitg/__init__.py`, `pipeline.py`, `policy.py`, `approval.py`,
`audit.py`, or the MCP server changes. The new CLI commands are additive; existing exit codes are
untouched.

### 2.3 Proposed interfaces

```python
# src/aiitg/hooks/claude_code.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

HookDecision = Literal["allow", "deny", "ask", "defer"]

@dataclass(frozen=True)
class HookConfig:
    enforce_extensions: frozenset[str] = frozenset({".docx", ".xlsx", ".xlsm", ".xls", ".pdf", ".html", ".htm", ".pptx"})
    quarantine_dir: Path = Path("~/.cache/aiitg/quarantine").expanduser()
    audit_path: Path | None = None          # None = do not audit
    queue_path: Path | None = None          # None = ask only, no queue write
    mode: str = "strip"                     # sanitize mode passed to process_file
    fail_closed: bool = True                # errors/unknown docs are denied
    substitute_sanitized: bool = True       # quarantine rewrites Read to sanitized text file
    max_file_bytes: int = 50 * 1024 * 1024

@dataclass(frozen=True)
class HookOutcome:
    permission_decision: HookDecision
    reason: str
    updated_input: dict[str, Any] | None = None
    additional_context: str | None = None
    exit_code: int = 0

def handle_pretooluse(payload: dict[str, Any], *, config: HookConfig | None = None) -> HookOutcome: ...
def handle_posttooluse(payload: dict[str, Any], *, config: HookConfig | None = None) -> HookOutcome: ...
def render_outcome(outcome: HookOutcome) -> tuple[str, int]: ...   # (stdout_text, exit_code)
```

`render_outcome` emits the exact documented JSON shape:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "aiitg: hidden content sanitized",
    "updatedInput": {"file_path": "/home/u/.cache/aiitg/quarantine/ab12cd.txt"},
    "additionalContext": "aiitg trust label: caution (DET-001 zero_width). The file you are reading was sanitized."
  }
}
```

### 2.4 Data flow — `Read`

1. Claude Code calls `Read {file_path: "/abs/report.docx"}`.
2. `aiitg hook pretooluse` reads the JSON from stdin.
3. Path classifier: extension in `enforce_extensions`? If not, exit 0 with no output (transparent,
   not audited by default).
4. `process_file(path, mode=config.mode)` runs the full existing pipeline (scan → sanitize →
   label → `default_policy`).
5. Map the decision:
   - `allow` → `HookOutcome("allow", reason=...)`, no `updatedInput`. Read proceeds normally.
   - `quarantine` → write `result.sanitized.text` to
     `<quarantine_dir>/<sha256[:16]>.txt`, return `permissionDecision: "allow"` with
     `updatedInput={"file_path": <sanitized path>, "offset": ..., "limit": ...}` (preserving any
     `offset`/`limit` the model passed) plus `additionalContext` describing the trust label and
     evidence. The model never sees the raw hidden payload; the human sees the same sanitized file
     path in the transcript.
   - `human_approval` → `permissionDecision: "ask"` with a reason naming rule POL-003; optionally
     `ApprovalQueue(queue_path).request(...)` first so the queue and the interactive prompt agree.
   - `block` → `permissionDecision: "deny"` with `permissionDecisionReason` naming the rule, the
     trust label, and the top evidence (detector id + location). Claude gets an actionable message
     and cannot read the file.
   - `decision is None` or scan `status == "error"` → `deny` when `fail_closed=True`
     (unsupported/parse-failed document), `allow` when `fail_closed=False`.
6. If `audit_path` is set, `AuditLog(audit_path).record(report=result.report, decision=..., ...)`.
   This reuses the existing append-only JSONL format unchanged.

### 2.5 Data flow — `WebFetch` and `PostToolUse`

`PreToolUse` on `WebFetch` cannot see the body. Two-phase approach:

- `PreToolUse` WebFetch: allow by default; optionally `deny` a URL allowlist/denylist via config.
  This is where a policy decision based on URL only can live.
- `PostToolUse` WebFetch: `tool_response` contains the fetched/processed text. Reuse the sanitizer's
  text-level primitives — `INVISIBLE_RE` and `BIDI_RE` from `src/aiitg/sanitize.py:25,28` — plus a
  small instruction-hint scan (the `_INSTRUCTION_HINTS` tuple in
  `src/aiitg/trust_label.py:40-45` is the existing precedent). Then return
  `updatedToolOutput` with the sanitized text and `additionalContext` warning.
  Note: this is text-level sanitization only; it cannot run the document parsers because the
  fetched payload is arbitrary HTML/text, and `updatedToolOutput` must match the tool's output
  shape.

An alternative, stronger WebFetch design: `PreToolUse` returns
`permissionDecision: "allow"` with `updatedInput={"url": ..., "prompt": ...}` pointing at the local
aiitg fetch proxy from Mechanism B, so the body is fetched and scanned before it ever reaches
Claude. That couples A to B and is deferred to M3.2.

### 2.6 Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Hook crashes / times out | Claude Code proceeds (non-blocking error) unless exit 2 | `handle_*` wraps everything; on unexpected exception, exit 2 with `deny` when `fail_closed=True` |
| Malformed stdin JSON | Same | Fail-closed deny for enforce-listed paths; allow otherwise |
| `updatedInput.file_path` sanitized file deleted | Read fails | Files are content-addressed; re-create on demand; orphan cleanup CLI command |
| `@`-referenced files | Hook never fires | Out of scope; document a `Read` deny rule as the mitigation (per Claude Code docs) |
| Bash extraction (`cat`, `curl`, `python`) | Content enters context un-scanned | Optionally match `Bash` and deny commands whose arguments reference enforce-listed extensions; heuristic, false positives likely |
| MCP filesystem read tools | Matcher can include `mcp__.*`, but each server has its own input schema | Treat as M3.1: add per-server adapters |
| Python hook latency | 100–400 ms per Read (document parse dominates) | Only enforce listed extensions; cache by `(path, mtime, size)` hash; `timeout` in settings |
| Windows path separators | Path match misses | Normalize `file_path.replace("\\", "/")` before any comparison |

### 2.7 Fail-closed vs assume-compromise placement

- **Detection is never 100%.** The hook does not claim the sanitized text is safe; it claims the
  content was inspected, labeled, and either rewritten or blocked.
- **Isolation**: the raw file is never copied into context; only a sanitized text file in a
  quarantine directory is exposed. The hook process reads one path and writes one file.
- **Least privilege**: the hook receives only `tool_input`; it does not enumerate the working tree
  or call the network.
- **Human approval**: `human_approval` maps to Claude Code's native `ask` prompt, and optionally to
  the existing `ApprovalQueue` so the same review workflow used by `aiitg approvals` applies.
- **Audit**: every enforced path writes one `AuditLog` line; the log is append-only JSONL and
  already carries label, decision, and risk score.

---

## 3. Mechanism B — Reverse proxy / HTTP interception

### 3.1 Integration point

A local HTTP server that speaks the same wire protocol as the upstream model API. The consumer
points its base URL at the proxy (for example `ANTHROPIC_BASE_URL=http://127.0.0.1:8787` for Claude
Code, or `OPENAI_BASE_URL` / an OpenAI SDK `base_url` argument). The proxy inspects request bodies,
scans document-like parts, then forwards with `httpx`.

Dependency note: `mcp 1.30.0` already pulls `starlette`, `uvicorn`, `python-multipart`,
`sse-starlette`, and `httpx` (verified via `importlib.metadata` in `.venv`). The proxy would still
declare `starlette`, `uvicorn`, and `httpx` explicitly in a new `[project.optional-dependencies]`
extra (`proxy`) so the core install stays as small as it is today.

### 3.2 Files to change / add

- `src/aiitg/proxy/__init__.py`
- `src/aiitg/proxy/config.py` — `ProxyConfig`
- `src/aiitg/proxy/inspect.py` — body parsing + part extraction + rewrite
- `src/aiitg/proxy/server.py` — Starlette app, forwarding, error shaping
- `src/aiitg/cli/app.py` — `aiitg proxy` command
- `pyproject.toml` — optional `proxy` extra; no change to existing dependencies

### 3.3 Proposed interfaces

```python
# src/aiitg/proxy/inspect.py
@dataclass(frozen=True)
class ContentPart:
    pointer: str                 # JSON pointer to the part, or multipart field name
    kind: str                    # "document" | "image" | "text"
    media_type: str | None
    filename: str | None
    data: bytes

def detect_provider(path: str, body: bytes, content_type: str) -> str: ...   # "anthropic" | "openai" | "unknown"
def extract_parts(body: bytes, content_type: str, provider: str) -> list[ContentPart]: ...
def apply_rewrite(body: bytes, content_type: str, provider: str, rewrites: dict[str, Any]) -> bytes: ...

# src/aiitg/proxy/server.py
@dataclass(frozen=True)
class ProxyConfig:
    upstream_base_url: str
    provider: str = "auto"
    audit_path: Path | None = None
    queue_path: Path | None = None
    mode: str = "strip"
    fail_closed: bool = True
    max_body_bytes: int = 64 * 1024 * 1024
    human_approval_status: int = 409          # 409 for M3.1; "hold" deferred

def create_app(config: ProxyConfig) -> Starlette: ...
```

Payload extraction per provider (initial scope):

- Anthropic Messages: `messages[*].content[*]` where `type` is `document` (`source.type == "base64"`),
  `image` (base64), or `text` (only the long-text heuristic).
- OpenAI Chat Completions: `messages[*].content` as a list of parts with `type` `text`,
  `image_url` (`data:` URL), or `file` (`file_data` / `file_id`).
- Multipart uploads (`/v1/files`, batch endpoints): each `application/octet-stream`/document part is
  a `ContentPart`; the proxy buffers within `max_body_bytes`.

Format resolution reuses the existing extension-first `FormatRegistry`
(`src/aiitg/core/registry.py:42-57`). All bundled parsers pass `sniff=None`
(verified via `grep register_parser src/aiitg/parsers/*.py`), so content that lacks a matching
extension is **not** detected today. The proxy therefore maps `media_type`/filename/magic bytes to a
temp filename with the right extension before calling `process_file`. This keeps `FormatRegistry`
untouched in M3.1.

### 3.4 Data flow

1. Client sends `POST /v1/messages` with a base64 PDF part.
2. Proxy buffers the body (bounded by `max_body_bytes`), determines provider and parts.
3. Each document part is written to a temp file with a resolved extension; `process_file(path)`
   produces report + label + decision. The temp file is deleted after the decision.
4. Decision mapping:
   - `allow` → forward the original body unchanged.
   - `quarantine` → replace the document part with a text part containing `result.sanitized.text`
     (plus a short system note part identifying aiitg and the trust label); forward the rewritten body.
   - `human_approval` → return `409` with a provider-shaped error body naming the rule and the
     approval request id; enqueue via `ApprovalQueue.request`. A later `--hold` mode can block the
     HTTP request until `approve`/`reject` (deferred; adds timeout/liveness risk).
   - `block` / `decision is None` / parse error → `403` with the same shape and the policy reason.
5. Responses are streamed through unchanged in M3.1 (`text/event-stream` is not inspected).
6. Every decision optionally writes `AuditLog` (request path, provider, label, decision, request id).

### 3.5 Optional local file-watch inbox mode

A materially simpler variant: watch a directory, scan each new file, write sanitized copies to an
`outbox/`, and emit an audit line. It avoids HTTP framing, streaming, provider schema drift, and
TLS questions, but it does not actually sit on the data path unless the consumer is re-pointed to
the sanitized directory. Assessed as a fallback only; not recommended as the first increment because
it reintroduces the exact adoption friction the goal is trying to remove.

### 3.6 Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Provider schema drift | Parts missed, content forwarded unscanned | Fail-closed on unknown part `type` when the part looks document-like; log unhandled part types |
| Streaming/chunked request bodies | Cannot inspect before forwarding without buffering | Buffer up to `max_body_bytes`; over limit → 413 |
| Multipart parsing | Malformed boundaries | Reject with 400 (fail-closed) |
| Client ignores base URL env var | Traffic never reaches proxy | Out of scope; document per-client configuration |
| TLS / certificate pinning | Setting a base URL may disable pinning or fail | Proxy binds localhost plain HTTP; document that upstream TLS is proxy→upstream |
| Provider features requiring exact request echo | Rewritten body breaks cache/signature semantics | Only rewrite when a decision is non-allow; otherwise byte-for-byte passthrough |
| Image/document parts with unsupported formats | aiitg has no OCR | Image parts pass through with a warning; document-like binary parts block when fail-closed |
| Large base64 expansion in logs | Audit bloat / secrets | Audit stores metadata only, never body content |

### 3.7 Fail-closed vs assume-compromise placement

- **Detection is never 100%.** The proxy blocks/quarantines on evidence and on *uninspectable*
  document-like inputs, rather than assuming a parse failure means "clean".
- **Isolation**: temp files are written to a private cache directory and deleted after inspection;
  the inspector never executes document content or macros.
- **Least privilege**: the proxy holds upstream credentials only to forward the client's own
  authorization header; it does not acquire its own credentials and never stores request bodies.
- **Human approval**: `409` + `ApprovalQueue` entry; the human reviews the same evidence JSON the
  CLI and MCP already expose.
- **Audit**: one `AuditLog` line per inspected request, including the provider path and the
  decisions, with no raw body content.

---

## 4. Coverage-gap table

Legend: **yes** = covered on the normal path; **partial** = covered only under stated conditions;
**no** = bypasses the mechanism.

| Untrusted content path | Mechanism A (Claude Code hook) | Mechanism B (local proxy) | Notes |
|---|---|---|---|
| `Read` of a local docx/xlsx/xls/pdf/html/pptx | yes (pre-execution decision, sanitized substitution) | no | A is the only mechanism that sees the path before the read |
| Files referenced with `@` in the prompt | no | no | Documented Claude Code behavior: `PreToolUse` does not fire; mitigate with a `Read` deny rule |
| `WebFetch` of a URL with hidden text | partial | no | A can only decide on the URL pre-fetch; body sanitization requires `PostToolUse.updatedToolOutput` and is text-level only |
| `WebSearch` results | no | no | No tool-output rewriting designed for this path |
| `Bash` (`cat`, `curl`, `python -c`) extracting a document | no (unless a heuristic Bash matcher is added) | no | Shell is an unbounded parser; not interceptable by path or body inspection |
| MCP filesystem/read tools (`mcp__.*`) | partial | no | Tool name can be matched, but input schemas vary per server |
| Anthropic-compatible API client pointed at the proxy | no | yes | Requires client base-URL configuration |
| OpenAI-compatible API client pointed at the proxy | no | yes | Requires client base-URL configuration |
| Client with hardcoded endpoint or ignoring base URL | no | no | Proxy is never on the path |
| Chunked / streaming request bodies | no | partial | Needs full buffering bounded by `max_body_bytes` |
| Base64 document blobs nested inside an unrecognized JSON shape | no | partial | Only handled if the provider schema is recognized |
| Multipart file uploads | no | yes | `python-multipart` parsing |
| Long pasted plain text (no file) | no | partial | Heuristic only; `text/plain` is not a `FormatRegistry` kind |
| Images / scanned PDFs / OCR-hidden text | no | no | aiitg has no OCR in M0–M2; images are passed through with a warning |
| Audio / video inputs | no | no | Out of scope |
| Unsupported document formats (`.doc`, `.rtf`, `.odt`) | partial (fail-closed deny) | partial (fail-closed block) | Never semantically scanned, but denied rather than trusted when fail-closed |
| `gRPC` / non-HTTP transports | no | no | Out of scope |
| Model responses containing fetched content | partial (`PostToolUse` rewrite for supported tools) | no | Response stream is passed through in M3.1 |

---

## 5. Recommendation and rationale

**Recommend Mechanism A first, as M3.0; schedule Mechanism B as M3.1; keep the file-watch inbox as a
fallback only.**

Rationale, weighing the three axes:

| Axis | Mechanism A | Mechanism B |
|---|---|---|
| Adoption friction | One project settings file; no change to the consuming library | Every client must be re-pointed (env var or SDK `base_url`), and any client that ignores it is uncovered |
| Implementation cost | Low: a JSON-in/JSON-out CLI command over `process_file`; no new server, no new protocol parsing | High: provider schema adapters, multipart, buffering, streaming, error-shape compatibility, an extra install extra |
| Coverage | Best for the file-read path (blocks before context), Claude Code specific; Bash and `@` refs remain gaps | Best for API-based tools on any client; blind to file reads and to clients that ignore base URLs |

A is the only mechanism that acts **before** untrusted content enters the model context for the most
common path (a file read), and it reuses `process_file`, `default_policy()`, `ApprovalQueue`, and
`AuditLog` with zero changes to those modules. B is broader but strictly later: it becomes valuable
once A is proven and the remaining consumers are API clients rather than Claude Code.

### 5.1 Minimal first increment (M3.0)

1. [x] `src/aiitg/hooks/__init__.py` and `src/aiitg/hooks/claude_code.py` with `HookConfig`,
   `HookOutcome`, `handle_pretooluse`, `handle_posttooluse`, `render_outcome`.
2. [x] CLI: `aiitg hook pretooluse` and `aiitg hook posttooluse` (read stdin, write stdout, exit 0/2),
   plus `aiitg hook-config` that prints the `.claude/settings.json` snippet.
3. [x] Enforcement scope: `Read` on the enforced extensions; `allow` / `deny` / `ask` mapping;
   `quarantine` rewrites `Read` to a sanitized `.txt` under a cache quarantine directory.
4. [x] Optional `--audit <path>` writing `AuditLog` entries with `AuditLog.record`; optional
   `--queue <path>` writing `ApprovalQueue` entries for `human_approval`.
5. [x] `fail_closed=True` default; unsupported format, parse error, or `decision is None` → deny for
   enforce-listed extensions.
6. [x] Tests in `tests/m3/` (see Section 6). No changes to existing modules, so the 105 tests stay
   green by construction.
7. [x] `(path, mtime_ns, size)` decision cache that short-circuits **before** `process_file`
   (added beyond the original plan after the latency measurement below).

Explicitly deferred to M3.1+: WebFetch `updatedToolOutput` rewriting, Bash heuristics, MCP tool
adapters, the HTTP proxy, and any auto-writing of user settings.

---

## M3.0 as-built

What shipped: `src/aiitg/hooks/{__init__,cache,claude_code}.py`, `src/aiitg/cli/hook_cmd.py`, a
4-line registration diff in `src/aiitg/cli/app.py`, and `tests/m3/`. Total suite: **183 tests**,
0 failures; `ruff check src tests` and `mypy src` clean. The count is now enforced by
`tests/test_readme_badge.py`, which fails when the README badge or its `make test # N tests` comment
disagrees with the collected test count (it had gone stale twice).

Deviations from the plan, and why:

1. **`ENFORCED` is `PARSEABLE ∪ {.doc, .rtf, .odt, .ppt, .docm, .xlsb}`.** The plan only listed
   parseable extensions. A protocol PoC showed that a `.doc` then took the "not enforced" branch and
   was **allowed** — the opposite of fail-closed. Unparseable-but-document-like formats now deny when
   `fail_closed`, and that decision is audited with a synthetic `ScanReport.from_error` + POL-001.
2. **The crash guard covers the whole decision *and* response-mapping path.** The same PoC crashed in
   the mapping stage (`Evidence.detector`; the real attribute is `detector_id`) and exited 1, which
   Claude Code treats as a *non-blocking* error: the read proceeds and the raw file reaches the model
   anyway. Both `handle_pretooluse` and `handle_posttooluse` now convert any exception into an
   explicit `deny` + exit 2 when `fail_closed`, and `tests/m3` injects a fault to assert it.
3. **`handle_posttooluse` never sets `updatedToolOutput`.** Claude Code requires the replacement to
   match each built-in tool's output shape, which is not verified here; M3.0 reports invisible/bidi
   characters through `additionalContext` only, which works for every tool. The WebFetch rewrite path
   moves to M3.1 with a per-tool shape adapter.
4. **`HookOutcome.audit` carries the written audit entry** so tests and callers can assert the
   append-only line without re-reading the file. The shipped `AuditLog`/`ApprovalQueue` signatures are
   untouched.
5. **Cache hit re-writes the quarantined substitute** if it is missing, and a cache miss for a
   `status == "error"` report is cached like any other decision (the report carries the error, so a
   repeat read does not re-parse a corrupt file).

Post-review fixes (review found one contract bug and one silent-failure gap):

6. **`render_outcome` is event-aware.** It emitted `permissionDecision` /
   `permissionDecisionReason` for *every* event, but the documented per-event table gives
   `permissionDecision` to `PreToolUse` and `PreModelSwitch` only — `PostToolUse` uses top-level
   `decision: "block"` + `reason`, and its only context field is `additionalContext`. The first
   `PostToolUse` payload therefore either had its warning dropped or was rejected as
   schema-invalid. The field sets now live in one place (`DOCUMENTED_FIELDS`) and `render_outcome`
   renders per event; `tests/m3/test_hooks.py::TestEventContract` asserts the emitted field set is a
   subset of the documented set for every outcome kind. The old tests only asserted the absence of
   `updatedToolOutput`, which is why a green suite hid the bug.
7. **PostToolUse can no longer emit a verdict at all.** A clean result prints nothing (exit 0), a
   finding prints `additionalContext` only, and a malformed payload or internal fault uses the
   documented "exit 2 + stderr" channel with no JSON on stdout.
8. **`hook-config` embeds an absolute executable path** (resolved with `shutil.which`, `shlex.quote`d)
   and warns on stderr when the executable is not on PATH: a hook command that cannot start is a
   *non-blocking* error in Claude Code, so the document would reach the model **unscanned** while the
   user believes it was checked. `aiitg hook doctor` checks the executable, the quarantine and cache
   directories, the fail-closed default and the enforced-format count, and exits 1 on any failure.
9. **The PostToolUse scan is bounded** (`HookConfig.max_posttooluse_texts`, default 64) so a large
   tool result cannot force a full-text scan on every call.

Second review round — what else was wrong (all fixed in this branch):

10. **`aiitg hook posttooluse` accepted options it could not apply** (`--mode`, `--cache-dir`,
    `--quarantine-dir`, `--max-file-bytes`, `--queue`). A flag that silently does nothing is the same
    failure class as a hook that silently does not run. Only `--audit` and `--fail-open` remain, and
    `--audit` now actually records PostToolUse findings (`POL-TOOL-001`, action `allow`, counts in the
    note) instead of being ignored.
11. **`hook doctor` did not check that the hook was wired.** It now reads the project and user
    `.claude/settings.json` / `settings.local.json` (`--settings` to point elsewhere), finds a
    `PreToolUse` command calling `aiitg hook pretooluse`, and verifies that command's executable
    resolves — a wired-but-unstartable hook is reported as FAIL rather than looking fine.
12. **Cached verdicts were not bound to the build.** The key is still `(path, mtime_ns, size)`, but
    entries now carry a namespace of `version | mode | detector set | policy rules` and a mismatched
    namespace is a miss, so an upgrade or `--mode` change cannot keep serving yesterday's verdict for
    an unchanged file. (`_cache_namespace`.)
13. **A damaged cache entry could become a `deny`.** `HookCache.get` now validates the entry's
    required keys and types and returns a miss for anything structurally incomplete, so corruption
    cannot flip a clean document. Verified live: deleting `report` from an entry and re-running still
    produced `allow`.
14. **`allow` decisions stored the document's text.** Only a `quarantine` decision needs
    `sanitized_text` (to write the substitute), so everything else stores an empty string instead of
    copying clean document bodies into the cache directory.
15. **Repository hygiene**: version bumped to `0.2.0` with a `CHANGELOG.md`; `SECURITY.md` (in-scope /
    out-of-scope threat model, including "the cache is not a trust boundary") and `CONTRIBUTING.md`;
    `[project.urls]` in `pyproject.toml`; README install path for end users (`uv tool install` /
    `pipx install`, because the hook needs `aiitg` on `PATH`) and a link to this document.

## Known gaps (M3.0, deliberate)

- No prune/cleanup command for the quarantine and decision-cache directories (they are inert data and
  safe to delete, but nothing expires them; the plan's §2.6 "orphan cleanup CLI" is not implemented).
- Repeated reads of the same unchanged document append one audit line per read (correct for an audit
  trail, but worth knowing before sizing the log).
- The `decision is None` branch in the adapter is unreachable in practice: `run_scan` already returns
  `status == "error"` for unsupported formats, which the pipeline turns into `POL-001` → `block`.
- The cache directory is user-writable, so a local attacker with the same level of access can forge a
  verdict. Documented in `SECURITY.md` as out of scope (the cache is not a trust boundary); a
  tamper-evident cache would need signing and is not attempted here.
- Still unverified end-to-end: `PostToolUse.updatedToolOutput` rewriting (needs per-tool output
  shapes) and anything requiring a live Claude Code session (matcher/`if` resolution, timeouts, the
  `ask` prompt rendering, `@`-referenced files).

Measured latency, real console script (`.venv/bin/aiitg hook pretooluse`, 5 runs, docx):

| path | median |
|---|---|
| cold (cache miss, `process_file` runs) | **447 ms** |
| warm (cache hit) | **91 ms** |
| floor (non-enforced extension: interpreter + `typer`/`aiitg` import) | 92 ms |

The cache therefore lands exactly on the floor: a repeat read of an unchanged document is ~5× faster,
and the remaining 91 ms is interpreter + CLI import cost that no in-process cache can remove. An
enforced read is roughly one extra import-and-parse over what `Read` already costs the agent.

---

## 6. Test plan

### 6.1 Unit tests (new `tests/m3/`)

`tests/m3/test_hooks.py`:

- Pure function tests over `handle_pretooluse` with fixture payloads: benign docx → `allow`;
  zero-width docx → `deny` or `ask` (assert the exact mapping from the default policy: any evidence
  → POL-002 quarantine, so the default policy will rarely reach `ask`; assert the actual behavior
  rather than the intent); unsupported extension → allow without invoking the pipeline
  (assert no audit line).
- `quarantine` path: assert the returned `updatedInput["file_path"]` exists, contains sanitized
  text with no `\u200b`, and that the original file is unchanged.
- `session_id` / `tool_name` propagation into the audit line (new optional `AuditLog.record`
  kwargs, defaulted so existing callers are unaffected).
- Malformed stdin and unexpected exception → `exit_code == 2` and `deny` when `fail_closed=True`.
- Reuse `tests/fixtures/builders.py` for inputs (`build_docx_benign`, `build_docx_with_zerowidth`) —
  no new binary fixtures are committed.

`tests/m3/test_proxy.py` (M3.1, but the plan reserves the file):

- `httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(cfg)))` with a fake upstream ASGI
  app; assert blocked body never reaches the fake upstream and forwarded bodies are byte-identical
  when `allow`.
- Base64 document part with zero-width content → rewritten to a text part; assert the base64 is gone
  from the forwarded body.
- `human_approval` → 409 and one `ApprovalQueue` pending entry.
- Oversized body → 413; malformed multipart → fail-closed response.
- Streaming response passthrough: fake upstream returns `text/event-stream`; assert chunks arrive
  in order and unmodified.

### 6.2 End-to-end tests

Hook e2e invokes the real console script exactly the way Claude Code does:

```bash
printf '%s' '{"session_id":"t","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/abs/evil.docx"},"tool_use_id":"toolu_1"}' \
  | .venv/bin/aiitg hook pretooluse --audit /tmp/aiitg-audit.jsonl --queue /tmp/aiitg-queue.jsonl
```

Assertions: exit code 0 with JSON on stdout for a decision, exit 2 for a fail-closed deny, and a
parseable audit line. Generate `/abs/evil.docx` with `tests/fixtures/builders.build_docx_with_zerowidth`
in a fixture rather than committing a binary.

CLI compatibility e2e (existing `tests/e2e/test_cli_e2e.py` style, Typer `CliRunner`): add only new
command tests; do not modify existing ones.

### 6.3 Commands and keeping the 105 green

```bash
.venv/bin/pytest -q tests/m3          # new tests
make test                             # full suite: must stay at 105 + new count
make lint                             # ruff over src tests
make typecheck                        # mypy over src (new hook/proxy modules included)
```

Guardrails for backward compatibility:

- No edits to `src/aiitg/__init__.py`, `pipeline.py`, `policy.py`, `approval.py`, `audit.py`,
  `mcp_server.py`, or existing CLI commands.
- New keyword arguments on `AuditLog.record` / `ApprovalQueue.request` must have defaults so all
  current call sites and tests still pass.
- Do not change `ScanReport.to_dict()` shape or existing exit codes 0/1/2/3.
- Avoid adding a new `ParsedDocument.kind` (e.g. `"text"`) in M3.0: detectors declare frozen
  `supported_kinds` sets, and touching them risks detector-chain tests. Use temp files with
  known extensions, and for plain text wrap it in minimal HTML so the existing `HtmlParser` and
  `supported_kinds` apply.

---

## 7. Risks, rollback, non-goals

### 7.1 Risks

- **Hook-contract drift**: the `hookSpecificOutput` schema is an external contract and may change.
  Mitigation: pin the documented field names in one renderer (`render_outcome`), test it directly,
  and keep the CLI stdout shape in one place.
- **Performance**: each enforced `Read` runs a full parse + 7 detectors. Mitigation: extension
  allowlist, `(path, mtime, size)` result cache, hook `timeout` in settings, and an `--no-scan`
  passthrough for large files.
- **False positives**: `default_policy` quarantines on any evidence (POL-002), so legitimately
  formatted documents with annotations or small fonts get rewritten. This is intentional
  (assume compromise), but the actionable reason text must name the detector and location.
- **Sanitized substitution loses structure**: `Sanitizer` produces plain text
  (`SanitizeResult.text`), so tables/layout are flattened for the model. This is a real usability
  cost and a candidate for a later `--mode redact` default or a structure-preserving sanitiser.
- **Proxy risks** (M3.1): provider schema drift, streaming buffering, credential handling,
  TLS interception questions, audit bloat if bodies are logged. Mitigation: metadata-only audit,
  byte-for-byte passthrough on allow, explicit extra dependency, no response inspection in M3.1.
- **Audit privacy**: `AuditLog` entries contain file names and evidence snippets by design; in
  shared environments this may leak sensitive names. Mitigation: document retention and path
  redaction as a follow-up.

### 7.2 Rollback

- Mechanism A: remove the hook entry from `.claude/settings.json` (or the plugin), or point it at
  `aiitg hook pretooluse --fail-open --no-audit`. No aiitg package state is required for the
  consumer to keep working, and no existing API/CLI/MCP behavior changed, so rollback is a config
  edit.
- Mechanism B: stop `aiitg proxy` and remove the base-URL override. Because the proxy only rewrites
  requests when a decision is non-`allow`, a stopped proxy cannot corrupt traffic.
- Both: the quarantine directory and JSONL audit/queue files are inert data on disk and can be
  deleted at any time.

### 7.3 Non-goals (this plan)

- OCR, image analysis, audio/video scanning, or any non-text hidden-content detection.
- Intercepting `Bash`, shell pipelines, `@`-referenced prompt files, `WebSearch`, or arbitrary
  non-HTTP transports.
- Response-side scanning of model output (the WebFetch `PostToolUse` case is text sanitization of a
  tool result, not model output inspection).
- A hosted or multi-tenant gateway; both mechanisms are local-first by design.
- Changing detection accuracy, detector IDs, the policy rule set, or the trust-label thresholds.
- Auto-editing user or project settings files without an explicit `--write`.

---

## 8. Open questions for the human (Moon)

These are the decisions that actually change the design; each has a default proposed so work can
start without blocking.

1. **Primary surface for M3.0**: Claude Code only, or must the first increment already support an
   API-client path? Default: Claude Code hooks first; proxy second.
2. **Fail-open vs fail-closed default**: when a document cannot be parsed or `decision is None`,
   should the default be deny (fail-closed) with an explicit `--fail-open` escape hatch, or the
   reverse? Default: fail-closed for enforce-listed extensions.
3. **Quarantine behavior for `Read`**: substitute a sanitized `.txt` via `updatedInput` (smooth,
   but loses layout), or deny and let the model ask a human (safer, more friction)? Default:
   substitute, with the flattening cost documented.
4. **Human approval UX**: use Claude Code's native `ask` prompt only, or also write an
   `ApprovalQueue` entry so `aiitg approvals` is the single review surface? Default: both.
5. **Audit/queue defaults**: where do the audit log and approval queue live by default — project
   `.aiitg/` or user cache `~/.cache/aiitg/`? And what retention/rotation policy is acceptable for
   a file that records document names? Default: user cache, no automatic rotation, documented.
6. **Hook installation**: print a settings snippet (safe, manual) or add `aiitg hooks install` that
   writes `.claude/settings.json`/`.claude/settings.local.json`? Default: print only.
7. **Proxy packaging** (M3.1): a `proxy` optional extra in this package, or a separate distribution?
   Default: optional extra.
8. **Proxy behavior for `human_approval`** (M3.1): immediate `409` + queue, or hold the request
   until a human decides (with a timeout)? Default: immediate 409.

