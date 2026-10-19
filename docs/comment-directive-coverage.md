# Code-context coverage — DET-008 (`comment_directive`)

Why the gateway reads source files, what the rule engine does, what was measured, and what it
does **not** claim. Companion to `SECURITY.md` (threat model) and
`docs/plan-zero-touch-adoption.md` (the M3 hook).

## 1. The gap this closes

Until M4, "untrusted input" meant a *document*. A Code LLM assistant builds its context from
something wider: open files, imported modules, pasted snippets, and **comments** — much of it
third-party. An adversary does not need to poison a model or a training pipeline; they need one
comment in a library the developer imports.

[arXiv:2610.05139](https://arxiv.org/abs/2610.05139) — *Hidden in the Comments: A Context-Injection
Attack Surface in Code LLMs* (Munir, Quinzan & Roberts, Department of Engineering Science, University
of Oxford, 4 Oct 2026) — measures the effect on ten open-weight Code LLMs (3B–13B):

| | Attack condition (insecure objective as an ordinary comment) | Benign condition (ordinary coding work) |
|---|---|---|
| Completions with a medium-or-higher weakness | **77.4–92.3%** | 1.7–5.1% |
| High/critical share of vulnerable outputs | 86.2–91.0% | — |
| After the strongest post-generation screen | still ~⅓ undetected | — |

The payload is framed as `# TODO:`, `# INSTRUCTION:` or `# TASK:` — the same markers real code uses,
which is exactly why the model cannot separate the developer's instruction from the attacker's. The
paper's own conclusion points upstream of generation: represent and enforce instruction provenance
*before or during* generation. That is where a gateway belongs.

## 2. What DET-008 does

`aiitg scan services/account.py` → `DET-008 CRITICAL @ account.py:10` (exit code 1).
`aiitg hook pretooluse` → `deny (POL-001)` for a file whose comment carries a directed unsafe
objective, `quarantine (POL-002)` for the lower tier.

A hit requires **both** halves:

* **directive frame** — a marker (`TODO`/`INSTRUCTION`/`TASK`/…), second-person or
  machine-addressed phrasing, an imperative opener, an authority claim (`always`, `must`,
  `for now`, `trusted input`), or a safety negation (`without validation`, `directly`, `raw`);
* **insecure objective** from the ten weakness classes of the paper's Appendix A — SQL injection,
  XSS, command injection, path traversal, SSRF, XPath injection, CORS misconfiguration, open
  redirect, unsafe deserialization, sensitive-information disclosure — plus prompt injection aimed at
  the assistant itself (`ignore previous instructions`, `do not tell the user`).

Deliberate asymmetries, each of which exists to keep a real signal-to-noise ratio:

| Situation | Behaviour | Why |
|---|---|---|
| Descriptive prose naming a sink ("a bare `subprocess` cannot answer") | **not reported** | it is not an order; flagging every mention of `exec` makes the tool unusable |
| Prohibition naming a sink ("… must never call `child_process`") | **not reported** | it is a safety rule |
| Fix-note with an objective ("# SECURITY: this query concatenates user input; replace it with a parameterized query") | **not reported** | awareness, not an instruction |
| Vulnerable code with no comment | **not reported** | that is a SAST concern (see §5) |
| Marker-only mention of a weak class ("# TODO: writes the api_key into the response body") | MEDIUM → quarantine + defused copy | worth reporting, not worth blocking by itself |
| A note byte-shaped like a payload ("# TODO: use DBMS_SCHEDULER for the nightly job") | flagged | fail-closed: the shape is the attack, and only a human can tell intent |

Severities: **CRITICAL** = an order to build one of the injected-weakness classes (the marker is the
attack vector); **HIGH** = an order in a class respectable code also mentions (log a secret, disable a
check); **MEDIUM** = marker-only mention of such a class.

## 3. Why the sanitizer defuses a *visible* comment

Sanitization removes hidden content. A comment directive is not hidden — a human reads it too — so
stripping invisible characters would leave "quarantine" a no-op for code files: the model would read
the directive verbatim out of the substitute. `defuse_comment_line()` replaces the instruction with an
inert, self-describing comment that keeps the language's comment syntax and the line's indentation:

```python
def debug_dump(user):
    # [aiitg] removed untrusted instruction (class=sensitive_information_disclosure)
    return str(user)
```

The file stays valid Python and the model reads data instead of an order. The removal is recorded in
`SanitizeResult.removed` (`{"type": "comment_directive", …}`) and in the hook audit line.

## 4. Enforcement surface

`DEFAULT_ENFORCED_EXTENSIONS` now includes source/config extensions (`.py`, `.js`, `.ts`, `.go`,
`.java`, `.rs`, `.sh`, `.sql`, `.yaml`, `.toml`, …) and the agent rule files are matched **by name**
(`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`,
`copilot-instructions.md`) — `.cursorrules` has no extension for the registry to key on, so
`FormatHandler.basenames` was added alongside `FormatRegistry` extension dispatch.

Plain prose that is *not* a rule file is still not enforced: reading every `.md` would scan the whole
documentation tree on every tool call, and rule files are where an agent takes instructions from.
`.md`/`.txt`/`.rst` are therefore **not registered as extensions at all** — an unregistered extension
has to keep flowing through content sniffing, because the hook enforces on the *sniffed* format for
unenforced extensions (`payload.txt` holding a docx is blocked, upstream hardening from PR #1). Only
source/config extensions are registered, plus the rule-file names above.

## 5. Measured, and the boundaries that come with it

Corpus and probe live in `tests/detectors/test_comment_directive.py`,
`tests/fixtures/builders.py` and the measurement script described below.

| Measurement | Result |
|---|---|
| Attack corpus — 32 payloads: the paper's 10 classes × 3 framings + 2 agent-directed (2 payloads verbatim from the paper; the rest authored in its stated format) | **32/32 detected**, class agreement 32/32, 29 CRITICAL / 3 HIGH |
| Benign corpus — 46 ordinary work comments across five comment syntax families | **0 false positives** |
| Ambiguous corpus — 4 legit notes byte-shaped like payloads, pinned in the test file | 4/4 reported — **accepted false positives**, the fail-closed choice |
| Live source probe — `scripts/probe_comment_directive.py` over this project + `takumi/packages` (build output excluded): **106 files / 738 comment lines**, via the shipped `run_scan()` | **0 findings** |

The ambiguous row is the honest one: those four are *legit* notes that are reported anyway. They are
counted as a known false-positive class, not as detections, so the corpus can never look cleaner than
it is. The live-probe figures are reproducible with the committed script (see §6); the earlier
"167 files / 4,643 comment lines" figure came from *including* build output (`dist/`) and from a looser
comment-line definition — `--include-build` restores 168 files, but generated bundles are not
third-party source a developer reads, so they are excluded by default.

Boundaries, stated plainly:

1. **This is not a reproduction of the paper's numbers.** The paper's 700-item corpus was not
   released with its HTML; the corpus here is authored from its stated format and classes. The table
   measures *this detector on this corpus*, not the paper's effect size.
2. **A pattern detector is incomplete by construction.** The paper itself reports that the strongest
   post-generation screen still misses ~⅓. A payload that avoids the framing vocabulary, or that
   opens with a prohibition word, is not caught. Recall is a dial, not a guarantee — which is why the
   policy outcome for a *reported* finding is fail-closed and the audit trail is the durable artefact.
3. **DET-008 reads instructions, not code.** A model that already wrote a vulnerable completion, and
   vulnerable code a human wrote, are SAST/DAST problems. The gateway's claim is narrower and
   testable: *the directive did not reach the model*.
4. **One false positive was found during development and fixed by rewording, not by weakening the
   rule.** The probe flagged this repository's own doc-comment quoting the paper's payload shape. The
   rule stayed strict (a comment that quotes a payload verbatim *is* reported — a quote-guard would
   hand an attacker an evasion), and the comment was reworded. Expect this class of report in
   security-conscious codebases.
5. **Not covered yet:** the inline-completion channel of an IDE assistant (DET-008 guards files the
   agent *reads*, not text an editor streams into a completion request), and `Bash`/`@`-reference
   paths already listed as M3 gaps.

## 6. Reproducing the measurements

```bash
make test                                   # unit + integration + e2e, incl. the corpus tests
pytest tests/detectors/test_comment_directive.py -q     # the attack/benign/ambiguous corpora

# The live false-positive probe. Build output is excluded by default; pass
# --include-build to reproduce the (older, larger) 168-file figure.
python scripts/probe_comment_directive.py . ../takumi/packages
python scripts/probe_comment_directive.py . ../takumi/packages --json
```

The probe walks a source tree, counts the full-line comments the detector actually reads (per
language family), and runs the shipped `run_scan()` over each file — it re-implements nothing, so it
measures the gateway as shipped. It is a *false-positive* measurement: it reports what the detector
flags on code written without any injected payload, and says nothing about recall.
