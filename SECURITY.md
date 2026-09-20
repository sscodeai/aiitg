# Security Policy

## Supported versions

The `main` branch is the supported release line. Security fixes land on `dev` first and are merged
into `main`; older commits and forks are not maintained.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.**

Use GitHub's private reporting flow: **Security → Report a vulnerability**
(<https://github.com/sscodeai/aiitg/security/advisories/new>). Include:

- the affected version (`aiitg version`),
- a minimal reproduction (a generated document, a payload, or the command line),
- what an attacker gains (e.g. hidden content that reaches the model despite `dangerous` evidence,
  a policy decision that can be bypassed, a crash path that fails open).

You will get an acknowledgement within a few days and a fix or an explicit "won't fix / by design"
answer. There is no bug bounty.

## What counts as a vulnerability

In scope — anything that breaks the project's promises:

- **Silent non-enforcement**: a path where untrusted content reaches the model while aiitg reports
  success (a hook that cannot run, a fail-closed branch that actually allows, a cache entry that
  overrides a real verdict).
- **Detection bypass**: a concealment technique that a human reader cannot see but aiitg reports as
  `safe` with no evidence, or a sanitized output that still carries the hidden payload.
- **Policy bypass**: reaching `allow` for a document the default policy would block/quarantine, or a
  `human_approval` decision that proceeds without a human.
- **Crash-to-allow**: any exception path that results in the document being consumed anyway.
- **Injection in the auditor's own surfaces**: audit-log or report content that can execute or
  mislead a downstream tool.

Out of scope (by design — see the README and `docs/plan-zero-touch-adoption.md`):

- Detection is **not** claimed to be complete. A novel concealment technique with no detector is a
  feature gap, not a vulnerability — unless aiitg reports the document as `safe` *because* the
  technique was concealed (that is in scope).
- An attacker who already has local user-level access: they can read the quarantine directory, forge
  cache entries, or edit `.claude/settings.json`. The decision cache and the audit log are local
  state, **not** a trust boundary; treat them like any other user-writable file.
- Content the operator deliberately approved (the human-approval queue is a human decision, and
  approving reveals the document by design).
- Attacks that require the model to ignore its own instructions (that is model alignment, not aiitg's
  trust boundary).
