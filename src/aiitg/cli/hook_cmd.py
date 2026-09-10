"""CLI surface for the Claude Code hook adapter (``aiitg hook ...``).

The handlers take JSON on stdin and write the documented ``hookSpecificOutput`` JSON on stdout,
with exit code 0 for a decision and 2 for a fail-closed block (Claude Code treats a non-2 exit
from a crashing hook as non-blocking, so 2 is the only exit code that is guaranteed to block).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import typer

from aiitg.hooks.claude_code import (
    HookConfig,
    HookOutcome,
    handle_posttooluse,
    handle_pretooluse,
    render_outcome,
)

hook_app = typer.Typer(
    name="hook",
    help="Claude Code hook adapters: enforce input trust without changing the consuming tool.",
    add_completion=False,
)

_MODES = ("strip", "redact")


def _build_config(
    *,
    audit: Path | None,
    queue: Path | None,
    fail_open: bool,
    mode: str,
    cache_dir: Path | None,
    no_cache: bool,
    quarantine_dir: Path | None,
    max_file_bytes: int,
) -> HookConfig:
    if mode not in _MODES:
        typer.echo(f"Error: --mode must be one of {_MODES}", err=True)
        raise typer.Exit(code=2)
    defaults = HookConfig()
    return HookConfig(
        quarantine_dir=quarantine_dir or defaults.quarantine_dir,
        cache_dir=None if no_cache else (cache_dir or defaults.cache_dir),
        audit_path=audit,
        queue_path=queue,
        mode=mode,
        fail_closed=not fail_open,
        max_file_bytes=max_file_bytes,
    )


def _read_payload() -> dict | None:
    """Parse stdin; ``None`` means unparseable (the handler decides deny/allow)."""
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        typer.echo(f"aiitg hook: malformed stdin JSON: {exc}", err=True)
        return None
    return payload if isinstance(payload, dict) else None


def _run(handler: Callable[..., HookOutcome], config: HookConfig) -> None:
    outcome = handler(_read_payload(), config=config)
    text, code = render_outcome(outcome)
    typer.echo(text)
    raise typer.Exit(code=code)


@hook_app.command("pretooluse")
def pretooluse(
    audit: Path | None = typer.Option(None, "--audit", help="Append audit lines to this JSONL path."),
    queue: Path | None = typer.Option(None, "--queue", help="Append human-approval requests to this JSONL path."),
    fail_open: bool = typer.Option(False, "--fail-open", help="Allow instead of deny when a scan cannot decide."),
    mode: str = typer.Option("strip", "--mode", help=f"Sanitizer mode: {' | '.join(_MODES)}."),
    cache_dir: Path | None = typer.Option(None, "--cache-dir", help="Decision cache directory."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the decision cache."),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir", help="Where sanitized substitutes are written."
    ),
    max_file_bytes: int = typer.Option(50 * 1024 * 1024, "--max-file-bytes", help="Deny files larger than this."),
) -> None:
    """Decide a Claude Code PreToolUse payload (JSON on stdin, JSON on stdout)."""
    _run(
        handle_pretooluse,
        _build_config(
            audit=audit,
            queue=queue,
            fail_open=fail_open,
            mode=mode,
            cache_dir=cache_dir,
            no_cache=no_cache,
            quarantine_dir=quarantine_dir,
            max_file_bytes=max_file_bytes,
        ),
    )


@hook_app.command("posttooluse")
def posttooluse(
    audit: Path | None = typer.Option(None, "--audit", help="Append audit lines to this JSONL path."),
    queue: Path | None = typer.Option(None, "--queue", help="Append human-approval requests to this JSONL path."),
    fail_open: bool = typer.Option(False, "--fail-open", help="Allow instead of deny when the payload is invalid."),
    mode: str = typer.Option("strip", "--mode", help=f"Sanitizer mode: {' | '.join(_MODES)}."),
    cache_dir: Path | None = typer.Option(None, "--cache-dir", help="Decision cache directory."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the decision cache."),
    quarantine_dir: Path | None = typer.Option(
        None, "--quarantine-dir", help="Where sanitized substitutes are written."
    ),
    max_file_bytes: int = typer.Option(50 * 1024 * 1024, "--max-file-bytes", help="Deny files larger than this."),
) -> None:
    """Flag invisible/bidi characters in a Claude Code PostToolUse payload."""
    _run(
        handle_posttooluse,
        _build_config(
            audit=audit,
            queue=queue,
            fail_open=fail_open,
            mode=mode,
            cache_dir=cache_dir,
            no_cache=no_cache,
            quarantine_dir=quarantine_dir,
            max_file_bytes=max_file_bytes,
        ),
    )


def hook_config(
    audit: Path | None = typer.Option(None, "--audit", help="Include --audit in the printed snippet."),
    queue: Path | None = typer.Option(None, "--queue", help="Include --queue in the printed snippet."),
    fail_open: bool = typer.Option(False, "--fail-open", help="Include --fail-open in the printed snippet."),
) -> None:
    """Print the `.claude/settings.json` snippet. Never writes any file."""
    command = "aiitg hook pretooluse"
    if audit:
        command += f" --audit {audit}"
    if queue:
        command += f" --queue {queue}"
    if fail_open:
        command += " --fail-open"
    snippet = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Read",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "WebFetch",
                    "hooks": [{"type": "command", "command": "aiitg hook posttooluse", "timeout": 30}],
                }
            ],
        }
    }
    typer.echo(json.dumps(snippet, indent=2))
    typer.echo("\n# Add this to .claude/settings.json (project) or ~/.claude/settings.json (user).", err=True)
