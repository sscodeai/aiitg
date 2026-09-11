"""CLI surface for the Claude Code hook adapter (``aiitg hook ...``).

The handlers take JSON on stdin and write the documented ``hookSpecificOutput`` JSON on stdout,
with exit code 0 for a decision and 2 for a fail-closed block (Claude Code treats a non-2 exit
from a crashing hook as non-blocking, so 2 is the only exit code that is guaranteed to block).
"""

from __future__ import annotations

import json
import shlex
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import typer

from aiitg.hooks.claude_code import (
    DEFAULT_ENFORCED_EXTENSIONS,
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

_NOT_ON_PATH = (
    "aiitg is not on PATH. A hook command that cannot start is a NON-BLOCKING error in Claude Code: "
    "the tool call proceeds and the document reaches the model UNSCANNED, while the user believes it "
    "was checked. Install it (pipx install / uv tool install .) or pass --exe <path>."
)


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
    if text:
        typer.echo(text)
    elif code != 0:
        # No JSON + exit 2 is the documented "surface this through stderr" path (PostToolUse).
        typer.echo(outcome.reason, err=True)
    raise typer.Exit(code=code)


def _resolve_exe() -> str | None:
    """Absolute path of the installed ``aiitg`` console script, or ``None`` when it is not on PATH."""
    return shutil.which("aiitg")


def _hook_command(extra: str = "") -> str:
    """The command a settings file should run, with the executable quoted and resolved."""
    exe = _resolve_exe() or "aiitg"
    return f"{shlex.quote(exe)} hook pretooluse{extra}"


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
    audit: Path | None = typer.Option(None, "--audit", help="Append findings to this JSONL audit path."),
    fail_open: bool = typer.Option(False, "--fail-open", help="Stay silent instead of warning on stderr."),
) -> None:
    """Flag invisible/bidi characters in a Claude Code PostToolUse payload.

    Only ``--audit`` and ``--fail-open`` apply: this event runs *after* the tool, so it can neither
    allow nor deny, never scans a file path and never writes a quarantine substitute.
    """
    defaults = HookConfig()
    _run(
        handle_posttooluse,
        HookConfig(
            quarantine_dir=defaults.quarantine_dir,
            cache_dir=None,
            audit_path=audit,
            queue_path=None,
            mode=defaults.mode,
            fail_closed=not fail_open,
            max_file_bytes=defaults.max_file_bytes,
        ),
    )


def _settings_candidates(explicit: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    home = Path.home() / ".claude"
    return [
        Path.cwd() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.local.json",
        home / "settings.json",
        home / "settings.local.json",
    ]


def _all_commands(node: object) -> list[str]:
    """Collect every ``"command"`` string in a settings object (any depth)."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "command" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_all_commands(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_all_commands(item))
    return found


def _check_wiring(settings: Path | None) -> tuple[bool, str]:
    """Is a PreToolUse hook pointing at *this* aiitg actually installed, and would it start?"""
    for candidate in _settings_candidates(settings):
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return False, f"{candidate}: unreadable ({exc})"
        commands = [cmd for cmd in _all_commands(data) if "hook pretooluse" in cmd]
        if not commands:
            continue
        command = commands[0]
        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            return False, f"{candidate}: cannot parse command ({exc})"
        if not tokens:
            continue
        executable = tokens[0]
        resolvable = Path(executable).is_file() or shutil.which(executable) is not None
        if not resolvable:
            return False, (
                f"{candidate}: wired as '{command}' but '{executable}' cannot be started — "
                "Claude Code treats that as a non-blocking error and the document passes unscanned"
            )
        return True, f"{candidate}: '{command}'"
    if settings is not None:
        return False, f"{settings}: no PreToolUse hook calling 'aiitg hook pretooluse'"
    return False, (
        "no .claude/settings.json (project or user) wires a PreToolUse hook — run `aiitg hook-config` "
        "and paste the snippet in, or the gateway is not on the path"
    )


def _writable(directory: Path) -> tuple[bool, str]:
    probe = directory / ".aiitg-doctor-probe"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe.write_text("probe", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return False, f"{directory} — {exc}"
    return True, str(directory)


@hook_app.command("doctor")
def doctor(
    quarantine_dir: Path | None = typer.Option(None, "--quarantine-dir", help="Quarantine directory to check."),
    cache_dir: Path | None = typer.Option(None, "--cache-dir", help="Cache directory to check."),
    exe: Path | None = typer.Option(None, "--exe", help="Explicit aiitg executable path (skips the PATH check)."),
    settings: Path | None = typer.Option(
        None, "--settings", help="Settings file to inspect instead of the standard .claude locations."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Self-check the hook setup: a hook that cannot run fails silently, so verify before trusting it."""
    defaults = HookConfig()
    target_q = quarantine_dir or defaults.quarantine_dir
    target_c = cache_dir or defaults.cache_dir or defaults.quarantine_dir

    checks: list[dict[str, object]] = []
    if exe is not None:
        ok = Path(exe).is_file()
        checks.append({"check": "executable", "ok": ok, "detail": str(exe)})
    else:
        found = _resolve_exe()
        checks.append({"check": "console script on PATH", "ok": found is not None, "detail": found or _NOT_ON_PATH})

    wired, wiring_detail = _check_wiring(settings)
    checks.append({"check": "PreToolUse hook wired", "ok": wired, "detail": wiring_detail})

    for label, directory in (("quarantine dir writable", target_q), ("cache dir writable", target_c)):
        ok, detail = _writable(directory)
        checks.append({"check": label, "ok": ok, "detail": detail})

    checks.append(
        {"check": "fail-closed default", "ok": defaults.fail_closed, "detail": "deny when a scan cannot decide"}
    )
    checks.append(
        {
            "check": "enforced formats",
            "ok": True,
            "detail": f"{len(DEFAULT_ENFORCED_EXTENSIONS)} extensions (parseable + unparseable document formats)",
        }
    )

    passed = all(bool(c["ok"]) for c in checks)
    if as_json:
        typer.echo(json.dumps({"ok": passed, "checks": checks, "hook_command": _hook_command()}, indent=2))
    else:
        for c in checks:
            typer.echo(f"{'PASS' if c['ok'] else 'FAIL'}  {c['check']}: {c['detail']}")
        typer.echo(f"\nhook command for .claude/settings.json:\n  {_hook_command()}")
        if not passed:
            typer.echo("\naiitg hook doctor found a blocking problem — fix it before relying on the hook.", err=True)
    raise typer.Exit(code=0 if passed else 1)


def hook_config(
    audit: Path | None = typer.Option(None, "--audit", help="Include --audit in the printed snippet."),
    queue: Path | None = typer.Option(None, "--queue", help="Include --queue in the printed snippet."),
    fail_open: bool = typer.Option(False, "--fail-open", help="Include --fail-open in the printed snippet."),
    exe: Path | None = typer.Option(None, "--exe", help="Explicit aiitg executable path to embed."),
) -> None:
    """Print the `.claude/settings.json` snippet. Never writes any file."""
    if exe is not None:
        resolved: str | None = str(exe)
    else:
        resolved = _resolve_exe()
        if resolved is None:
            typer.echo(_NOT_ON_PATH, err=True)

    extra = ""
    if audit:
        extra += f" --audit {audit}"
    if queue:
        extra += f" --queue {queue}"
    if fail_open:
        extra += " --fail-open"

    exe_token = shlex.quote(resolved or "aiitg")
    pre_command = f"{exe_token} hook pretooluse{extra}"
    post_command = f"{exe_token} hook posttooluse"
    snippet = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Read",
                    "hooks": [{"type": "command", "command": pre_command, "timeout": 30}],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "WebFetch",
                    "hooks": [{"type": "command", "command": post_command, "timeout": 30}],
                }
            ],
        }
    }
    typer.echo(json.dumps(snippet, indent=2))
    typer.echo("\n# Add this to .claude/settings.json (project) or ~/.claude/settings.json (user).", err=True)
    typer.echo("# Verify with: aiitg hook doctor", err=True)
