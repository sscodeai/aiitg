"""aiitg CLI — typer app."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from aiitg._version import __version__
from aiitg.approval import ApprovalQueue
from aiitg.audit import AuditLog
from aiitg.core.detector import default_detector_registry, run_scan
from aiitg.core.evidence import ScanReport, Severity
from aiitg.pipeline import process_file
from aiitg.policy import default_policy
from aiitg.reporters.json_reporter import JsonReporter
from aiitg.reporters.rich_reporter import RichReporter

app = typer.Typer(
    name="aiitg",
    help="AI Input Trust Gateway — hidden content auditor for documents fed to LLMs/Agents.",
    add_completion=False,
)


def _resolve_min_severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2)


def _scan_one(path: Path, min_severity: Severity, skip_detectors: set[str] | None = None) -> tuple[ScanReport, int]:
    """Scan one file, return (report, exit_code)."""
    registry = default_detector_registry()
    report = run_scan(str(path), registry)
    report = report.filter(min_severity=min_severity)
    if skip_detectors:
        report = _drop_detectors(report, skip_detectors)
        report = report.filter(min_severity=min_severity)
    # exit code: 0 = no evidence at/above threshold; 1 = found; 3 = scan error
    if report.status == "error":
        return report, 3
    if report.has_severity(min_severity):
        return report, 1
    return report, 0


def _drop_detectors(report: ScanReport, skip: set[str]) -> ScanReport:
    """Remove evidence from skipped detectors (post-scan filter)."""
    report.evidence = [ev for ev in report.evidence if ev.detector_id not in skip]
    return report


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, resolve_path=True, help="File or directory to scan."),
    format: str = typer.Option("json", "--format", help="Output format: json | rich"),
    min_severity: str = typer.Option("low", "--min-severity", help="Minimum severity to report/fail on."),
    output: str = typer.Option("-", "--output", help="Output file ('-' = stdout)."),
    skip_detector: list[str] = typer.Option([], "--skip-detector", help="Detector ID(s) to skip."),
    recursive: bool = typer.Option(False, "--recursive", help="Scan a directory recursively."),
    jsonl: bool = typer.Option(False, "--jsonl", help="Emit one JSON object per line (directory scans)."),
) -> None:
    """Scan a file or directory for hidden content / prompt-injection vectors."""
    sev = _resolve_min_severity(min_severity)
    if format not in ("json", "rich"):
        typer.echo(f"Error: invalid --format {format!r} (choose json|rich)", err=True)
        raise typer.Exit(code=2)

    if target.is_dir():
        if not recursive:
            typer.echo("Error: target is a directory; use --recursive to scan it.", err=True)
            raise typer.Exit(code=2)
        files = sorted(target.rglob("*")) if recursive else sorted(target.iterdir())
        files = [f for f in files if f.is_file()]
        overall_exit = 0
        skip = set(skip_detector)
        for f in files:
            report, code = _scan_one(f, sev, skip)
            if jsonl:
                sys.stdout.write(report.to_json() + "\n")
            else:
                _emit(report, format, output, file=True)
            overall_exit = max(overall_exit, code)
        raise typer.Exit(code=overall_exit)

    report, code = _scan_one(target, sev, set(skip_detector))
    _emit(report, format, output)
    raise typer.Exit(code=code)


@app.command()
def sanitize(
    target: Path = typer.Argument(..., exists=True, resolve_path=True, help="File to sanitize."),
    mode: str = typer.Option("strip", "--mode", help="strip (remove) | redact (replace with [REDACTED])."),
    min_severity: str = typer.Option("low", "--min-severity", help="Minimum severity to strip."),
    output: str = typer.Option("-", "--output", help="Output file ('-' = stdout)."),
) -> None:
    """Sanitize a file: strip/redact hidden content, print the cleaned text."""
    sev = _resolve_min_severity(min_severity)
    result = process_file(str(target), mode=mode, min_severity=sev)
    text = result.sanitized.text
    if output == "-":
        sys.stdout.write(text + ("\n" if text and not text.endswith("\n") else ""))
    else:
        Path(output).write_text(text, encoding="utf-8")
    if result.sanitized.removed_count > 0:
        typer.echo(
            f"# sanitized: removed {result.sanitized.removed_count} hidden item(s) "
            f"({len(result.report.evidence)} evidence finding(s) total)",
            err=True,
        )


@app.command()
def trust(
    target: Path = typer.Argument(..., exists=True, resolve_path=True, help="File to trust-label."),
    format: str = typer.Option("json", "--format", help="json | rich"),
) -> None:
    """Compute the trust label for a file (safe/caution/dangerous)."""
    result = process_file(str(target))
    label = result.label
    from rich.console import Console

    console = Console()
    if format == "rich":
        color = "bold green" if result.is_safe else ("bold yellow" if not result.is_dangerous else "bold red")
        console.print(f"Trust label: [{color}]{label.value.value}[/] (score {label.score:.2f})")
        dims = (
            f"structure: {label.structure_score:.2f}  "
            f"content: {label.content_score:.2f}  meta: {label.meta_score:.2f}"
        )
        console.print(f"  {dims}")
        for r in label.reasons:
            console.print(f"  - {r}")
    else:
        import json

        typer.echo(json.dumps(label.to_dict(), ensure_ascii=False, indent=2))


@app.command()
def policy(
    target: Path = typer.Argument(..., exists=True, resolve_path=True, help="File to evaluate against the policy."),
    format: str = typer.Option("json", "--format", help="json | rich"),
    audit: str = typer.Option("", "--audit", help="Append decision to audit log at this path."),
) -> None:
    """Evaluate a file against the default policy → allow/quarantine/approval/block."""
    from rich.console import Console

    result = process_file(str(target))
    engine = default_policy()
    decision = engine.evaluate(result.report, result.label.value)

    if audit:
        AuditLog(audit).record(report=result.report, decision=decision, sanitized=False)

    console = Console()
    color = {
        "allow": "bold green",
        "quarantine": "bold yellow",
        "human_approval": "bold magenta",
        "block": "bold red",
    }[decision.action.value]
    if format == "rich":
        console.print(f"Policy decision: [{color}]{decision.action.value}[/] ({decision.rule_id})")
        console.print(f"  reason: {decision.reason}")
        summary = (
            f"  trust: {result.label.value.value} (score {result.label.score:.2f})  "
            f"risk: {result.report.risk_score:.2f}"
        )
        console.print(summary)
    else:
        import json

        payload = {
            "decision": decision.to_dict(),
            "trust_label": result.label.to_dict(),
            "risk_score": result.report.risk_score,
            "file": result.report.file,
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@app.command()
def audit(
    log: str = typer.Argument(..., help="Path to audit JSONL log."),
    limit: int = typer.Option(50, "--limit", help="Entries to show."),
    format: str = typer.Option("json", "--format", help="json | rich"),
) -> None:
    """Show recent audit log entries."""
    entries = AuditLog(log).read(limit=limit)
    if format == "rich":
        from rich.console import Console

        console = Console()
        console.print(f"Audit log: {log} ({len(entries)} entries shown)")
        for e in entries:
            decision = (e.get("decision") or {}).get("action", "?")
            console.print(
                f"  [{e.get('timestamp', '')}] {e.get('file', '?')} "
                f"risk={e.get('risk_score', '?')} label={((e.get('trust_label') or {}).get('value', '?'))} "
                f"decision={decision}"
            )
    else:
        import json

        typer.echo(json.dumps(entries, ensure_ascii=False, indent=2))


@app.command()
def approvals(
    queue: str = typer.Argument(..., help="Path to approval queue JSONL."),
    action: str = typer.Option("list", "--action", help="list | approve | reject"),
    id: str = typer.Option("", "--id", help="Request id (for approve/reject)."),
    by: str = typer.Option("human", "--by", help="Who is deciding."),
    format: str = typer.Option("json", "--format", help="json | rich"),
) -> None:
    """Manage the human-approval queue (list pending / approve / reject)."""
    q = ApprovalQueue(queue)
    if action == "list":
        entries = q.pending()
        if format == "rich":
            from rich.console import Console

            console = Console()
            console.print(f"Pending approvals: {len(entries)}")
            for e in entries:
                console.print(f"  [{e.get('id')}] {e.get('file', '?')} — {e.get('reason', '?')}")
        else:
            import json

            typer.echo(json.dumps(entries, ensure_ascii=False, indent=2))
    elif action == "approve":
        if not id:
            typer.echo("Error: --id required for approve", err=True)
            raise typer.Exit(code=2)
        entry = q.approve(id, by=by)
        if entry is None:
            typer.echo(f"Error: no pending request with id {id}", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"Approved {id}: {entry['file']}")
    elif action == "reject":
        if not id:
            typer.echo("Error: --id required for reject", err=True)
            raise typer.Exit(code=2)
        entry = q.reject(id, by=by)
        if entry is None:
            typer.echo(f"Error: no pending request with id {id}", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"Rejected {id}: {entry['file']}")
    else:
        typer.echo("Error: --action must be list|approve|reject", err=True)
        raise typer.Exit(code=2)


@app.command()
def list_detectors() -> None:
    """List all bundled detectors."""
    registry = default_detector_registry()
    typer.echo("Bundled detectors:")
    for det in registry.detectors:
        kinds = ", ".join(sorted(det.supported_kinds))
        typer.echo(f"  {det.id} {det.name:20s} [{kinds}] — {det.description}")


@app.command()
def version() -> None:
    """Print the aiitg version."""
    typer.echo(f"aiitg {__version__}")


def _emit(report: ScanReport, format: str, output: str, *, file: bool = False) -> None:
    """Render a report to the chosen format and output destination."""
    if format == "rich":
        text = RichReporter().render(report)
    else:
        text = JsonReporter().render(report)
    if output == "-":
        sys.stdout.write(text + ("\n" if format == "rich" else "\n"))
    else:
        Path(output).write_text(text + "\n", encoding="utf-8")


def main() -> None:
    app()
