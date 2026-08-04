"""Rich reporter — human-readable terminal table."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ai_input_trust_gateway.core.evidence import ScanReport, Severity
from ai_input_trust_gateway.reporters.base import Reporter

SEV_COLORS = {
    Severity.INFO: "cyan",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "orange1",
    Severity.CRITICAL: "red",
}


class RichReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        console = Console(record=True, width=140)
        if report.status == "error":
            console.print(f"[bold red]Scan failed:[/] {report.error}")
            return console.export_text()

        console.print(
            f"[bold]AI Input Trust Gateway[/] — [cyan]{report.file}[/] ({report.kind}, "
            f"risk {report.risk_score:.2f}, {report.summary['total']} finding(s))"
        )

        if not report.evidence:
            console.print("[green]No evidence found.[/]")
            return console.export_text()

        table = Table(title="Evidence", show_lines=False)
        table.add_column("ID", style="bold")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Location", overflow="fold")

        for ev in report.evidence:
            loc = ev.location
            loc_str = (
                f"p{loc.paragraph}" if loc.paragraph is not None else
                f"{loc.sheet}:r{loc.row}" if loc.sheet else
                f"page {loc.page}" if loc.page else
                (loc.element or "")
            )
            table.add_row(
                ev.detector_id,
                f"[{SEV_COLORS.get(ev.severity, 'white')}]{ev.severity.value}[/]",
                ev.title,
                loc_str,
            )
        console.print(table)
        return console.export_text()
