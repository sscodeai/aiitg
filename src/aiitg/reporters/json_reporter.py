"""JSON reporter — canonical, machine-readable output (default)."""

from __future__ import annotations

from aiitg.core.evidence import ScanReport
from aiitg.reporters.base import Reporter


class JsonReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        return report.to_json()
