"""JSON reporter — canonical, machine-readable output (default)."""

from __future__ import annotations

from ai_input_trust_gateway.core.evidence import ScanReport
from ai_input_trust_gateway.reporters.base import Reporter


class JsonReporter(Reporter):
    def render(self, report: ScanReport) -> str:
        return report.to_json()
