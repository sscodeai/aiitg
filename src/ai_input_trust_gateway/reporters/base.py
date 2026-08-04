"""Reporter protocol."""

from __future__ import annotations

from typing import Protocol

from ai_input_trust_gateway.core.evidence import ScanReport


class Reporter(Protocol):
    """Renders a :class:`ScanReport` to a string."""

    def render(self, report: ScanReport) -> str:
        ...
