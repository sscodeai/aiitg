"""Core data models and orchestration for the AI Input Trust Gateway.

Layering: ``cli -> reporters -> detectors -> parsers -> core``.
Everything in :mod:`core` has **zero third-party dependencies** so the core
logic stays minimal and unit-testable in isolation.
"""

from aiitg.core.document import ParsedDocument, PdfPage, Sheet, TextParagraph, TextRun
from aiitg.core.evidence import Evidence, Location, ScanReport, Severity

__all__ = [
    "ParsedDocument",
    "TextParagraph",
    "TextRun",
    "Sheet",
    "PdfPage",
    "Evidence",
    "Location",
    "Severity",
    "ScanReport",
]
