"""Parser package: auto-collects all registered parsers.

Importing this package triggers the decorators in each parser module, which
stash their :class:`FormatHandler` on the class. ``ALL_HANDLERS`` collects
them for the default registry.
"""

from __future__ import annotations

from ai_input_trust_gateway.core.registry import FormatHandler
from ai_input_trust_gateway.parsers import (
    docx_parser,
    html_parser,
    ooxml_raw,
    pdf_parser,
    xlsx_parser,
)

ALL_HANDLERS: list[FormatHandler] = [
    getattr(cls, "_handler")
    for cls in (
        docx_parser.DocxParser,
        xlsx_parser.XlsxParser,
        pdf_parser.PdfParser,
        html_parser.HtmlParser,
    )
]

__all__ = ["ALL_HANDLERS", "ooxml_raw"]
