"""Legacy .xls parser: xlrd → unified text model.

Old binary Excel files (pre-2007) are still common in enterprise, and they
carry the same hidden-content risks as xlsx (hidden sheets/rows/cols, white
text, macros — OLE2 native). xlrd 2.x handles .xls only (which is exactly
what this parser targets; .xlsx goes to XlsxParser).
"""

from __future__ import annotations

from pathlib import Path

import xlrd

from ai_input_trust_gateway.core.document import ParsedDocument, Sheet, TextParagraph, TextRun
from ai_input_trust_gateway.parsers.base import register_parser


def _normalize_color(val: str | None) -> str | None:
    if not val:
        return None
    v = val.strip().lstrip("#").upper()
    if len(v) == 6 and all(c in "0123456789ABCDEF" for c in v):
        return v
    return None


@register_parser("xls", ("xls",), sniff=None)
class XlsParser:
    """Parse legacy .xls into :class:`ParsedDocument`."""

    def parse(self, path: Path) -> ParsedDocument:
        doc_model = ParsedDocument(kind="xls", source_path=str(path))
        try:
            book = xlrd.open_workbook(str(path), formatting_info=True)
        except Exception:  # noqa: BLE001 — xlrd may lack formatting_info on some files
            book = xlrd.open_workbook(str(path))
            doc_model.warnings.append("formatting_info unavailable; hidden-sheet detection limited")

        for sheet in book.sheets():
            sheet_model = Sheet(
                name=sheet.name,
                state="hidden" if sheet.visibility == 1 else "visible",
            )
            doc_model.sheets.append(sheet_model)

            for row_idx in range(sheet.nrows):
                for col_idx in range(sheet.ncols):
                    cell = sheet.cell(row_idx, col_idx)
                    if cell.value in (None, ""):
                        continue
                    text = str(cell.value)
                    if not text:
                        continue
                    run = TextRun(text=text, raw={"row": row_idx + 1, "col": col_idx + 1})
                    doc_model.paragraphs.append(
                        TextParagraph(
                            text=text,
                            index=row_idx + 1,
                            runs=[run],
                            raw={"sheet": sheet.name, "row": row_idx + 1, "col": col_idx + 1},
                        )
                    )

        # metadata
        try:
            doc_model.metadata = {
                "author": book.user_name or "",
                "sheet_names": [s.name for s in book.sheets()],
            }
        except Exception:  # noqa: BLE001
            doc_model.metadata = {}

        return doc_model
