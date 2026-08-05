"""DET-004: hidden sheets / hidden rows / hidden columns in xlsx.

Hidden spreadsheet regions are invisible in normal viewing but fully present
in the file — a classic smuggling spot for instructions or malicious values.
Only non-empty hidden regions are flagged (empty hidden regions are noise).
"""

from __future__ import annotations

from ai_input_trust_gateway.core.detector import Detector
from ai_input_trust_gateway.core.document import ParsedDocument
from ai_input_trust_gateway.core.evidence import Evidence, Location, Severity


class HiddenSheetDetector(Detector):
    id = "DET-004"
    name = "hidden_sheet"
    description = "Hidden sheets / rows / columns in xlsx that contain data (invisible but machine-readable)."
    supported_kinds = frozenset({"xlsx", "xls"})
    default_severity = Severity.MEDIUM

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        for sheet in doc.sheets:
            if sheet.state in ("hidden", "veryHidden"):
                # collect text from this sheet's paragraphs
                sheet_text = " ".join(
                    p.text for p in doc.paragraphs if p.raw.get("sheet") == sheet.name
                )
                evidence.append(
                    self.make_evidence(
                        title=f"Hidden sheet: {sheet.name}",
                        description=(
                            f"Sheet '{sheet.name}' is {sheet.state} — invisible in normal view "
                            "but fully machine-readable."
                        ),
                        location=Location(source=doc.source_name, sheet=sheet.name, element=f"sheet:{sheet.name}"),
                        raw={"state": sheet.state, "text_length": len(sheet_text)},
                    )
                )

            # hidden rows with content
            non_empty_hidden_rows = self._non_empty_rows(doc, sheet.name)
            if non_empty_hidden_rows:
                evidence.append(
                    self.make_evidence(
                        title=f"Hidden rows with data in '{sheet.name}'",
                        description=(
                            f"{len(non_empty_hidden_rows)} hidden row(s) containing data in sheet '{sheet.name}' — "
                            "hidden rows are invisible to users but parsed by machines."
                        ),
                        location=Location(source=doc.source_name, sheet=sheet.name, row=non_empty_hidden_rows[0]),
                        raw={"rows": non_empty_hidden_rows[:50]},
                    )
                )

            # hidden cols with content
            non_empty_hidden_cols = self._non_empty_cols(doc, sheet.name)
            if non_empty_hidden_cols:
                evidence.append(
                    self.make_evidence(
                        title=f"Hidden columns with data in '{sheet.name}'",
                        description=(
                            f"{len(non_empty_hidden_cols)} hidden column(s) containing data in sheet '{sheet.name}'."
                        ),
                        location=Location(source=doc.source_name, sheet=sheet.name, col=non_empty_hidden_cols[0]),
                        raw={"cols": non_empty_hidden_cols[:50]},
                    )
                )
        return evidence

    def _non_empty_rows(self, doc: ParsedDocument, sheet_name: str) -> list[int]:
        hidden = {
            int(r) for r in next((s.rows_hidden for s in doc.sheets if s.name == sheet_name), [])
        }
        rows: set[int] = set()
        for p in doc.paragraphs:
            if p.raw.get("sheet") == sheet_name and p.text:
                row_val = p.raw.get("row")
                if row_val is not None:
                    try:
                        rows.add(int(row_val))
                    except (TypeError, ValueError):
                        continue
        return sorted(hidden & rows)

    def _non_empty_cols(self, doc: ParsedDocument, sheet_name: str) -> list[int]:
        hidden = {
            int(c) for c in next((s.cols_hidden for s in doc.sheets if s.name == sheet_name), [])
        }
        cols: set[int] = set()
        for p in doc.paragraphs:
            if p.raw.get("sheet") == sheet_name and p.text:
                col_val = p.raw.get("col")
                if col_val is not None:
                    try:
                        cols.add(int(col_val))
                    except (TypeError, ValueError):
                        continue
        return sorted(hidden & cols)
