"""Unified, format-agnostic intermediate document model.

Parsers produce a :class:`ParsedDocument`; detectors consume only this model
(never raw file-format libraries). This keeps detectors decoupled from formats:
a new format = a new parser; a new attack = a new detector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TextRun:
    """A styled span of text (format-agnostic)."""

    text: str
    font_size: float | None = None  # pt; None = not explicitly set
    color: str | None = None  # normalized "RRGGBB"
    highlight: str | None = None
    is_hidden: bool = False  # docx w:vanish / xlsx hidden cell / html display:none
    is_header_footer: bool = False
    transparency: float | None = None  # pdf ExtGState alpha (0-1); None = opaque
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class TextParagraph:
    """A paragraph of text with its styled runs."""

    text: str
    index: int | None = None  # docx paragraph index / xlsx row number
    runs: list[TextRun] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Sheet:
    """A spreadsheet sheet (xlsx only)."""

    name: str
    state: str = "visible"  # visible | hidden | veryHidden
    rows_hidden: list[int | str] = field(default_factory=list)
    cols_hidden: list[int | str] = field(default_factory=list)
    merged_ranges: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class PdfPage:
    """A PDF page with its extracted text spans."""

    number: int  # 1-based
    text: str = ""
    spans: list[dict[str, Any]] = field(default_factory=list)  # {text,font_size,tm,alpha}
    annotations: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedDocument:
    """The single intermediate representation consumed by all detectors."""

    kind: str  # "docx" | "xlsx" | "pdf" | "html"
    source_path: str | None = None
    paragraphs: list[TextParagraph] = field(default_factory=list)
    sheets: list[Sheet] = field(default_factory=list)
    pages: list[PdfPage] = field(default_factory=list)
    html_root: Any = None  # bs4 Tag (html only)
    ooxml_parts: dict[str, bytes] = field(default_factory=dict)  # part_name -> bytes (OOXML only)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_text(self) -> str:
        """Concatenated visible text across paragraphs (and pages for pdf)."""
        parts: list[str] = [p.text for p in self.paragraphs if p.text]
        for page in self.pages:
            if page.text:
                parts.append(page.text)
        return "\n".join(parts)

    def find_run(self, paragraph_index: int | None, run_index: int | None) -> TextRun | None:
        """Locate a run by paragraph/run index (docx semantics)."""
        if paragraph_index is None or run_index is None:
            return None
        for p in self.paragraphs:
            if p.index == paragraph_index:
                if 0 <= run_index < len(p.runs):
                    return p.runs[run_index]
        return None

    @property
    def source_name(self) -> str:
        if not self.source_path:
            return "memory"
        return str(Path(self.source_path).name)
