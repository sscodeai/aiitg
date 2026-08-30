"""Sanitization — strip hidden content from a parsed document.

M1 core: consume :class:`Evidence` (with coordinate-level :class:`Location`)
and produce a *cleaned* text view that is safe to feed to an LLM.

Two modes:
- ``strip`` (default): remove hidden content entirely (zero-width chars, hidden
  runs, hidden sheets/rows, hidden HTML elements, comments, OOXML nodes).
- ``redact``: replace hidden content with ``[REDACTED]`` markers so the text
  keeps its shape but the dangerous payload is neutralized.

The sanitizer works on :class:`ParsedDocument` (the same intermediate model
detectors consume), so it is format-agnostic — same code path for all 4 formats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aiitg.core.document import ParsedDocument, TextParagraph
from aiitg.core.evidence import Evidence, Severity

# Character classes that should never reach an LLM context
INVISIBLE_RE = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff\u00ad\u034f\u180e\u061c]"
)
BIDI_RE = re.compile("[\u202a\u202b\u202c\u202d\u202e]")


@dataclass
class SanitizeResult:
    """Output of sanitization: cleaned text + a record of what was removed."""

    text: str
    removed: list[dict] = field(default_factory=list)  # {type, location, reason}
    mode: str = "strip"

    @property
    def removed_count(self) -> int:
        return len(self.removed)


def sanitize_paragraph(para: TextParagraph, mode: str = "strip") -> str:
    """Sanitize a single paragraph: drop invisible chars + hidden runs.

    In ``redact`` mode hidden runs become ``[REDACTED]``; in ``strip`` mode
    they are removed entirely. Invisible characters are always stripped in
    both modes (they carry no semantic content, only injection payload).
    """
    # 1) drop hidden runs (w:vanish / display:none / hidden cell)
    kept_runs: list[str] = []
    for run in para.runs:
        if run.is_hidden:
            kept_runs.append("[REDACTED]" if mode == "redact" else "")
            continue
        kept_runs.append(run.text)

    text = "".join(kept_runs)
    # 2) strip invisible chars regardless of mode
    text = INVISIBLE_RE.sub("", text)
    # 3) strip bidi overrides (can reorder visible text)
    text = BIDI_RE.sub("", text)
    return text


class Sanitizer:
    """Strip/redact hidden content from a parsed document."""

    def __init__(self, mode: str = "strip", *, min_severity: Severity = Severity.LOW) -> None:
        if mode not in ("strip", "redact"):
            raise ValueError("mode must be 'strip' or 'redact'")
        self.mode = mode
        self.min_severity = min_severity

    def sanitize(self, doc: ParsedDocument, evidence: list[Evidence]) -> SanitizeResult:
        """Produce a cleaned text view of ``doc`` based on ``evidence``.

        Args:
            doc: the parsed document (from the same scan that produced evidence)
            evidence: detector output (evidence with coordinates)

        Returns:
            :class:`SanitizeResult` with the cleaned text + removal record.
        """
        # collect hidden locations per paragraph index
        hidden_paragraphs: set[int] = set()
        hidden_sheets: set[str] = set()
        hidden_runs: set[tuple[int, int]] = set()
        for ev in evidence:
            loc = ev.location
            if loc.paragraph is not None:
                # hidden sheet row/col → the whole paragraph is hidden
                if ev.detector_id == "DET-004":
                    hidden_paragraphs.add(loc.paragraph)
                elif loc.run is not None:
                    hidden_runs.add((loc.paragraph, loc.run))
                elif loc.char_range is not None:
                    # char-level: handled below via regex on the paragraph text
                    pass
            if loc.sheet is not None:
                hidden_sheets.add(loc.sheet)

        removed: list[dict] = []
        out_lines: list[str] = []
        for para in doc.paragraphs:
            # skip paragraphs in hidden sheets
            sheet_name = para.raw.get("sheet")
            if sheet_name in hidden_sheets:
                removed.append({"type": "hidden_sheet", "location": sheet_name, "reason": "hidden sheet"})
                continue

            # skip whole hidden paragraphs (DET-004 rows)
            if para.index is not None and para.index in hidden_paragraphs:
                removed.append(
                    {"type": "hidden_paragraph", "location": para.index, "reason": "hidden row/paragraph"}
                )
                continue

            # sanitize runs
            cleaned = self._sanitize_paragraph_runs(para, hidden_runs)
            if cleaned.strip():
                out_lines.append(cleaned)

        text = "\n".join(out_lines)
        return SanitizeResult(text=text, removed=removed, mode=self.mode)

    def _sanitize_paragraph_runs(self, para: TextParagraph, hidden_runs: set[tuple[int, int]]) -> str:
        """Sanitize a paragraph's runs, honoring hidden run coordinates."""
        parts: list[str] = []
        for i, run in enumerate(para.runs):
            if para.index is not None and (para.index, i) in hidden_runs:
                parts.append("[REDACTED]" if self.mode == "redact" else "")
                continue
            if run.is_hidden:
                parts.append("[REDACTED]" if self.mode == "redact" else "")
                continue
            parts.append(run.text)
        text = "".join(parts)
        text = INVISIBLE_RE.sub("", text)
        text = BIDI_RE.sub("", text)
        return text
