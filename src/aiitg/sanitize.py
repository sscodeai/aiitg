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
from aiitg.parsers.text_parser import COMMENT_PREFIXES

#: DET-008 findings carry a coordinate (line) whose *visible* text has to be
#: neutralized. Stripping invisible characters is not enough here: the payload is plain
#: text a human can read, and the point of quarantine is that the model must not read
#: it as an instruction.
DIRECTIVE_DETECTOR = "DET-008"
_DEFUSE_MARKER = "[aiitg] removed untrusted instruction"
_REDACT_MARKER = "[REDACTED: untrusted code-comment directive]"

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


def _line_comment_prefix(line: str, lang: str | None) -> str:
    """The comment prefix a defused replacement should keep for this line."""
    stripped = line.lstrip()
    for prefix in COMMENT_PREFIXES.get(lang or "", ()):
        if stripped.lower().startswith(prefix):
            return prefix
    return ""


def defuse_comment_line(line: str, *, lang: str | None, klass: str, mode: str = "strip") -> str:
    """Replace a directive comment with an inert, self-describing one.

    The replacement stays a comment in the same language, keeping the line's
    indentation, so the file keeps its shape (and its syntax); what disappears is the
    instruction.
    """
    indent = line[: len(line) - len(line.lstrip())]
    prefix = _line_comment_prefix(line, lang)
    marker = _REDACT_MARKER if mode == "redact" else f"{_DEFUSE_MARKER} (class={klass})"
    return f"{indent}{prefix} {marker}".rstrip()


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
        directive_lines: dict[int, str] = {}
        for ev in evidence:
            loc = ev.location
            if ev.detector_id == DIRECTIVE_DETECTOR and loc.paragraph is not None:
                directive_lines[loc.paragraph] = str(ev.raw.get("class", "unknown"))
                continue
            if loc.paragraph is not None:
                # hidden sheet row/col → the whole paragraph is hidden
                if ev.detector_id == "DET-004":
                    hidden_paragraphs.add(loc.paragraph)
                elif loc.run is not None:
                    hidden_runs.add((loc.paragraph, loc.run))
                elif loc.char_range is not None:
                    # char-level: handled below via regex on the paragraph text
                    pass
            if ev.detector_id == "DET-004" and loc.sheet is not None and loc.row is None and loc.col is None:
                hidden_sheets.add(loc.sheet)

        removed: list[dict] = []
        out_lines: list[str] = []
        lang = doc.metadata.get("lang")
        for para in doc.paragraphs:
            # defuse an instruction-bearing comment before anything else looks at it
            if para.index is not None and para.index in directive_lines:
                klass = directive_lines[para.index]
                out_lines.append(defuse_comment_line(para.text, lang=lang, klass=klass, mode=self.mode))
                removed.append(
                    {"type": "comment_directive", "location": para.index, "reason": f"unsafe instruction ({klass})"}
                )
                continue
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
