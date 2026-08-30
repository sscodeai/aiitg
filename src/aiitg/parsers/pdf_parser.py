"""pdf parser: pypdf → pages with text spans + transparency.

Extracts per-page text with visitor callbacks to capture font size and the
text matrix, plus ExtGState alpha for transparency detection. Encrypted or
unreadable documents degrade to ``warnings`` instead of crashing.
"""

from __future__ import annotations

from pathlib import Path

from pypdf import PdfReader

from aiitg.core.document import ParsedDocument, PdfPage, TextParagraph, TextRun
from aiitg.parsers.base import register_parser


def _extract_spans(page) -> list[dict]:
    """Extract text spans with font_size and text matrix via visitor callback."""
    spans: list[dict] = []
    # pypdf 6.x: extract_text(visitor_text=callable)
    # visitor receives (text, cm, tm, font_dict, font_size)

    def visitor(text: str, cm, tm, font_dict, font_size) -> None:  # type: ignore[no-untyped-def]
        if not text or not text.strip():
            return
        spans.append(
            {
                "text": text,
                "font_size": float(font_size) if font_size else None,
                "cm": list(cm) if cm is not None else None,
                "tm": list(tm) if tm is not None else None,
            }
        )

    try:
        page.extract_text(visitor_text=visitor)
    except Exception:  # noqa: BLE001
        return []
    return spans


def _extract_alpha(page) -> float | None:
    """Best-effort ExtGState alpha (transparency) for the page.

    Reads /Resources/ExtGState → /ca (fill alpha) or /CA (stroke alpha).
    """
    try:
        resources = page.get("/Resources")
        if resources is None:
            return None
        eg = resources.get("/ExtGState")
        if eg is None:
            return None
        eg = eg.get_object()
        alphas: list[float] = []
        if isinstance(eg, dict):
            for _, gs in eg.items():
                gs = gs.get_object()
                if isinstance(gs, dict):
                    for key in ("/ca", "/CA"):
                        val = gs.get(key)
                        if val is not None:
                            try:
                                alphas.append(float(val))
                            except (TypeError, ValueError):
                                pass
        if not alphas:
            return None
        # use the most transparent (min alpha) as the page's effective transparency
        return min(alphas)
    except Exception:  # noqa: BLE001
        return None


def _extract_annotations(page) -> list[dict]:
    """Extract text annotations (comments) from the page."""
    annots: list[dict] = []
    try:
        raw = page.get("/Annots")
        if raw is None:
            return annots
        for annot in raw:
            annot = annot.get_object()
            if isinstance(annot, dict):
                contents = annot.get("/Contents")
                subtype = annot.get("/Subtype")
                if contents:
                    annots.append({"subtype": str(subtype), "contents": str(contents)})
    except Exception:  # noqa: BLE001
        pass
    return annots


@register_parser("pdf", ("pdf",), sniff=None)
class PdfParser:
    """Parse .pdf into :class:`ParsedDocument`."""

    def parse(self, path: Path) -> ParsedDocument:
        doc_model = ParsedDocument(kind="pdf", source_path=str(path))
        try:
            reader = PdfReader(str(path))
        except Exception as exc:  # noqa: BLE001
            doc_model.warnings.append(f"failed to open PDF: {exc}")
            return doc_model

        if reader.is_encrypted:
            doc_model.warnings.append("PDF is encrypted; text extraction limited")

        for i, page in enumerate(reader.pages, start=1):
            spans = _extract_spans(page)
            text = "".join(s["text"] for s in spans)
            pdf_page = PdfPage(
                number=i,
                text=text,
                spans=spans,
                annotations=_extract_annotations(page),
            )
            # transparency from page resources
            alpha = _extract_alpha(page)
            if alpha is not None:
                pdf_page.raw["alpha"] = alpha
            doc_model.pages.append(pdf_page)

            # paragraph view: whole page as one paragraph (per-span runs)
            runs = [
                TextRun(
                    text=s["text"],
                    font_size=s.get("font_size"),
                    transparency=pdf_page.raw.get("alpha"),
                    raw={"tm": s.get("tm")},
                )
                for s in spans
                if s.get("text")
            ]
            doc_model.paragraphs.append(TextParagraph(text=text, index=i, runs=runs))

        try:
            meta = reader.metadata
            if meta:
                doc_model.metadata = {
                    k.replace("/", "").lower(): str(v) for k, v in meta.items() if v is not None
                }
        except Exception:  # noqa: BLE001
            doc_model.metadata = {}

        return doc_model
