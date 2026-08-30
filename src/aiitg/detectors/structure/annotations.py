"""DET-006: comments / annotations.

Word comments (word/comments.xml), PDF text annotations, and HTML comments are
invisible in normal reading but part of the machine-parsed content — a common
place to hide instructions or extra content.
"""

from __future__ import annotations

import re

from lxml import etree

from aiitg.core.detector import Detector
from aiitg.core.document import ParsedDocument
from aiitg.core.evidence import Evidence, Location, Severity

HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_LONG_DESC = (
    "Comments/annotations (Word comments, PDF annotations, HTML comments) — "
    "machine-visible, human-hidden."
)


class AnnotationsDetector(Detector):
    id = "DET-006"
    name = "annotations"
    description = _LONG_DESC
    supported_kinds = frozenset({"docx", "pdf", "html"})
    default_severity = Severity.LOW

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        if doc.kind == "docx":
            evidence.extend(self._scan_docx_comments(doc))
        elif doc.kind == "pdf":
            evidence.extend(self._scan_pdf_annotations(doc))
        elif doc.kind == "html":
            evidence.extend(self._scan_html_comments(doc))
        return evidence

    def _scan_docx_comments(self, doc: ParsedDocument) -> list[Evidence]:
        out: list[Evidence] = []
        comments_xml = doc.ooxml_parts.get("word/comments.xml")
        if comments_xml:
            try:
                root = etree.fromstring(comments_xml)
                comments = [
                    "".join(t.text or "" for t in el.iter() if t.tag.endswith("}t"))
                    for el in root.iter()
                    if el.tag.endswith("}comment")
                ]
                comments = [c for c in comments if c.strip()]
                if comments:
                    out.append(
                        self.make_evidence(
                            title=f"{len(comments)} Word comment(s) present",
                            description="Word comments are invisible in normal reading but parsed by machines.",
                            location=Location(source=doc.source_name, element="word/comments.xml"),
                            raw={"comments": comments[:20], "count": len(comments)},
                        )
                    )
            except Exception:  # noqa: BLE001
                pass
        return out

    def _scan_pdf_annotations(self, doc: ParsedDocument) -> list[Evidence]:
        out: list[Evidence] = []
        for page in doc.pages:
            for annot in page.annotations:
                contents = annot.get("contents", "")
                if not contents or not contents.strip():
                    continue
                out.append(
                    self.make_evidence(
                        title="PDF annotation/comment with text",
                        description=(
                            f"PDF annotation ({annot.get('subtype', 'unknown')}) on page "
                            f"{page.number} contains text."
                        ),
                        location=Location(source=doc.source_name, page=page.number),
                        raw={"subtype": annot.get("subtype"), "contents": contents[:500]},
                    )
                )
        return out

    def _scan_html_comments(self, doc: ParsedDocument) -> list[Evidence]:
        out: list[Evidence] = []
        if doc.html_root is None:
            return out
        html_str = str(doc.html_root)
        matches = HTML_COMMENT_RE.findall(html_str)
        # only report comments containing non-whitespace text
        meaningful = [m.strip() for m in matches if m.strip()]
        if meaningful:
            out.append(
                self.make_evidence(
                    title=f"{len(meaningful)} HTML comment(s) with content",
                    description="HTML comments are invisible to readers but part of the parsed document.",
                    location=Location(source=doc.source_name, element="html"),
                    raw={"comments": meaningful[:20], "count": len(meaningful)},
                )
            )
        return out
