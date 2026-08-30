"""DET-003: extremely small (tiny) font text.

Text rendered at ≤2pt is effectively unreadable to humans but still extracted
by parsers. Threshold configurable via constructor arg.
"""

from __future__ import annotations

from aiitg.core.detector import Detector
from aiitg.core.document import ParsedDocument
from aiitg.core.evidence import Evidence, Location, Severity


class TinyFontDetector(Detector):
    id = "DET-003"
    name = "tiny_font"
    description = (
        "Text rendered at extremely small font size (default ≤2pt) — hard for "
        "humans to read, machine-readable."
    )
    supported_kinds = frozenset({"docx", "xlsx", "pdf", "html", "pptx", "xls"})
    default_severity = Severity.MEDIUM

    def __init__(self, min_size_pt: float = 2.0) -> None:
        super().__init__()
        self.min_size_pt = min_size_pt

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        for para in doc.paragraphs:
            for run in para.runs:
                if run.font_size is None:
                    continue
                if run.font_size <= self.min_size_pt and run.font_size > 0:
                    evidence.append(
                        self.make_evidence(
                            title="Extremely small font text",
                            description=(
                                f"Font size {run.font_size}pt (threshold {self.min_size_pt}pt). "
                                "Tiny text can hide instructions a human cannot comfortably read."
                            ),
                            location=Location(
                                source=doc.source_name,
                                paragraph=para.index,
                                run=para.runs.index(run),
                            ),
                            raw={"text": run.text, "font_size": run.font_size, "threshold": self.min_size_pt},
                        )
                    )
        return evidence
