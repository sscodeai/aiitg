"""DET-002: hidden text via styling (white text / transparency / display:none).

The "Human-AI Visibility Gap": a human sees the document's visible text, but
an LLM parser reads *everything*, including text styled to be invisible.
"""

from __future__ import annotations

from aiitg.core.detector import Detector
from aiitg.core.document import ParsedDocument
from aiitg.core.evidence import Evidence, Location, Severity

# colors close to white on a white background
NEAR_WHITE = {"FFFFFF", "FEFEFE", "FDFDFD", "FFFEFE", "FEFFFF", "FFFFFE"}


class HiddenStyleDetector(Detector):
    id = "DET-002"
    name = "hidden_style"
    description = (
        "Text hidden via styling: white/background color, transparency, "
        "display:none, w:vanish."
    )
    supported_kinds = frozenset({"docx", "xlsx", "pdf", "html", "pptx", "xls"})
    default_severity = Severity.HIGH

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        for para in doc.paragraphs:
            for run in para.runs:
                reasons = self._hidden_reasons(run)
                if not reasons:
                    continue
                evidence.append(
                    self.make_evidence(
                        title="Hidden text via styling",
                        description=(
                            "; ".join(reasons)
                            + ". A human reader cannot see this text, but an LLM parser reads it."
                        ),
                        location=Location(
                            source=doc.source_name,
                            paragraph=para.index,
                            run=para.runs.index(run),
                        ),
                        raw={
                            "text": run.text,
                            "font_size": run.font_size,
                            "color": run.color,
                            "transparency": run.transparency,
                            "is_hidden": run.is_hidden,
                            "reasons": reasons,
                        },
                    )
                )
        return evidence

    def _hidden_reasons(self, run) -> list[str]:
        reasons: list[str] = []
        if run.is_hidden:
            reasons.append("flagged hidden (w:vanish / display:none / hidden cell)")
        if run.color and run.color.upper() in NEAR_WHITE:
            reasons.append(f"near-white text color #{run.color.upper()}")
        if run.transparency is not None and run.transparency < 0.1:
            reasons.append(f"transparent text (alpha={run.transparency})")
        return reasons
