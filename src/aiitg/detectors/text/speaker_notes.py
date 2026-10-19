"""DET-009: directive content in PowerPoint speaker notes.

A slide's speaker notes are not shown when the deck is presented, but they are part
of the file and every text extractor (and therefore every LLM that summarises the
deck) reads them. That makes notes the same class of channel as Word comments and PDF
annotations: machine-readable, human-invisible-in-normal-view.

The pptx parser already exposes notes as paragraphs tagged ``element="notes"``. Until
this detector existed nothing scored them, so a deck whose *only* injection was a
plain-text instruction in the notes scanned clean and was allowed through (the existing
detectors only fire on zero-width characters or hidden styling, so a plain-text note
was invisible to all of them).

Scope: this reads the notes text, it does not judge the slide content. A note that is a
*generic* reminder is not reported; a note that tries to instruct the reader (a model or
a human) is. As with DET-008, a pattern detector is incomplete by construction — the
value is that the channel is now covered and the finding is fail-closed.
"""

from __future__ import annotations

import re

from aiitg.core.detector import Detector
from aiitg.core.document import ParsedDocument
from aiitg.core.evidence import Evidence, Location, Severity

#: Strong injection signals: an explicit attempt to override instructions or to hide
#: something from a human. A note carrying one of these is HIGH.
_STRONG_RE = re.compile(
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\b"
    r"|disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)\b"
    r"|do\s+not\s+(?:tell|inform|mention|reveal|disclose)\b"
    r"|don'?t\s+(?:tell|inform|mention|reveal|disclose)\b"
    r"|secret\s+instructions?\b"
    r"|忽略(?:之前|以前|上述|上面|所有|此前)"
    r"|不要(?:告诉|通知|提及|透露|披露|提醒)",
    re.IGNORECASE,
)

#: Weaker directive signals: the note addresses a machine/system or tells the reader
#: what verdict to reach. Reported, but not treated as blocking on their own.
_DIRECTIVE_RE = re.compile(
    r"(?:system|ai|assistant|model|copilot|claude)\s*(?:指令|指示|提示|prompt|instruction)"
    r"|(?:必须|请)(?:给|给出|选择|推荐|录用|批准|评分)"
    r"|(?:强烈推荐|直接录用|必须录用|优先资助|给[^，。\n]{0,6}满分)"
    r"|\byou\s+must\s+(?:always|never)\b",
    re.IGNORECASE,
)


class SpeakerNotesDetector(Detector):
    id = "DET-009"
    name = "speaker_notes"
    description = (
        "Directive/injection content in PowerPoint speaker notes — machine-readable "
        "but not shown when the deck is presented."
    )
    supported_kinds = frozenset({"pptx"})
    default_severity = Severity.MEDIUM

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        for para in doc.paragraphs:
            if para.raw.get("element") != "notes":
                continue
            strong = _STRONG_RE.search(para.text)
            directive = _DIRECTIVE_RE.search(para.text)
            match = strong or directive
            if match is None:
                continue
            tier = "strong" if strong is not None else "directive"
            evidence.append(
                self.make_evidence(
                    title="Directive in speaker notes",
                    description=(
                        f"Speaker notes contain a {tier} instruction ('{match.group(0)}'). "
                        "Notes are not shown in the presentation but are read by any text "
                        "extractor or LLM that ingests the deck."
                    ),
                    severity=Severity.HIGH if strong is not None else Severity.MEDIUM,
                    location=Location(
                        source=doc.source_name,
                        paragraph=para.index,
                        run=0,
                        element=f"notes:slide{para.raw.get('slide')}",
                        char_range=(match.start(), match.end()),
                    ),
                    raw={
                        "text": para.text,
                        "slide": para.raw.get("slide"),
                        "tier": tier,
                        "phrase": match.group(0),
                    },
                )
            )
        return evidence
