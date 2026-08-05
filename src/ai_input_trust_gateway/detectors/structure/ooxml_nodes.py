"""DET-005: OOXML structural hidden nodes.

Tracked-deleted text (w:del/w:delText), comment range markers, alternate
content (mc:AlternateContent), and other OOXML nodes that can carry
machine-visible but human-hidden content.
"""

from __future__ import annotations

import re

from lxml import etree

from ai_input_trust_gateway.core.detector import Detector
from ai_input_trust_gateway.core.document import ParsedDocument
from ai_input_trust_gateway.core.evidence import Evidence, Location, Severity

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

# OOXML node names that can carry hidden content, per part
RISKY_PATTERNS: dict[str, list[str]] = {
    "word/document.xml": [
        "w:del", "w:delText", "w:commentRangeStart", "w:commentRangeEnd",
        "w:altChunk", "w:proofErr", "w:ins", "w:smartTag",
    ],
    "xl/worksheets/sheet*.xml": [
        "mc:AlternateContent", "mc:Choice", "mc:Fallback",
        "x14:conditionalFormatting", "v:alternateContent",
    ],
    "ppt/slides/slide*.xml": [
        "mc:AlternateContent", "mc:Choice", "mc:Fallback",
        "a:comment", "p:comment",
    ],
    "ppt/notesSlides/notesSlide*.xml": [
        "mc:AlternateContent", "mc:Choice", "mc:Fallback",
    ],
}

# Also scan any part for common hidden markers regardless of name
GENERIC_MARKERS = ["altChunk", "AlternateContent"]
_DET_DESC = (
    "OOXML structural nodes that hide content from humans but not parsers "
    "(tracked-delete, altChunk, comments)."
)


class OOXMLNodesDetector(Detector):
    id = "DET-005"
    name = "ooxml_nodes"
    description = _DET_DESC
    supported_kinds = frozenset({"docx", "xlsx", "pptx"})
    default_severity = Severity.MEDIUM

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        for part_name, part_bytes in doc.ooxml_parts.items():
            if not self._relevant_part(part_name):
                continue
            try:
                root = etree.fromstring(part_bytes)
            except Exception:  # noqa: BLE001 — a malformed part shouldn't kill the scan
                continue
            self._scan_part(part_name, root, doc, evidence)
        return evidence

    def _relevant_part(self, name: str) -> bool:
        return any(re.match(pattern.replace("*", ".*"), name) for pattern in RISKY_PATTERNS)

    def _scan_part(self, part_name: str, root: etree._Element, doc: ParsedDocument, evidence: list[Evidence]) -> None:
        for pattern, tags in RISKY_PATTERNS.items():
            if not re.match(pattern.replace("*", ".*"), part_name):
                continue
            for tag in tags:
                ns, local = tag.split(":")
                local_name = f"{{{W_NS if ns == 'w' else 'http://schemas.openxmlformats.org/markup-compatibility/2006'}}}{local}"
                # fall back to any-namespace match
                matches = [el for el in root.iter() if el.tag == local_name or el.tag.endswith(f"}}{local}")]
                for el in matches:
                    # for w:delText, capture the hidden text
                    text = ""
                    if el.tag.endswith("}delText"):
                        text = el.text or ""
                    evidence.append(
                        self.make_evidence(
                            title=f"OOXML hidden node: {tag}",
                            description=(
                                f"Part '{part_name}' contains <{tag}> — content visible to machine parsers "
                                "but hidden from normal document views."
                            ),
                            location=Location(
                                source=doc.source_name,
                                element=f"{part_name}#{tag}",
                            ),
                            raw={
                                "part": part_name,
                                "node": tag,
                                "text": text[:500],
                                "count": len(matches),
                            },
                        )
                    )
                    break  # one evidence per node type per part is enough
