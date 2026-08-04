"""DET-001: zero-width / invisible Unicode character detection.

Unicode defines several code points that occupy zero width on screen but are
still tokenized by LLMs. Attackers embed instructions between such characters
(or as pure zero-width runs) so a human reader sees nothing while the model
reads a full sentence.

Reference: arXiv 2507.06185 (Hidden Prompts in Manuscripts Exploit
AI-Assisted Peer Review), 2508.20863 (Hidden Prompt-Injection in Peer Review).
"""

from __future__ import annotations

from ai_input_trust_gateway.core.detector import Detector
from ai_input_trust_gateway.core.document import ParsedDocument
from ai_input_trust_gateway.core.evidence import Evidence, Location, Severity

# Zero-width / invisible / formatting characters that LLMs still read.
ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u2060": "WORD JOINER",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u00ad": "SOFT HYPHEN",
    "\u034f": "COMBINING GRAPHEME JOINER",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u061c": "ARABIC LETTER MARK",
}

# bidi override characters: can reorder visible text to hide instructions
BIDI_OVERRIDES = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
}


def _invisible_chars_in(text: str) -> list[tuple[str, str, int]]:
    """Return [(char, name, index)] for every invisible char in text."""
    out: list[tuple[str, str, int]] = []
    for i, ch in enumerate(text):
        name = ZERO_WIDTH_CHARS.get(ch)
        if name is not None:
            out.append((ch, name, i))
    return out


class ZeroWidthDetector(Detector):
    id = "DET-001"
    name = "zero_width"
    description = "Zero-width / invisible Unicode characters that a human reader never sees but LLMs tokenize."
    supported_kinds = frozenset({"docx", "xlsx", "pdf", "html"})
    default_severity = Severity.HIGH

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        for para in doc.paragraphs:
            for ch, name, idx in _invisible_chars_in(para.text):
                ev = self.make_evidence(
                    title="Zero-width character found in visible text",
                    description=(
                        f"{name} (U+{ord(ch):04X}) at character {idx}. "
                        "Invisible characters can smuggle prompt instructions that "
                        "a human reader never sees but an LLM tokenizes."
                    ),
                    location=Location(
                        source=doc.source_name,
                        paragraph=para.index,
                        char_range=(idx, idx + 1),
                    ),
                    raw={
                        "char": ch,
                        "codepoint": f"U+{ord(ch):04X}",
                        "name": name,
                        "context": self.snippet(para.text, (idx, idx + 1)),
                    },
                )
                evidence.append(ev)
        return evidence
