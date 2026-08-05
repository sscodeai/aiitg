"""Trust labeling — multi-dimensional credibility scoring of a scanned document.

M1 core: turn a scan report into an actionable trust decision.

Three dimensions:
- **structure**: hidden content (zero-width, hidden runs, hidden sheets, OOXML
  nodes, comments) — evidence of deliberate concealment.
- **content**: semantic injection signals (instruction-like text in metadata or
  hidden regions) — evidence of manipulation intent.
- **meta**: document metadata risk (macro/VBA, suspicious keywords).

Each dimension scores 0..1; the aggregate produces a ``TrustLabel``:
- ``safe`` (score >= 0.7): no significant hidden content, feed to LLM directly
- ``caution`` (0.4 <= score < 0.7): some hidden content, sanitize before feeding
- ``dangerous`` (score < 0.4): significant concealment, block / human review
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ai_input_trust_gateway.core.evidence import Evidence, ScanReport, Severity

# weights per severity for structure dimension
_STRUCT_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}

# detector IDs that signal deliberate concealment (structure)
_STRUCT_DETECTORS = {"DET-001", "DET-002", "DET-003", "DET-004", "DET-005", "DET-006"}
# detector IDs that signal manipulation intent (content)
_CONTENT_DETECTORS = {"DET-007"}

# keywords that suggest instruction-like payloads (in metadata or hidden text)
_INSTRUCTION_HINTS = (
    "ignore", "instruction", "prompt", "system", "override", "always",
    "never", "secret", "password", "do not reveal", "rate this", "score",
    "rank this", "select this",
)


class TrustLabelValue(StrEnum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"


@dataclass
class TrustLabel:
    """The credibility verdict for a scanned document."""

    value: TrustLabelValue
    score: float  # 0..1
    structure_score: float
    content_score: float
    meta_score: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": self.value.value,
            "score": round(self.score, 3),
            "dimensions": {
                "structure": round(self.structure_score, 3),
                "content": round(self.content_score, 3),
                "meta": round(self.meta_score, 3),
            },
            "reasons": self.reasons,
        }


def _structure_score(evidence: list[Evidence]) -> tuple[float, list[str]]:
    """Score 0..1 based on hidden-content evidence; higher = worse (less trustworthy)."""
    hits = [ev for ev in evidence if ev.detector_id in _STRUCT_DETECTORS]
    if not hits:
        return 1.0, []
    # weighted penalty: sum weights, cap at 1.0
    penalty = min(1.0, sum(_STRUCT_WEIGHT.get(ev.severity, 0.2) for ev in hits))
    score = 1.0 - penalty
    reasons = [
        f"hidden content: {len(hits)} finding(s) "
        f"({'/'.join(sorted({ev.detector_id for ev in hits}))})"
    ]
    return score, reasons


def _content_score(evidence: list[Evidence], doc_text: str = "") -> tuple[float, list[str]]:
    """Score based on semantic injection signals in metadata / hidden text."""
    reasons: list[str] = []
    penalty = 0.0

    # metadata-based signals (DET-007)
    for ev in evidence:
        if ev.detector_id == "DET-007" and ev.title == "Suspicious metadata content":
            penalty += 0.4
            reasons.append("suspicious keywords in metadata")

    # scan the raw text for instruction-like phrasing near hidden content
    lower = doc_text.lower()
    for hint in _INSTRUCTION_HINTS:
        if hint in lower:
            penalty += 0.15
            reasons.append(f"instruction-like phrasing in document ('{hint}')")
            break  # count once per category

    penalty = min(penalty, 1.0)
    return 1.0 - penalty, reasons


def _meta_score(evidence: list[Evidence]) -> tuple[float, list[str]]:
    """Score based on metadata risk (VBA macros, JS)."""
    reasons: list[str] = []
    penalty = 0.0
    for ev in evidence:
        if ev.detector_id == "DET-007":
            if "VBA" in ev.title or "macro" in ev.title.lower():
                penalty += 0.6
                reasons.append("VBA/macro present")
            elif "JavaScript" in ev.title:
                penalty += 0.3
                reasons.append("JavaScript present")
    return 1.0 - min(penalty, 1.0), reasons


def compute_trust_label(report: ScanReport, doc_text: str = "") -> TrustLabel:
    """Compute a :class:`TrustLabel` from a scan report.

    Args:
        report: the scan report (evidence list used for scoring)
        doc_text: raw document text (used for content-dimension phrasing scan)

    Returns:
        :class:`TrustLabel` with aggregate + per-dimension scores.
    """
    structure, struct_reasons = _structure_score(report.evidence)
    content, content_reasons = _content_score(report.evidence, doc_text)
    meta, meta_reasons = _meta_score(report.evidence)

    # aggregate: structure 0.5 + content 0.3 + meta 0.2
    score = 0.5 * structure + 0.3 * content + 0.2 * meta

    # Conservative cap: any evidence of deliberate concealment (structure < 1.0)
    # must never yield "safe". Major concealment (HIGH/CRITICAL: structure ≤ 0.2)
    # → never above dangerous threshold; minor concealment → never above caution.
    if structure < 1.0:
        if structure <= 0.2 + 1e-9:
            score = min(score, 0.39)  # never above dangerous threshold (0.4)
        else:
            score = min(score, 0.6)  # never above caution threshold

    if score >= 0.7:
        value = TrustLabelValue.SAFE
    elif score >= 0.4:
        value = TrustLabelValue.CAUTION
    else:
        value = TrustLabelValue.DANGEROUS

    return TrustLabel(
        value=value,
        score=score,
        structure_score=structure,
        content_score=content,
        meta_score=meta,
        reasons=struct_reasons + content_reasons + meta_reasons,
    )
