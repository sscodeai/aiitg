"""Pipeline — scan → sanitize → trust-label in one call.

The M1 "document → cleaned text → LLM" closed loop. Feed an untrusted file
in, get back: the scan report (evidence), the sanitized text (safe to hand to
an LLM), and a trust label (whether the document should be used at all).

Typical usage::

    from ai_input_trust_gateway import process_file

    result = process_file("report.docx")
    if result.label.value == "safe":
        llm_context = result.sanitized.text          # feed directly
    elif result.label.value == "caution":
        llm_context = result.sanitized.text          # sanitized is enough
    else:  # dangerous
        human_review(result.report)                  # block / escalate
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_input_trust_gateway.core.detector import default_detector_registry, run_scan
from ai_input_trust_gateway.core.document import ParsedDocument
from ai_input_trust_gateway.core.evidence import ScanReport, Severity
from ai_input_trust_gateway.core.registry import default_format_registry
from ai_input_trust_gateway.policy import Decision, default_policy
from ai_input_trust_gateway.sanitize import Sanitizer, SanitizeResult
from ai_input_trust_gateway.trust_label import TrustLabel, TrustLabelValue, compute_trust_label


@dataclass
class PipelineResult:
    """Full output of the scan → sanitize → label → decide pipeline."""

    report: ScanReport
    sanitized: SanitizeResult
    label: TrustLabel
    decision: Decision | None = None
    doc: ParsedDocument | None = None

    @property
    def is_safe(self) -> bool:
        return self.label.value.value == "safe"

    @property
    def is_dangerous(self) -> bool:
        return self.label.value.value == "dangerous"

    @property
    def is_blocked(self) -> bool:
        return self.decision is not None and self.decision.is_blocked


def process_file(path: str, *, mode: str = "strip", min_severity: Severity | None = None) -> PipelineResult:
    """Scan + sanitize + trust-label a single file.

    Args:
        path: file to process
        mode: sanitizer mode, "strip" (default) or "redact"
        min_severity: minimum severity to keep in the scan report

    Returns:
        :class:`PipelineResult` with report, sanitized text, and trust label.
    """
    registry = default_detector_registry()
    report = run_scan(str(path), registry)
    if min_severity is not None:
        report = report.filter(min_severity=min_severity)

    # parse again (report already has the doc internally? — re-parse for sanitize)
    fmt = default_format_registry().detect(path)
    if fmt is None:
        return PipelineResult(
            report=report,
            sanitized=SanitizeResult(text="", removed=[], mode=mode),
            label=TrustLabel(
                value=TrustLabelValue.DANGEROUS,
                score=0.0,
                structure_score=0.0,
                content_score=0.0,
                meta_score=0.0,
                reasons=["unsupported format"],
            ),
        )
    doc = default_format_registry().parse(path)

    sanitizer = Sanitizer(mode=mode, min_severity=min_severity or Severity.LOW)
    sanitized = sanitizer.sanitize(doc, report.evidence)

    label = compute_trust_label(report, doc_text=doc.all_text)

    # M2: policy decision (Assume Compromise execution layer)
    decision = default_policy().evaluate(report, label.value)

    # embed label + decision into report for a single serializable output
    report.trust_label = label.to_dict()
    report.decision = decision.to_dict()

    return PipelineResult(report=report, sanitized=sanitized, label=label, decision=decision, doc=doc)
