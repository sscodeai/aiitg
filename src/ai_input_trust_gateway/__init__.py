"""AI Input Trust Gateway — hidden content auditor for documents fed to LLMs/Agents.

Core principle: **External content is data, never authority.**

Scan untrusted documents (docx/xlsx/pdf/html) for hidden content that could
smuggle prompt-injection instructions a human reader never sees, and emit a
structured, coordinate-level evidence report.
"""

from ai_input_trust_gateway._version import __version__
from ai_input_trust_gateway.core.detector import Detector, DetectorRegistry, run_scan
from ai_input_trust_gateway.core.document import ParsedDocument, PdfPage, Sheet, TextParagraph, TextRun
from ai_input_trust_gateway.core.evidence import Evidence, Location, ScanReport, Severity
from ai_input_trust_gateway.core.registry import FormatRegistry

__all__ = [
    "__version__",
    "ParsedDocument",
    "TextParagraph",
    "TextRun",
    "Sheet",
    "PdfPage",
    "Evidence",
    "Location",
    "Severity",
    "ScanReport",
    "Detector",
    "DetectorRegistry",
    "run_scan",
    "FormatRegistry",
    "scan_file",
    "process_file",
]


def scan_file(path: str, *, min_severity: Severity | None = None) -> ScanReport:
    """Convenience entry point: scan a single file with the default registry.

    Auto-dispatches by file extension (with sniff fallback), runs the detector
    chain for the detected format, and returns a :class:`ScanReport`.

    Args:
        path: Path to the file to scan.
        min_severity: If given, only evidence at or above this severity is kept.

    Returns:
        A :class:`ScanReport` (never raises for parse errors — those become
        ``scan.status == "error"``).
    """
    from ai_input_trust_gateway.core.detector import default_detector_registry
    from ai_input_trust_gateway.core.registry import default_format_registry

    fmt = default_format_registry().detect(path)
    if fmt is None:
        from ai_input_trust_gateway.core.errors import ScanError

        return ScanReport.from_error(ScanError(kind="unsupported_format", message=f"unsupported format: {path}"))
    doc = default_format_registry().parse(path)
    return default_detector_registry().run(doc, min_severity=min_severity)
