"""Detector base class, registry, and scan orchestration."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import UTC, datetime

from aiitg.core.document import ParsedDocument
from aiitg.core.errors import ScanError
from aiitg.core.evidence import Evidence, Location, ScanReport, Severity


class Detector(ABC):
    """Base class for all detectors.

    Subclasses implement :meth:`scan` (pure, side-effect free: no I/O, no
    mutation of ``doc``). Registration happens via :class:`DetectorRegistry`.
    """

    id: str  # unique, e.g. "DET-001"
    name: str  # snake_case, e.g. "zero_width"
    description: str
    supported_kinds: frozenset[str] = frozenset()
    default_severity: Severity = Severity.MEDIUM

    @abstractmethod
    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        """Return evidence list for the parsed document (may be empty)."""
        ...

    def make_evidence(
        self,
        *,
        title: str,
        description: str,
        location: Location,
        severity: Severity | None = None,
        raw: dict | None = None,
    ) -> Evidence:
        return Evidence(
            detector_id=self.id,
            detector_name=self.name,
            severity=severity or self.default_severity,
            title=title,
            description=description,
            location=location,
            raw=raw or {},
        )

    def snippet(self, text: str, span: tuple[int, int], radius: int = 40) -> str:
        """Extract a human-readable hit snippet from ``text`` around ``span``.

        The span is clamped to text bounds; the snippet shows ``radius``
        characters on each side (or from the start/end when clamped).
        """
        start, end = span
        start = max(0, min(start, len(text)))
        end = max(start, min(end, len(text)))
        s = max(0, start - radius)
        e = min(len(text), end + radius)
        prefix = "…" if s > 0 else ""
        suffix = "…" if e < len(text) else ""
        return f"{prefix}{text[s:e]}{suffix}"


class DetectorRegistry:
    """Holds all detectors and runs the chain for a parsed document."""

    def __init__(self, detectors: Iterable[Detector] | None = None) -> None:
        self._detectors: dict[str, Detector] = {}
        for det in detectors or []:
            self.register(det)

    def register(self, detector: Detector) -> None:
        if detector.id in self._detectors:
            raise ValueError(f"duplicate detector id: {detector.id}")
        self._detectors[detector.id] = detector

    @property
    def detectors(self) -> list[Detector]:
        return [self._detectors[k] for k in sorted(self._detectors)]

    def get(self, detector_id: str) -> Detector | None:
        return self._detectors.get(detector_id)

    def detectors_for(self, kind: str) -> list[Detector]:
        return [d for d in self.detectors if kind in d.supported_kinds]

    def run(
        self,
        doc: ParsedDocument,
        *,
        min_severity: Severity | None = None,
        skip_detectors: set[str] | None = None,
    ) -> ScanReport:
        """Run the full chain for ``doc`` and build a :class:`ScanReport`.

        Per-detector exceptions are caught and appended as ``warnings`` on the
        report (one detector must never break the whole scan).
        """
        skip = skip_detectors or set()
        evidence: list[Evidence] = []
        warnings: list[str] = []
        for det in self.detectors_for(doc.kind):
            if det.id in skip:
                continue
            try:
                hits = det.scan(doc)
                evidence.extend(hits)
            except Exception as exc:  # noqa: BLE001 — one detector must not kill the scan
                warnings.append(f"{det.id} ({det.name}) failed: {exc}")
        evidence.sort(key=lambda ev: (ev.detector_id, str(ev.location.to_dict())))

        started = datetime.now(UTC)
        report = ScanReport(
            file=doc.source_name,
            kind=doc.kind,
            started_at=started.isoformat(),
            duration_ms=0,
            evidence=evidence,
        )
        report.warnings = warnings  # type: ignore[attr-defined]  # assigned dynamically
        if min_severity is not None:
            report = report.filter(min_severity=min_severity)
        return report


def run_scan(path: str, registry: DetectorRegistry | None = None) -> ScanReport:
    """Convenience: parse ``path`` and run the detector chain.

    Returns a :class:`ScanReport` — parse errors become ``status == "error"``.
    """
    from aiitg.core.registry import default_format_registry

    if registry is None:
        registry = default_detector_registry()
    fmt = default_format_registry().detect(path)
    if fmt is None:
        return ScanReport.from_error(
            ScanError(kind="unsupported_format", message=f"unsupported format: {path}"), file=path
        )
    doc = default_format_registry().parse(path)
    return registry.run(doc)


_default_registry: DetectorRegistry | None = None


def default_detector_registry() -> DetectorRegistry:
    """Lazily-built registry with all bundled detectors (imports them)."""
    global _default_registry
    if _default_registry is None:
        from aiitg.detectors import ALL_DETECTORS

        _default_registry = DetectorRegistry(ALL_DETECTORS)
    return _default_registry
