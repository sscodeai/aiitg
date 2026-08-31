"""Evidence data model — the single source of truth for all scan output.

Everything the CLI/reporters emit (JSON, rich, exit codes) derives from
:class:`Evidence` and :class:`ScanReport`. There is no second representation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Severity levels, ordered low -> high (ordering used for filtering)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"invalid severity: {value!r} (choose from {[s.value for s in cls]})") from None

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


def severity_at_least(sev: Severity, minimum: Severity) -> bool:
    """True if ``sev`` is at or above ``minimum`` (used for filters/exit codes)."""
    return sev.rank >= minimum.rank


# Weight used for the aggregate risk_score (documented in README).
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 8.0,
    Severity.HIGH: 20.0,
    Severity.CRITICAL: 40.0,
}


@dataclass
class Location:
    """Coordinate-level location of an evidence hit.

    Fields are format-specific but always populated for the active format:
    - docx: ``paragraph`` (index), ``run`` (index), ``char_range``
    - xlsx: ``sheet``, ``row`` (1-based), ``col`` (1-based), ``char_range``
    - pdf:  ``page`` (1-based), ``char_range``
    - html: ``element`` (CSS-ish path), ``char_range``
    ``element`` covers non-text locations (XML part name, XPath, comment index).
    """

    source: str = "memory"
    paragraph: int | None = None
    run: int | None = None
    sheet: str | None = None
    row: int | None = None
    col: int | None = None
    page: int | None = None
    char_range: tuple[int, int] | None = None
    element: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d.get("char_range") is not None:
            d["char_range"] = list(d["char_range"])
        return d


@dataclass
class Evidence:
    """A single detection result, self-contained (location + raw to reproduce)."""

    detector_id: str  # e.g. "DET-001"
    detector_name: str  # e.g. "zero_width"
    severity: Severity
    title: str
    description: str
    location: Location = field(default_factory=Location)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["location"] = self.location.to_dict()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


@dataclass
class ScanReport:
    """Full scan result: file info, summary, risk score, evidence list."""

    file: str
    kind: str
    schema_version: str = "0.1.0"
    tool_name: str = "aiitg"
    tool_version: str = "0.1.0"
    status: str = "ok"  # ok | error
    error: dict[str, Any] | None = None
    started_at: str = ""
    duration_ms: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    trust_label: dict | None = None  # filled by pipeline when trust labeling runs
    decision: dict | None = None  # filled by pipeline when policy evaluation runs

    @classmethod
    def from_error(cls, error: Any, *, file: str = "") -> ScanReport:
        err = error.to_dict() if hasattr(error, "to_dict") else {"kind": "unknown", "message": str(error)}
        return cls(file=file, kind="unknown", status="error", error=err)

    @property
    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for ev in self.evidence:
            counts[ev.severity.value] += 1
        counts["total"] = len(self.evidence)
        return counts

    @property
    def risk_score(self) -> float:
        """Aggregate 0..1 risk. Weighted sum capped at 100 then /100."""
        total = sum(SEVERITY_WEIGHTS.get(ev.severity, 0.0) for ev in self.evidence)
        return round(min(1.0, total / 100.0), 4)

    def filter(self, min_severity: Severity | None = None) -> ScanReport:
        if min_severity is None:
            return self
        kept = [ev for ev in self.evidence if severity_at_least(ev.severity, min_severity)]
        return ScanReport(
            file=self.file,
            kind=self.kind,
            schema_version=self.schema_version,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            status=self.status,
            error=self.error,
            started_at=self.started_at,
            duration_ms=self.duration_ms,
            evidence=kept,
        )

    def has_severity(self, min_severity: Severity) -> bool:
        """True if any evidence is at or above ``min_severity`` (drives exit code)."""
        return any(severity_at_least(ev.severity, min_severity) for ev in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": {"name": self.tool_name, "version": self.tool_version},
            "scan": {
                "file": self.file,
                "kind": self.kind,
                "started_at": self.started_at,
                "duration_ms": self.duration_ms,
                "status": self.status,
                "error": self.error,
            },
            "summary": self.summary,
            "risk_score": self.risk_score,
            "trust_label": self.trust_label,
            "decision": self.decision,
            "evidence": [ev.to_dict() for ev in self.evidence],
        }

    def to_json(self, path: str | None = None, *, indent: int | None = 2) -> str:
        text = json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return text
