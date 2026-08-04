"""Unit tests: core data models + registry + reporter serialization."""

from __future__ import annotations

import json

import pytest

from ai_input_trust_gateway.core.document import ParsedDocument, TextParagraph, TextRun
from ai_input_trust_gateway.core.errors import ScanError
from ai_input_trust_gateway.core.evidence import (
    Evidence,
    Location,
    ScanReport,
    Severity,
    severity_at_least,
)


class TestSeverity:
    def test_rank_ordering(self):
        order = (
            Severity.INFO.rank < Severity.LOW.rank
            < Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank
        )
        assert order

    def test_parse(self):
        assert Severity.parse("high") == Severity.HIGH
        assert Severity.parse("CRITICAL") == Severity.CRITICAL

    def test_parse_invalid(self):
        with pytest.raises(ValueError):
            Severity.parse("super")

    def test_severity_at_least(self):
        assert severity_at_least(Severity.HIGH, Severity.LOW)
        assert not severity_at_least(Severity.LOW, Severity.HIGH)
        assert severity_at_least(Severity.HIGH, Severity.HIGH)


class TestLocation:
    def test_defaults(self):
        loc = Location()
        assert loc.source == "memory"
        assert loc.paragraph is None

    def test_to_dict_char_range_list(self):
        loc = Location(source="f.docx", paragraph=3, char_range=(10, 12))
        d = loc.to_dict()
        assert d["char_range"] == [10, 12]


class TestEvidence:
    def test_to_dict(self):
        ev = Evidence(
            detector_id="DET-001",
            detector_name="zero_width",
            severity=Severity.HIGH,
            title="t",
            description="d",
            location=Location(source="f.docx", paragraph=1),
            raw={"char": "\u200b"},
        )
        d = ev.to_dict()
        assert d["severity"] == "high"
        assert d["location"]["paragraph"] == 1
        assert d["raw"]["char"] == "\u200b"

    def test_to_json_roundtrip(self):
        ev = Evidence(detector_id="DET-001", detector_name="z", severity=Severity.LOW, title="t", description="d")
        parsed = json.loads(ev.to_json())
        assert parsed["detector_id"] == "DET-001"
        assert parsed["severity"] == "low"


class TestScanReport:
    def test_summary_counts(self):
        report = ScanReport(
            file="f",
            kind="docx",
            evidence=[
                Evidence(detector_id="a", detector_name="a", severity=Severity.HIGH, title="t", description="d"),
                Evidence(detector_id="b", detector_name="b", severity=Severity.LOW, title="t", description="d"),
            ],
        )
        s = report.summary
        assert s["total"] == 2
        assert s["high"] == 1
        assert s["low"] == 1

    def test_risk_score(self):
        report = ScanReport(
            file="f",
            kind="docx",
            evidence=[
                Evidence(detector_id="a", detector_name="a", severity=Severity.HIGH, title="t", description="d"),
            ],
        )
        # 1 x high(20) / 100 = 0.2
        assert report.risk_score == 0.2

    def test_filter(self):
        report = ScanReport(
            file="f",
            kind="docx",
            evidence=[
                Evidence(detector_id="a", detector_name="a", severity=Severity.LOW, title="t", description="d"),
                Evidence(detector_id="b", detector_name="b", severity=Severity.HIGH, title="t", description="d"),
            ],
        )
        filtered = report.filter(min_severity=Severity.HIGH)
        assert len(filtered.evidence) == 1
        assert filtered.evidence[0].severity == Severity.HIGH

    def test_has_severity(self):
        report = ScanReport(
            file="f", kind="docx",
            evidence=[
                Evidence(
                    detector_id="a", detector_name="a", severity=Severity.MEDIUM,
                    title="t", description="d",
                )
            ],
        )
        assert report.has_severity(Severity.MEDIUM)
        assert not report.has_severity(Severity.HIGH)

    def test_to_dict_structure(self):
        report = ScanReport(file="a.docx", kind="docx")
        d = report.to_dict()
        assert d["schema_version"] == "0.1.0"
        assert d["scan"]["file"] == "a.docx"
        assert d["scan"]["status"] == "ok"
        assert d["risk_score"] == 0.0

    def test_from_error(self):
        report = ScanReport.from_error(ScanError("unsupported_format", "nope"), file="x")
        assert report.status == "error"
        assert report.error is not None
        assert report.error["kind"] == "unsupported_format"


class TestParsedDocument:
    def test_all_text(self):
        doc = ParsedDocument(
            kind="docx",
            paragraphs=[
                TextParagraph(text="hello", index=0),
                TextParagraph(text="world", index=1),
            ],
        )
        assert doc.all_text == "hello\nworld"

    def test_source_name(self):
        doc = ParsedDocument(kind="docx", source_path="/tmp/foo.docx")
        assert doc.source_name == "foo.docx"

    def test_find_run(self):
        doc = ParsedDocument(
            kind="docx",
            paragraphs=[
                TextParagraph(text="abc", index=0, runs=[TextRun(text="abc")]),
            ],
        )
        run = doc.find_run(0, 0)
        assert run is not None
        assert run.text == "abc"
        assert doc.find_run(99, 99) is None
