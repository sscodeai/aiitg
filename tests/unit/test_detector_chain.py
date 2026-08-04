"""Unit tests: registry dispatch + detector chain + reporters."""

from __future__ import annotations

from ai_input_trust_gateway.core.detector import Detector, DetectorRegistry
from ai_input_trust_gateway.core.document import ParsedDocument
from ai_input_trust_gateway.core.errors import ScanError
from ai_input_trust_gateway.core.evidence import Evidence, Location, Severity
from ai_input_trust_gateway.core.registry import FormatHandler, FormatRegistry


class DummyDetector(Detector):
    id = "DET-999"
    name = "dummy"
    description = "dummy"
    supported_kinds = frozenset({"docx"})
    default_severity = Severity.INFO

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        return [
            self.make_evidence(
                title="dummy hit",
                description="dummy",
                location=Location(source=doc.source_name, paragraph=0),
            )
        ]


class TestRegistry:
    def test_detect_by_extension(self):
        reg = FormatRegistry()

        class P:
            def parse(self, path):
                return ParsedDocument(kind="docx", source_path=str(path))

        reg.register(FormatHandler(kind="docx", extensions=("docx",), parser_cls=P))
        assert reg.detect("foo.docx").kind == "docx"  # type: ignore[union-attr]
        assert reg.detect("foo.pdf") is None

    def test_detect_sniff_fallback(self, tmp_path):
        reg = FormatRegistry()

        class P:
            def parse(self, path):
                return ParsedDocument(kind="weird", source_path=str(path))

        reg.register(FormatHandler(kind="weird", extensions=(), parser_cls=P, sniff=lambda head: head.startswith(b"X")))
        f = tmp_path / "foo.unk"
        f.write_bytes(b"Xsome magic content")
        assert reg.detect(str(f)).kind == "weird"  # type: ignore[union-attr]

    def test_parse_unsupported(self, tmp_path):
        reg = FormatRegistry()
        f = tmp_path / "x.xyz"
        f.write_bytes(b"data")
        with pytest_raises(ScanError):
            reg.parse(f)

    def test_parse_wraps_parser_error(self, tmp_path):
        reg = FormatRegistry()

        class Boom:
            def parse(self, path):
                raise RuntimeError("boom")

        reg.register(FormatHandler(kind="docx", extensions=("docx",), parser_cls=Boom))
        f = tmp_path / "x.docx"
        f.write_bytes(b"data")
        with pytest_raises(ScanError):
            reg.parse(f)


class TestDetectorRegistry:
    def test_register_duplicate(self):
        reg = DetectorRegistry()
        reg.register(DummyDetector())
        try:
            reg.register(DummyDetector())
            assert False, "should have raised"
        except ValueError:
            pass

    def test_detectors_for_kind(self):
        reg = DetectorRegistry([DummyDetector()])
        assert len(reg.detectors_for("docx")) == 1
        assert len(reg.detectors_for("xlsx")) == 0

    def test_run_sorts_by_id(self):
        class A(Detector):
            id = "DET-AAA"
            name = "a"
            description = "a"
            supported_kinds = frozenset({"docx"})

            def scan(self, doc):
                return [self.make_evidence(title="a", description="a", location=Location(source=doc.source_name))]

        class B(Detector):
            id = "DET-BBB"
            name = "b"
            description = "b"
            supported_kinds = frozenset({"docx"})

            def scan(self, doc):
                return [self.make_evidence(title="b", description="b", location=Location(source=doc.source_name))]

        reg = DetectorRegistry([B(), A()])
        doc = ParsedDocument(kind="docx", source_path="f.docx")
        report = reg.run(doc)
        assert [ev.detector_id for ev in report.evidence] == ["DET-AAA", "DET-BBB"]

    def test_run_skip_detector(self):
        reg = DetectorRegistry([DummyDetector()])
        doc = ParsedDocument(kind="docx", source_path="f.docx")
        report = reg.run(doc, skip_detectors={"DET-999"})
        assert len(report.evidence) == 0

    def test_run_detector_exception_isolation(self):
        class Crash(Detector):
            id = "DET-CRASH"
            name = "crash"
            description = "crash"
            supported_kinds = frozenset({"docx"})

            def scan(self, doc):
                raise RuntimeError("kaboom")

        reg = DetectorRegistry([Crash(), DummyDetector()])
        doc = ParsedDocument(kind="docx", source_path="f.docx")
        report = reg.run(doc)
        # crash detector isolated; dummy still runs
        assert len(report.evidence) == 1
        assert report.evidence[0].detector_id == "DET-999"


def pytest_raises(exc):
    import pytest

    return pytest.raises(exc)
