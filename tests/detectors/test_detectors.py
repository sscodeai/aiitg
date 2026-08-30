"""Detector tests: one file per detector, builder-generated malicious samples."""

from aiitg.core.evidence import Severity
from tests.fixtures import builders


class TestZeroWidth:
    def test_docx_hit(self, scan_file, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "zw.docx")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-001"]
        assert len(hits) >= 1
        ev = hits[0]
        assert ev.severity == Severity.HIGH
        assert ev.location.paragraph is not None
        assert ev.raw["codepoint"] == "U+200B"

    def test_docx_benign_clean(self, scan_file, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-001"]
        assert len(hits) == 0


class TestHiddenStyle:
    def test_docx_white_text(self, scan_file, tmp_path):
        f = builders.build_docx_with_white_text(tmp_path / "white.docx")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-002"]
        assert len(hits) >= 1
        assert any("white" in h.description.lower() for h in hits)

    def test_html_hidden_style(self, scan_file, tmp_path):
        f = builders.build_html_hidden_style(tmp_path / "hidden.html")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-002"]
        assert len(hits) >= 1

    def test_benign_clean(self, scan_file, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        report = scan_file(f)
        assert len([ev for ev in report.evidence if ev.detector_id == "DET-002"]) == 0


class TestTinyFont:
    def test_docx_tiny(self, scan_file, tmp_path):
        f = builders.build_docx_with_tiny_font(tmp_path / "tiny.docx")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-003"]
        assert len(hits) >= 1
        assert hits[0].raw["font_size"] <= 2.0

    def test_html_tiny(self, scan_file, tmp_path):
        f = builders.build_html_tiny_font(tmp_path / "tiny.html")
        report = scan_file(f)
        assert len([ev for ev in report.evidence if ev.detector_id == "DET-003"]) >= 1

    def test_pdf_tiny(self, scan_file, tmp_path):
        f = builders.build_pdf_tiny_text(tmp_path / "tiny.pdf")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-003"]
        assert len(hits) >= 1

    def test_benign_clean(self, scan_file, tmp_path):
        f = builders.build_pdf_benign(tmp_path / "clean.pdf")
        report = scan_file(f)
        assert len([ev for ev in report.evidence if ev.detector_id == "DET-003"]) == 0


class TestHiddenSheet:
    def test_hidden_sheet(self, scan_file, tmp_path):
        f = builders.build_xlsx_hidden_sheet(tmp_path / "hs.xlsx")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-004"]
        assert len(hits) >= 1
        assert any("Hidden sheet" in h.title for h in hits)

    def test_hidden_row(self, scan_file, tmp_path):
        f = builders.build_xlsx_hidden_row(tmp_path / "hr.xlsx")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-004"]
        assert len(hits) >= 1
        assert any("rows" in h.title for h in hits)

    def test_benign_clean(self, scan_file, tmp_path):
        f = builders.build_xlsx_benign(tmp_path / "clean.xlsx")
        report = scan_file(f)
        assert len([ev for ev in report.evidence if ev.detector_id == "DET-004"]) == 0


class TestOOXMLNodes:
    def test_tracked_delete(self, scan_file, tmp_path):
        f = builders.build_docx_with_tracked_delete(tmp_path / "del.docx")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-005"]
        assert len(hits) >= 1

    def test_benign_clean(self, scan_file, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        report = scan_file(f)
        assert len([ev for ev in report.evidence if ev.detector_id == "DET-005"]) == 0


class TestAnnotations:
    def test_html_comments(self, scan_file, tmp_path):
        f = tmp_path / "c.html"
        f.write_text(
            "<html><body><p>hi</p><!-- SECRET INSTRUCTION --></body></html>", encoding="utf-8"
        )
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-006"]
        assert len(hits) >= 1
        assert "SECRET INSTRUCTION" in hits[0].raw["comments"][0]

    def test_benign_clean(self, scan_file, tmp_path):
        f = builders.build_html_benign(tmp_path / "clean.html")
        report = scan_file(f)
        assert len([ev for ev in report.evidence if ev.detector_id == "DET-006"]) == 0


class TestDocumentMeta:
    def test_vba_macros_xlsx(self, scan_file, tmp_path):
        # xlsx with a vbaProject.bin part (simulate macro-enabled)
        import zipfile

        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        assert ws is not None
        ws.title = "Sheet1"
        ws["A1"] = "hi"
        wb.save(str(tmp_path / "base.xlsx"))
        # rebuild zip adding vbaProject.bin
        import io

        buf = io.BytesIO()
        with zipfile.ZipFile(tmp_path / "base.xlsx") as zf:
            names = zf.namelist()
            parts = {n: zf.read(n) for n in names}
        parts["xl/vbaProject.bin"] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # OLE magic
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for n, data in parts.items():
                zf.writestr(n, data)
        f = tmp_path / "macro.xlsm"
        f.write_bytes(buf.getvalue())

        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-007"]
        assert any("VBA" in h.title for h in hits)

    def test_html_js(self, scan_file, tmp_path):
        f = tmp_path / "js.html"
        f.write_text("<html><body><script>alert(1)</script><p>hi</p></body></html>", encoding="utf-8")
        report = scan_file(f)
        hits = [ev for ev in report.evidence if ev.detector_id == "DET-007"]
        assert any("JavaScript" in h.title for h in hits)
