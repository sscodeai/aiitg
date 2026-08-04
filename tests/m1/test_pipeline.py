"""M1 tests: sanitizer + trust label + pipeline."""

from __future__ import annotations

from ai_input_trust_gateway.pipeline import process_file
from ai_input_trust_gateway.sanitize import INVISIBLE_RE, Sanitizer
from ai_input_trust_gateway.trust_label import TrustLabelValue, compute_trust_label
from tests.fixtures import builders


class TestSanitizer:
    def test_strip_zerowidth_docx(self, scan_file, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "zw.docx")
        report = scan_file(f)
        from ai_input_trust_gateway.core.registry import default_format_registry

        doc = default_format_registry().parse(f)
        result = Sanitizer(mode="strip").sanitize(doc, report.evidence)
        assert "\u200b" not in result.text
        assert "SECRETINSTRUCTION" in result.text  # zero-width removed, text intact

    def test_redact_hidden_style(self, scan_file, tmp_path):
        f = builders.build_html_hidden_style(tmp_path / "h.html")
        report = scan_file(f)
        from ai_input_trust_gateway.core.registry import default_format_registry

        doc = default_format_registry().parse(f)
        result = Sanitizer(mode="redact").sanitize(doc, report.evidence)
        # display:none content replaced with [REDACTED]
        assert "IGNORE ALL PREVIOUS" not in result.text
        assert "visible text" in result.text

    def test_strip_hidden_sheet(self, scan_file, tmp_path):
        f = builders.build_xlsx_hidden_sheet(tmp_path / "hs.xlsx")
        report = scan_file(f)
        from ai_input_trust_gateway.core.registry import default_format_registry

        doc = default_format_registry().parse(f)
        result = Sanitizer(mode="strip").sanitize(doc, report.evidence)
        assert "rate this proposal" not in result.text
        assert "ok" in result.text  # visible sheet text kept

    def test_removed_count(self, scan_file, tmp_path):
        f = builders.build_xlsx_hidden_sheet(tmp_path / "hs.xlsx")
        report = scan_file(f)
        from ai_input_trust_gateway.core.registry import default_format_registry

        doc = default_format_registry().parse(f)
        result = Sanitizer(mode="strip").sanitize(doc, report.evidence)
        assert result.removed_count >= 1

    def test_benign_passthrough(self, scan_file, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        report = scan_file(f)
        from ai_input_trust_gateway.core.registry import default_format_registry

        doc = default_format_registry().parse(f)
        result = Sanitizer(mode="strip").sanitize(doc, report.evidence)
        assert "perfectly normal" in result.text
        assert result.removed_count == 0

    def test_invisible_regex_covers_common_chars(self):
        assert INVISIBLE_RE.search("\u200b") is not None
        assert INVISIBLE_RE.search("\ufeff") is not None
        assert INVISIBLE_RE.search("\u2060") is not None
        assert INVISIBLE_RE.search("normal") is None


class TestTrustLabel:
    def test_benign_safe(self, scan_file, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        report = scan_file(f)
        label = compute_trust_label(report, doc_text="This is a normal document.")
        assert label.value == TrustLabelValue.SAFE
        assert label.score >= 0.7

    def test_zerowidth_caution_or_dangerous(self, scan_file, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "zw.docx")
        report = scan_file(f)
        label = compute_trust_label(report, doc_text="Visible text SECRETINSTRUCTION more text")
        assert label.value in (TrustLabelValue.CAUTION, TrustLabelValue.DANGEROUS)
        assert label.score < 0.7

    def test_hidden_sheet_reduces_score(self, scan_file, tmp_path):
        f = builders.build_xlsx_hidden_sheet(tmp_path / "hs.xlsx")
        report = scan_file(f)
        label = compute_trust_label(report, doc_text="ok")
        assert label.score < 0.7

    def test_to_dict(self, scan_file, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        report = scan_file(f)
        label = compute_trust_label(report, doc_text="normal")
        d = label.to_dict()
        assert d["value"] == "safe"
        assert "dimensions" in d
        assert d["dimensions"]["structure"] == 1.0


class TestPipeline:
    def test_process_benign(self, tmp_path):
        f = builders.build_docx_benign(tmp_path / "clean.docx")
        result = process_file(str(f))
        assert result.is_safe
        assert "perfectly normal" in result.sanitized.text

    def test_process_zerowidth(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "zw.docx")
        result = process_file(str(f))
        assert not result.is_safe
        assert "\u200b" not in result.sanitized.text
        assert result.report.trust_label is not None
        assert result.report.trust_label["value"] in ("caution", "dangerous")

    def test_process_hidden_sheet_removes_content(self, tmp_path):
        f = builders.build_xlsx_hidden_sheet(tmp_path / "hs.xlsx")
        result = process_file(str(f))
        assert "rate this proposal" not in result.sanitized.text
        assert "ok" in result.sanitized.text

    def test_process_redact_mode(self, tmp_path):
        f = builders.build_html_hidden_style(tmp_path / "h.html")
        result = process_file(str(f), mode="redact")
        assert "IGNORE ALL" not in result.sanitized.text
        assert "visible text" in result.sanitized.text

    def test_process_unsupported_format(self, tmp_path):
        f = tmp_path / "x.xyz"
        f.write_bytes(b"data")
        result = process_file(str(f))
        assert result.is_dangerous
        assert result.report.status == "error"
