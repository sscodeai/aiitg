"""End-to-end CLI tests: build malicious sample → aiitg scan → exit codes."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from ai_input_trust_gateway.cli.app import app
from tests.fixtures import builders

runner = CliRunner()


def _run_scan(path: Path, *args: str):
    return runner.invoke(app, ["scan", str(path), *args])


class TestCLIScan:
    def test_malicious_docx_exit_1_and_json(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = _run_scan(f, "--format", "json")
        assert result.exit_code == 1, result.output
        assert '"DET-001"' in result.output
        assert '"risk_score"' in result.output
        assert '"evidence"' in result.output

    def test_benign_docx_exit_0(self, tmp_path):
        f = builders.build_docx_benign(tmp_path / "ok.docx")
        result = _run_scan(f, "--format", "json")
        assert result.exit_code == 0, result.output

    def test_min_severity_high_skips_low(self, tmp_path):
        f = builders.build_docx_with_tiny_font(tmp_path / "tiny.docx")
        # tiny font is MEDIUM; with min-severity high, no evidence at/above → exit 0
        result = _run_scan(f, "--min-severity", "high")
        assert result.exit_code == 0, result.output

    def test_unsupported_format_exit_3(self, tmp_path):
        f = tmp_path / "x.xyz"
        f.write_bytes(b"not a real file")
        result = _run_scan(f)
        assert result.exit_code == 3, result.output

    def test_rich_format(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = _run_scan(f, "--format", "rich")
        assert result.exit_code == 1
        assert "Evidence" in result.output or "finding" in result.output

    def test_directory_recursive(self, tmp_path):
        d = tmp_path / "inbox"
        d.mkdir()
        builders.build_docx_with_zerowidth(d / "a.docx")
        builders.build_docx_benign(d / "b.docx")
        result = _run_scan(d, "--recursive")
        assert result.exit_code == 1  # at least one file found something

    def test_skip_detector(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = _run_scan(f, "--skip-detector", "DET-001")
        # with DET-001 skipped, the docx has no other hits → exit 0
        assert result.exit_code == 0, result.output

    def test_output_file(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        out = tmp_path / "out.json"
        result = _run_scan(f, "--output", str(out))
        assert result.exit_code == 1
        assert out.exists()
        assert '"DET-001"' in out.read_text(encoding="utf-8")


class TestCLIList:
    def test_list_detectors(self):
        result = runner.invoke(app, ["list-detectors"])
        assert result.exit_code == 0
        for det_id in ("DET-001", "DET-002", "DET-003", "DET-004", "DET-005", "DET-006", "DET-007"):
            assert det_id in result.output


class TestCLIVersion:
    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "aiitg" in result.output
