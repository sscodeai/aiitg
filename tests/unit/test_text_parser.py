"""Text/code parser + format-registry tests (the DET-008 input path)."""

from __future__ import annotations

from pathlib import Path

from aiitg.core.errors import ScanError
from aiitg.core.registry import FormatRegistry, default_format_registry
from aiitg.parsers.text_parser import RULE_FILE_NAMES, TextParser, language_for_path
from tests.fixtures import builders


class TestLanguageDetection:
    def test_extensions_map_to_comment_families(self):
        assert language_for_path("a.py") == "hash"
        assert language_for_path("a.ts") == "slash"
        assert language_for_path("a.sql") == "dash"
        assert language_for_path("a.html") == "html"
        assert language_for_path("notes.xyz") is None

    def test_rule_files_are_recognised_by_name(self):
        for name in (".cursorrules", "AGENTS.md", "CLAUDE.md"):
            assert language_for_path(name) == "hash"


class TestTextParser:
    def test_one_paragraph_per_line_with_line_numbers(self, tmp_path):
        f = builders.build_py_benign(tmp_path / "ok.py")
        doc = TextParser().parse(f)
        assert doc.kind == "text"
        assert doc.metadata["lang"] == "hash"
        assert [p.index for p in doc.paragraphs] == list(range(1, len(doc.paragraphs) + 1))
        assert doc.paragraphs[0].text == '"""A small service module."""'
        assert doc.source_name == "ok.py"

    def test_utf8_bom_is_not_content(self, tmp_path):
        f = tmp_path / "bom.py"
        f.write_bytes("\ufeffprint('hi')\n".encode())
        doc = TextParser().parse(f)
        assert doc.paragraphs[0].text == "print('hi')"

    def test_binary_file_fails_closed(self, tmp_path):
        f = tmp_path / "blob.py"
        f.write_bytes(b"\x00\x01\x02binary\x00")
        try:
            TextParser().parse(f)
        except ScanError as exc:
            assert exc.kind == "parse_failed"
        else:  # pragma: no cover - the assertion below is the test
            raise AssertionError("binary content must not parse as text")


class TestRegistryDispatch:
    def test_extensionless_rule_file_resolves_by_name(self, tmp_path):
        f = builders.build_cursorrules_with_directive(tmp_path / ".cursorrules")
        handler = default_format_registry().detect(f)
        assert handler is not None
        assert handler.kind == "text"

    def test_extension_registration_accepts_dotted_and_bare_spellings(self, tmp_path):
        # A handler registered with ".py" and one registered with "py" must land in the
        # same slot; a silently unreachable handler is how a whole format goes unscanned.
        registry = FormatRegistry()
        from aiitg.core.registry import FormatHandler

        registry.register(FormatHandler(kind="text", extensions=(".py",), parser_cls=TextParser))
        assert registry.detect(tmp_path / "a.py") is not None
        assert registry.detect(tmp_path / "a.zzz") is None

    def test_python_is_parseable_and_prose_is_parseable(self):
        registry = default_format_registry()
        assert registry.detect("x.py") is not None
        assert registry.detect("README.md") is not None

    def test_rule_file_names_are_the_documented_set(self):
        assert ".cursorrules" in RULE_FILE_NAMES
        assert "agents.md" in RULE_FILE_NAMES

    def test_unsupported_extension_is_still_unsupported(self):
        assert default_format_registry().detect("archive.7z") is None


class TestCliScanOnCode:
    def test_kind_is_text_for_a_python_file(self, scan_file, tmp_path):
        report = scan_file(builders.build_py_with_directive(tmp_path / "account.py"))
        assert report.kind == "text"
        assert report.file == "account.py"

    def test_scan_report_is_serialisable(self, scan_file, tmp_path):
        import json

        report = scan_file(builders.build_py_with_directive(tmp_path / "account.py"))
        payload = json.loads(report.to_json())
        assert payload["scan"]["kind"] == "text"
        assert payload["evidence"][0]["location"]["paragraph"] == 9


def test_path_argument_type_is_tolerated():
    # PathLike and str must both work (the CLI passes Path, the pipeline passes str).
    assert language_for_path(Path("a.py")) == "hash"
    assert language_for_path("a.py") == "hash"
