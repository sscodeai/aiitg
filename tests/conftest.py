"""Shared pytest fixtures: scan helpers + tmp-path builders."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_input_trust_gateway.core.detector import default_detector_registry, run_scan  # noqa: E402
from ai_input_trust_gateway.core.evidence import ScanReport  # noqa: E402


@pytest.fixture
def registry():
    return default_detector_registry()


@pytest.fixture
def scan_file():
    """Scan a file path, returning a ScanReport."""

    def _scan(path: Path) -> ScanReport:
        return run_scan(str(path), default_detector_registry())

    return _scan


@pytest.fixture
def tmp_docx(tmp_path):
    return tmp_path / "sample.docx"


@pytest.fixture
def tmp_xlsx(tmp_path):
    return tmp_path / "sample.xlsx"


@pytest.fixture
def tmp_pdf(tmp_path):
    return tmp_path / "sample.pdf"


@pytest.fixture
def tmp_html(tmp_path):
    return tmp_path / "sample.html"
