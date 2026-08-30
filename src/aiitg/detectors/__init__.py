"""Detector package: auto-collects all bundled detectors.

Importing this package registers every detector module. ``ALL_DETECTORS``
feeds :func:`aiitg.core.detector.default_detector_registry`.
"""

from __future__ import annotations

from aiitg.core.detector import Detector
from aiitg.detectors.metadata.document_meta import DocumentMetaDetector
from aiitg.detectors.structure.annotations import AnnotationsDetector
from aiitg.detectors.structure.hidden_sheet import HiddenSheetDetector
from aiitg.detectors.structure.ooxml_nodes import OOXMLNodesDetector
from aiitg.detectors.text.hidden_style import HiddenStyleDetector
from aiitg.detectors.text.tiny_font import TinyFontDetector
from aiitg.detectors.text.zero_width import ZeroWidthDetector

ALL_DETECTORS: list[Detector] = [
    ZeroWidthDetector(),
    HiddenStyleDetector(),
    TinyFontDetector(),
    HiddenSheetDetector(),
    OOXMLNodesDetector(),
    AnnotationsDetector(),
    DocumentMetaDetector(),
]

__all__ = ["ALL_DETECTORS"]
