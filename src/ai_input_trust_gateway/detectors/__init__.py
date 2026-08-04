"""Detector package: auto-collects all bundled detectors.

Importing this package registers every detector module. ``ALL_DETECTORS``
feeds :func:`ai_input_trust_gateway.core.detector.default_detector_registry`.
"""

from __future__ import annotations

from ai_input_trust_gateway.core.detector import Detector
from ai_input_trust_gateway.detectors.metadata.document_meta import DocumentMetaDetector
from ai_input_trust_gateway.detectors.structure.annotations import AnnotationsDetector
from ai_input_trust_gateway.detectors.structure.hidden_sheet import HiddenSheetDetector
from ai_input_trust_gateway.detectors.structure.ooxml_nodes import OOXMLNodesDetector
from ai_input_trust_gateway.detectors.text.hidden_style import HiddenStyleDetector
from ai_input_trust_gateway.detectors.text.tiny_font import TinyFontDetector
from ai_input_trust_gateway.detectors.text.zero_width import ZeroWidthDetector

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
