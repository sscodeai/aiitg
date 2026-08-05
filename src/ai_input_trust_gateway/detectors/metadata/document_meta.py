"""DET-007: document metadata risks (authors, macros, VBA, JS).

Metadata itself is not hidden content, but suspicious metadata (macro-enabled
files, external links, unusual authors/titles) is a signal worth surfacing —
and OLE2 macro documents are a classic attack vector.
"""

from __future__ import annotations

from ai_input_trust_gateway.core.detector import Detector
from ai_input_trust_gateway.core.document import ParsedDocument
from ai_input_trust_gateway.core.evidence import Evidence, Location, Severity

# metadata fields worth surfacing
RISKY_META_KEYS = ("author", "creator", "title", "subject", "keywords", "comments", "description")

SUSPICIOUS_KEYWORDS = [
    "ignore", "instruction", "prompt", "system", "override", "secret",
    "password", "do not reveal", "always", "never tell",
]


class DocumentMetaDetector(Detector):
    id = "DET-007"
    name = "document_meta"
    description = "Suspicious document metadata / macro / VBA / embedded-object signals."
    supported_kinds = frozenset({"docx", "xlsx", "pdf", "html", "pptx", "xls"})
    default_severity = Severity.LOW

    def scan(self, doc: ParsedDocument) -> list[Evidence]:
        evidence: list[Evidence] = []
        evidence.extend(self._scan_meta(doc))
        if doc.kind in ("docx", "xlsx"):
            evidence.extend(self._scan_macros(doc))
        if doc.kind == "html":
            evidence.extend(self._scan_html_js(doc))
        return evidence

    def _scan_meta(self, doc: ParsedDocument) -> list[Evidence]:
        out: list[Evidence] = []
        hits: dict[str, str] = {}
        for key, value in doc.metadata.items():
            if not isinstance(value, str) or not value.strip():
                continue
            lowered = value.lower()
            if any(kw in lowered for kw in SUSPICIOUS_KEYWORDS):
                hits[key] = value[:200]
        if hits:
            out.append(
                self.make_evidence(
                    title="Suspicious metadata content",
                    description="Document metadata contains prompt-injection-like keywords.",
                    location=Location(source=doc.source_name, element="metadata"),
                    raw={"hits": hits},
                )
            )
        return out

    def _scan_macros(self, doc: ParsedDocument) -> list[Evidence]:
        out: list[Evidence] = []
        # OLE2 (xls/doc): check for VBA macros via oletools
        try:
            from oletools.olevba import detect_vba_macros

            if detect_vba_macros(str(doc.source_path)):
                out.append(
                    self.make_evidence(
                        title="VBA macros detected",
                        description="The document contains VBA macros — a classic attack vector for hidden behavior.",
                        location=Location(source=doc.source_name, element="ole"),
                        severity=Severity.MEDIUM,
                        raw={"macros": True},
                    )
                )
        except Exception:  # noqa: BLE001 — oletools optional
            pass

        # OOXML: presence of vbaProject.bin (macro-enabled xlsm/docm)
        for part_name in doc.ooxml_parts:
            if "vbaProject" in part_name:
                out.append(
                    self.make_evidence(
                        title="Embedded VBA project",
                        description=f"OOXML part '{part_name}' indicates an embedded VBA macro project.",
                        location=Location(source=doc.source_name, element=part_name),
                        severity=Severity.MEDIUM,
                        raw={"part": part_name},
                    )
                )
        return out

    def _scan_html_js(self, doc: ParsedDocument) -> list[Evidence]:
        out: list[Evidence] = []
        if doc.html_root is None:
            return out
        scripts = doc.html_root.find_all("script")
        if scripts:
            out.append(
                self.make_evidence(
                    title="JavaScript present in HTML",
                    description="The page contains <script> elements — only audited structurally, not executed.",
                    location=Location(source=doc.source_name, element="html/script"),
                    raw={"script_count": len(scripts)},
                )
            )
        return out
