"""Low-level OOXML (zip) part reader shared by docx/xlsx parsers and raw-node detectors."""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

from lxml import etree

from aiitg.core.errors import ScanError

OOXML_NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "mc": "http://schemas.openxmlformats.org/markup-compatibility/2006",
    "v": "urn:schemas-microsoft-com:vml",
    "x14": "http://schemas.microsoft.com/office/excel/2010/spreadsheet",
    "x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
}


class OOXMLRawReader:
    """Read raw parts out of an OOXML zip container."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            self._zip = zipfile.ZipFile(self.path)
        except zipfile.BadZipFile as exc:
            raise ScanError(kind="parse_failed", message=f"not a valid zip/OOXML file: {self.path.name}") from exc

    def part_names(self, prefix: str | None = None) -> list[str]:
        names = [n for n in self._zip.namelist() if not n.endswith("/")]
        if prefix:
            names = [n for n in names if n.startswith(prefix)]
        return sorted(names)

    def part_bytes(self, name: str) -> bytes:
        try:
            return self._zip.read(name)
        except KeyError as exc:
            raise ScanError(kind="parse_failed", message=f"missing part: {name}") from exc

    def xml_root(self, name: str) -> etree._Element:
        return etree.fromstring(self.part_bytes(name))

    def iter_parts(self, prefix: str) -> Iterator[tuple[str, etree._Element]]:
        for name in self.part_names(prefix):
            yield name, self.xml_root(name)

    def has_part(self, name: str) -> bool:
        return name in self._zip.namelist()

    def close(self) -> None:
        self._zip.close()

    def __enter__(self) -> OOXMLRawReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def is_zip_with_ooxml(head: bytes) -> bool:
    """Sniff: zip magic + at least one OOXML-ish part name."""
    if not head.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(BytesIO(head)) as zf:
            names = zf.namelist()
        return any(n.endswith((".xml", ".rels")) for n in names[:50])
    except Exception:  # noqa: BLE001
        return False
