"""Format registry: dispatch a file to its parser by extension + sniff."""

from __future__ import annotations

import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aiitg.core.document import ParsedDocument
from aiitg.core.errors import ScanError


class Parser(Protocol):
    """A parser turns a file path into a :class:`ParsedDocument`."""

    def parse(self, path: Path) -> ParsedDocument:
        ...


@dataclass
class FormatHandler:
    kind: str
    extensions: tuple[str, ...]
    parser_cls: type[Parser]
    sniff: Callable[[bytes], bool] | None = None


class FormatRegistry:
    """Map file extensions (and optional content sniffing) to parsers."""

    def __init__(self) -> None:
        self._handlers: dict[str, FormatHandler] = {}
        self._sniffers: list[FormatHandler] = []

    def register(self, handler: FormatHandler) -> None:
        for ext in handler.extensions:
            self._handlers[ext.lower()] = handler
        if handler.sniff is not None:
            self._sniffers.append(handler)

    def _handler_for_kind(self, kind: str) -> FormatHandler | None:
        seen: set[int] = set()
        for handler in self._handlers.values():
            if id(handler) in seen:
                continue
            seen.add(id(handler))
            if handler.kind == kind:
                return handler
        return None

    def _sniff_path(self, path: Path, head: bytes) -> FormatHandler | None:
        """Best-effort content detection for files with misleading extensions."""
        if head.startswith(b"%PDF"):
            return self._handler_for_kind("pdf")
        if head.startswith(b"\xd0\xcf\x11\xe0"):
            return self._handler_for_kind("xls")
        stripped = head[:512].lstrip().lower()
        if stripped.startswith((b"<!doctype html", b"<html")):
            return self._handler_for_kind("html")
        if head.startswith(b"PK"):
            try:
                with zipfile.ZipFile(path) as zf:
                    names = set(zf.namelist())
            except (OSError, zipfile.BadZipFile):
                return None
            if "word/document.xml" in names:
                return self._handler_for_kind("docx")
            if "xl/workbook.xml" in names:
                return self._handler_for_kind("xlsx")
            if "ppt/presentation.xml" in names:
                return self._handler_for_kind("pptx")
        return None

    def detect(self, path: str | Path) -> FormatHandler | None:
        """Detect format by extension, falling back to content sniffing."""
        p = Path(path)
        ext = p.suffix.lower().lstrip(".")
        handler = self._handlers.get(ext)
        if handler is not None:
            return handler
        # sniff fallback: try to read the first bytes and ask each sniffer
        try:
            head = p.read_bytes()[:4096]
        except OSError:
            return None
        path_handler = self._sniff_path(p, head)
        if path_handler is not None:
            return path_handler
        for h in self._sniffers:
            if h.sniff is not None and h.sniff(head):
                return h
        return None

    def parse(self, path: str | Path) -> ParsedDocument:
        p = Path(path)
        handler = self.detect(p)
        if handler is None:
            raise ScanError(
                kind="unsupported_format",
                message=f"unsupported format: {p.name} (supported: {sorted(self._handlers)})",
            )
        try:
            return handler.parser_cls().parse(p)
        except ScanError:
            raise
        except Exception as exc:  # noqa: BLE001 — wrap parser failures structurally
            raise ScanError(kind="parse_failed", message=f"failed to parse {p.name}: {exc}") from exc


_default_registry: FormatRegistry | None = None


def default_format_registry() -> FormatRegistry:
    """Lazily-built registry with all bundled parsers."""
    global _default_registry
    if _default_registry is None:
        from aiitg.parsers import ALL_HANDLERS

        _default_registry = FormatRegistry()
        for handler in ALL_HANDLERS:
            _default_registry.register(handler)
    return _default_registry
