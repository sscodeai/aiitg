"""Format registry: dispatch a file to its parser by extension + sniff."""

from __future__ import annotations

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
    basenames: tuple[str, ...] = ()  # exact, lowercased file names (e.g. ".cursorrules")


class FormatRegistry:
    """Map file extensions (and optional content sniffing) to parsers."""

    def __init__(self) -> None:
        self._handlers: dict[str, FormatHandler] = {}
        self._sniffers: list[FormatHandler] = []
        self._basenames: dict[str, FormatHandler] = {}

    def register(self, handler: FormatHandler) -> None:
        for ext in handler.extensions:
            # Keys are dotless (``py``), matching ``Path.suffix.lstrip(".")``; accept
            # either spelling from callers so a dotted registration cannot silently
            # create an unreachable handler.
            self._handlers[ext.lower().lstrip(".")] = handler
        for name in handler.basenames:
            self._basenames[name.lower()] = handler
        if handler.sniff is not None:
            self._sniffers.append(handler)

    def detect(self, path: str | Path) -> FormatHandler | None:
        """Detect format by extension, then exact file name, then content sniffing."""
        p = Path(path)
        ext = p.suffix.lower().lstrip(".")
        handler = self._handlers.get(ext)
        if handler is not None:
            return handler
        by_name = self._basenames.get(p.name.lower())
        if by_name is not None:
            return by_name
        # sniff fallback: try to read the first bytes and ask each sniffer
        try:
            head = p.read_bytes()[:4096]
        except OSError:
            return None
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
