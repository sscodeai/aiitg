"""Format registry: dispatch a file to its parser by extension + sniff."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ai_input_trust_gateway.core.document import ParsedDocument
from ai_input_trust_gateway.core.errors import ScanError


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
        from ai_input_trust_gateway.parsers import ALL_HANDLERS

        _default_registry = FormatRegistry()
        for handler in ALL_HANDLERS:
            _default_registry.register(handler)
    return _default_registry
