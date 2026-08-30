"""Parser protocol and registration helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol

from aiitg.core.document import ParsedDocument
from aiitg.core.registry import FormatHandler


class Parser(Protocol):
    """A parser turns a file path into a :class:`ParsedDocument`."""

    def parse(self, path: Path) -> ParsedDocument:
        ...


def register_parser(
    kind: str,
    extensions: Iterable[str],
    sniff: Callable[[bytes], bool] | None = None,
) -> Callable[[type[Parser]], type[Parser]]:
    """Decorator: register a parser class for the given kind/extensions.

    Usage::

        @register_parser("docx", ("docx",))
        class DocxParser:
            def parse(self, path): ...
    """

    def deco(cls: type[Parser]) -> type[Parser]:
        handler = FormatHandler(kind=kind, extensions=tuple(extensions), parser_cls=cls, sniff=sniff)
        # stash for collection by parsers/__init__.py
        cls._handler = handler  # type: ignore[attr-defined]
        return cls

    return deco
