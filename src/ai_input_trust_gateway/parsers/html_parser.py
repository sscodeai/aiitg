"""html parser: BeautifulSoup → DOM model with inline-style awareness.

Captures text nodes with their inline style (color / display / font-size) so
detectors can find white text, display:none, and tiny fonts.
"""

from __future__ import annotations

import re
from pathlib import Path

from bs4 import BeautifulSoup, Tag

from ai_input_trust_gateway.core.document import ParsedDocument, TextParagraph, TextRun
from ai_input_trust_gateway.parsers.base import register_parser

_STYLE_RE = re.compile(r"([a-z-]+)\s*:\s*([^;]+)")


def _parse_style(style: str | None) -> dict[str, str]:
    """Parse an inline style attribute into a normalized dict."""
    out: dict[str, str] = {}
    if not style:
        return out
    for m in _STYLE_RE.finditer(style):
        key = m.group(1).strip().lower()
        val = m.group(2).strip().lower()
        out[key] = val
    return out


def _color_to_hex(val: str) -> str | None:
    """Best-effort CSS color → RRGGBB."""
    v = val.strip().lower()
    if v in ("white", "#fff", "#ffffff"):
        return "FFFFFF"
    if v.startswith("#"):
        h = v[1:]
        if len(h) == 3:
            return "".join(c * 2 for c in h).upper()
        if len(h) == 6 and all(c in "0123456789abcdef" for c in h):
            return h.upper()
    return None


def _element_path(tag: Tag) -> str:
    """Build a CSS-ish path like html/body/div[2]/span[1] for the element."""
    parts: list[str] = []
    cur: Tag | None = tag
    while cur is not None and cur.name:
        parent = cur.parent
        if isinstance(parent, Tag):
            siblings = [c for c in parent.children if isinstance(c, Tag) and c.name == cur.name]
            idx = siblings.index(cur) + 1 if cur in siblings else 1
            parts.append(f"{cur.name}[{idx}]")
        else:
            parts.append(cur.name)
        cur = parent if isinstance(parent, Tag) else None
    return "/".join(reversed(parts))


@register_parser("html", ("html", "htm"), sniff=None)
class HtmlParser:
    """Parse .html into :class:`ParsedDocument`."""

    def parse(self, path: Path) -> ParsedDocument:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()

        soup = BeautifulSoup(raw, "lxml")
        doc_model = ParsedDocument(kind="html", source_path=str(path), html_root=soup)

        # collect text-bearing elements with inline styles
        seen: set[int] = set()
        for tag in soup.find_all(["p", "span", "div", "td", "li", "a", "h1", "h2", "h3", "h4"]):
            if id(tag) in seen:
                continue
            seen.add(id(tag))
            text = tag.get_text("", strip=False)
            if not text or not text.strip():
                continue
            style = _parse_style(_as_str(tag.get("style")))
            runs: list[TextRun] = []
            for child in tag.children:
                if isinstance(child, Tag):
                    ctext = child.get_text("", strip=False)
                    if not ctext:
                        continue
                    cstyle = _parse_style(_as_str(child.get("style")))
                    # child inherits parent style unless it overrides
                    merged = {**style, **cstyle}
                    runs.append(
                        TextRun(
                            text=ctext,
                            font_size=_css_font_size(merged),
                            color=_color_to_hex(merged.get("color", "")),
                            is_hidden=_is_hidden(merged),
                            raw={"element": _element_path(child)},
                        )
                    )
                elif isinstance(child, str) and child.strip():
                    runs.append(
                        TextRun(
                            text=child.strip(),
                            font_size=_css_font_size(style),
                            color=_color_to_hex(style.get("color", "")),
                            is_hidden=_is_hidden(style),
                            raw={"element": _element_path(tag)},
                        )
                    )
            if not runs:
                runs = [
                    TextRun(
                        text=text,
                        font_size=_css_font_size(style),
                        color=_color_to_hex(style.get("color", "")),
                        is_hidden=_is_hidden(style),
                        raw={"element": _element_path(tag)},
                    )
                ]
            doc_model.paragraphs.append(
                TextParagraph(
                    text=text,
                    index=len(doc_model.paragraphs),
                    runs=runs,
                    raw={"element": _element_path(tag)},
                )
            )

        # metadata from <meta> tags
        meta: dict[str, str] = {}
        for m in soup.find_all("meta"):
            name = _as_str(m.get("name") or m.get("property"))
            content = _as_str(m.get("content"))
            if name and content:
                meta[name.lower()] = content
        doc_model.metadata = meta

        return doc_model


def _as_str(val) -> str:
    """bs4 attribute values can be list-like; coerce to str."""
    if val is None:
        return ""
    if isinstance(val, (list, tuple)):
        return " ".join(str(v) for v in val)
    return str(val)


def _css_font_size(style: dict[str, str]) -> float | None:
    """Parse font-size: Npx|Npt → float pt (px→pt ~ /1.3333)."""
    val = style.get("font-size")
    if not val:
        return None
    m = re.match(r"([\d.]+)\s*(px|pt)", val)
    if not m:
        return None
    num = float(m.group(1))
    if m.group(2) == "px":
        return round(num / 1.3333, 2)
    return num


def _is_hidden(style: dict[str, str]) -> bool:
    if style.get("display") == "none":
        return True
    if style.get("visibility") == "hidden":
        return True
    if _color_to_hex(style.get("color", "")) == "FFFFFF" and "color" in style:
        return True
    return False
