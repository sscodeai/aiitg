"""Source-code parser — the format-agnostic view of code/config/rule files.

Why a code parser belongs in a document gateway: a Code LLM assistant builds its
context from open files, imported modules, pasted snippets and comments, much of
which comes from third parties (arXiv:2610.05139, "Hidden in the Comments"). A
directive written as an ordinary comment inside untrusted context is
indistinguishable from the developer's own instruction — so the same pre-LLM gate
that guards documents has to be able to read source files.

This parser produces one :class:`TextParagraph` per line with ``index`` = 1-based
line number, so a finding can be reported (and defused) at line granularity.
``metadata["lang"]`` carries the comment syntax family, which is what the
comment-directive detector needs; the parser itself does no security reasoning.
"""

from __future__ import annotations

from pathlib import Path

from aiitg.core.document import ParsedDocument, TextParagraph, TextRun
from aiitg.core.errors import ScanError
from aiitg.parsers.base import register_parser

#: Source-code / config extensions the gateway can read. A pre-inference gate has to
#: keep up with the agent, so this leans inclusive: an unscannable code file would
#: otherwise be the way around the gate.
CODE_EXTENSIONS = frozenset(
    {
        ".py", ".pyi", ".sh", ".bash", ".zsh", ".ps1", ".rb", ".pl", ".php", ".lua",
        ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
        ".go", ".java", ".kt", ".kts", ".scala", ".rs", ".c", ".h", ".cc", ".cpp",
        ".hpp", ".cs", ".swift", ".dart", ".r",
        ".sql", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
        ".env", ".tf", ".gradle", ".groovy", ".ex", ".exs", ".erl", ".clj",
    }
)

#: Prose formats. Deliberately **not** registered as extensions: an unknown or prose
#: extension has to keep flowing through content sniffing, so that a *document* wearing a
#: misleading name is still caught (`payload.txt` holding a docx, `notes.md` holding a
#: spreadsheet — the hook sniffs an unenforced extension and enforces on the sniffed
#: kind). Rule files are reached by name instead, see :data:`RULE_FILE_NAMES`.
PROSE_EXTENSIONS = frozenset({".md", ".markdown", ".txt", ".rst", ".adoc"})

#: Agent rule / instruction files: whole-line instruction files that a coding agent
#: loads into its context. ``.cursorrules`` and friends need a basename match because
#: they have no extension for the registry to key on.
RULE_FILE_NAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        "gemini.md",
        ".cursorrules",
        ".windsurfrules",
        "copilot-instructions.md",
    }
)

#: Comment syntax families. ``hash`` is also the family used for rule files, whose
#: every non-blank line is an instruction by construction.
COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
    "hash": ("#",),
    "slash": ("//", "/*", "*", "*/"),
    "dash": ("--",),
    "html": ("<!--",),
    "vb": ("'", "rem "),
    "semicolon": (";",),
}

_EXT_LANG: dict[str, str] = {
    ".py": "hash", ".pyi": "hash", ".sh": "hash", ".bash": "hash", ".zsh": "hash",
    ".ps1": "hash", ".rb": "hash", ".pl": "hash", ".r": "hash", ".yaml": "hash",
    ".yml": "hash", ".toml": "hash", ".ini": "hash", ".cfg": "hash", ".conf": "hash",
    ".properties": "hash", ".env": "hash", ".tf": "hash", ".ex": "hash", ".exs": "hash",
    ".psm1": "hash", ".md": "hash", ".markdown": "hash", ".txt": "hash", ".rst": "hash",
    ".adoc": "hash",
    ".js": "slash", ".jsx": "slash", ".mjs": "slash", ".cjs": "slash", ".ts": "slash",
    ".tsx": "slash", ".go": "slash", ".java": "slash", ".kt": "slash", ".kts": "slash",
    ".scala": "slash", ".rs": "slash", ".c": "slash", ".h": "slash", ".cc": "slash",
    ".cpp": "slash", ".hpp": "slash", ".cs": "slash", ".swift": "slash", ".dart": "slash",
    ".php": "slash", ".groovy": "slash", ".gradle": "slash", ".clj": "slash",
    ".vue": "slash", ".svelte": "slash", ".css": "slash", ".scss": "slash", ".less": "slash",
    ".sql": "dash", ".lua": "dash", ".hs": "dash", ".elm": "dash", ".erl": "hash",
    ".html": "html", ".htm": "html", ".xml": "html", ".xhtml": "html", ".svg": "html",
    ".vb": "vb", ".vbs": "vb", ".bas": "vb",
}


def language_for_path(path: str | Path) -> str | None:
    """Return the comment-syntax family of ``path`` (None = not a scanned text file)."""
    p = Path(path)
    if p.name.lower() in RULE_FILE_NAMES:
        return "hash"
    return _EXT_LANG.get(p.suffix.lower())


def comment_body(line: str, lang: str | None) -> str | None:
    """Return the comment text of ``line``, or None when the line has no comment.

    ``lang=None`` means "instruction file": every non-blank line is content. This is
    deliberately generous — it is what lets the detector look inside a directive
    whether it hides in a comment or in a rule file.
    """
    stripped = line.strip()
    if not stripped:
        return None
    if lang is None:
        return stripped
    for prefix in COMMENT_PREFIXES.get(lang, ()):
        if stripped.lower().startswith(prefix):
            return stripped[len(prefix):].strip()
    return None


@register_parser("text", sorted(CODE_EXTENSIONS), basenames=tuple(sorted(RULE_FILE_NAMES)))
class TextParser:
    """Parse a text/source file into one paragraph per line."""

    def parse(self, path: Path) -> ParsedDocument:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise ScanError(kind="parse_failed", message=f"cannot read {path}: {exc}") from exc
        if b"\x00" in raw[:4096]:
            # Fail closed: a file we call source code but cannot decode must not be
            # treated as a clean one.
            raise ScanError(kind="parse_failed", message=f"{Path(path).name} looks binary, cannot scan as text")

        text = raw.decode("utf-8", errors="replace")
        if text.startswith("\ufeff"):
            text = text[1:]  # a BOM is an encoding artefact, not hidden content

        lang = language_for_path(path)
        paragraphs = [
            TextParagraph(text=line, index=i, runs=[TextRun(text=line)], raw={"line": i})
            for i, line in enumerate(text.splitlines(), start=1)
        ]
        return ParsedDocument(
            kind="text",
            source_path=str(path),
            paragraphs=paragraphs,
            metadata={
                "lang": lang,
                "extension": Path(path).suffix.lower(),
                "line_count": len(paragraphs),
            },
        )
