#!/usr/bin/env python3
"""Live false-positive probe for DET-008 (`comment_directive`) over real source trees.

`docs/comment-directive-coverage.md` reports a live probe over third-party source. This
is the script that produces that row, committed so the number is reproducible instead of
being a claim in prose. It walks the given roots, counts comment lines per comment-syntax
family, and runs the shipped detector chain over every file, reporting only DET-008 hits.

The selection rule is deliberately explicit and conservative: a file is a candidate when
it is a known code/config extension (`CODE_EXTENSIONS`) or an agent rule file by name
(`RULE_FILE_NAMES`), and it is not inside a build/cache/VCS directory. The detector is
applied with the production `run_scan()`, not a re-implementation, so the probe measures
what the gateway actually does.

Usage::

    python scripts/probe_comment_directive.py .                  # this repository
    python scripts/probe_comment_directive.py . ../takumi/packages
    python scripts/probe_comment_directive.py . --json

The probe is a *false-positive* measurement: it counts what the detector reports on code
that was written without any injected payload. It says nothing about recall.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from aiitg.core.detector import default_detector_registry, run_scan
from aiitg.parsers.text_parser import CODE_EXTENSIONS, RULE_FILE_NAMES, comment_body, language_for_path

#: Directories that are VCS metadata, dependency caches or tool state, never sources.
EXCLUDE_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
        "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache",
        ".tox", "htmlcov", ".coverage", ".next", ".turbo", ".idea", ".vscode",
    }
)

#: Build output. Excluded by default: generated bundles are not third-party source a
#: developer reads, and counting them inflates the corpus (the original 167-file figure
#: came from *not* excluding these). ``--include-build`` restores that behaviour.
BUILD_DIRS = frozenset({"dist", "build", "out", "target", ".output"})


def iter_source_files(root: Path, *, include_build: bool = False) -> list[Path]:
    """Every candidate source/config/rule file under ``root``, sorted for determinism."""
    excluded = EXCLUDE_DIRS if include_build else EXCLUDE_DIRS | BUILD_DIRS
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excluded for part in path.parts):
            continue
        if path.name.lower() in RULE_FILE_NAMES or path.suffix.lower() in CODE_EXTENSIONS:
            out.append(path)
    return sorted(out)


def count_comment_lines(path: Path, lang: str | None) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if comment_body(line, lang) is not None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DET-008 false-positive probe over source trees.")
    parser.add_argument("roots", nargs="*", default=["."], help="source trees to scan")
    parser.add_argument("--json", action="store_true", help="emit the full result as JSON")
    parser.add_argument(
        "--include-build",
        action="store_true",
        help="also walk build output (dist/build/out/target); off by default",
    )
    args = parser.parse_args(argv)

    registry = default_detector_registry()
    files = 0
    comment_lines = 0
    by_lang: Counter[str] = Counter()
    findings: list[dict[str, object]] = []

    for root_arg in args.roots:
        root = Path(root_arg)
        if not root.exists():
            print(f"probe: skipping missing root {root}", file=sys.stderr)
            continue
        for path in iter_source_files(root, include_build=args.include_build):
            files += 1
            lang = language_for_path(path)
            n_comments = count_comment_lines(path, lang)
            comment_lines += n_comments
            by_lang[lang or "rule"] += n_comments
            report = run_scan(str(path), registry)
            for ev in report.evidence:
                if ev.detector_id != "DET-008":
                    continue
                findings.append(
                    {
                        "file": str(path),
                        "line": ev.location.paragraph,
                        "severity": ev.severity.value,
                        "class": ev.raw.get("class"),
                        "title": ev.title,
                    }
                )

    result = {
        "roots": [str(r) for r in args.roots],
        "include_build": args.include_build,
        "files": files,
        "comment_lines": comment_lines,
        "comment_line_langs": dict(sorted(by_lang.items())),
        "det_008_findings": len(findings),
        "findings": findings,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"roots:          {', '.join(result['roots'])}")
        print(f"files scanned:  {files}")
        langs = ", ".join(f"{k}={v}" for k, v in result["comment_line_langs"].items())
        print(f"comment lines:  {comment_lines} (by family: {langs})")
        print(f"DET-008 hits:   {len(findings)}")
        for f in findings:
            print(f"  {f['severity']:8} {str(f['class']):34} {f['file']}:{f['line']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
