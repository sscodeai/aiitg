"""Persistent decision cache for the hook adapter.

A hook runs in a fresh process for every enforced tool call, so the one-shot lazy
parser imports plus the parse itself are paid on every read (~390 ms measured for a
docx). This cache short-circuits *before* ``process_file`` and brings a repeat read of
an unchanged document down to the interpreter floor (~46 ms).

Two properties matter for a security tool:

* **Identity, not just mtime.** Entries are keyed on ``(path, mtime_ns, size)`` *and* carry a
  :attr:`HookCache.namespace` describing the build, sanitizer mode, detector set and policy that
  produced the verdict. A different namespace is a miss, so upgrading aiitg (or changing
  ``--mode``) can never reuse an old decision for an unchanged file.
* **A damaged entry must be a miss, never a verdict.** Any missing key or wrong type makes
  :meth:`HookCache.get` return ``None``, so corruption cannot turn into a deny for a clean file.

The directory is inert data: deleting it is always safe.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

__all__ = ["HookCache"]


class HookCache:
    """JSON-file cache keyed on a file's identity (path + mtime_ns + size) and a namespace."""

    #: Every entry must carry these keys; anything else is treated as absent.
    REQUIRED_KEYS: tuple[str, ...] = (
        "namespace",
        "path",
        "mtime_ns",
        "size",
        "action",
        "label",
        "report",
    )

    def __init__(self, directory: str | Path, *, namespace: str = "") -> None:
        self.directory = Path(directory).expanduser()
        self.namespace = namespace

    @staticmethod
    def _key(path: Path, mtime_ns: int, size: int) -> str:
        material = f"{path}\0{mtime_ns}\0{size}".encode()
        return hashlib.sha256(material).hexdigest()[:32]

    def _entry_path(self, path: Path, mtime_ns: int, size: int) -> Path:
        return self.directory / f"{self._key(path, mtime_ns, size)}.json"

    def _is_usable(self, data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        if data.get("namespace") != self.namespace:
            return False
        if any(key not in data for key in self.REQUIRED_KEYS):
            return False
        return isinstance(data.get("report"), dict)

    def get(self, path: str | Path) -> dict[str, Any] | None:
        """Return the cached entry, or ``None`` on miss / corruption / identity change."""
        try:
            stat = os.stat(path)
        except OSError:
            return None
        entry = self._entry_path(Path(path), stat.st_mtime_ns, stat.st_size)
        if not entry.is_file():
            return None
        try:
            data = json.loads(entry.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not self._is_usable(data):
            return None
        if data["mtime_ns"] != stat.st_mtime_ns or data["size"] != stat.st_size:
            return None
        return data

    def put(self, path: str | Path, payload: dict[str, Any]) -> None:
        """Store ``payload`` for the current identity of ``path`` (atomic write)."""
        try:
            stat = os.stat(path)
        except OSError:
            return
        data = {
            "path": str(path),
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
            "namespace": self.namespace,
            **payload,
        }
        if not self._is_usable(data):
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self._entry_path(Path(path), stat.st_mtime_ns, stat.st_size)
        tmp = target.with_name(f"{target.name}.{os.getpid()}.tmp")
        try:
            tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, target)
        except OSError:
            tmp.unlink(missing_ok=True)
