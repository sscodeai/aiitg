"""Structured error hierarchy for scan/parse failures."""

from __future__ import annotations

from typing import Any


class ScanError(Exception):
    """A structured error that can be serialized into a scan report."""

    def __init__(self, kind: str, message: str, *, location: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.location = location or {}

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "message": self.message, "location": self.location}
