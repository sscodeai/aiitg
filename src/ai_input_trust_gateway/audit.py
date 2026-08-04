"""Audit log — append-only JSONL record of every scan/decision.

M2 core: the "audit" leg of Assume Compromise. Every time a document is
processed, an audit entry records: file, kind, risk score, trust label,
policy decision, and which detector fired. Entries are append-only JSONL so
they can be tailed, shipped to a SIEM, or replayed for forensics.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ai_input_trust_gateway.core.evidence import ScanReport
from ai_input_trust_gateway.policy import Decision


class AuditLog:
    """Append-only JSONL audit store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        report: ScanReport,
        decision: Decision,
        sanitized: bool = False,
        note: str = "",
    ) -> dict[str, Any]:
        """Append one audit entry; returns the entry (also written)."""
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "file": report.file,
            "kind": report.kind,
            "status": report.status,
            "risk_score": report.risk_score,
            "summary": report.summary,
            "trust_label": report.trust_label,
            "decision": decision.to_dict(),
            "sanitized": sanitized,
            "note": note,
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def read(self, limit: int = 100) -> list[dict[str, Any]]:
        """Read the most recent ``limit`` entries (newest last)."""
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries[-limit:]

    def count(self) -> int:
        return len(self.read(limit=10**9))
