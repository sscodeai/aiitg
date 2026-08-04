"""Human approval queue — the "human in the loop" leg of Assume Compromise.

When the policy decides a document needs human approval (or a quarantine
needs sign-off before sanitized content is used), a request lands in this
queue. A human reviews the evidence and either approves (proceed with
sanitized text) or rejects (block the document).

Storage is a JSONL file: each entry is a request with id, file, reason,
decision, status (pending / approved / rejected), and timestamps.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ai_input_trust_gateway.core.evidence import ScanReport
from ai_input_trust_gateway.policy import Decision


class ApprovalQueue:
    """JSONL-backed human approval queue."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def request(
        self,
        *,
        report: ScanReport,
        decision: Decision,
        sanitized_text: str = "",
    ) -> dict[str, Any]:
        """Create a new approval request (status: pending)."""
        entry = {
            "id": uuid.uuid4().hex[:12],
            "created_at": datetime.now(UTC).isoformat(),
            "file": report.file,
            "kind": report.kind,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
            "risk_score": report.risk_score,
            "trust_label": report.trust_label,
            "evidence": [ev.to_dict() for ev in report.evidence],
            "sanitized_text_preview": sanitized_text[:500],
            "status": "pending",
            "decided_at": None,
            "decision_by": None,
        }
        self._append(entry)
        return entry

    def pending(self) -> list[dict[str, Any]]:
        return [e for e in self._read() if e.get("status") == "pending"]

    def get(self, request_id: str) -> dict[str, Any] | None:
        for e in self._read():
            if e.get("id") == request_id:
                return e
        return None

    def approve(self, request_id: str, by: str = "human") -> dict[str, Any] | None:
        return self._decide(request_id, "approved", by)

    def reject(self, request_id: str, by: str = "human") -> dict[str, Any] | None:
        return self._decide(request_id, "rejected", by)

    def _decide(self, request_id: str, status: str, by: str) -> dict[str, Any] | None:
        entries = self._read()
        found = None
        for e in entries:
            if e.get("id") == request_id and e.get("status") == "pending":
                e["status"] = status
                e["decided_at"] = datetime.now(UTC).isoformat()
                e["decision_by"] = by
                found = e
                break
        if found is None:
            return None
        self._write_all(entries)
        return found

    def _read(self) -> list[dict[str, Any]]:
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
        return entries

    def _append(self, entry: dict[str, Any]) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _write_all(self, entries: list[dict[str, Any]]) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
