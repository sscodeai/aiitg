"""Tests for the Claude Code hook adapter (M3.0)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from aiitg import __version__ as aiitg_version
from aiitg.hooks import claude_code
from aiitg.hooks.claude_code import (
    HookConfig,
    HookOutcome,
    handle_posttooluse,
    handle_pretooluse,
    render_outcome,
)
from aiitg.pipeline import PipelineResult
from aiitg.policy import Decision, DecisionAction
from aiitg.sanitize import SanitizeResult
from aiitg.trust_label import TrustLabel, TrustLabelValue
from tests.fixtures import builders

REPO_ROOT = Path(__file__).resolve().parents[2]


def payload(
    path: str | Path | None, *, tool: str = "Read", event: str = "PreToolUse", extra: dict | None = None
) -> dict:
    tool_input: dict = {}
    if path is not None:
        tool_input["file_path"] = str(path)
    tool_input.update(extra or {})
    return {
        "session_id": "test-session",
        "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": str(REPO_ROOT),
        "permission_mode": "default",
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": "toolu_test",
    }


def config(tmp_path: Path, **overrides) -> HookConfig:
    base = {
        "quarantine_dir": tmp_path / "quarantine",
        "cache_dir": tmp_path / "cache",
        "audit_path": None,
        "queue_path": None,
    }
    base.update(overrides)
    return HookConfig(**base)


class TestExtraction:
    def test_no_evidence_note(self):
        from aiitg.core.evidence import ScanReport

        assert claude_code._evidence_note(ScanReport(file="x", kind="docx")) == "no evidence"

    def test_error_note_uses_message(self):
        from aiitg.core.evidence import ScanReport

        report = ScanReport(
            file="x.xyz",
            kind="unknown",
            status="error",
            error={"kind": "unsupported_format", "message": "cannot parse"},
        )
        assert claude_code._evidence_note(report) == "scan error: cannot parse"

    def test_where_renders_coordinates(self):
        from aiitg.core.evidence import Location

        loc = Location(source="paragraph", paragraph=0, run=2, char_range=(19, 20))
        assert claude_code._where(loc) == "paragraph: para 0, run 2, chars 19-20"


class TestPreToolUseDecisions:
    def test_benign_docx_is_allowed(self, tmp_path):
        f = builders.build_docx_benign(tmp_path / "ok.docx")
        outcome = handle_pretooluse(payload(f), config=config(tmp_path))
        assert outcome.permission_decision == "allow"
        assert outcome.updated_input is None
        assert outcome.exit_code == 0
        assert "clean" in outcome.reason

    def test_zero_width_docx_is_denied_by_pol_001(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        outcome = handle_pretooluse(payload(f), config=config(tmp_path))
        assert outcome.permission_decision == "deny"
        assert "POL-001" in outcome.reason
        assert "DET-001" in outcome.reason
        assert "dangerous" in outcome.reason

    def test_tiny_font_is_quarantined_and_rewritten(self, tmp_path):
        f = builders.build_docx_with_tiny_font(tmp_path / "tiny.docx")
        outcome = handle_pretooluse(payload(f), config=config(tmp_path))
        assert outcome.permission_decision == "allow", outcome.reason
        assert outcome.updated_input is not None
        rewritten = Path(outcome.updated_input["file_path"])
        assert rewritten.is_file()
        assert rewritten.parent == tmp_path / "quarantine"
        text = rewritten.read_text(encoding="utf-8")
        assert "\u200b" not in text
        # the substitution must be surfaced, never silent
        assert outcome.additional_context
        assert "sanitized" in outcome.additional_context
        assert "caution" in outcome.additional_context

    def test_quarantine_without_substitution_denies(self, tmp_path):
        f = builders.build_docx_with_tiny_font(tmp_path / "tiny.docx")
        outcome = handle_pretooluse(payload(f), config=config(tmp_path, substitute_sanitized=False))
        assert outcome.permission_decision == "deny"
        assert "POL-002" in outcome.reason

    def test_offset_and_limit_are_preserved(self, tmp_path):
        f = builders.build_docx_with_tiny_font(tmp_path / "tiny.docx")
        outcome = handle_pretooluse(payload(f, extra={"offset": 10, "limit": 40}), config=config(tmp_path))
        assert outcome.updated_input is not None
        assert outcome.updated_input["offset"] == 10
        assert outcome.updated_input["limit"] == 40

    def test_unparseable_doc_denies_when_fail_closed(self, tmp_path):
        f = tmp_path / "legacy.doc"
        f.write_bytes(b"\xd0\xcf\x11\xe0 fake legacy payload")
        outcome = handle_pretooluse(payload(f), config=config(tmp_path))
        assert outcome.permission_decision == "deny"
        assert "cannot be scanned" in outcome.reason

    def test_unparseable_doc_allows_when_fail_open(self, tmp_path):
        f = tmp_path / "legacy.doc"
        f.write_bytes(b"\xd0\xcf\x11\xe0 fake legacy payload")
        outcome = handle_pretooluse(payload(f), config=config(tmp_path, fail_closed=False))
        assert outcome.permission_decision == "allow"

    def test_unparseable_doc_writes_audit_line(self, tmp_path):
        f = tmp_path / "legacy.doc"
        f.write_bytes(b"\xd0\xcf\x11\xe0 fake legacy payload")
        audit = tmp_path / "audit.jsonl"
        handle_pretooluse(payload(f), config=config(tmp_path, audit_path=audit))
        entry = json.loads(audit.read_text(encoding="utf-8").strip())
        assert entry["decision"]["rule_id"] == "POL-001"
        assert "unparseable" in entry["note"]

    def test_non_enforced_extension_never_runs_the_pipeline(self, tmp_path, monkeypatch):
        f = tmp_path / "notes.md"
        f.write_text("plain notes", encoding="utf-8")

        def explode(*args, **kwargs):
            raise AssertionError("pipeline must not run for non-enforced extensions")

        monkeypatch.setattr(claude_code, "process_file", explode)
        outcome = handle_pretooluse(payload(f), config=config(tmp_path))
        assert outcome.permission_decision == "allow"
        assert "not enforced" in outcome.reason

    def test_other_tool_and_event_are_ignored(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        bash = handle_pretooluse(payload(f, tool="Bash"), config=config(tmp_path))
        post = handle_pretooluse(payload(f, event="PostToolUse"), config=config(tmp_path))
        assert bash.permission_decision == "allow"
        assert post.permission_decision == "allow"

    def test_missing_file_path_is_allowed(self, tmp_path):
        assert handle_pretooluse(payload(None), config=config(tmp_path)).permission_decision == "allow"

    def test_missing_file_denies_when_fail_closed(self, tmp_path):
        outcome = handle_pretooluse(payload(tmp_path / "nope.docx"), config=config(tmp_path))
        assert outcome.permission_decision == "deny"
        assert "missing or unreadable" in outcome.reason

    def test_oversized_file_denies(self, tmp_path):
        f = builders.build_docx_benign(tmp_path / "big.docx")
        outcome = handle_pretooluse(payload(f), config=config(tmp_path, max_file_bytes=10))
        assert outcome.permission_decision == "deny"
        assert "max_file_bytes" in outcome.reason

    def test_human_approval_maps_to_ask_and_enqueues(self, tmp_path, monkeypatch):
        f = builders.build_docx_benign(tmp_path / "ok.docx")
        queue = tmp_path / "queue.jsonl"

        def fake_process(path, **kwargs):
            from aiitg.core.evidence import ScanReport

            scan = ScanReport(file=str(path), kind="docx")
            return PipelineResult(
                report=scan,
                sanitized=SanitizeResult(text="body", removed=[], mode="strip"),
                label=TrustLabel(
                    value=TrustLabelValue.CAUTION,
                    score=0.7,
                    structure_score=0.8,
                    content_score=0.7,
                    meta_score=1.0,
                    reasons=["annotations"],
                ),
                decision=Decision(
                    action=DecisionAction.HUMAN_APPROVAL, rule_id="POL-003", reason="needs a human"
                ),
            )

        monkeypatch.setattr(claude_code, "process_file", fake_process)
        outcome = handle_pretooluse(payload(f), config=config(tmp_path, queue_path=queue))
        assert outcome.permission_decision == "ask"
        assert "POL-003" in outcome.reason
        assert queue.is_file()
        assert json.loads(queue.read_text(encoding="utf-8").strip())["status"] == "pending"

    def test_audit_line_is_written_for_scanned_files(self, tmp_path):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        audit = tmp_path / "audit.jsonl"
        handle_pretooluse(payload(f), config=config(tmp_path, audit_path=audit))
        entry = json.loads(audit.read_text(encoding="utf-8").strip())
        assert entry["decision"]["action"] == "block"
        assert "session=test-session" in entry["note"]


class TestFailClosedGuards:
    def test_malformed_payload_denies_with_exit_2(self, tmp_path):
        outcome = handle_pretooluse(None, config=config(tmp_path))
        assert outcome.permission_decision == "deny"
        assert outcome.exit_code == 2
        assert "malformed" in outcome.reason

    def test_malformed_payload_allows_when_fail_open(self, tmp_path):
        outcome = handle_pretooluse(None, config=config(tmp_path, fail_closed=False))
        assert outcome.permission_decision == "allow"
        assert outcome.exit_code == 0

    def test_injected_fault_denies_with_exit_2(self, tmp_path, monkeypatch):
        f = builders.build_docx_benign(tmp_path / "ok.docx")

        def boom(*args, **kwargs):
            raise RuntimeError("detector exploded")

        monkeypatch.setattr(claude_code, "process_file", boom)
        outcome = handle_pretooluse(payload(f), config=config(tmp_path))
        assert outcome.permission_decision == "deny"
        assert outcome.exit_code == 2
        assert "hook error" in outcome.reason

    def test_injected_fault_allows_when_fail_open(self, tmp_path, monkeypatch):
        f = builders.build_docx_benign(tmp_path / "ok.docx")

        def boom(*args, **kwargs):
            raise RuntimeError("detector exploded")

        monkeypatch.setattr(claude_code, "process_file", boom)
        outcome = handle_pretooluse(payload(f), config=config(tmp_path, fail_closed=False))
        assert outcome.permission_decision == "allow"
        assert outcome.exit_code == 0

    def test_mapping_crash_still_denies(self, tmp_path, monkeypatch):
        """A crash in the response-mapping stage must not escape as a non-blocking exit 1."""
        f = builders.build_docx_benign(tmp_path / "ok.docx")

        def bad_where(location):
            raise AttributeError("'Evidence' object has no attribute 'detector'")

        monkeypatch.setattr(claude_code, "_evidence_note", bad_where)
        outcome = handle_pretooluse(payload(f), config=config(tmp_path))
        assert outcome.permission_decision == "deny"
        assert outcome.exit_code == 2


class TestDecisionCache:
    def test_cache_hit_skips_the_pipeline_and_mtime_invalidates(self, tmp_path, monkeypatch):
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        calls = {"n": 0}
        real = claude_code.process_file

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(claude_code, "process_file", counting)
        cfg = config(tmp_path)

        first = handle_pretooluse(payload(f), config=cfg)
        assert calls["n"] == 1
        second = handle_pretooluse(payload(f), config=cfg)
        assert calls["n"] == 1, "second read of an unchanged file must be served from the cache"
        assert second.permission_decision == first.permission_decision
        assert second.reason == first.reason

        stat = os.stat(f)
        os.utime(f, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10**9))
        handle_pretooluse(payload(f), config=cfg)
        assert calls["n"] == 2, "a modified file must not be served from the cache"

    def test_cache_can_be_disabled(self, tmp_path, monkeypatch):
        f = builders.build_docx_benign(tmp_path / "ok.docx")
        calls = {"n": 0}
        real = claude_code.process_file

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(claude_code, "process_file", counting)
        cfg = config(tmp_path, cache_dir=None)
        handle_pretooluse(payload(f), config=cfg)
        handle_pretooluse(payload(f), config=cfg)
        assert calls["n"] == 2

    def test_a_changed_namespace_is_a_miss(self, tmp_path, monkeypatch):
        """A different build / mode / detector set must not reuse yesterday's verdict."""
        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        calls = {"n": 0}
        real = claude_code.process_file

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(claude_code, "process_file", counting)
        cfg_strip = config(tmp_path)
        handle_pretooluse(payload(f), config=cfg_strip)
        assert calls["n"] == 1

        # same file, same stat, different sanitizer mode -> namespace differs -> must re-decide
        cfg_redact = config(tmp_path, mode="redact")
        handle_pretooluse(payload(f), config=cfg_redact)
        assert calls["n"] == 2, "a mode change must not be served from the cache"

    def test_namespace_covers_build_detectors_and_policy(self, tmp_path):
        cfg = config(tmp_path)
        base = claude_code._cache_namespace(cfg)
        assert aiitg_version in base
        assert "|strip|" in base
        assert base != claude_code._cache_namespace(config(tmp_path, mode="redact"))

    def test_structurally_damaged_entry_is_a_miss_not_a_verdict(self, tmp_path, monkeypatch):
        """A truncated/garbled entry must never become a deny for a clean file."""
        f = builders.build_docx_benign(tmp_path / "ok.docx")
        calls = {"n": 0}
        real = claude_code.process_file

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(claude_code, "process_file", counting)
        cfg = config(tmp_path)
        first = handle_pretooluse(payload(f), config=cfg)
        assert first.permission_decision == "allow"
        assert calls["n"] == 1

        for entry in (tmp_path / "cache").glob("*.json"):
            data = json.loads(entry.read_text(encoding="utf-8"))
            del data["report"]  # valid JSON, structurally incomplete
            entry.write_text(json.dumps(data), encoding="utf-8")

        second = handle_pretooluse(payload(f), config=cfg)
        assert calls["n"] == 2, "a damaged entry must be treated as a miss"
        assert second.permission_decision == "allow", "cache damage must not flip a verdict"

    def test_entry_with_a_foreign_namespace_is_ignored(self, tmp_path, monkeypatch):
        f = builders.build_docx_benign(tmp_path / "ok.docx")
        calls = {"n": 0}
        real = claude_code.process_file

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(claude_code, "process_file", counting)
        cfg = config(tmp_path)
        handle_pretooluse(payload(f), config=cfg)
        for entry in (tmp_path / "cache").glob("*.json"):
            data = json.loads(entry.read_text(encoding="utf-8"))
            data["namespace"] = "some-other-build|strip|0:x|y"
            entry.write_text(json.dumps(data), encoding="utf-8")
        handle_pretooluse(payload(f), config=cfg)
        assert calls["n"] == 2

    def test_corrupt_cache_entry_is_a_miss(self, tmp_path, monkeypatch):
        f = builders.build_docx_benign(tmp_path / "ok.docx")
        calls = {"n": 0}
        real = claude_code.process_file

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(claude_code, "process_file", counting)
        cfg = config(tmp_path)
        handle_pretooluse(payload(f), config=cfg)
        for entry in (tmp_path / "cache").glob("*.json"):
            entry.write_text("{ not json", encoding="utf-8")
        handle_pretooluse(payload(f), config=cfg)
        assert calls["n"] == 2


class TestRenderOutcome:
    def test_documented_shape(self):
        text, code = render_outcome(HookOutcome("deny", "nope"))
        body = json.loads(text)
        hso = body["hookSpecificOutput"]
        assert hso["hookEventName"] == "PreToolUse"
        assert hso["permissionDecision"] == "deny"
        assert hso["permissionDecisionReason"] == "nope"
        assert "updatedInput" not in hso
        assert "additionalContext" not in hso
        assert code == 0

    def test_updated_input_and_context_are_emitted_for_pretooluse(self):
        outcome = HookOutcome(
            "allow",
            "ok",
            updated_input={"file_path": "/tmp/x.txt"},
            additional_context="sanitized",
            exit_code=2,
        )
        text, code = render_outcome(outcome)
        hso = json.loads(text)["hookSpecificOutput"]
        assert hso["hookEventName"] == "PreToolUse"
        assert hso["updatedInput"] == {"file_path": "/tmp/x.txt"}
        assert hso["additionalContext"] == "sanitized"
        assert code == 2

    def test_posttooluse_drops_fields_the_event_does_not_honour(self):
        """`updatedInput` is a PreToolUse field; carrying it on PostToolUse would be a contract break."""
        outcome = HookOutcome(
            "allow",
            "ok",
            updated_input={"file_path": "/tmp/x.txt"},
            additional_context="sanitized",
            event="PostToolUse",
        )
        hso = json.loads(render_outcome(outcome)[0])["hookSpecificOutput"]
        assert set(hso) == {"hookEventName", "additionalContext"}

    def test_emit_json_false_produces_no_stdout(self):
        text, code = render_outcome(HookOutcome("allow", "reason", exit_code=2, event="PostToolUse", emit_json=False))
        assert text == ""
        assert code == 2


class TestEventContract:
    """The emitted field set must match the documented per-event contract.

    This is the test class that P1 needed: `PostToolUse` does not honour `permissionDecision`
    (the tool has already run), so emitting it either drops the warning or fails schema validation.
    """

    @staticmethod
    def _hso(outcome):
        text, _ = render_outcome(outcome)
        if not text:
            return None
        body = json.loads(text)
        assert set(body) <= {"hookSpecificOutput"}, f"unexpected top-level keys: {set(body)}"
        return body["hookSpecificOutput"]

    def _assert_contract(self, outcome, event: str):
        hso = self._hso(outcome)
        if hso is None:
            return None
        assert hso["hookEventName"] == event
        allowed = claude_code.DOCUMENTED_FIELDS[event]
        extra = set(hso) - allowed
        assert not extra, f"{event} emitted fields the event does not honour: {sorted(extra)}"
        return hso

    def test_pretooluse_outcomes_use_pretooluse_fields_only(self, tmp_path):
        cfg = config(tmp_path)
        evil = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        ok = builders.build_docx_benign(tmp_path / "ok.docx")
        tiny = builders.build_docx_with_tiny_font(tmp_path / "tiny.docx")
        legacy = tmp_path / "legacy.doc"
        legacy.write_bytes(b"\xd0\xcf\x11\xe0 fake")

        cases = [
            handle_pretooluse(payload(ok), config=cfg),
            handle_pretooluse(payload(evil), config=cfg),
            handle_pretooluse(payload(tiny), config=cfg),
            handle_pretooluse(payload(legacy), config=cfg),
            handle_pretooluse(None, config=cfg),
            handle_pretooluse(payload(tmp_path / "notes.md"), config=cfg),
        ]
        for outcome in cases:
            hso = self._assert_contract(outcome, "PreToolUse")
            assert hso is not None
            assert hso["permissionDecision"] in {"allow", "deny", "ask", "defer"}

    def test_posttooluse_never_emits_permission_decision(self, tmp_path):
        cfg = config(tmp_path)
        with_findings = payload(None, event="PostToolUse", tool="WebFetch")
        with_findings["tool_response"] = "text\u200bhere"
        clean = payload(None, event="PostToolUse", tool="WebFetch")
        clean["tool_response"] = "text here"

        for outcome in (handle_posttooluse(with_findings, config=cfg), handle_posttooluse(clean, config=cfg)):
            hso = self._assert_contract(outcome, "PostToolUse")
            if hso is not None:
                assert "permissionDecision" not in hso
                assert "permissionDecisionReason" not in hso
                assert "updatedToolOutput" not in hso

    def test_posttooluse_clean_result_emits_nothing(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "nothing hidden"
        text, code = render_outcome(handle_posttooluse(body, config=config(tmp_path)))
        assert text == ""
        assert code == 0


class TestPostToolUse:
    def test_invisible_characters_are_flagged_in_context(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "benign text\u200bwith an invisible instruction"
        outcome = handle_posttooluse(body, config=config(tmp_path))
        assert outcome.permission_decision == "allow"
        assert outcome.additional_context
        assert "invisible" in outcome.additional_context
        text, code = render_outcome(outcome)
        hso = json.loads(text)["hookSpecificOutput"]
        assert hso["hookEventName"] == "PostToolUse"
        assert set(hso) == {"hookEventName", "additionalContext"}
        assert code == 0

    def test_bidi_characters_are_flagged(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "visible\u202eevil"
        outcome = handle_posttooluse(body, config=config(tmp_path))
        assert outcome.additional_context
        assert "bidi" in outcome.additional_context

    def test_clean_tool_result_is_transparent(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "nothing hidden here"
        outcome = handle_posttooluse(body, config=config(tmp_path))
        assert outcome.permission_decision == "allow"
        assert outcome.additional_context is None
        assert render_outcome(outcome) == ("", 0)

    def test_wrong_event_emits_nothing(self, tmp_path):
        outcome = handle_posttooluse(payload(None), config=config(tmp_path))
        assert outcome.permission_decision == "allow"
        assert render_outcome(outcome) == ("", 0)

    def test_malformed_payload_uses_exit_2_and_no_json(self, tmp_path):
        outcome = handle_posttooluse(None, config=config(tmp_path))
        text, code = render_outcome(outcome)
        assert text == "", "PostToolUse must not emit a permission verdict"
        assert code == 2
        assert "malformed" in outcome.reason

    def test_malformed_payload_stays_silent_when_fail_open(self, tmp_path):
        outcome = handle_posttooluse(None, config=config(tmp_path, fail_closed=False))
        assert render_outcome(outcome) == ("", 0)

    def test_findings_are_written_to_the_audit_log(self, tmp_path):
        audit = tmp_path / "audit.jsonl"
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "a\u200bb"
        outcome = handle_posttooluse(body, config=config(tmp_path, audit_path=audit))
        assert outcome.audit is not None
        entry = json.loads(audit.read_text(encoding="utf-8").strip())
        assert entry["decision"]["rule_id"] == "POL-TOOL-001"
        assert entry["decision"]["action"] == "allow", "PostToolUse cannot block; the record must say so"
        assert "invisible=1" in entry["note"]

    def test_no_audit_flag_writes_nothing(self, tmp_path):
        audit = tmp_path / "audit.jsonl"
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "a\u200bb"
        handle_posttooluse(body, config=config(tmp_path))
        assert not audit.exists()

    def test_scan_is_bounded_by_max_posttooluse_texts(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = [f"chunk {i}" for i in range(200)]
        body["tool_response"][150] = "hidden\u200binstruction"
        limited = handle_posttooluse(body, config=config(tmp_path, max_posttooluse_texts=10))
        full = handle_posttooluse(body, config=config(tmp_path, max_posttooluse_texts=200))
        assert limited.additional_context is None, "scan must stop at the configured bound"
        assert full.additional_context is not None


class TestConsoleScript:
    """The real path a Claude Code hook takes: process + JSON on stdin."""

    @staticmethod
    def _script() -> str | None:
        """Prefer the project venv, fall back to the installed console script (CI installs it on PATH)."""
        local = REPO_ROOT / ".venv" / "bin" / "aiitg"
        return str(local) if local.exists() else shutil.which("aiitg")

    def test_real_console_script_blocks_evil_docx(self, tmp_path):
        script = self._script()
        if script is None:
            pytest.skip("console script not installed in this environment")
        evil = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = subprocess.run(
            [script, "hook", "pretooluse", "--cache-dir", str(tmp_path / "c")],
            input=json.dumps(payload(evil)),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        verdict = json.loads(result.stdout)["hookSpecificOutput"]
        assert verdict["permissionDecision"] == "deny"
        assert "POL-001" in verdict["permissionDecisionReason"]

    def test_real_console_script_handles_malformed_stdin_with_exit_2(self, tmp_path):
        script = self._script()
        if script is None:
            pytest.skip("console script not installed in this environment")
        result = subprocess.run(
            [script, "hook", "pretooluse", "--cache-dir", str(tmp_path / "c")],
            input="{not json",
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 2
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_hook_config_prints_and_writes_nothing(self, tmp_path):
        from typer.testing import CliRunner

        from aiitg.cli.app import app

        result = CliRunner().invoke(app, ["hook-config"])
        assert result.exit_code == 0, result.output
        assert "PreToolUse" in result.output
        assert "aiitg hook pretooluse" in result.output
        assert list(tmp_path.iterdir()) == []
