"""CLI-level tests for `aiitg hook ...` (the surface a project's settings.json calls)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aiitg.cli.app import app
from tests.fixtures import builders
from tests.m3.test_hooks import payload

runner = CliRunner()


def _hook_args(tmp_path: Path, *extra: str) -> list[str]:
    return ["hook", "pretooluse", "--cache-dir", str(tmp_path / "cache"), *extra]


class TestHookPretoolUseCLI:
    def test_deny_is_reported_as_json_with_exit_0(self, tmp_path):
        evil = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        result = runner.invoke(app, _hook_args(tmp_path), input=json.dumps(payload(evil)))
        assert result.exit_code == 0, result.output
        verdict = json.loads(result.stdout)["hookSpecificOutput"]
        assert verdict["permissionDecision"] == "deny"
        assert verdict["hookEventName"] == "PreToolUse"

    def test_benign_docx_is_allowed(self, tmp_path):
        ok = builders.build_docx_benign(tmp_path / "ok.docx")
        result = runner.invoke(app, _hook_args(tmp_path), input=json.dumps(payload(ok)))
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_quarantine_rewrites_the_read_target(self, tmp_path):
        tiny = builders.build_docx_with_tiny_font(tmp_path / "tiny.docx")
        result = runner.invoke(
            app,
            _hook_args(tmp_path, "--quarantine-dir", str(tmp_path / "q")),
            input=json.dumps(payload(tiny)),
        )
        assert result.exit_code == 0, result.output
        verdict = json.loads(result.stdout)["hookSpecificOutput"]
        assert verdict["permissionDecision"] == "allow"
        rewritten = Path(verdict["updatedInput"]["file_path"])
        assert rewritten.is_file()
        assert rewritten.parent == tmp_path / "q"
        assert "\u200b" not in rewritten.read_text(encoding="utf-8")
        assert verdict["additionalContext"]

    def test_malformed_stdin_exits_2_with_a_deny(self, tmp_path):
        result = runner.invoke(app, _hook_args(tmp_path), input="{not json")
        assert result.exit_code == 2
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_fail_open_flips_the_fail_closed_denies(self, tmp_path):
        legacy = tmp_path / "legacy.doc"
        legacy.write_bytes(b"\xd0\xcf\x11\xe0 fake")
        result = runner.invoke(app, _hook_args(tmp_path, "--fail-open"), input=json.dumps(payload(legacy)))
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_fail_closed_is_the_default_for_unparseable_formats(self, tmp_path):
        legacy = tmp_path / "legacy.doc"
        legacy.write_bytes(b"\xd0\xcf\x11\xe0 fake")
        result = runner.invoke(app, _hook_args(tmp_path), input=json.dumps(payload(legacy)))
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_audit_flag_writes_an_append_only_line(self, tmp_path):
        evil = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        audit = tmp_path / "audit.jsonl"
        result = runner.invoke(app, _hook_args(tmp_path, "--audit", str(audit)), input=json.dumps(payload(evil)))
        assert result.exit_code == 0, result.output
        line = json.loads(audit.read_text(encoding="utf-8").strip())
        assert line["decision"]["rule_id"] == "POL-001"
        assert line["file"].endswith("evil.docx")

    def test_invalid_mode_is_a_usage_error(self, tmp_path):
        ok = builders.build_docx_benign(tmp_path / "ok.docx")
        result = runner.invoke(app, _hook_args(tmp_path, "--mode", "shred"), input=json.dumps(payload(ok)))
        assert result.exit_code == 2


class TestHookPostToolUseCLI:
    def test_invisible_characters_are_reported(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "looks normal\u200bhere"
        result = runner.invoke(app, ["hook", "posttooluse"], input=json.dumps(body))
        assert result.exit_code == 0, result.output
        verdict = json.loads(result.stdout)["hookSpecificOutput"]
        assert verdict["hookEventName"] == "PostToolUse"
        assert "invisible" in verdict["additionalContext"]

    def test_malformed_stdin_exits_2(self, tmp_path):
        result = runner.invoke(app, ["hook", "posttooluse"], input="not json at all")
        assert result.exit_code == 2


class TestHookConfigCommand:
    def test_prints_settings_snippet_only(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["hook-config", "--audit", "/tmp/aiitg-audit.jsonl"])
        assert result.exit_code == 0, result.output
        snippet = json.loads(result.stdout)
        assert snippet["hooks"]["PreToolUse"][0]["matcher"] == "Read"
        assert "--audit /tmp/aiitg-audit.jsonl" in snippet["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert list(tmp_path.iterdir()) == [], "hook-config must never write a file"

    def test_existing_help_lists_the_new_commands(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "hook" in result.stdout
        assert "hook-config" in result.stdout
