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
    def test_invisible_characters_are_reported_as_context_only(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "looks normal\u200bhere"
        result = runner.invoke(app, ["hook", "posttooluse"], input=json.dumps(body))
        assert result.exit_code == 0, result.output
        hso = json.loads(result.stdout)["hookSpecificOutput"]
        assert hso["hookEventName"] == "PostToolUse"
        assert set(hso) == {"hookEventName", "additionalContext"}
        assert "invisible" in hso["additionalContext"]

    def test_clean_tool_result_prints_nothing(self, tmp_path):
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "clean"
        result = runner.invoke(app, ["hook", "posttooluse"], input=json.dumps(body))
        assert result.exit_code == 0
        assert result.stdout.strip() == ""

    def test_flags_the_event_cannot_honour_are_rejected(self, tmp_path):
        """These options could never be applied on PostToolUse, so they must not be accepted."""
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "clean"
        for flag in ("--mode", "--cache-dir", "--quarantine-dir", "--max-file-bytes", "--queue"):
            result = runner.invoke(app, ["hook", "posttooluse", flag, "x"], input=json.dumps(body))
            assert result.exit_code != 0, f"{flag} was accepted but cannot do anything"

    def test_audit_flag_records_findings(self, tmp_path):
        audit = tmp_path / "audit.jsonl"
        body = payload(None, event="PostToolUse", tool="WebFetch")
        body["tool_response"] = "x\u200by"
        result = runner.invoke(app, ["hook", "posttooluse", "--audit", str(audit)], input=json.dumps(body))
        assert result.exit_code == 0, result.output
        entry = json.loads(audit.read_text(encoding="utf-8").strip())
        assert entry["decision"]["rule_id"] == "POL-TOOL-001"

    def test_malformed_stdin_exits_2_without_a_permission_verdict(self, tmp_path):
        result = runner.invoke(app, ["hook", "posttooluse"], input="not json at all")
        assert result.exit_code == 2
        assert result.stdout.strip() == "", "PostToolUse must not print a permission verdict"
        assert "malformed" in result.output


class TestHookConfigCommand:
    def test_prints_settings_snippet_only(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["hook-config", "--audit", "/tmp/aiitg-audit.jsonl"])
        assert result.exit_code == 0, result.output
        snippet = json.loads(result.stdout)
        assert snippet["hooks"]["PreToolUse"][0]["matcher"] == "Read"
        assert "--audit /tmp/aiitg-audit.jsonl" in snippet["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert list(tmp_path.iterdir()) == [], "hook-config must never write a file"

    def test_embeds_an_absolute_executable_path_when_asked(self, tmp_path):
        fake = tmp_path / "bin" / "aiitg"
        fake.parent.mkdir()
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        result = runner.invoke(app, ["hook-config", "--exe", str(fake)])
        assert result.exit_code == 0, result.output
        command = json.loads(result.stdout)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert command.startswith(str(fake)), command
        assert command.endswith("hook pretooluse")

    def test_quotes_a_path_containing_spaces(self, tmp_path):
        fake = tmp_path / "my tools" / "aiitg"
        fake.parent.mkdir()
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        result = runner.invoke(app, ["hook-config", "--exe", str(fake)])
        command = json.loads(result.stdout)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert "'" in command and command.split("'")[1].endswith("aiitg"), command

    def test_warns_when_the_executable_is_not_on_path(self, monkeypatch):
        monkeypatch.setattr("aiitg.cli.hook_cmd._resolve_exe", lambda: None)
        result = runner.invoke(app, ["hook-config"])
        assert result.exit_code == 0, result.output
        assert "not on PATH" in result.output
        assert "UNSCANNED" in result.output

    def test_existing_help_lists_the_new_commands(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "hook" in result.stdout
        assert "hook-config" in result.stdout


def _settings_with_hook(tmp_path, exe_path: str) -> Path:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Read", "hooks": [{"type": "command", "command": f"{exe_path} hook pretooluse"}]}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    return settings


class TestHookDoctor:
    def test_missing_executable_fails(self, tmp_path):
        result = runner.invoke(
            app,
            [
                "hook",
                "doctor",
                "--exe",
                str(tmp_path / "does-not-exist"),
                "--settings",
                str(_settings_with_hook(tmp_path, str(tmp_path / "does-not-exist"))),
                "--quarantine-dir",
                str(tmp_path / "q"),
                "--cache-dir",
                str(tmp_path / "c"),
            ],
        )
        assert result.exit_code == 1
        assert "FAIL  executable" in result.output

    def test_reports_success_when_everything_is_wired(self, tmp_path):
        exe = tmp_path / "aiitg"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        settings = _settings_with_hook(tmp_path, str(exe))
        result = runner.invoke(
            app,
            [
                "hook",
                "doctor",
                "--exe",
                str(exe),
                "--settings",
                str(settings),
                "--quarantine-dir",
                str(tmp_path / "q"),
                "--cache-dir",
                str(tmp_path / "c"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "FAIL" not in result.output
        assert "PASS  PreToolUse hook wired" in result.output
        assert "hook pretooluse" in result.output

    def test_unwired_settings_fail(self, tmp_path):
        """The check that matters: configuring nothing must not look like success."""
        exe = tmp_path / "aiitg"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        settings = tmp_path / "settings.json"
        settings.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "hook",
                "doctor",
                "--exe",
                str(exe),
                "--settings",
                str(settings),
                "--quarantine-dir",
                str(tmp_path / "q"),
                "--cache-dir",
                str(tmp_path / "c"),
            ],
        )
        assert result.exit_code == 1
        assert "FAIL  PreToolUse hook wired" in result.output

    def test_wired_but_unstartable_command_fails(self, tmp_path):
        settings = _settings_with_hook(tmp_path, str(tmp_path / "gone" / "aiitg"))
        result = runner.invoke(
            app,
            [
                "hook",
                "doctor",
                "--settings",
                str(settings),
                "--quarantine-dir",
                str(tmp_path / "q"),
                "--cache-dir",
                str(tmp_path / "c"),
            ],
        )
        assert result.exit_code == 1
        assert "cannot be started" in result.output

    def test_unreadable_settings_fail(self, tmp_path):
        settings = tmp_path / "settings.json"
        settings.write_text("{ not json", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "hook",
                "doctor",
                "--settings",
                str(settings),
                "--quarantine-dir",
                str(tmp_path / "q"),
                "--cache-dir",
                str(tmp_path / "c"),
            ],
        )
        assert result.exit_code == 1
        assert "FAIL  PreToolUse hook wired" in result.output

    def test_fails_when_a_directory_is_not_writable(self, tmp_path):
        exe = tmp_path / "aiitg"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        settings = _settings_with_hook(tmp_path, str(exe))
        blocked = tmp_path / "readonly"
        blocked.mkdir()
        blocked.chmod(0o500)
        try:
            result = runner.invoke(
                app,
                [
                    "hook",
                    "doctor",
                    "--exe",
                    str(exe),
                    "--settings",
                    str(settings),
                    "--quarantine-dir",
                    str(blocked / "q"),
                    "--cache-dir",
                    str(tmp_path / "c"),
                ],
            )
            assert result.exit_code == 1
            assert "FAIL  quarantine dir writable" in result.output
        finally:
            blocked.chmod(0o700)

    def test_json_output_is_machine_readable(self, tmp_path):
        exe = tmp_path / "aiitg"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "hook",
                "doctor",
                "--json",
                "--exe",
                str(exe),
                "--settings",
                str(_settings_with_hook(tmp_path, str(exe))),
                "--quarantine-dir",
                str(tmp_path / "q"),
                "--cache-dir",
                str(tmp_path / "c"),
            ],
        )
        payload_json = json.loads(result.stdout)
        assert payload_json["ok"] is True
        names = {c["check"] for c in payload_json["checks"]}
        assert {"executable", "PreToolUse hook wired", "fail-closed default"} <= names
