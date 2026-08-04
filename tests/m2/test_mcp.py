"""MCP server smoke test: spawn via stdio, list tools, call scan_file."""

from __future__ import annotations

from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tests.fixtures import builders


def _first_text(content: list[Any]) -> str:
    """Extract the first text payload from MCP content (defensive)."""
    for c in content:
        text = getattr(c, "text", None)
        if text:
            return str(text)
    return ""


async def _call(path: str) -> dict:
    params = StdioServerParameters(
        command=".venv/bin/aiitg-mcp",
        args=[],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert {"scan_file", "sanitize_file", "trust_file", "policy_file"} <= names, names

            result = await session.call_tool("policy_file", {"path": path})
            return {"tool_names": names, "result_text": _first_text(result.content)}


class TestMCPServer:
    def test_tools_listed_and_policy_works(self, tmp_path):
        import json

        f = builders.build_docx_benign(tmp_path / "clean.docx")
        out = anyio.run(_call, str(f))
        assert "policy_file" in out["tool_names"]
        payload = json.loads(out["result_text"])
        assert payload["decision"]["action"] == "allow"
        assert payload["file"] == "clean.docx"

    def test_scan_file_returns_evidence(self, tmp_path):
        import json

        f = builders.build_docx_with_zerowidth(tmp_path / "evil.docx")
        params = StdioServerParameters(command=".venv/bin/aiitg-mcp", args=[])

        async def run() -> str:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("scan_file", {"path": str(f)})
                    return _first_text(result.content)

        out = anyio.run(run)
        payload = json.loads(out)
        assert payload["summary"]["total"] >= 1
        assert any(ev["detector_id"] == "DET-001" for ev in payload["evidence"])
