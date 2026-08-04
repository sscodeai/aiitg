"""MCP server — expose the AI Input Trust Gateway to MCP-capable agents.

Run::

    aiitg-mcp                      # stdio transport (default for agents)
    aiitg-mcp --transport http     # HTTP transport (for remote gateways)

Tools exposed:
- ``scan_file``    : scan a file, return evidence + risk score
- ``sanitize_file``: sanitize a file, return cleaned text (safe for LLM context)
- ``trust_file``   : trust label a file (safe/caution/dangerous)
- ``policy_file``  : evaluate against default policy (allow/quarantine/approval/block)

The server is the "gateway" form of the library: agents call it before
feeding untrusted document content into their context. External content is
data, never authority.
"""

from __future__ import annotations

import json

import typer
from mcp.server.fastmcp import FastMCP

from ai_input_trust_gateway import process_file
from ai_input_trust_gateway.policy import default_policy

app = typer.Typer(add_completion=False)

mcp = FastMCP("aiitg")


@mcp.tool()
def scan_file(path: str) -> str:
    """Scan a file for hidden content / prompt-injection vectors.

    Returns JSON with evidence list, summary, and risk score.
    """
    result = process_file(path)
    payload = {
        "file": result.report.file,
        "kind": result.report.kind,
        "risk_score": result.report.risk_score,
        "summary": result.report.summary,
        "trust_label": result.label.to_dict(),
        "evidence": [ev.to_dict() for ev in result.report.evidence],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool()
def sanitize_file(path: str, mode: str = "strip") -> str:
    """Sanitize a file: strip/redact hidden content, return cleaned text.

    ``mode``: "strip" (default, remove hidden content) or "redact" (replace
    with [REDACTED]). The returned text is safe to feed to an LLM.
    """
    result = process_file(path, mode=mode)
    return result.sanitized.text


@mcp.tool()
def trust_file(path: str) -> str:
    """Compute the trust label for a file: safe / caution / dangerous."""
    result = process_file(path)
    return json.dumps(result.label.to_dict(), ensure_ascii=False, indent=2)


@mcp.tool()
def policy_file(path: str) -> str:
    """Evaluate a file against the default policy.

    Returns the decision (allow / quarantine / human_approval / block) plus
    the trust label and risk score. Agents should block/quarantine before
    using content when the decision is not "allow".
    """
    result = process_file(path)
    decision = default_policy().evaluate(result.report, result.label.value)
    return json.dumps(
        {
            "file": result.report.file,
            "decision": decision.to_dict(),
            "trust_label": result.label.to_dict(),
            "risk_score": result.report.risk_score,
        },
        ensure_ascii=False,
        indent=2,
    )


@app.command()
def main(
    transport: str = typer.Option("stdio", "--transport", help="stdio | http"),
) -> None:
    """Run the aiitg MCP server."""
    if transport == "http":
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
