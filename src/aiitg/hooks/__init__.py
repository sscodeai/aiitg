"""Claude Code hook adapter (M3.0) — zero-touch adoption for aiitg.

Usage from a project's ``.claude/settings.json`` (see ``aiitg hook-config``)::

    {
      "hooks": {
        "PreToolUse": [
          {"matcher": "Read", "hooks": [{"type": "command", "command": "aiitg hook pretooluse"}]}
        ]
      }
    }

No source change is needed in the consuming tool: it keeps calling ``Read`` as usual and the
adapter decides whether the document may enter the model's context.
"""

from aiitg.hooks.cache import HookCache
from aiitg.hooks.claude_code import (
    DEFAULT_ENFORCED_EXTENSIONS,
    PARSEABLE_EXTENSIONS,
    UNPARSEABLE_DOC_EXTENSIONS,
    HookConfig,
    HookOutcome,
    handle_posttooluse,
    handle_pretooluse,
    render_outcome,
)

__all__ = [
    "DEFAULT_ENFORCED_EXTENSIONS",
    "PARSEABLE_EXTENSIONS",
    "UNPARSEABLE_DOC_EXTENSIONS",
    "HookCache",
    "HookConfig",
    "HookOutcome",
    "handle_posttooluse",
    "handle_pretooluse",
    "render_outcome",
]
