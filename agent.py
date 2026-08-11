#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["claude-agent-sdk"]
# ///
"""A read-only agent: shell access, structurally unable to change the machine.

Run with `uv run agent.py "how much disk is free?"`.

Everything security-relevant lives in guard.py, which imports nothing and is
tested without an API key. This file is only the wiring, and the wiring is short
on purpose: the less policy that lives next to the transport, the easier the
policy is to review.

The one non-obvious decision is why the guard runs in a PreToolUse hook rather
than being expressed only through the SDK's declarative `allowed_tools`.
Declarative allow-lists in this SDK are evaluated as a permission *grant*: a
matching tool is auto-approved, and an auto-approval short-circuits the callback
that would otherwise be consulted. So a declarative list can widen access but it
cannot be relied on to narrow it. A PreToolUse hook runs before the call
regardless of how the tool was approved, which is the only place a deny-by-default
policy can actually sit.

Both are used here anyway. `allowed_tools` and `disallowed_tools` are defence in
depth and they document intent to a reader; the hook is the control.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from claude_agent_sdk import (  # type: ignore[import-not-found]
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
)

import guard

AUDIT_LOG = os.environ.get("READONLY_AGENT_AUDIT", "audit.jsonl")


def _audit(event: dict) -> None:
    """Append one line per decision. An unauditable guard is unfalsifiable.

    This is what lets you answer "has it ever written anything?" with evidence
    rather than with confidence.
    """
    event["at"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, default=str) + "\n")


async def pre_tool(input_data, tool_use_id, context):  # noqa: ANN001, ARG001
    """PreToolUse hook. Deny-by-default, and log both outcomes."""
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {}) or {}

    decision = guard.decide(tool_name, tool_input)
    _audit({
        "tool": tool_name,
        "allowed": decision.allow,
        "reason": decision.reason,
        # The input is logged with the same fragment scrubbing the guard uses, so
        # the audit log cannot become the leak the guard exists to prevent.
        "input": {k: v for k, v in tool_input.items() if not any(
            frag in json.dumps({k: v}, default=str).lower()
            for frag in guard.DENIED_FRAGMENTS
        )},
    })

    if decision.allow:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": decision.reason,
        }
    }


async def ask(question: str) -> None:
    options = ClaudeAgentOptions(
        system_prompt=(
            "You answer questions about this machine. You are read-only: you "
            "cannot write, edit or change anything, and attempts to do so will "
            "be refused. If you cannot answer with the tools you have, say so "
            "and say what you would have needed."
        ),
        allowed_tools=sorted(guard.ALLOWED_TOOLS),
        disallowed_tools=["Write", "Edit", "MultiEdit", "NotebookEdit", "Task", "KillShell"],
        permission_mode="default",
        max_turns=12,
        hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[pre_tool])]},
    )

    async with ClaudeSDKClient(options=options) as client:
        await client.query(question)
        async for message in client.receive_response():
            for block in getattr(message, "content", []) or []:
                text = getattr(block, "text", None)
                if text:
                    print(text, end="", flush=True)
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: agent.py \"your question\"")
    asyncio.run(ask(" ".join(sys.argv[1:])))
