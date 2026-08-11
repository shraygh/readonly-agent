"""Deny-by-default tool guard for an LLM agent that has shell access.

This module is deliberately free of any agent-SDK import. The whole point is
that the security decision is a pure function of (tool_name, tool_input), so it
can be tested exhaustively without an API key, without a network, and without a
running agent. See test_guard.py.

The threat model is narrow and worth stating, because a guard whose threat model
is vague is a guard nobody can review:

  An agent is answering questions about a machine. It is useful because it can
  read files and run a few read-only commands. It must not be able to change the
  machine, and it must not be able to read credentials, even if the model is
  confused, jailbroken, or following instructions embedded in a file it read.

What this does NOT defend against: a compromised host, a malicious SDK, a tool
that lies about its own name, or an operator who adds a write tool to ALLOWED.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# Policy. Everything not named here is denied.
# ---------------------------------------------------------------------------

#: Tools the agent may call at all. Deny-by-default means this is a whitelist,
#: not a starting point. Adding a tool here is a security decision.
ALLOWED_TOOLS: frozenset[str] = frozenset({"Read", "Grep", "Glob", "Bash"})

#: Commands Bash may invoke. The head of the command line must match exactly.
#: Every one of these is read-only in its ordinary form.
ALLOWED_BINARIES: frozenset[str] = frozenset({
    "cat", "ls", "rg", "jq", "head", "tail", "wc", "date", "df", "uptime",
})

#: Shell metacharacters that would let one allowed binary launch something else.
#: `cat x | sh` is not a read-only command, and neither is `cat $(rm -rf /)`.
SHELL_METACHARACTERS: tuple[str, ...] = (
    ">", "<", "|", ";", "&", "`", "$(", "${", "\n", "\r",
)

#: Directories that must never be read, resolved before comparison.
DENIED_DIRS: tuple[str, ...] = (
    "~/.ssh", "~/.gnupg", "~/.aws", "~/.config/gcloud", "~/.kube",
)

#: Substrings that deny a request wherever they appear in the tool input.
#: This is a cheap first pass, not the real defence. The path resolution below
#: is the real defence.
#: Note the singulars. An early version of this list said "secrets" and the test
#: suite caught that `AWS_SECRET` walked straight through it. Substring matching
#: only helps if the substring is the shortest form of the word.
DENIED_FRAGMENTS: tuple[str, ...] = (
    "id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
    "credential", "secret", "api_key", "apikey", "private_key",
    ".env", ".npmrc", ".netrc", ".pypirc",
    "token", "passwd", "shadow",
)

#: Tool-input keys that can carry a filesystem path. Each is resolved and
#: checked. Missing a key here is the most likely way to introduce a hole, which
#: is why the test suite asserts on this list directly.
PATH_KEYS: tuple[str, ...] = ("file_path", "path", "pattern", "notebook_path", "command")


@dataclass(frozen=True)
class Decision:
    """The result of a guard check. `allow` is the answer; `reason` is for logs."""

    allow: bool
    reason: str = ""

    def __bool__(self) -> bool:  # so `if decide(...)` reads naturally
        return self.allow


def _expand(path: str) -> str:
    """Resolve a path to something comparable: user, symlinks, `..`, all gone.

    `os.path.realpath` is what makes the directory denylist meaningful. A plain
    string comparison is defeated by `~/.ssh/../.ssh/id_rsa`, by a symlink
    pointing into `~/.ssh`, and by a relative path from the wrong cwd.
    """
    return os.path.realpath(os.path.expanduser(path))


def _denied_roots() -> tuple[str, ...]:
    return tuple(_expand(d) for d in DENIED_DIRS)


def _is_under(path: str, root: str) -> bool:
    """True if `path` is `root` or sits beneath it.

    `os.path.commonpath` rather than `str.startswith`, because startswith says
    `/home/user/.sshfoo` is under `/home/user/.ssh` and it is not.
    """
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives on Windows
        return False


def _extract_candidate_paths(tool_input: Mapping[str, Any]) -> list[str]:
    """Pull every value that could be a path out of a tool input.

    A command string is split on whitespace, because `cat a b` carries two
    paths and only checking the whole string would miss both.
    """
    out: list[str] = []
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if not isinstance(value, str) or not value:
            continue
        parts = value.split() if key == "command" else [value]
        out.extend(p for p in parts if p.startswith(("/", "~", "./", "../")) or "/" in p)
    return out


def _bash_is_read_only(command: str) -> Decision:
    if not command.strip():
        return Decision(False, "empty command")
    for meta in SHELL_METACHARACTERS:
        if meta in command:
            return Decision(False, f"shell metacharacter {meta!r} not permitted")
    head = command.split()[0]
    head = os.path.basename(head)  # /bin/cat and cat are the same decision
    if head not in ALLOWED_BINARIES:
        return Decision(False, f"{head!r} is not in the read-only allowlist")
    return Decision(True)


def decide(tool_name: str, tool_input: Mapping[str, Any] | None = None) -> Decision:
    """Decide whether one tool call may proceed. Deny-by-default.

    Order matters. The tool whitelist runs first because it is the cheapest and
    the most absolute check; a Write call is denied before anyone looks at its
    arguments.
    """
    tool_input = tool_input or {}

    if tool_name not in ALLOWED_TOOLS:
        return Decision(False, f"read-only session: {tool_name!r} is not permitted")

    blob = json.dumps(tool_input, default=str).lower()
    for fragment in DENIED_FRAGMENTS:
        if fragment in blob:
            return Decision(False, f"sensitive fragment {fragment!r} in tool input")

    roots = _denied_roots()
    for candidate in _extract_candidate_paths(tool_input):
        resolved = _expand(candidate)
        for root in roots:
            if _is_under(resolved, root):
                return Decision(False, f"path resolves under a denied directory: {root}")

    if tool_name == "Bash":
        verdict = _bash_is_read_only(str(tool_input.get("command", "")))
        if not verdict:
            return verdict

    return Decision(True)
