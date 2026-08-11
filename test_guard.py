"""Tests for the tool guard.

Run with `python3 test_guard.py`. No pytest, no API key, no network, because a
security check that is awkward to run does not get run.

The bias of this file is deliberate: it spends far more assertions on things that
must be DENIED than on things that must be allowed. A guard that wrongly allows
is a hole; a guard that wrongly denies is an inconvenience. It also asserts on
the policy lists themselves, because the likeliest future regression is somebody
adding a write tool to ALLOWED_TOOLS or a path-carrying key that PATH_KEYS does
not cover.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

import guard

PASS = 0
FAIL: list[str] = []


def check(label: str, condition: bool) -> None:
    global PASS
    if condition:
        PASS += 1
    else:
        FAIL.append(label)


def denied(label: str, tool: str, tool_input: dict | None = None) -> None:
    d = guard.decide(tool, tool_input)
    check(f"DENY {label} (got: {d.reason or 'allowed'})", not d.allow)


def allowed(label: str, tool: str, tool_input: dict | None = None) -> None:
    d = guard.decide(tool, tool_input)
    check(f"ALLOW {label} (denied because: {d.reason})", d.allow)


# --- The tool whitelist is absolute -----------------------------------------

for tool in ("Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Task",
             "KillShell", "MultiEdit", "", "read", "READ", "Bash ", " Bash"):
    denied(f"tool {tool!r}", tool, {"file_path": "/etc/hostname"})

allowed("Read of an ordinary file", "Read", {"file_path": "/etc/hostname"})
allowed("Grep with a harmless pattern", "Grep", {"pattern": "TODO"})
allowed("Glob", "Glob", {"pattern": "*.md"})


# --- Bash is read-only ------------------------------------------------------

for cmd in (
    "rm -rf /", "mv a b", "cp a b", "chmod 777 x", "curl http://x", "sh -c ls",
    "python3 -c 'print(1)'", "git push", "systemctl restart nginx", "dd if=/dev/zero of=/dev/sda",
):
    denied(f"bash {cmd!r}", "Bash", {"command": cmd})

for cmd in (
    "cat a > b", "cat a >> b", "ls | sh", "ls; rm x", "ls && rm x", "ls `rm x`",
    "cat $(rm x)", "cat ${HOME}/.ssh/id_rsa", "ls\nrm x", "cat a < b",
):
    denied(f"bash metacharacter {cmd!r}", "Bash", {"command": cmd})

denied("bash empty", "Bash", {"command": "   "})
denied("bash missing command key", "Bash", {})

allowed("bash cat", "Bash", {"command": "cat /etc/hostname"})
allowed("bash absolute path binary", "Bash", {"command": "/bin/cat /etc/hostname"})
allowed("bash df", "Bash", {"command": "df -h"})
allowed("bash rg", "Bash", {"command": "rg --count TODO ."})


# --- Fragment denylist ------------------------------------------------------

for frag_input in (
    {"file_path": "/home/u/.env"},
    {"file_path": "/tmp/my-credentials.json"},
    {"command": "cat /tmp/token.txt"},
    {"pattern": "AWS_SECRET"},          # 'secret' fragment
    {"file_path": "/etc/shadow"},
    {"file_path": "/home/u/.netrc"},
):
    denied(f"fragment {frag_input}", "Read", frag_input)


# --- Path resolution is the real defence ------------------------------------

home = os.path.expanduser("~")

for path in (
    f"{home}/.ssh/id_rsa",
    f"{home}/.ssh/../.ssh/config",          # traversal that lands back inside
    f"{home}/.gnupg/pubring.kbx",
    "~/.ssh/config",                        # tilde form
    f"{home}/.aws/credentials",
):
    denied(f"path {path}", "Read", {"file_path": path})

denied("denied dir named in a Bash argument", "Bash", {"command": f"cat {home}/.ssh/config"})

# A symlink into a denied directory must not launder the read. This is the case
# a substring check cannot catch and realpath can.
tmp = tempfile.mkdtemp()
try:
    link = os.path.join(tmp, "innocent.txt")
    real_ssh = os.path.join(home, ".ssh")
    if os.path.isdir(real_ssh):
        os.symlink(real_ssh, os.path.join(tmp, "linkdir"))
        denied("symlink into a denied directory",
               "Read", {"file_path": os.path.join(tmp, "linkdir", "config")})
    else:
        # No ~/.ssh on this machine: build the equivalent case from scratch so the
        # test still proves something rather than silently skipping.
        fake = os.path.join(tmp, "fake_ssh")
        os.makedirs(fake)
        guard.DENIED_DIRS = guard.DENIED_DIRS + (fake,)  # type: ignore[misc]
        os.symlink(fake, os.path.join(tmp, "linkdir"))
        denied("symlink into a denied directory (synthetic)",
               "Read", {"file_path": os.path.join(tmp, "linkdir", "x")})
    # A sibling whose name merely starts with a denied root must still be allowed.
    sibling = real_ssh + "foo"
    d = guard.decide("Read", {"file_path": os.path.join(sibling, "notes.md")})
    check("ALLOW sibling dir whose name prefixes a denied root", d.allow)
finally:
    shutil.rmtree(tmp, ignore_errors=True)


# --- Assertions on the policy itself ----------------------------------------

WRITE_SHAPED = {"Write", "Edit", "MultiEdit", "NotebookEdit", "Task", "KillShell"}
check("no write-shaped tool is in ALLOWED_TOOLS",
      not (WRITE_SHAPED & set(guard.ALLOWED_TOOLS)))

MUTATING = {"rm", "mv", "cp", "chmod", "chown", "dd", "tee", "sh", "bash", "zsh",
            "python", "python3", "node", "curl", "wget", "git", "systemctl", "kill"}
check("no mutating binary is in ALLOWED_BINARIES",
      not (MUTATING & set(guard.ALLOWED_BINARIES)))

check("PATH_KEYS covers the common path-carrying keys",
      {"file_path", "path", "pattern", "command"} <= set(guard.PATH_KEYS))

check("Decision is falsy when it denies", not bool(guard.Decision(False, "x")))
check("Decision is truthy when it allows", bool(guard.Decision(True)))


# --- Report -----------------------------------------------------------------

print(f"{PASS} passed, {len(FAIL)} failed")
for f in FAIL:
    print("  FAILED:", f)
sys.exit(1 if FAIL else 0)
