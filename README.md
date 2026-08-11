# readonly-agent

A deny-by-default tool guard for an LLM agent that has shell access.

The agent can read files and run a short list of read-only commands. It cannot
write, move, delete, install, or reach a credential, and that is enforced by a
pure function you can test without an API key.

```
$ python3 test_guard.py
61 passed, 0 failed
```

## Why this exists

Giving an agent a shell is useful and the useful version is also the dangerous
version. The usual answer is a declarative allow-list of tools, and on its own
that is not enough for two reasons.

**A declarative allow-list is a grant, not a limit.** In the SDK this is written
against, a tool matching `allowed_tools` is auto-approved, and the auto-approval
short-circuits the callback that would otherwise be consulted. So the declarative
list can widen access and cannot be relied on to narrow it. The only place a
deny-by-default policy can sit is a `PreToolUse` hook, which runs before the call
regardless of how the call was approved. Both are used here: the declarative
lists are defence in depth and they document intent, and the hook is the control.

**A string comparison is not a path check.** `~/.ssh/../.ssh/id_rsa` does not
contain the substring you are looking for. Neither does a symlink pointing into
`~/.ssh`, nor a relative path evaluated from a different working directory. Every
path-shaped value is therefore resolved with `os.path.realpath` before it is
compared, and the comparison uses `os.path.commonpath` rather than
`str.startswith`, because `startswith` believes `~/.sshfoo` is inside `~/.ssh`.

## The design

`guard.py` imports nothing outside the standard library and knows nothing about
any agent SDK. It exposes one function:

```python
decide(tool_name, tool_input) -> Decision   # Decision(allow: bool, reason: str)
```

That shape is the whole point. The security decision is a pure function of the
tool call, so it can be tested exhaustively, offline, in a loop, with no
credentials and no network. `agent.py` is the wiring and is deliberately thin.

Four checks run in this order, cheapest and most absolute first:

1. **Tool whitelist.** Anything not in `ALLOWED_TOOLS` is denied. A `Write` call
   is refused before anyone looks at its arguments.
2. **Fragment denylist** over the whole serialised input, as a cheap first pass.
3. **Path resolution.** Every path-shaped value is resolved and rejected if it
   lands under a denied directory. This is the real defence, not step 2.
4. **Command allow-list**, for `Bash` only. The head of the command must be an
   allowed binary, and the command must contain no shell metacharacter, because
   `cat x | sh` is not a read-only command and neither is `cat $(rm -rf /)`.

## The threat model, stated so it can be argued with

An agent is answering questions about a machine. It is useful because it can read
files and run a few read-only commands. It must not be able to change the
machine, and it must not be able to read credentials, **even if the model is
confused, jailbroken, or following instructions embedded in a file it just read.**

This does not defend against a compromised host, a malicious SDK, a tool that
lies about its own name, or an operator who adds a write tool to `ALLOWED_TOOLS`.
A guard whose threat model is vague is a guard nobody can review.

## The tests are biased on purpose

`test_guard.py` spends far more assertions on what must be denied than on what
must be allowed, because a guard that wrongly allows is a hole and a guard that
wrongly denies is an inconvenience.

It also asserts on the policy lists themselves. The likeliest future regression
is not a logic bug, it is somebody adding a write-shaped tool to `ALLOWED_TOOLS`,
or adding a new tool whose path argument uses a key that `PATH_KEYS` does not
cover. So there are tests that fail if either happens.

The symlink case builds a real symlink into a denied directory at runtime and
asserts the read is refused. If the machine has no `~/.ssh`, it constructs the
equivalent case from scratch rather than skipping, because a test that silently
skips is how a guard rots.

**This suite has already earned its place once.** An early version of
`DENIED_FRAGMENTS` contained `"secrets"`, plural. The test asserting that
`AWS_SECRET` is refused failed, because substring matching only helps if the
substring is the shortest form of the word. That is now a comment in the source
next to the fix.

## Auditing

`agent.py` appends one JSON line per decision, allowed or denied, to
`audit.jsonl`. That is what lets you answer "has it ever written anything?" with
evidence instead of with confidence.

The logged input is scrubbed with the same fragment list the guard uses, so the
audit log cannot become the leak the guard exists to prevent.

## Running it

```bash
python3 test_guard.py                      # no dependencies, no API key
uv run agent.py "how much disk is free?"   # needs claude-agent-sdk and credentials
```

## Adapting it

Read `ALLOWED_TOOLS`, `ALLOWED_BINARIES`, `DENIED_DIRS` and `DENIED_FRAGMENTS` as
policy and change them for your machine. Adding to the first two is a security
decision and should be reviewed as one. If you add a tool whose input carries a
path under a new key, add that key to `PATH_KEYS` in the same change, and note
that the test suite will fail if you forget.

## Licence

MIT. See `LICENSE`.
