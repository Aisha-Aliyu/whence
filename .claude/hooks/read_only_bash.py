#!/usr/bin/env python3
"""Keep the review agent read-only: it may look and test, never change anything.

The review agent (.claude/agents/reviewer.md) has no file-editing tools, but it needs
Bash to read the diff and run the checks. Claude Code runs this script before every
command started with the Bash or Monitor tools (a PreToolUse hook in
.claude/settings.json). For any caller other than the review agent it allows the
command at once. For the review agent it allows only the read-only git commands and
the test, lint and type commands listed below, and blocks everything else with exit
code 2: chained commands, pipes, redirects, variables, substitutions, and options
that write files or start other programs.

The rule lives in settings.json rather than in the agent's own file because Claude
Code skips an agent file's hooks in a folder that has not been marked as trusted.

Running the tests runs the project's own code, so this limits what the review agent
chooses to run; it is not a sandbox. It uses only the Python standard library.
"""

from __future__ import annotations

import json
import re
import shlex
import sys

REVIEWER = "reviewer"  # the name in .claude/agents/reviewer.md
SHELL_TOOLS = ("Bash", "Monitor")
READ_ONLY_GIT = frozenset(
    {"diff", "log", "show", "status", "blame", "ls-files", "rev-parse", "merge-base"}
    | {"grep"}
)
# git options that write a file or start another program. git also accepts any
# unambiguous start of a long option, such as --op for --open-files-in-pager, so a
# shortened form is blocked too. `-O` in git grep starts a program of its own choosing,
# so any short option group that contains O is blocked.
GIT_WRITES = ("--output", "--ext-diff", "--textconv", "--open-files-in-pager")
# Outside quotes, these make bash chain, redirect, expand or run something else.
UNQUOTED_SPECIAL = set(";&|<>`$\\(){}*?[]!#")
# Inside double quotes, bash still expands these.
DOUBLE_QUOTED_SPECIAL = set("$`\\")
TOOL_VERSION = re.compile(r"^(ruff|mypy)@\d+(\.\d+){1,3}$")
ALLOWED = (
    "git diff, log, show, status, blame, ls-files, rev-parse, merge-base and grep; "
    "git branch --show-current; python3 -m unittest; uvx ruff@<version> check; "
    "uvx ruff@<version> format --check; uvx mypy@<version> --strict"
)


def plain_words(command: str) -> list[str] | None:
    """The words of a command that bash would not expand, or None if it would."""
    quote = ""
    for char in command:
        if char in "\n\r":
            return None
        if quote == "'":
            quote = "" if char == "'" else quote
        elif quote == '"':
            if char in DOUBLE_QUOTED_SPECIAL:
                return None
            quote = "" if char == '"' else quote
        elif char in "'\"":
            quote = char
        elif char in UNQUOTED_SPECIAL:
            return None
    try:
        return shlex.split(command)
    except ValueError:  # a quote that is never closed
        return None


def git_allowed(args: list[str]) -> bool:
    if args == ["branch", "--show-current"]:
        return True
    if not args or args[0] not in READ_ONLY_GIT:
        return False
    for arg in args[1:]:
        name = arg.partition("=")[0]
        if name.startswith("--") and len(name) > 2:
            if any(o.startswith(name) or name.startswith(o) for o in GIT_WRITES):
                return False
        elif name.startswith("-") and "O" in name:
            return False
    return True


def uvx_allowed(args: list[str]) -> bool:
    """Only the lint and type commands in CLAUDE.md, with paths and no other options."""
    if not args or not TOOL_VERSION.match(args[0]):
        return False
    tool, rest = args[0].partition("@")[0], args[1:]
    if tool == "ruff" and rest[:2] == ["format", "--check"]:
        paths = rest[2:]
    elif tool == "ruff" and rest[:1] == ["check"]:
        paths = [arg for arg in rest[1:] if arg != "--no-fix"]  # never apply fixes
    elif tool == "mypy" and rest[:1] == ["--strict"]:
        paths = rest[1:]
    else:
        return False
    return all(not path.startswith("-") for path in paths)


def decide(command: str) -> str | None:
    """Return why the command is blocked, or None when it is allowed."""
    words = plain_words(command)
    if words is None:
        return (
            "Chained commands, pipes, redirects, variables, substitutions and "
            "wildcards are blocked."
        )
    program, args = (words[0], words[1:]) if words else ("", [])
    if program == "git" and git_allowed(args):
        return None
    if program == "python3" and args[:2] == ["-m", "unittest"]:
        return None
    if program == "uvx" and uvx_allowed(args):
        return None
    return "Only read-only git commands and the test, lint and type commands run."


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read())
        if not isinstance(payload, dict):
            raise TypeError("the hook input is not a JSON object")
        if payload.get("agent_type") != REVIEWER:
            return 0
        if payload.get("tool_name") not in SHELL_TOOLS:
            return 0
        command = payload.get("tool_input", {}).get("command")
        if not isinstance(command, str):
            raise TypeError("the review agent may only run shell commands")
    except Exception as error:  # noqa: BLE001 - unreadable input must block
        sys.stderr.write(f"The read-only check blocked this ({error}).\n")
        return 2
    reason = decide(command)
    if reason is None:
        return 0
    sys.stderr.write(
        f"The review agent is read-only. {reason} Allowed: {ALLOWED}. Read files with "
        "the Read tool and search with Grep and Glob.\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
