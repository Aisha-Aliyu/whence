#!/usr/bin/env python3
"""Check every package before Claude Code installs it.

Claude Code runs this script before each Bash command (a PreToolUse hook, set up in
.claude/settings.json). The script reads the command the way bash would, finds every
package the command would install, and blocks the command unless each package passes
these checks:

1. It exists on PyPI or npm, so a misspelled or invented name fails. Attackers
   register names that AI tools invent, which is called slopsquatting.
2. The package is at least 30 days old and the chosen version at least 7 days old.
   Malicious releases are usually found and removed within days.
3. OSV, the open source vulnerability database, has no malware report and no known
   vulnerability for that version.
4. The version is not yanked on PyPI or deprecated on npm.

It also enforces the project's install rules: Python packages come from PyPI through
uv, JavaScript packages come from npm through pnpm, and nothing installs from a URL,
a git repository, a local path, a custom index or a requirements file. Piping a
download into a shell is blocked too.

Exit code 0 lets the command run. Exit code 2 blocks it, and the message on stderr
tells Claude why. If a check cannot finish, for example because a registry is
unreachable, the command is blocked. Installs from the reviewed lockfiles
(`uv sync`, `pnpm install`) run without checks.

The script reads shell commands, so it cannot see installs that run inside a script,
a Makefile or a program, or commands disguised on purpose. It guards against
mistakes; it is not a sandbox.

It uses only the Python standard library, so it never needs an install itself.
"""

from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.client import HTTPException
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------- policy

MIN_PACKAGE_AGE = timedelta(days=30)
MIN_VERSION_AGE = timedelta(days=7)
MAX_PACKAGES = 15
# Claude Code lets a PreToolUse hook that times out pass, so the script gives up and
# blocks on its own, well before the 120 second timeout in .claude/settings.json.
DEADLINE_SECONDS = 60.0
HTTP_TIMEOUT_SECONDS = 15.0
HTTP_ATTEMPTS = 2
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024  # a few npm packages have very large metadata
MAX_JSON_BYTES = 300 * 1024 * 1024
WORKERS = 2
USER_AGENT = "whence-package-check/1 (+https://github.com/Aisha-Aliyu/whence)"
REPO_ROOT = Path(__file__).resolve().parents[2]
APPROVALS_FILE = ".claude/approved-packages.txt"
APPROVALS_REF = "origin/main"
PYPI = "PyPI"
NPM = "npm"


def words(text: str) -> frozenset[str]:
    return frozenset(text.split())


# ---------------------------------------------------------------- shell vocabulary

SHELLS = words("sh bash zsh dash ksh mksh ash fish")
INTERPRETERS = words("node deno bun perl ruby php pwsh")
INLINE_CODE_FLAGS = words("-e -E --eval -p --print -r")
DOWNLOADERS = words("curl wget fetch aria2c http https xh")
DOWNLOAD_SUBSTITUTION = re.compile(
    r"(\$\(|<\(|`)\s*(sudo\s+)?(curl|wget|fetch|aria2c)\b"
)
PYTHON = re.compile(r"^python(\d+(\.\d+)?)?$")
PIP = re.compile(r"^pip(3(\.\d+)?)?$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
RESERVED_WORDS = words("! { } if then else elif do while until")
WRAPPERS = words(
    "sudo doas env nice ionice nohup setsid time timeout stdbuf command builtin exec"
)
# Wrapper options that take a separate value, as in `sudo -u root`.
WRAPPER_VALUE_FLAGS = {
    "sudo": words(
        "-u -g -C -D -h -p -R -r -T -t -U --user --group --chdir --host --prompt "
        "--chroot --role --type --command-timeout --other-user --close-from"
    ),
    "doas": words("-u -C"),
    "env": words("-u -C --unset --chdir"),
    "nice": words("-n --adjustment"),
    "ionice": words("-c -n -p -P -u --class --classdata"),
    "time": words("-f -o --format --output"),
    "timeout": words("-s -k --signal --kill-after"),
    "stdbuf": words("-i -o -e --input --output --error"),
    "exec": words("-a"),
}

# Package tools this project does not use. Installs through them would skip the check.
UNUSED_PYTHON_TOOLS = words("pipx poetry pipenv pdm conda mamba micromamba pixi")
UNUSED_JS_TOOLS = words("npx pnpx yarn yarnpkg bun bunx deno")
INSTALL_TOOLS = (
    UNUSED_PYTHON_TOOLS | UNUSED_JS_TOOLS | words("pip pip3 uv uvx npm pnpm")
)
INSTALL_WORD = re.compile(
    r"\b(pip3?|uvx?|pipx|npm|npx|pnpm|pnpx|yarn|bunx?|deno|poetry|pipenv|pdm|conda|"
    r"mamba|curl|wget)\b"
)
PYTHON_WAY = (
    "Add Python packages with `uv add <name>==<version>`, run the project's own tools "
    "with `uv run <tool>`, and run one-off tools with `uvx <name>@<version>`."
)
JS_WAY = (
    "Add JavaScript packages with `pnpm add <name>@<version>`, run the project's own "
    "tools with `pnpm exec <tool>`, and run one-off tools with "
    "`pnpm dlx <name>@<version>`."
)

PIP_VALUE_FLAGS = words(
    "--python --log --proxy --retries --timeout --exists-action --trusted-host --cert "
    "--client-cert --cache-dir --use-feature --use-deprecated --progress-bar "
    "--keyring-provider"
)
NPM_INSTALL_VERBS = words(
    "install i in ins inst insta instal isnt isnta isntal isntall add ci clean-install "
    "ic install-clean isntall-clean install-test it install-ci-test cit update up "
    "upgrade udpate exec x create init innit"
)
NPM_VALUE_FLAGS = words(
    "--prefix -w --workspace --userconfig --globalconfig --cache --loglevel --registry "
    "--tag --omit --include --before --location"
)
UV_GLOBAL_VALUE_FLAGS = words(
    "--directory --project --cache-dir --config-file --color --python-preference"
)
UV_VALUE_FLAGS = UV_GLOBAL_VALUE_FLAGS | words(
    "--group --optional --extra --package --script --bounds --marker -m --python -p "
    "--config-setting -C --exclude-newer --exclude-newer-package --upgrade-package -P "
    "--refresh-package --reinstall-package --no-build-isolation-package "
    "--no-build-package --no-binary-package --link-mode --resolution --prerelease "
    "--keyring-provider --index-strategy --fork-strategy --python-platform --rev --tag "
    "--branch --torch-backend --env-file --from --with --with-executables-from"
)
UV_RUN_VALUE_FLAGS = UV_VALUE_FLAGS - {"-m"}  # `uv run -m pytest` runs a module
# Options that install from a file, a URL, another index or a local path.
UV_BLOCKED_FLAGS = words(
    "-r --requirements --requirement -c --constraints --constraint --overrides "
    "--override --build-constraints --build-constraint -e --editable -i --index-url "
    "--extra-index-url --index --default-index -f --find-links --allow-insecure-host "
    "--trusted-host --with-requirements --with-editable"
)
PNPM_GLOBAL_VALUE_FLAGS = words(
    "--filter -F --filter-prod -C --dir --reporter --loglevel --workspace-concurrency "
    "--test-pattern --changed-files-ignore-pattern --package"
)
PNPM_VALUE_FLAGS = PNPM_GLOBAL_VALUE_FLAGS | words(
    "--virtual-store-dir --store-dir --modules-dir --lockfile-dir --global-dir "
    "--global-bin-dir --cache-dir --state-dir --network-concurrency "
    "--child-concurrency --resolution-mode --package-import-method"
)
PNPM_BLOCKED_FLAGS = words("--registry")

NPM_NAME = re.compile(
    r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$"
)
EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
NPM_RELEASE = re.compile(r"^\d+\.\d+\.\d+$")
DIST_TAG = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")
NOT_FROM_NPM = (
    "git+",
    "git:",
    "git@",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "file:",
    "link:",
    "http:",
    "https:",
    "portal:",
    "patch:",
    "jsr:",
    "catalog:",
)
PY_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[A-Za-z0-9._,\s-]*\])?(.*)$",
    re.DOTALL,
)
PY_VERSION = re.compile(r"^[0-9][0-9A-Za-z.!+_-]{0,63}$")
PY_RELEASE = re.compile(r"^\d+(\.\d+)*$")
NOT_FROM_PYPI = ("git+", "hg+", "svn+", "bzr+", "file:", ".", "/", "~", "\\")
ARCHIVES = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".egg", ".tar")
OSV_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,80}$")


class ParseError(Exception):
    """The command could not be read."""


class CheckError(Exception):
    """A check could not finish, so the command is blocked."""


class Unreachable(CheckError):
    """A registry or OSV could not be reached."""


# ---------------------------------------------------------------- reading shell text


@dataclass
class Token:
    kind: str  # "word", "op", "redirect" or "heredoc"
    value: str
    quoted: bool = False  # heredoc only: a quoted delimiter keeps the body literal


REDIRECTS = words("&>> <<< <<- &> >> << >& <& >| <> > <")
# Longest first, so `&&` wins over `&`.
OPERATORS = sorted(REDIRECTS | words("&& || ;; |& ; & | ( )"), key=len, reverse=True)
MAX_NESTING = 32


class Lexer:
    """Splits shell text into words and operators, the way bash reads it.

    It also collects the commands inside $(...), `...`, <(...) and >(...), so those
    get checked too. Here-document bodies are data, unless a shell reads them.
    """

    def __init__(self, text: str, arithmetic: bool = False, level: int = 0) -> None:
        if level > MAX_NESTING:
            raise ParseError("the command is nested too deeply")
        self.text = text
        self.arithmetic = arithmetic  # inside (( )) only parentheses are operators
        self.level = level
        self.tokens: list[Token] = []
        self.nested: list[list[Token]] = []
        self.word: list[str] = []
        self.in_word = False
        self.pending: list[tuple[Token, str, bool]] = []

    def add(self, text: str) -> None:
        self.word.append(text)
        self.in_word = True

    def end_word(self) -> None:
        if self.in_word:
            self.tokens.append(Token("word", "".join(self.word)))
        self.word, self.in_word = [], False

    def run(self, i: int = 0, until_paren: bool = False) -> int:
        """Read from i. With until_paren, stop at the unmatched ')' and return its index."""
        text, n, depth = self.text, len(self.text), 0
        while i < n:
            c = text[i]
            if c == "\\":
                if not text.startswith("\\\n", i):  # a backslash-newline joins lines
                    self.add(text[i + 1 : i + 2] or "\\")
                i += 2
            elif c in " \t\r":
                self.end_word()
                i += 1
            elif c == "\n":
                self.end_word()
                self.tokens.append(Token("op", "\n"))
                i = self.read_heredoc_bodies(i + 1)
            elif c == "#" and not self.in_word and not self.arithmetic:
                end = text.find("\n", i)
                i = n if end == -1 else end
            elif c == "'":
                end = text.find("'", i + 1)
                if end == -1:
                    raise ParseError("a single quote is not closed")
                self.add(text[i + 1 : end])
                i = end + 1
            elif c == '"':
                i = self.read_double_quoted(i + 1)
            elif c == "`":
                i = self.read_backquoted(i + 1)
            elif c == "$":
                i = self.read_dollar(i, in_double_quotes=False)
            elif c in "<>" and text.startswith("(", i + 1) and not self.arithmetic:
                end = self.read_nested(i + 2)  # process substitution
                self.add(text[i : end + 1])
                i = end + 1
            elif text.startswith("((", i) and not self.in_word and not self.arithmetic:
                end = self.read_nested(i + 1, arithmetic=True)  # (( x << 2 ))
                self.add(text[i : end + 1])
                self.end_word()
                i = end + 1
            else:
                op = self.operator_at(i) if c in "&|;()<>" else None
                if op is None or (self.arithmetic and op not in ("(", ")")):
                    self.add(c)
                    i += 1
                elif op in REDIRECTS:
                    i = self.read_redirect(i, op)
                else:
                    self.end_word()
                    if op == "(":
                        depth += 1
                    elif op == ")":
                        if until_paren and depth == 0:
                            return i
                        depth -= 1
                    self.tokens.append(Token("op", op))
                    i += len(op)
        if until_paren:
            raise ParseError("a $( or <( is not closed")
        self.end_word()
        return n

    def operator_at(self, i: int) -> str | None:
        return next((op for op in OPERATORS if self.text.startswith(op, i)), None)

    def read_nested(self, start: int, arithmetic: bool = False) -> int:
        sub = Lexer(self.text, arithmetic=arithmetic, level=self.level + 1)
        end = sub.run(start, until_paren=True)
        self.nested.append(sub.tokens)
        self.nested.extend(sub.nested)
        return end

    def read_double_quoted(self, i: int) -> int:
        text, n = self.text, len(self.text)
        self.in_word = True
        while i < n:
            c = text[i]
            if c == '"':
                return i + 1
            if c == "\\" and text[i + 1 : i + 2] in ("\n", "$", "`", '"', "\\"):
                if text[i + 1] != "\n":
                    self.add(text[i + 1])
                i += 2
            elif c == "$":
                i = self.read_dollar(i, in_double_quotes=True)
            elif c == "`":
                i = self.read_backquoted(i + 1)
            else:
                self.add(c)
                i += 1
        raise ParseError("a double quote is not closed")

    def read_dollar(self, i: int, in_double_quotes: bool) -> int:
        text = self.text
        following = text[i + 1 : i + 2]
        if following == "(":
            end = self.read_nested(i + 2, arithmetic=text.startswith("$((", i))
            self.add(text[i : end + 1])
            return end + 1
        if following == "'" and not in_double_quotes:
            return self.read_ansi_c(i + 2)
        if following == '"' and not in_double_quotes:
            return self.read_double_quoted(i + 2)
        self.add("$")
        return i + 1

    def read_backquoted(self, i: int) -> int:
        text, n = self.text, len(self.text)
        inner: list[str] = []
        while i < n:
            c = text[i]
            if c == "\\" and text[i + 1 : i + 2] in ("$", "`", "\\"):
                inner.append(text[i + 1])
                i += 2
            elif c == "`":
                command = "".join(inner)
                sub = Lexer(command, level=self.level + 1)
                sub.run()
                self.nested.append(sub.tokens)
                self.nested.extend(sub.nested)
                self.add(f"`{command}`")
                return i + 1
            else:
                inner.append(c)
                i += 1
        raise ParseError("a backquote is not closed")

    def read_ansi_c(self, i: int) -> int:
        """Read a $'...' string. Its escapes are kept as written."""
        text, n = self.text, len(self.text)
        start = i
        while i < n:
            if text[i] == "\\":
                i += 2
            elif text[i] == "'":
                self.add(text[start:i])
                return i + 1
            else:
                i += 1
        raise ParseError("a $' quote is not closed")

    def read_redirect(self, i: int, op: str) -> int:
        if self.in_word and "".join(self.word).isdigit():
            self.word, self.in_word = [], False  # a file descriptor, as in 2>/dev/null
        else:
            self.end_word()
        i += len(op)
        if op in ("<<", "<<-"):
            delimiter, quoted, i = self.read_delimiter(i)
            token = Token("heredoc", "", quoted)
            self.tokens.append(token)
            self.pending.append((token, delimiter, op == "<<-"))
        else:
            self.tokens.append(Token("redirect", op))
        return i

    def read_delimiter(self, i: int) -> tuple[str, bool, int]:
        text, n = self.text, len(self.text)
        while i < n and text[i] in " \t":
            i += 1
        parts: list[str] = []
        quoted = False
        while i < n and text[i] not in " \t\r\n;&|()<>":
            c = text[i]
            if c in "'\"":
                end = text.find(c, i + 1)
                if end == -1:
                    raise ParseError(
                        "a quote in a here-document delimiter is not closed"
                    )
                parts.append(text[i + 1 : end])
                quoted, i = True, end + 1
            elif c == "\\" and i + 1 < n:
                parts.append(text[i + 1])
                quoted, i = True, i + 2
            else:
                parts.append(c)
                i += 1
        if not parts and not quoted:
            raise ParseError("a here-document has no delimiter")
        return "".join(parts), quoted, i

    def read_heredoc_bodies(self, i: int) -> int:
        text, n = self.text, len(self.text)
        for token, delimiter, strip_tabs in self.pending:
            lines: list[str] = []
            while i < n:
                end = text.find("\n", i)
                line = text[i:] if end == -1 else text[i:end]
                i = n if end == -1 else end + 1
                if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                    break
                lines.append(line)
            token.value = "".join(f"{line}\n" for line in lines)
            if not token.quoted:
                self.scan_expansions(token.value)
        self.pending = []
        return i

    def scan_expansions(self, body: str) -> None:
        """An unquoted here-document still runs $(...) and `...`, so collect those."""
        scanner = Lexer(body, level=self.level + 1)
        i = 0
        while i < len(body):
            if body[i] == "\\":
                i += 2
            elif body[i] == "$":
                i = scanner.read_dollar(i, in_double_quotes=True)
            elif body[i] == "`":
                i = scanner.read_backquoted(i + 1)
            else:
                i += 1
        self.nested.extend(scanner.nested)


def lex(text: str) -> Lexer:
    lexer = Lexer(text)
    lexer.run()
    return lexer


def split_words(text: str) -> list[str]:
    try:
        return [token.value for token in lex(text).tokens if token.kind == "word"]
    except ParseError:
        return [text]


# ---------------------------------------------------------------- finding installs


@dataclass(frozen=True)
class Request:
    """One package that a command would install."""

    ecosystem: str
    name: str
    version: str | None  # None means the latest release

    def label(self, version: str | None = None) -> str:
        shown = version or self.version
        if not shown:
            return f"{self.ecosystem} {self.name}"
        separator = "==" if self.ecosystem == PYPI else "@"
        return f"{self.ecosystem} {self.name}{separator}{shown}"

    def url(self, version: str | None = None) -> str:
        shown = version or self.version
        if self.ecosystem == PYPI:
            base = f"https://pypi.org/project/{self.name}/"
            return f"{base}{shown}/" if shown else base
        base = f"https://www.npmjs.com/package/{self.name}"
        return f"{base}/v/{shown}" if shown else base


@dataclass
class Plan:
    """The packages a command would install, and the rules it breaks."""

    requests: list[Request] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


@dataclass
class Command:
    argv: list[str] = field(default_factory=list)
    heredocs: list[str] = field(default_factory=list)


def pipelines(tokens: list[Token]) -> list[list[Command]]:
    """Group tokens into pipelines of simple commands. Redirect targets are dropped."""
    result: list[list[Command]] = []
    pipeline: list[Command] = []
    command = Command()
    skip_target = False
    for token in tokens:
        if token.kind == "word":
            if skip_target:
                skip_target = False
            else:
                command.argv.append(token.value)
        elif token.kind == "redirect":
            skip_target = True
        elif token.kind == "heredoc":
            command.heredocs.append(token.value)
        elif token.value in ("|", "|&"):
            pipeline.append(command)
            command, skip_target = Command(), False
        else:
            pipeline.append(command)
            result.append(pipeline)
            pipeline, command, skip_target = [], Command(), False
    pipeline.append(command)
    result.append(pipeline)
    cleaned = [[c for c in p if c.argv or c.heredocs] for p in result]
    return [p for p in cleaned if p]


def strip_wrappers(argv: list[str]) -> list[str]:
    """Drop VAR=value, sudo, env, timeout and similar prefixes before the real program."""
    i = 0
    while i < len(argv):
        word = argv[i]
        if word in RESERVED_WORDS or ASSIGNMENT.match(word):
            i += 1
            continue
        name = os.path.basename(word)
        if name not in WRAPPERS:
            break
        value_flags = WRAPPER_VALUE_FLAGS.get(name, frozenset())
        i += 1
        while i < len(argv) and argv[i].startswith("-") and argv[i] != "-":
            if argv[i] == "--":
                i += 1
                break
            i += 2 if argv[i] in value_flags else 1
        if name == "timeout" and i < len(argv):
            i += 1  # the duration
    return argv[i:]


def program_of(argv: list[str]) -> tuple[str, list[str]]:
    stripped = strip_wrappers(argv)
    if not stripped:
        return "", []
    return os.path.basename(stripped[0]), stripped[1:]


def python_module(args: list[str]) -> tuple[str, list[str]] | None:
    """For `python -m pip install x`, return ("pip", ["install", "x"])."""
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-") or arg in ("-", "--"):
            return None
        if arg.startswith("--"):
            i += 1
            continue
        letters = arg[1:]
        for k, letter in enumerate(letters):
            rest = letters[k + 1 :]
            if letter == "c":
                return None
            if letter == "m":
                if rest:
                    return rest, args[i + 1 :]
                return (args[i + 1], args[i + 2 :]) if i + 1 < len(args) else None
            if letter in "XW":  # options that take a value
                i += 1 if rest else 2
                break
        else:
            i += 1
    return None


def python_reads_stdin(args: list[str]) -> bool:
    """True when python would run the program that arrives on stdin."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-", "/dev/stdin"):
            return True
        if not arg.startswith("-"):
            return False  # a script file
        if arg.startswith("--"):
            i += 1
            continue
        letters = arg[1:]
        for k, letter in enumerate(letters):
            if letter in "cm":
                return False  # inline code or a module
            if letter in "XW":
                i += 1 if letters[k + 1 :] else 2
                break
        else:
            i += 1
    return True


def shell_options(args: list[str]) -> tuple[bool, bool, str | None]:
    """Return (has -c, has -s, first operand) for a shell's arguments."""
    has_c = has_s = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return has_c, has_s, args[i + 1] if i + 1 < len(args) else None
        if arg in ("--rcfile", "--init-file"):
            i += 2
        elif arg.startswith("--"):
            i += 1
        elif arg.startswith(("-", "+")) and len(arg) > 1:
            has_c = has_c or "c" in arg[1:]
            has_s = has_s or "s" in arg[1:]
            i += 2 if arg in ("-o", "+o", "-O", "+O") else 1
        else:
            return has_c, has_s, arg
    return has_c, has_s, None


def reads_code_from_stdin(program: str, args: list[str]) -> bool:
    """True when a shell or interpreter would run whatever arrives on stdin."""
    if program in SHELLS:
        has_c, has_s, operand = shell_options(args)
        return not has_c and (has_s or operand in (None, "-", "/dev/stdin"))
    if PYTHON.match(program):
        return python_reads_stdin(args)
    if program in INTERPRETERS:
        if any(arg.partition("=")[0] in INLINE_CODE_FLAGS for arg in args):
            return False
        operands = [arg for arg in args if not arg.startswith("-") or arg == "-"]
        return not operands or operands[0] in ("-", "/dev/stdin")
    return False


def starts_install_tool(argv: list[str], j: int) -> bool:
    name = os.path.basename(argv[j])
    if name in INSTALL_TOOLS or PIP.match(name):
        return True
    if PYTHON.match(name):
        module = python_module(argv[j + 1 :])
        return module is not None and module[0] in ("pip", "pipx", "uv")
    return False


def read_args(
    args: list[str],
    value_flags: frozenset[str],
    blocked_flags: frozenset[str],
    plan: Plan,
    tool: str,
    stop_at_operand: bool = False,
) -> tuple[list[str], dict[str, list[str]]]:
    """Split arguments into operands and option values. Blocked options add a problem.

    With stop_at_operand, reading stops at the first operand, which is returned with
    everything after it: the command that uvx, uv run or pnpm dlx starts.
    """
    operands: list[str] = []
    values: dict[str, list[str]] = {}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1 :]
            break
        if not arg.startswith("-") or arg == "-":
            if stop_at_operand:
                operands += args[i:]
                break
            operands.append(arg)
            i += 1
            continue
        name, eq, inline = arg.partition("=")
        attached = (
            not name.startswith("--") and len(name) > 2 and name[:2] in blocked_flags
        )
        if name in blocked_flags or attached:
            plan.problems.append(
                f"`{tool} {name[:2] if attached else name}` installs from a source the "
                "check cannot vet (a file, a URL, a custom index or a local path). Name "
                "each package from PyPI or npm instead."
            )
        takes_value = (name in value_flags or name in blocked_flags) and not eq
        takes_value = takes_value and not attached
        value = args[i + 1] if takes_value and i + 1 < len(args) else inline
        values.setdefault(name, []).append(value)
        i += 2 if takes_value else 1
    return operands, values


def first_operand(args: list[str], value_flags: frozenset[str]) -> str | None:
    i = 0
    while i < len(args):
        if not args[i].startswith("-") or args[i] == "-":
            return args[i]
        i += 2 if args[i] in value_flags else 1
    return None


def parse_pypi_spec(spec: str, plan: Plan, at_version: bool = False) -> None:
    text = spec.strip()
    if not text:
        return
    if at_version and "@" in text and "://" not in text and not re.search(r"\s@", text):
        base, _, pin = text.partition("@")  # uvx ruff@0.14.0
        text = base if pin in ("", "latest") else f"{base}=={pin}"
    if (
        "://" in text
        or text.startswith(NOT_FROM_PYPI)
        or text.lower().endswith(ARCHIVES)
        or re.search(r"@\s*[A-Za-z0-9+.-]+:", text)
    ):
        plan.problems.append(
            f"`{spec}` is not a package name from PyPI (it is a URL, a git repository, "
            "a local path or an archive). Install packages by name from PyPI."
        )
        return
    match = PY_REQUIREMENT.match(text)
    if not match:
        plan.problems.append(f"`{spec}` is not a valid Python package name.")
        return
    name, _extras, rest = match.groups()
    rest = rest.split(";", 1)[0].strip()  # drop an environment marker
    version: str | None = None
    if rest.startswith("===") and rest[3:].strip():
        version = rest[3:].strip()
    elif rest.startswith("==") and rest[2:].strip():
        version = rest[2:].strip()
    elif rest:
        plan.problems.append(
            f"`{spec}` is not an exact version. Pin one with `name==X.Y.Z`, or use the "
            "bare name, so the check vets the exact version that gets installed."
        )
        return
    if version is not None and not PY_VERSION.match(version):
        plan.problems.append(
            f"`{spec}` is not an exact version. Pin one with `name==X.Y.Z`, or use the "
            "bare name, so the check vets the exact version that gets installed."
        )
        return
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    plan.requests.append(Request(PYPI, normalized, version))


def parse_npm_spec(spec: str, plan: Plan) -> None:
    text = spec.strip()
    if not text:
        return
    if text.startswith((*NOT_FROM_NPM, ".", "/", "~")) or text.endswith(
        (".tgz", ".tar.gz", ".tar")
    ):
        plan.problems.append(
            f"`{spec}` is not a package from the npm registry. Install packages by name."
        )
        return
    if text.startswith("@"):
        at = text.find("@", 1)
        name, version = (
            (text, None) if at == -1 else (text[:at], text[at + 1 :] or None)
        )
    else:
        name, _, rest = text.partition("@")
        version = rest or None
    if version and version.startswith("npm:"):
        parse_npm_spec(version[4:], plan)  # an alias, as in my-zod@npm:zod@4.1.12
        return
    if version and version.startswith("workspace:"):
        return  # a package from this repository, not from the registry
    if version and (
        version.startswith(NOT_FROM_NPM) or "/" in version or ":" in version
    ):
        plan.problems.append(f"`{spec}` is not a package from the npm registry.")
        return
    if len(name) > 214 or not NPM_NAME.match(name):
        plan.problems.append(
            f"`{spec}` looks like a GitHub repository, not an npm package. Install "
            "packages by name."
            if "/" in name and not name.startswith("@")
            else f"`{spec}` is not a valid npm package name."
        )
        return
    if version == "latest":
        version = None
    elif version and EXACT_SEMVER.match(version.removeprefix("v")):
        version = version.removeprefix("v")
    elif version and not DIST_TAG.match(version):
        plan.problems.append(
            f"`{spec}` is not an exact version. Pin one with `name@X.Y.Z`, or use the bare "
            "name, so the check vets the exact version that gets installed."
        )
        return
    plan.requests.append(Request(NPM, name, version))


def create_package(spec: str) -> str:
    """`pnpm create next-app` runs create-next-app; `pnpm create @scope` runs @scope/create."""

    def prefixed(name: str) -> str:
        return name if name.startswith("create-") else f"create-{name}"

    if spec.startswith("@"):
        at = spec.find("@", 1)
        base, version = (spec, "") if at == -1 else (spec[:at], spec[at:])
        scope, _, name = base.partition("/")
        return (f"{scope}/{prefixed(name)}" if name else f"{scope}/create") + version
    name, at_sign, version = spec.partition("@")
    return prefixed(name) + at_sign + version


def blocked_tool(plan: Plan, tool: str, alternative: str) -> None:
    plan.problems.append(
        f"`{tool}` is not used in this project, so the package check cannot vet what it "
        f"installs. {alternative}"
    )


def plan_uv(args: list[str], plan: Plan) -> None:
    rest, _ = read_args(
        args, UV_GLOBAL_VALUE_FLAGS, UV_BLOCKED_FLAGS, plan, "uv", stop_at_operand=True
    )
    sub, tail = (rest[0], rest[1:]) if rest else ("", [])
    if sub == "add":
        specs, _ = read_args(tail, UV_VALUE_FLAGS, UV_BLOCKED_FLAGS, plan, "uv add")
        for spec in specs:
            parse_pypi_spec(spec, plan)
    elif sub == "pip" and tail[:1] in (["install"], ["sync"]):
        plan.problems.append(
            f"`uv pip {tail[0]}` changes the environment without updating pyproject.toml "
            "and uv.lock. Use `uv add <name>==<version>`, which the check vets, or "
            "`uv sync` to install the reviewed lockfile."
        )
    elif sub == "tool" and tail[:1] in (["run"], ["install"]):
        plan_tool_run(tail[1:], plan, f"uv tool {tail[0]}")
    elif sub == "run":
        _, values = read_args(
            tail,
            UV_RUN_VALUE_FLAGS,
            UV_BLOCKED_FLAGS,
            plan,
            "uv run",
            stop_at_operand=True,
        )
        for spec in values.get("--with", []):
            for item in spec.split(","):
                parse_pypi_spec(item, plan, at_version=True)


def plan_tool_run(args: list[str], plan: Plan, tool: str) -> None:
    """uvx, uv tool run and uv tool install: the package is --from or the command."""
    operands, values = read_args(
        args, UV_VALUE_FLAGS, UV_BLOCKED_FLAGS, plan, tool, stop_at_operand=True
    )
    target = (values.get("--from") or operands[:1])[-1:]
    extras = [item for value in values.get("--with", []) for item in value.split(",")]
    for spec in target + extras:
        parse_pypi_spec(spec, plan, at_version=True)


def plan_pnpm(args: list[str], plan: Plan, depth: int) -> None:
    rest, options = read_args(
        args,
        PNPM_GLOBAL_VALUE_FLAGS,
        PNPM_BLOCKED_FLAGS,
        plan,
        "pnpm",
        stop_at_operand=True,
    )
    if not rest:
        return
    verb, tail = rest[0], rest[1:]
    if verb == "dlx":
        plan_dlx(tail, plan, depth, options.get("--package", []))
        return
    if verb not in ("add", "install", "i", "update", "up", "upgrade", "create"):
        return
    specs, _ = read_args(
        tail, PNPM_VALUE_FLAGS, PNPM_BLOCKED_FLAGS, plan, f"pnpm {verb}"
    )
    if verb == "create":
        specs = [create_package(spec) for spec in specs[:1]]
    for spec in specs:
        parse_npm_spec(spec, plan)


def plan_dlx(args: list[str], plan: Plan, depth: int, packages: list[str]) -> None:
    """pnpm dlx: --package values are the packages, otherwise the command is."""
    operands, values = read_args(
        args,
        PNPM_VALUE_FLAGS,
        PNPM_BLOCKED_FLAGS,
        plan,
        "pnpm dlx",
        stop_at_operand=True,
    )
    found = packages + values.get("--package", [])
    shell_mode = "-c" in values or "--shell-mode" in values
    command = operands[0] if operands else None
    if shell_mode and command:
        plan_command(command, plan, depth + 1)  # pnpm dlx -c runs the text in a shell
    if not found and command:
        found = (split_words(command) if shell_mode else [command])[:1]
    for spec in found:
        parse_npm_spec(spec, plan)


def plan_program(
    program: str, args: list[str], heredocs: list[str], plan: Plan, depth: int
) -> None:
    """Apply the install rules to one program and its arguments."""
    runs_code = (
        program in SHELLS
        or program in INTERPRETERS
        or program in ("eval", "source", ".")
        or PYTHON.match(program)
    )
    if runs_code and any(DOWNLOAD_SUBSTITUTION.search(arg) for arg in args):
        plan.problems.append(
            "Running a downloaded script is blocked, because nothing checks what it runs. "
            "Download the file, read it, then decide whether to run it."
        )
    if program in SHELLS:
        has_c, has_s, operand = shell_options(args)
        if has_c and operand is not None:
            plan_command(operand, plan, depth + 1)
        elif operand is None or has_s:
            for body in heredocs:  # bash <<'EOF' runs the here-document as a script
                plan_command(body, plan, depth + 1)
        return
    if program == "eval":
        plan_command(" ".join(args), plan, depth + 1)
        return
    if program == "xargs":
        if any(starts_install_tool(args, j) for j in range(len(args))):
            plan.problems.append(
                "Packages passed through `xargs` cannot be checked. Name each package in "
                "the command."
            )
        return
    if PYTHON.match(program):
        module = python_module(args)
        if module is None:
            return
        program, args = module
    if program == "uv":
        plan_uv(args, plan)
    elif program == "uvx":
        plan_tool_run(args, plan, "uvx")
    elif program == "pnpm":
        plan_pnpm(args, plan, depth)
    elif PIP.match(program):
        if first_operand(args, PIP_VALUE_FLAGS) in ("install", "download", "wheel"):
            blocked_tool(plan, "pip install", PYTHON_WAY)
    elif program == "npm":
        verb = first_operand(args, NPM_VALUE_FLAGS)
        if verb in NPM_INSTALL_VERBS or (verb == "audit" and "fix" in args):
            blocked_tool(plan, f"npm {verb}", JS_WAY)
    elif program in UNUSED_PYTHON_TOOLS:
        blocked_tool(plan, program, PYTHON_WAY)
    elif program in UNUSED_JS_TOOLS:
        blocked_tool(plan, program, JS_WAY)


def plan_simple_command(command: Command, plan: Plan, depth: int) -> None:
    argv = command.argv
    stripped = strip_wrappers(argv)
    program = os.path.basename(stripped[0]) if stripped else ""
    if program:
        plan_program(program, stripped[1:], command.heredocs, plan, depth)
    # A later word that starts an install, as in `watch -n 5 pnpm add zod` or
    # `uv run pip install x`, is checked as a command of its own.
    k = len(argv) - len(stripped)
    for j in range(1, len(argv)):
        if j == k or (program == "uv" and j == k + 1 and argv[j] == "pip"):
            continue
        if starts_install_tool(argv, j):
            if depth < MAX_NESTING:
                plan_simple_command(Command(argv[j:]), plan, depth + 1)
            break


def plan_tokens(tokens: list[Token], plan: Plan, depth: int) -> None:
    for pipeline in pipelines(tokens):
        for position, command in enumerate(pipeline):
            program, args = program_of(command.argv)
            earlier = pipeline[:position]
            if earlier and reads_code_from_stdin(program, args):
                if any(program_of(e.argv)[0] in DOWNLOADERS for e in earlier):
                    plan.problems.append(
                        "Piping a download into a shell or interpreter is blocked, "
                        "because nothing checks what it runs. Download the file, read "
                        "it, then decide whether to run it."
                    )
                if program in SHELLS:  # `echo "uv add x" | sh` runs the text it reads
                    for feeder in earlier:
                        plan_fed_text(feeder, plan, depth + 1)
            plan_simple_command(command, plan, depth)


def plan_fed_text(command: Command, plan: Plan, depth: int) -> None:
    for body in command.heredocs:
        plan_command(body, plan, depth)
    program, args = program_of(command.argv)
    if program in ("echo", "printf"):
        plan_command(
            " ".join(arg for arg in args if not arg.startswith("-")), plan, depth
        )


def plan_command(text: str, plan: Plan, depth: int = 0) -> None:
    if depth > MAX_NESTING:
        plan.problems.append("The command is nested too deeply to check. Simplify it.")
        return
    try:
        lexer = lex(text)
    except ParseError as error:
        if INSTALL_WORD.search(text):
            plan.problems.append(
                f"The check could not read this command ({error}), so it cannot tell what "
                "it installs. Fix the quoting or split it into simpler commands."
            )
        return
    plan_tokens(lexer.tokens, plan, depth)
    for nested in lexer.nested:
        plan_tokens(nested, plan, depth + 1)


# ---------------------------------------------------------------- registries and OSV


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


class Registry:
    """Reads PyPI, npm and OSV. Every request has a timeout and respects the deadline."""

    pypi_url = "https://pypi.org"
    npm_url = "https://registry.npmjs.org"
    osv_url = "https://api.osv.dev"

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline  # a time.monotonic() value

    def get_json(
        self,
        url: str,
        body: dict[str, Any] | None = None,
        accept: str = "application/json",
    ) -> Any:
        """Return parsed JSON, or None for HTTP 404. Retries once after a transient error."""
        host = urllib.parse.urlsplit(url).hostname or url
        error: CheckError = Unreachable(f"could not reach {host}")
        for attempt in range(HTTP_ATTEMPTS):
            remaining = self.deadline - time.monotonic()
            if remaining <= 1:
                raise Unreachable(f"ran out of time waiting for {host}")
            try:
                timeout = min(HTTP_TIMEOUT_SECONDS, remaining)
                return self.fetch(url, body, accept, timeout, host)
            except urllib.error.HTTPError as http_error:
                http_error.close()
                if http_error.code == 404:
                    return None
                error = Unreachable(f"{host} answered HTTP {http_error.code}")
                if http_error.code not in (429, 500, 502, 503, 504):
                    raise error from http_error
            except (urllib.error.URLError, HTTPException, OSError) as network_error:
                reason = getattr(network_error, "reason", network_error)
                error = Unreachable(f"could not reach {host} ({reason})")
            if attempt + 1 < HTTP_ATTEMPTS:
                pause = 0.5 + random.random()  # jitter, so retries do not line up
                time.sleep(min(pause, max(0.0, self.deadline - time.monotonic() - 1)))
        raise error

    def fetch(
        self,
        url: str,
        body: dict[str, Any] | None,
        accept: str,
        timeout: float,
        host: str,
    ) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": accept,
            "Accept-Encoding": "gzip",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            chunks: list[bytes] = []
            size = 0
            while chunk := response.read(64 * 1024):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES or time.monotonic() > self.deadline:
                    raise CheckError(
                        f"{host} sent more data than the check can read in time"
                    )
                chunks.append(chunk)
            raw = b"".join(chunks)
            if (response.headers.get("Content-Encoding") or "").lower() == "gzip":
                raw = gunzip(raw, host)
        try:
            return json.loads(raw)
        except ValueError as error:
            raise CheckError(
                f"{host} sent a response the check could not read"
            ) from error

    def pypi_project(self, name: str) -> dict[str, Any] | None:
        url = f"{self.pypi_url}/pypi/{urllib.parse.quote(name)}/json"
        return as_dict(self.get_json(url)) or None

    def pypi_release(self, name: str, version: str) -> dict[str, Any] | None:
        path = f"{urllib.parse.quote(name)}/{urllib.parse.quote(version)}"
        return as_dict(self.get_json(f"{self.pypi_url}/pypi/{path}/json")) or None

    def pypi_files(self, name: str) -> list[Any]:
        url = f"{self.pypi_url}/simple/{urllib.parse.quote(name)}/"
        index = self.get_json(url, accept="application/vnd.pypi.simple.v1+json")
        return as_list(as_dict(index).get("files"))

    def npm_package(self, name: str) -> dict[str, Any] | None:
        url = f"{self.npm_url}/{urllib.parse.quote(name, safe='@')}"
        return as_dict(self.get_json(url)) or None

    def osv_ids(self, ecosystem: str, name: str, version: str) -> list[str]:
        body: dict[str, Any] = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }
        ids: list[str] = []
        for _ in range(20):
            answer = as_dict(self.get_json(f"{self.osv_url}/v1/query", body=body))
            for vuln in map(as_dict, as_list(answer.get("vulns"))):
                if vuln.get("withdrawn"):
                    continue
                primary = vuln.get("id")
                for candidate in [primary, *as_list(vuln.get("aliases"))]:
                    if not isinstance(candidate, str) or not OSV_ID.match(candidate):
                        continue
                    if candidate == primary or candidate.startswith("MAL-"):
                        ids.append(candidate)
            token = answer.get("next_page_token")
            if not token:
                return ids
            body["page_token"] = token
        raise CheckError("api.osv.dev returned too many pages")


def gunzip(raw: bytes, host: str) -> bytes:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = decompressor.decompress(raw, MAX_JSON_BYTES)
    except zlib.error as error:
        raise CheckError(f"{host} sent a broken compressed response") from error
    if decompressor.unconsumed_tail:
        raise CheckError(f"{host} sent a response too large to check")
    return data


# ---------------------------------------------------------------- the checks


@dataclass
class Finding:
    request: Request
    problems: list[str] = field(default_factory=list)
    version: str | None = None
    summary: str = ""
    cooldown: bool = False  # an age rule failed, so an approval could allow it
    unreachable: bool = False


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    text = re.sub(
        r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], text, count=1
    )
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def earliest(times: Iterable[datetime | None]) -> datetime | None:
    return min((t for t in times if t is not None), default=None)


def age_text(delta: timedelta) -> str:
    if delta.days < 1:
        return "less than a day ago"
    return f"{delta.days} day{'s' if delta.days != 1 else ''} ago"


def version_from_filename(filename: str) -> str | None:
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        return parts[1] if len(parts) >= 5 else None
    for suffix in (".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz"):
        if filename.endswith(suffix):
            return filename[: -len(suffix)].rpartition("-")[2] or None
    return None


def newest_old_enough(
    times: dict[str, datetime], now: datetime, pattern: re.Pattern[str], exclude: str
) -> str | None:
    """The newest stable version that is past the 7 day cooldown."""
    candidates = [
        version
        for version, when in times.items()
        if pattern.match(version)
        and version != exclude
        and now - when >= MIN_VERSION_AGE
    ]
    if not candidates:
        return None
    return max(
        candidates, key=lambda v: tuple(int(part) for part in re.findall(r"\d+", v))
    )


def approval_key(request: Request, version: str) -> str:
    if request.ecosystem == PYPI:
        return f"pypi/{request.name}=={version}".lower()
    return f"npm/{request.name}@{version}".lower()


def parse_approvals(text: str) -> set[str]:
    approved = set()
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if entry:
            approved.add(entry)
    return approved


def load_approvals(root: Path = REPO_ROOT, ref: str = APPROVALS_REF) -> set[str]:
    """Read approvals from the reviewed main branch, never from the working tree.

    Claude can edit files in its own branch, so an approval counts only after it has
    been reviewed and merged.
    """
    try:
        result = subprocess.run(
            ["git", "--no-pager", "-C", str(root), "show", f"{ref}:{APPROVALS_FILE}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    return parse_approvals(result.stdout) if result.returncode == 0 else set()


def osv_problems(registry: Registry, request: Request, version: str) -> list[str]:
    ids = sorted(set(registry.osv_ids(request.ecosystem, request.name, version)))
    malware = [i for i in ids if i.startswith("MAL-")]
    if malware:
        return [
            (
                f"OSV lists this package as malware ({', '.join(malware[:3])}). Never "
                f"install it. https://osv.dev/vulnerability/{malware[0]}"
            )
        ]
    if not ids:
        return []
    links = " ".join(f"https://osv.dev/vulnerability/{i}" for i in ids[:5])
    more = f" and {len(ids) - 5} more" if len(ids) > 5 else ""
    return [
        f"Version {version} has known vulnerabilities: {links}{more}. Pick another."
    ]


def age_problems(
    finding: Finding,
    first: datetime,
    published: datetime,
    now: datetime,
    suggestion: Callable[[], str | None],
) -> None:
    if now - first < MIN_PACKAGE_AGE:
        finding.cooldown = True
        finding.problems.append(
            f"This package was first published {age_text(now - first)}. Packages younger "
            "than 30 days are blocked, because most malicious packages are brand new."
        )
    if now - published < MIN_VERSION_AGE:
        finding.cooldown = True
        older = suggestion()
        hint = f" {older} is past the cooldown; use it instead." if older else ""
        finding.problems.append(
            f"Version {finding.version} was published {age_text(now - published)}. "
            f"Versions younger than 7 days are blocked while the community checks them.{hint}"
        )


def summarize(
    finding: Finding, published: datetime, now: datetime, latest: Any
) -> None:
    request, version = finding.request, finding.version
    finding.summary = (
        f"{request.label(version)}, published {age_text(now - published)}: "
        f"{request.url(version)}"
    )
    if isinstance(latest, str) and version != latest:
        finding.summary += f" (latest release: {latest})"


def check_pypi(
    request: Request, registry: Registry, now: datetime, approved: set[str]
) -> Finding:
    finding = Finding(request)
    project = registry.pypi_project(request.name)
    if project is None:
        finding.problems.append(
            "No package with this name exists on PyPI. The name may be misspelled or "
            "invented (slopsquatting). Search: "
            f"https://pypi.org/search/?q={urllib.parse.quote(request.name)}"
        )
        return finding
    latest = as_dict(project.get("info")).get("version")
    version = request.version or latest
    if not isinstance(version, str) or not PY_VERSION.match(version):
        raise CheckError(f"PyPI gave no usable version for {request.name}")
    finding.version = version
    release = (
        project if version == latest else registry.pypi_release(request.name, version)
    )
    if release is None:
        finding.problems.append(f"Version {version} does not exist on PyPI.")
        return finding
    if as_dict(release.get("info")).get("yanked"):
        finding.problems.append(f"Version {version} was yanked by its maintainers.")
    published = earliest(
        parse_time(as_dict(item).get("upload_time_iso_8601"))
        for item in as_list(release.get("urls"))
    )
    if published is None:
        finding.problems.append(f"PyPI lists no files for version {version}.")
        return finding
    if approval_key(request, version) not in approved:
        files = [as_dict(item) for item in registry.pypi_files(request.name)]
        first = (
            earliest(parse_time(item.get("upload-time")) for item in files) or published
        )

        def suggestion() -> str | None:
            times: dict[str, datetime] = {}
            yanked: set[str] = set()
            for item in files:
                found = version_from_filename(str(item.get("filename", "")))
                when = parse_time(item.get("upload-time"))
                if found and when:
                    times[found] = min(times.get(found, when), when)
                    if item.get("yanked"):
                        yanked.add(found)
            usable = {v: t for v, t in times.items() if v not in yanked}
            older = newest_old_enough(usable, now, PY_RELEASE, version)
            return f"{request.name}=={older}" if older else None

        age_problems(finding, first, published, now, suggestion)
    finding.problems += osv_problems(registry, request, version)
    summarize(finding, published, now, latest)
    return finding


def check_npm(
    request: Request, registry: Registry, now: datetime, approved: set[str]
) -> Finding:
    finding = Finding(request)
    doc = as_dict(registry.npm_package(request.name))
    versions = as_dict(doc.get("versions"))
    if not versions:
        finding.problems.append(
            "No package with this name exists on npm, or it was unpublished. The name may "
            "be misspelled or invented (slopsquatting). Search: "
            f"https://www.npmjs.com/search?q={urllib.parse.quote(request.name)}"
        )
        return finding
    tags = as_dict(doc.get("dist-tags"))
    wanted = request.version or "latest"
    version = wanted if EXACT_SEMVER.match(wanted) else tags.get(wanted)
    if not isinstance(version, str) or not EXACT_SEMVER.match(version):
        finding.problems.append(
            f"npm has no release tagged `{wanted}`. Pin an exact version."
        )
        return finding
    finding.version = version
    manifest = versions.get(version)
    if not isinstance(manifest, dict):
        finding.problems.append(f"Version {version} does not exist on npm.")
        return finding
    if manifest.get("deprecated"):
        # The deprecation text is written by the package author, so it is not repeated.
        finding.problems.append(
            f"Version {version} is deprecated on npm. Read why on the package page, then "
            "pick another version or package."
        )
    times = as_dict(doc.get("time"))
    published = parse_time(times.get(version))
    if published is None:
        raise CheckError(f"npm gave no publish date for {request.name} {version}")
    if approval_key(request, version) not in approved:
        per_version: dict[str, datetime] = {}
        for candidate in versions:
            when = parse_time(times.get(candidate))
            if when is not None:
                per_version[candidate] = when
        first = (
            parse_time(times.get("created"))
            or earliest(per_version.values())
            or published
        )

        def suggestion() -> str | None:
            usable = {
                v: t
                for v, t in per_version.items()
                if not as_dict(versions.get(v)).get("deprecated")
            }
            older = newest_old_enough(usable, now, NPM_RELEASE, version)
            return f"{request.name}@{older}" if older else None

        age_problems(finding, first, published, now, suggestion)
    finding.problems += osv_problems(registry, request, version)
    summarize(finding, published, now, tags.get("latest"))
    return finding


@dataclass
class Outcome:
    code: int  # 0 allows the command, 2 blocks it
    message: str = ""  # stderr, shown to Claude when the command is blocked
    context: str = ""  # a note for Claude when every package passed


def evaluate(
    command: str,
    registry: Registry,
    now: datetime,
    approvals: set[str] | None = None,
    cloud: bool = False,
) -> Outcome:
    plan = Plan()
    try:
        plan_command(command, plan)
    except Exception as error:  # noqa: BLE001 - a reader bug must not stop ordinary commands
        if not INSTALL_WORD.search(command):
            return Outcome(0)
        reason = f"The check could not read this command ({type(error).__name__})."
        plan = Plan(problems=[f"{reason} Split it into simpler commands."])
    requests = list(dict.fromkeys(plan.requests))
    problems = list(dict.fromkeys(plan.problems))
    if not requests and not problems:
        return Outcome(0)
    if len(requests) > MAX_PACKAGES:
        problems.append(
            f"This command names {len(requests)} packages. Install at most {MAX_PACKAGES} "
            "at a time, so each one can be checked."
        )
    findings: list[Finding] = []
    if not problems:
        approved = load_approvals() if approvals is None else approvals

        def check(request: Request) -> Finding:
            checker = check_pypi if request.ecosystem == PYPI else check_npm
            try:
                return checker(request, registry, now, approved)
            except CheckError as error:
                unreachable = isinstance(error, Unreachable)
                problem = f"The check could not finish: {error}."
                return Finding(request, [problem], unreachable=unreachable)

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            findings = list(pool.map(check, requests))
    blocked = [finding for finding in findings if finding.problems]
    if problems or blocked:
        return Outcome(2, message=block_message(problems, blocked, cloud))
    summaries = "; ".join(finding.summary for finding in findings)
    return Outcome(0, context=f"The package check passed for {summaries}.")


def block_message(problems: list[str], blocked: list[Finding], cloud: bool) -> str:
    lines = [
        "The package check blocked this command (.claude/hooks/check_packages.py)."
    ]
    lines += [f"- {problem}" for problem in problems]
    for finding in blocked:
        request, version = finding.request, finding.version
        where = f"{request.label(version)} ({request.url(version)})"
        lines += [f"- {where}: {problem}" for problem in finding.problems]
    lines.append(
        "Do not work around this check. Tell Aisha what was blocked and why, with the "
        "links above."
    )
    cooled = [
        approval_key(f.request, f.version) for f in blocked if f.cooldown and f.version
    ]
    if cooled:
        lines.append(
            "If Aisha decides a version is safe to use before the cooldown ends, she adds "
            f"`{cooled[0]}` to .claude/approved-packages.txt in a pull request. The check "
            f"reads approvals from {APPROVALS_REF}, so an approval counts only after review "
            "and merge; then run `git fetch origin main`."
        )
    if any(finding.unreachable for finding in blocked):
        hint = (
            "The check needs https://pypi.org, https://registry.npmjs.org and "
            "https://api.osv.dev."
        )
        if cloud:
            hint += (
                " In a Claude Code cloud session, Aisha adds any missing host to the "
                "environment's allowed domains (see docs/workflow.md)."
            )
        lines.append(hint)
    return "\n".join(lines)


# ---------------------------------------------------------------- entry point


def start_watchdog(seconds: float, on_timeout: Callable[[], None]) -> threading.Timer:
    timer = threading.Timer(seconds, on_timeout)
    timer.daemon = True
    timer.start()
    return timer


def give_up() -> None:
    sys.stderr.write(
        f"The package check ran out of time ({DEADLINE_SECONDS:.0f} seconds) while "
        "contacting PyPI, npm or OSV, so it blocked the command to be safe. Try again. If "
        "it keeps happening, check that those sites are reachable.\n"
    )
    sys.stderr.flush()
    os._exit(2)


def main() -> int:
    start_watchdog(DEADLINE_SECONDS, give_up)
    deadline = time.monotonic() + DEADLINE_SECONDS - 2
    try:
        payload = json.loads(sys.stdin.buffer.read())
        if not isinstance(payload, dict):
            raise TypeError("the hook input is not a JSON object")
        if payload.get("tool_name") != "Bash":
            return 0
        tool_input = payload.get("tool_input")
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        if not isinstance(command, str):
            raise TypeError("the hook input has no command")
        cloud = os.environ.get("CLAUDE_CODE_REMOTE") == "true"
        outcome = evaluate(
            command, Registry(deadline), datetime.now(timezone.utc), cloud=cloud
        )
    except Exception as error:  # noqa: BLE001 - any failure must block, never allow
        outcome = Outcome(
            2,
            f"The package check failed ({type(error).__name__}: {error}), so it blocked "
            "the command to be safe.",
        )
    if outcome.message:
        sys.stderr.write(outcome.message + "\n")
    if outcome.context:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": outcome.context,
            }
        }
        sys.stdout.write(json.dumps(output) + "\n")
    return outcome.code


if __name__ == "__main__":
    exit_code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exit_code)  # do not wait for network threads that are still running
