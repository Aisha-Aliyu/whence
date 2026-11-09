#!/usr/bin/env python3
"""Check every package before Claude Code installs it.

Claude Code runs this script before each shell command it starts with the Bash or
Monitor tools (a PreToolUse hook, set up in .claude/settings.json). The script reads
the command the way bash would, finds every package the command would install, and
blocks the command unless each package passes these checks:

1. It exists on PyPI or npm, so a misspelled or invented name fails. Attackers
   register names that AI tools invent, which is called slopsquatting.
2. The package is at least 30 days old, and every file of the chosen version is at
   least 7 days old. Malicious releases are usually found and removed within days.
3. OSV, the open source vulnerability database, has no malware report and no known
   vulnerability for that version.
4. The version is not yanked on PyPI or deprecated on npm.

It also enforces the project's install rules: Python packages come from PyPI through
uv, JavaScript packages come from npm through pnpm, always at an exact version, and
nothing installs from a URL, a git repository, a local path, a requirements file, or
another index, registry or mirror set by an option or an environment variable. Bulk
upgrades are blocked, because Dependabot proposes upgrades in reviewed pull requests.
Running a downloaded script, by a pipe or in the same command that downloads it, is
blocked too.

Exit code 0 lets the command run. Exit code 2 blocks it, and the message on stderr
tells Claude why. If a check cannot finish, for example because a registry is
unreachable, the command is blocked. Installs from the lockfile (`uv sync`,
`pnpm install`) run without checks.

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
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.client import HTTPException
from typing import Any, TypeGuard

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
MAX_SCRIPT_BYTES = 1024 * 1024
MAX_FOLDERS = 16  # folders a command may `cd` into before the check stops following
WORKERS = 2
USER_AGENT = "whence-package-check/1 (+https://github.com/Aisha-Aliyu/whence)"
# Approvals come from main on GitHub, so nothing in a session can fake one.
APPROVALS_URL = "https://raw.githubusercontent.com/Aisha-Aliyu/whence/main/.claude/approved-packages.txt"
SHELL_TOOLS = ("Bash", "Monitor")  # Claude Code tools that run shell commands
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
RUN_DOWNLOAD = (
    "Running a downloaded script is blocked, because nothing checks what it runs. "
    "Download the file, read it, then decide whether to run it."
)
PIPE_DOWNLOAD = (
    "Piping a download into a shell or interpreter is blocked, because nothing "
    "checks what it runs. Download the file, read it, then decide whether to run it."
)
URL_SCHEME = re.compile(r"https?://", re.IGNORECASE)
PYTHON = re.compile(r"^python(\d+(\.\d+)?)?$")
PIP = re.compile(r"^pip(3(\.\d+)?)?$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
# `$(which pnpm) add zod` runs pnpm.
LOOKED_UP_PROGRAM = re.compile(
    r"^(?:\$\(|`)\s*(?:which|command -v|type -P)\s+([\w.@/+-]+)\s*(?:\)|`)$"
)
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
# Programs that run a command handed to them as one string, as in `su -c "..."`.
COMMAND_STRING_RUNNERS = words("su runuser flock script")
# Programs whose arguments are never commands, so a word such as `pip` in
# `grep -rn pip docs/` is only text.
NO_COMMAND_ARGS = words(
    "grep egrep fgrep rg ag ack which type whereis whatis apropos man info echo printf "
    "cat head tail less more wc ls tree file stat realpath readlink basename dirname "
    "tee jq yq sed awk sort uniq cut tr diff cmp comm touch mkdir rmdir rm cp mv ln "
    "chmod chown du df cd pwd export unset alias test true false"
)
XARGS_VALUE_FLAGS = words(
    "-n -P -L -d -E -s -a --max-args --max-procs --max-lines --delimiter --eof "
    "--max-chars --arg-file --process-slot-var"
)
XARGS_INPUT = "xargs-input"  # stands for the words xargs reads from stdin

# Settings that send downloads to another index, registry or mirror, or turn off
# certificate or signature checks. They are blocked as options (--index-url,
# --registry, --config.registry) and as environment variables (UV_INDEX_URL,
# npm_config_registry, COREPACK_NPM_REGISTRY).
RISKY_SETTING = re.compile(
    r"index|registry|mirror|find.links|config.file|userconfig|globalconfig|insecure|"
    r"trusted.host|strict.ssl|cafile|tls.reject|integrity",
    re.IGNORECASE,
)
PACKAGE_TOOL_VARIABLE = re.compile(
    r"^(uv|pip|npm_config|pnpm_config|yarn|node|corepack)_", re.IGNORECASE
)

# Package tools this project does not use. Installs through them would skip the check.
UNUSED_PYTHON_TOOLS = words("pipx poetry pipenv pdm conda mamba micromamba pixi")
UNUSED_JS_TOOLS = words("npx pnpx yarn yarnpkg bun bunx deno")
INSTALL_TOOLS = (
    UNUSED_PYTHON_TOOLS | UNUSED_JS_TOOLS | words("pip pip3 uv uvx npm pnpm")
)
PACKAGE_MANAGERS = INSTALL_TOOLS | {"corepack"}
# The programs `corepack <program>[@version]` runs, and the npm package each comes from.
COREPACK_TOOLS = {
    "pnpm": "pnpm",
    "pnpx": "pnpm",
    "yarn": "yarn",
    "yarnpkg": "yarn",
    "npm": "npm",
    "npx": "npm",
}
INSTALL_WORD = re.compile(
    r"\b(pip3?|uvx?|pipx|npm|npx|pnpm|pnpx|yarn|bunx?|deno|poetry|pipenv|pdm|conda|"
    r"mamba|corepack|curl|wget|upgrade-deps)\b"
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
BULK_UPGRADE = (
    "upgrades packages without the check. Change one package at a time to an exact "
    "version (`uv add <name>==<version>` or `pnpm add <name>@<version>`); Dependabot "
    "proposes routine upgrades in reviewed pull requests."
)

PIP_VERBS = words(
    "install download uninstall freeze inspect list show check config search cache "
    "index wheel hash completion debug help lock"
)
PIP_VALUE_FLAGS = words(
    "--python --log --proxy --retries --timeout --exists-action --trusted-host --cert "
    "--client-cert --cache-dir --use-feature --use-deprecated --progress-bar "
    "--keyring-provider"
)
NPM_INSTALL_VERBS = words(
    "install i in ins inst insta instal isnt isnta isntal isntall add ci clean-install "
    "ic install-clean isntall-clean install-test it install-ci-test cit sit "
    "clean-install-test update up upgrade udpate exec x create init innit link ln "
    "dedupe ddp"
)
NPM_VERBS = NPM_INSTALL_VERBS | words(
    "run run-script rum urn test t tst start stop restart view v info show search s "
    "se find help config c get set ls list ll la outdated audit doctor version whoami "
    "ping pkg explain why query fund repo docs home bugs root prefix bin cache token "
    "profile org team access owner deprecate dist-tag publish unpublish login logout "
    "adduser pack diff edit explore prune rebuild rb sbom star stars unstar completion"
)
NPM_VALUE_FLAGS = words(
    "--prefix -w --workspace --userconfig --globalconfig --cache --loglevel --registry "
    "--tag --omit --include --before --location --install-strategy"
)

UV_SUBCOMMANDS = words(
    "add remove sync lock export tree tool python pip venv build publish cache self "
    "version run init help format auth"
)
UV_VALUE_FLAGS = words(
    "--directory --project --cache-dir --config-file --color --python-preference "
    "--group --optional --extra --package --script --bounds --marker -m --python -p "
    "--config-setting -C --exclude-newer --exclude-newer-package --upgrade-package -P "
    "--refresh-package --reinstall-package --no-build-isolation-package "
    "--no-build-package --no-binary-package --link-mode --resolution --prerelease "
    "--keyring-provider --index-strategy --fork-strategy --python-platform --rev --tag "
    "--branch --torch-backend --env-file --from --with --with-executables-from "
    "--only-group --no-group --no-extra --preview-features --allow-insecure-host"
)
UV_BOOL_FLAGS = words(
    "--dev --frozen --locked --no-sync --isolated --active --no-dev --all-extras "
    "--all-packages --all-groups --no-project --module --quiet --verbose --offline "
    "--no-cache --native-tls --no-config --no-progress --preview --exact --inexact "
    "--compile-bytecode --no-editable --refresh --reinstall --no-build --no-binary "
    "--no-build-isolation --managed-python --no-managed-python --no-python-downloads "
    "--no-env-file --raw --raw-sources --workspace --no-workspace --seed -q -v -n"
)
UV_RUN_VALUE_FLAGS = UV_VALUE_FLAGS - {
    "-m",
    "--script",
}  # in `uv run` both are switches
UV_RUN_BOOL_FLAGS = UV_BOOL_FLAGS | {"-m", "--script", "-s"}
# Options that install from a file or a local path. Index options are risky settings.
UV_FILE_FLAGS = words(
    "-r --requirements --requirement -c --constraints --constraint --overrides "
    "--override --build-constraints --build-constraint -e --editable -i -f "
    "--with-requirements --with-editable"
)
UV_UPGRADE_FLAGS = words("-U --upgrade -P --upgrade-package")

PNPM_VERBS = words(
    "add install i update up upgrade dlx create exec run test t start stop restart "
    "remove rm uninstall un link ln unlink import rebuild rb prune fetch install-test "
    "it patch patch-commit patch-remove audit list ls why outdated licenses root bin "
    "store env setup init deploy pack publish server config c get set cache "
    "self-update doctor approve-builds ignored-builds help recursive multi m"
)
PNPM_VALUE_FLAGS = words(
    "--filter -F --filter-prod -C --dir --reporter --loglevel --workspace-concurrency "
    "--test-pattern --changed-files-ignore-pattern --package --virtual-store-dir "
    "--store-dir --modules-dir --lockfile-dir --global-dir --global-bin-dir "
    "--cache-dir --state-dir --network-concurrency --child-concurrency "
    "--resolution-mode --package-import-method --resume-from --allow-build"
)
PNPM_BOOL_FLAGS = words(
    "--save-dev --save-prod --save-optional --save-exact --save-peer --save-catalog "
    "--global --workspace --workspace-root --recursive --ignore-scripts --offline "
    "--prefer-offline --frozen-lockfile --no-frozen-lockfile --lockfile-only --silent "
    "--stream --aggregate-output --color --no-color --use-stderr --fix-lockfile "
    "--ignore-workspace --shamefully-hoist --strict-peer-dependencies --no-optional "
    "--prod --dev --shell-mode --latest -D -P -O -E -g -w -r -s -c -L"
)

NPM_NAME = re.compile(
    r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$"
)
EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
NPM_RELEASE = re.compile(r"^\d+\.\d+\.\d+$")
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
# Versions from a registry are shown to Claude only in this short, plain form, so a
# package author cannot write a message to Claude inside a version string.
SHOWN_VERSION = re.compile(r"^\d+(\.\d+){0,3}([-+.]?[a-z]{0,10}\.?\d{0,6})?$")
# PEP 723 inline script metadata, as in `# /// script`.
SCRIPT_METADATA = re.compile(r"(?m)^# /// script$\s(?P<content>(^#(| .*)$\s)+)^# ///$")


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
# Written right before a redirect: a descriptor, as in 2>, or {name}, which opens one.
DESCRIPTOR_WORD = re.compile(r"[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}")
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
        if self.in_word and DESCRIPTOR_WORD.fullmatch("".join(self.word)):
            self.word, self.in_word = [], False  # not an argument, as in 2>/dev/null
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
    """One package at one exact version that a command would install."""

    ecosystem: str
    name: str
    version: str

    def label(self) -> str:
        separator = "==" if self.ecosystem == PYPI else "@"
        return f"{self.ecosystem} {self.name}{separator}{self.version}"

    def url(self) -> str:
        if self.ecosystem == PYPI:
            return f"https://pypi.org/project/{self.name}/{self.version}/"
        return f"https://www.npmjs.com/package/{self.name}/v/{self.version}"


@dataclass
class Plan:
    """The packages a command would install, and the rules it breaks."""

    requests: list[Request] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    downloads: set[str] = field(default_factory=set)  # names of files it downloads
    # Names of files it writes; "*" stands for files the check cannot name.
    written: set[str] = field(default_factory=set)
    # Scripts whose dependency header `uv run` reads.
    scripts: list[str] = field(default_factory=list)
    # Every folder the command could be in, for reading script files. A `cd` may not
    # happen (after `&&` or `||`) or may be undone (in a subshell), so earlier folders
    # stay in the set. None when a `cd` goes somewhere the check cannot work out.
    cwds: set[str] | None = field(default_factory=lambda: {"."})


# What >& and <& take to copy or close a descriptor, as in >&2 or <&-, not a file name.
DUPLICATE = re.compile(r"[0-9]+-?|-")


@dataclass
class Command:
    argv: list[str] = field(default_factory=list)
    heredocs: list[str] = field(default_factory=list)
    redirects: list[tuple[str, str]] = field(default_factory=list)  # (operator, target)
    # Bodies of here-documents whose delimiter is not quoted. The shell runs the $(...)
    # and `...` in them before the command reads them.
    expanded: list[str] = field(default_factory=list)

    def inputs(self) -> list[str]:
        """What arrives on stdin through < and <<< (here-documents are separate)."""
        return [target for op, target in self.redirects if op in ("<", "<<<", "<>")]

    def here_strings(self) -> list[str]:
        return [target for op, target in self.redirects if op == "<<<"]

    def outputs(self) -> set[str]:
        """The files its redirects write, as in > file, &> file and >& file."""
        ops = (">", ">>", ">|", "&>", "&>>", "<>")
        names = {target for op, target in self.redirects if op in ops}
        return names | {
            t for op, t in self.redirects if op == ">&" and not DUPLICATE.fullmatch(t)
        }


# First words that open a compound command, and the word that closes each one.
BLOCK_WORDS = {
    "{": "}",
    "if": "fi",
    "case": "esac",
    "for": "done",
    "while": "done",
    "until": "done",
    "select": "done",
}


@dataclass
class Block:
    """A subshell, group, loop or if statement, or the whole command."""

    closer: str | None
    feeders: list[Command]  # commands whose output reaches the block's stdin
    earlier: list[Command] = field(default_factory=list)  # in the current pipeline
    inside: list[Command] = field(default_factory=list)  # every command in the block


def fed_commands(tokens: list[Token]) -> list[tuple[Command, list[Command]]]:
    """Each simple command, with the commands whose output may reach its stdin.

    A pipe feeds every command in the subshell, group, loop or if statement it leads
    into, as in `curl ... | (cd /tmp && sh)`, and such a block feeds the command it
    pipes into, as in `... | while read l; do echo "$l"; done | sh`. Commands earlier
    in a pipeline count even when they only pass the data on.
    """
    found: list[tuple[Command, list[Command]]] = []
    blocks = [Block(None, [])]
    command, redirect = Command(), None

    def finish() -> None:
        nonlocal command, redirect
        if command.argv or command.heredocs or command.redirects:
            block = blocks[-1]
            found.append((command, block.feeders + block.earlier))
            block.earlier.append(command)
            for each in blocks:
                each.inside.append(command)
        command, redirect = Command(), None

    for token in tokens:
        value = token.value
        first = token.kind == "word" and redirect is None and not command.argv
        if token.kind == "word" and redirect is not None:
            command.redirects.append((redirect, value))
            redirect = None
        elif (first and value in BLOCK_WORDS) or (token.kind == "op" and value == "("):
            finish()
            outer = blocks[-1]
            closer = BLOCK_WORDS.get(value, ")")
            blocks.append(Block(closer, outer.feeders + outer.earlier))
        elif (first or token.kind == "op") and value == blocks[-1].closer:
            finish()
            block = blocks.pop()
            blocks[-1].earlier.extend(block.inside)  # its output may reach a pipe
        elif token.kind == "word":
            command.argv.append(value)
        elif token.kind == "redirect":
            redirect = value
        elif token.kind == "heredoc":
            command.heredocs.append(value)
            if not token.quoted:
                command.expanded.append(value)
        else:
            finish()
            # Anything but a pipe starts a new pipeline. The arms of a case
            # statement still read its stdin, through the block.
            if value not in ("|", "|&"):
                blocks[-1].earlier.clear()
    finish()
    return found


def simple_commands(tokens: list[Token]) -> list[Command]:
    """Every simple command in the tokens, in order."""
    return [command for command, _ in fed_commands(tokens)]


def program_name(word: str) -> str:
    match = LOOKED_UP_PROGRAM.match(word)
    return os.path.basename(match.group(1) if match else word)


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
        flags: set[str] = set()
        i += 1
        while i < len(argv) and argv[i].startswith("-") and argv[i] != "-":
            flag, eq, inline = argv[i].partition("=")
            if flag == "--":
                i += 1
                break
            if name == "env" and flag in ("-S", "--split-string"):
                value = inline if eq else (argv[i + 1] if i + 1 < len(argv) else "")
                return strip_wrappers(split_words(value) + argv[i + (1 if eq else 2) :])
            flags.add(flag)
            i += 2 if flag in value_flags and not eq else 1
        if name == "command" and flags & {"-v", "-V"}:
            return []  # `command -v pnpm` only looks the program up
        while name == "env" and i < len(argv) and "=" in argv[i]:
            i += 1  # env takes NAME=value pairs before the command
        if name == "timeout" and i < len(argv):
            i += 1  # the duration
    return argv[i:]


@dataclass
class PythonCall:
    module: str | None = None  # python -m module
    code: str | None = None  # python -c code
    script: str | None = None  # python script.py, or "-" for stdin
    rest: list[str] = field(default_factory=list)  # the arguments after it


def read_python_args(args: list[str]) -> PythonCall:
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-") or arg == "-":
            return PythonCall(script=arg, rest=args[i + 1 :])
        if arg == "--":
            following = args[i + 1 : i + 2]
            return PythonCall(
                script=following[0] if following else None, rest=args[i + 2 :]
            )
        if arg.startswith("--"):
            i += 1
            continue
        letters = arg[1:]
        for k, letter in enumerate(letters):
            attached = letters[k + 1 :]
            if letter in "cm":
                value = attached or (args[i + 1] if i + 1 < len(args) else "")
                rest = args[i + 1 :] if attached else args[i + 2 :]
                if letter == "c":
                    return PythonCall(code=value, rest=rest)
                return PythonCall(module=value, rest=rest)
            if letter in "XW":  # options that take a value
                i += 1 if attached else 2
                break
        else:
            i += 1
    return PythonCall()  # no script: python reads its program from stdin


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


# Files that are open descriptors. `3<&0` makes /dev/fd/3 stdin too.
STDIN_PATH = re.compile(r"dev/(std(in|out|err)|fd/[0-9]+)|proc/[^/]+/fd/[0-9]+")


def from_stdin(operand: str | None) -> bool:
    """True when a script operand may be stdin.

    That covers no operand and "-", /dev/stdin and descriptors such as /dev/fd/3,
    process substitutions, which may read stdin, and names known only when the
    command runs, such as "$f". Leading slashes and .. parts are ignored, because
    ../../dev/stdin reaches /dev/stdin as well.
    """
    if operand is None or operand == "-":
        return True
    if operand.startswith("<(") or "$" in operand or "`" in operand:
        return True
    path = os.path.normpath(operand).lstrip("/")
    while path.startswith("../"):
        path = path[3:]
    return STDIN_PATH.fullmatch(path) is not None


def inline_code(args: list[str]) -> list[str]:
    """The code given to node -e, perl -e and similar."""
    found = []
    for i, arg in enumerate(args):
        name, eq, value = arg.partition("=")
        if name in INLINE_CODE_FLAGS:
            found.append(value if eq else (args[i + 1] if i + 1 < len(args) else ""))
    return found


def script_of(program: str, args: list[str]) -> str | None:
    """The script file a shell or interpreter runs, if it runs one."""
    if program in SHELLS:
        has_c, _, operand = shell_options(args)
        return None if has_c else operand
    if PYTHON.match(program):
        return read_python_args(args).script
    if program in INTERPRETERS and not inline_code(args):
        return next(
            (arg for arg in args if not arg.startswith("-") or arg == "-"), None
        )
    if program in ("source", "."):
        return args[0] if args else None
    return None


def reads_code_from_stdin(program: str, args: list[str], depth: int = 0) -> bool:
    """True when a shell or interpreter would run code from stdin, or from a file
    that may be stdin."""
    if program in SHELLS:
        has_c, has_s, operand = shell_options(args)
        if has_c:  # `bash -c 'source /dev/stdin'` runs stdin through its command text
            return operand is not None and text_runs_stdin(operand, depth + 1)
        return has_s or from_stdin(operand)
    if PYTHON.match(program):
        call = read_python_args(args)
        return call.module is None and call.code is None and from_stdin(call.script)
    if program in INTERPRETERS:
        return not inline_code(args) and from_stdin(script_of(program, args))
    if program == "eval":
        # `eval "$(cat)"` runs whatever a substitution prints, which may be stdin.
        expands = any("$" in arg or "`" in arg for arg in args)
        return expands or text_runs_stdin(" ".join(args), depth + 1)
    return program in ("source", ".") and from_stdin(script_of(program, args))


def runs_stdin_code(command: Command, depth: int = 0) -> bool:
    """True when a command runs code from stdin, and so from anything piped into it.

    Its redirects do not change that. zsh, which Claude Code uses when it is the
    user's shell, reads a pipe as one more input, so `curl ... | sh < local.sh` runs
    the download and then local.sh. Bash can hand the pipe back through another
    descriptor, as in `sh 3<&0 <<EOF 0<&3`, or through a substitution, as in
    `sh <<< "$(cat)"`.
    """
    program, args = program_of(command.argv)
    return reads_code_from_stdin(program, args, depth)


def text_runs_stdin(text: str, depth: int) -> bool:
    """True when shell text contains a command that runs code from stdin.

    Any position counts, because `cat | sh` inside `bash -c` passes the outer stdin
    on to sh. Text that cannot be read, or is nested too deeply, counts as running
    stdin, so the caller blocks instead of guessing.
    """
    if depth > MAX_NESTING:
        return True
    try:
        lexer = lex(text)
    except ParseError:
        return True
    for tokens in [lexer.tokens, *lexer.nested]:
        if any(runs_stdin_code(command, depth) for command in simple_commands(tokens)):
            return True
    return False


def code_texts(program: str, args: list[str], command: Command) -> list[str]:
    """The text a program runs as code, as opposed to data it only reads."""
    texts: list[str] = []
    if program in SHELLS:
        operand = shell_options(args)[2]
        texts += [operand] if operand else []
    elif program == "eval":
        texts += args
    elif PYTHON.match(program):
        call = read_python_args(args)
        texts += [t for t in (call.code, call.script) if t]
    elif program in INTERPRETERS:
        texts += inline_code(args) or [t for t in [script_of(program, args)] if t]
    elif program in ("source", "."):
        texts += args[:1]
    if reads_code_from_stdin(program, args):
        # What arrives on stdin is code. The shell fills in the substitutions of an
        # unquoted here-document first, so `sh <<EOF` with $(curl ...) runs the download.
        texts += command.inputs() + command.expanded
    return texts


def downloaded_files(program: str, args: list[str], command: Command) -> set[str]:
    """The names of the files a curl or wget command saves."""
    names = command.outputs()
    letter, long_flag = (
        ("o", "--output") if program == "curl" else ("O", "--output-document")
    )
    remote = program == "wget"  # wget names the file after the URL unless -O is given
    i = 0
    while i < len(args):
        arg = args[i]
        following = args[i + 1] if i + 1 < len(args) else ""
        if arg == long_flag or arg.startswith(f"{long_flag}="):
            names.add(arg.partition("=")[2] if "=" in arg else following)
            remote = False
            i += 1 if "=" in arg else 2
            continue
        if arg.startswith("-") and not arg.startswith("--") and letter in arg[1:]:
            rest = arg[arg.index(letter, 1) + 1 :]  # -o file, -ofile, -sSLo file, -qO-
            names.add(rest or following)
            remote = False
            i += 1 if rest else 2
            continue
        short_remote = arg.startswith("-") and not arg.startswith("--") and "O" in arg
        if program == "curl" and (
            short_remote or arg in ("--remote-name", "--remote-name-all")
        ):
            remote = True
        i += 1
    if remote:
        names |= {
            urllib.parse.urlsplit(a).path.rpartition("/")[2] for a in args if "://" in a
        }
    return {os.path.basename(name) for name in names if name and name != "-"}


# git subcommands that change files in the working tree.
GIT_WRITES = words(
    "checkout switch restore reset stash apply am pull merge rebase cherry-pick revert mv"
)


def target_directory(args: list[str]) -> str | None:
    """The folder given to cp, mv, ln or install with -t or --target-directory."""
    for i, arg in enumerate(args):
        if arg in ("-t", "--target-directory"):
            return args[i + 1] if i + 1 < len(args) else ""
        if arg.startswith("--target-directory="):
            return arg.partition("=")[2]
        if arg.startswith("-t") and len(arg) > 2 and not arg.startswith("--"):
            return arg[2:]
    return None


def edits_in_place(program: str, args: list[str]) -> bool:
    """True when sed or perl rewrites its files: -i, also inside a cluster like -pi."""
    takes_value = "efl" if program == "sed" else "0CdDeEFIlmMx"
    for arg in args:
        if arg.startswith("--in-place"):
            return True
        if arg.startswith("-") and not arg.startswith("--"):
            for letter in arg[1:]:
                if letter == "i":
                    return True
                if letter in takes_value:  # the rest of the cluster is its value
                    break
    return False


def copies_folders(args: list[str]) -> bool:
    """True when cp or rsync copies folders: -r, -R, -a or their long forms."""
    return any(
        arg in ("--recursive", "--archive")
        or (
            arg.startswith("-")
            and not arg.startswith("--")
            and bool(set(arg) & set("rRa"))
        )
        for arg in args
    )


def written_files(program: str, args: list[str], command: Command) -> set[str]:
    """The names of files a command writes, or "*" when it may write files the check
    cannot name, such as `git checkout` or a redirect to "$FILE".

    Only names are kept, so a file with the same name in another folder counts too.
    """
    names = command.outputs()
    operands = [arg for arg in args if not arg.startswith("-")]
    if program == "tee" or (
        program in ("sed", "perl") and edits_in_place(program, args)
    ):
        names |= set(operands)
    elif program == "dd":
        names |= {arg[3:] for arg in args if arg.startswith("of=")}
    elif program in ("cp", "mv", "ln", "install", "rsync") and operands:
        if program in ("cp", "rsync") and copies_folders(args):
            names.add("*")  # files inside the folders it copies
        folder = target_directory(args)
        if folder is not None:
            names |= set(operands) - {folder}
        else:
            *sources, destination = operands
            names.add(destination)
            last = os.path.basename(destination.rstrip("/"))
            # Copying into a folder keeps each source's name. A destination without a
            # dot in its name, such as `.` or `backup`, is taken to be a folder.
            into_folder = destination.endswith("/") or "." not in last.strip(".")
            if into_folder or len(sources) > 1:
                names |= set(sources)
    elif program in ("patch", "unzip") or (program == "git" and git_writes(args)):
        names.add("*")
    elif program == "tar" and any(
        arg in ("--extract", "--get") or re.fullmatch(r"-?[A-Za-z]*x[A-Za-z]*", arg)
        for arg in args
    ):
        names.add("*")  # `tar xzf a.tgz` can overwrite any file
    names = {"*" if "$" in name or "`" in name else name for name in names}
    return {
        os.path.basename(name.rstrip("/")) for name in names if name and name != "-"
    }


def git_writes(args: list[str]) -> bool:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in ("-C", "-c") else 1
    return i < len(args) and args[i] in GIT_WRITES


def command_string(args: list[str]) -> str | None:
    """The command text after -c or --command, as in `su -c "uv add x"`."""
    for i, arg in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else None
        if arg == "--command":
            return following
        if arg.startswith("--command="):
            return arg.partition("=")[2]
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            return arg[arg.index("c", 1) + 1 :] or following
    return None


def watch_command(args: list[str]) -> list[str]:
    """`watch -n 5 "pnpm add zod"` runs its arguments through sh -c."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] in ("-x", "--exec"):
            return []  # the arguments run directly, and the general scan finds them
        i += 2 if args[i] in ("-n", "--interval") else 1
    return args[i:]


def starts_nested_command(argv: list[str], j: int) -> bool:
    """True when argv[j] starts a command that runs inside another program."""
    name = program_name(argv[j])
    base = name.partition("@")[0]  # corepack runs pnpm@10.0.0
    if base in PACKAGE_MANAGERS or PIP.match(base) or name in SHELLS:
        return True
    if PYTHON.match(name):
        return top_module(read_python_args(argv[j + 1 :]).module) in PACKAGE_MANAGERS
    return False


def top_module(module: str | None) -> str:
    """`python -m pip.__main__` runs pip, so the first name decides what runs."""
    return (module or "").partition(".")[0]


def unknown_option(
    word: str, value_flags: frozenset[str], bool_flags: frozenset[str]
) -> bool:
    return (
        word.startswith("--")
        and "=" not in word
        and word not in value_flags
        and word not in bool_flags
    )


def risky_option(name: str) -> bool:
    return name.startswith("--") and RISKY_SETTING.search(name) is not None


def risky_variable(name: str) -> bool:
    return (
        PACKAGE_TOOL_VARIABLE.match(name) is not None
        and RISKY_SETTING.search(name) is not None
    )


def find_verb(
    args: list[str],
    verbs: frozenset[str],
    value_flags: frozenset[str],
    bool_flags: frozenset[str],
) -> int | None:
    """The index of a tool's subcommand, as in `uv --directory api add x`.

    A word right after an option we do not know may be that option's value, so it is
    skipped unless it is a known subcommand.
    """
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return i + 1 if i + 1 < len(args) else None
        if arg.startswith("-") and arg != "-":
            name, eq, _ = arg.partition("=")
            i += 2 if name in value_flags and not eq else 1
            continue
        previous = args[i - 1] if i else ""
        if arg in verbs or not unknown_option(previous, value_flags, bool_flags):
            return i
        i += 1
    return None


def read_args(
    args: list[str],
    value_flags: frozenset[str],
    bool_flags: frozenset[str],
    file_flags: frozenset[str],
    plan: Plan,
    tool: str,
    stop_at_operand: bool = False,
) -> tuple[list[str], dict[str, list[str]], list[str]]:
    """Split arguments into operands, option values and possible option values.

    Options that read packages from a file or a path, or that point at another index
    or registry, add a problem to the plan. A word right after an option we do not
    know is returned separately: it may be that option's value or an operand, so
    callers check it either way. With stop_at_operand, reading stops at the first
    operand, which is returned with everything after it: the command that uvx,
    uv run or pnpm dlx starts.
    """
    operands: list[str] = []
    values: dict[str, list[str]] = {}
    maybes: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1 :]
            break
        if not arg.startswith("-") or arg == "-":
            if i and unknown_option(args[i - 1], value_flags, bool_flags):
                maybes.append(arg)
            elif stop_at_operand:
                operands += args[i:]
                break
            else:
                operands.append(arg)
            i += 1
            continue
        name, eq, inline = arg.partition("=")
        attached = (
            not name.startswith("--") and len(name) > 2 and name[:2] in file_flags
        )
        if name in file_flags or attached or risky_option(name):
            plan.problems.append(
                f"`{tool} {name[:2] if attached else name}` installs from a file, a path or "
                "another index or registry, or turns off certificate checks, so the check "
                "cannot vet it. Name each package from PyPI or npm instead."
            )
        takes_value = (
            (name in value_flags or name in file_flags) and not eq and not attached
        )
        value = args[i + 1] if takes_value and i + 1 < len(args) else inline
        values.setdefault(name, []).append(value)
        i += 2 if takes_value else 1
    return operands, values, maybes


def pin_problem(spec: str, example: str) -> str:
    return (
        f"`{spec}` is not an exact version. Pin one, as in `{example}`, so the check vets "
        "the exact version that gets installed."
    )


def parse_pypi_spec(spec: str, plan: Plan, at_version: bool = False) -> None:
    text = spec.strip()
    if not text:
        return
    if at_version and "@" in text and "://" not in text and not re.search(r"\s@", text):
        base, _, pin = text.partition("@")  # uvx ruff@0.14.0
        text = f"{base}=={pin}" if pin else base
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
    version = ""
    if rest.startswith("==="):
        version = rest[3:].strip()
    elif rest.startswith("=="):
        version = rest[2:].strip()
    if not PY_VERSION.fullmatch(version):
        plan.problems.append(pin_problem(spec, f"{name}==1.2.3"))
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
        name, version = (text, "") if at == -1 else (text[:at], text[at + 1 :])
    else:
        name, _, version = text.partition("@")
    if version.startswith("npm:"):
        parse_npm_spec(version[4:], plan)  # an alias, as in my-zod@npm:zod@4.1.12
        return
    if version.startswith("workspace:"):
        return  # a package from this repository, not from the registry
    if version.startswith(NOT_FROM_NPM) or "/" in version or ":" in version:
        plan.problems.append(f"`{spec}` is not a package from the npm registry.")
        return
    if len(name) > 214 or not NPM_NAME.fullmatch(name):
        plan.problems.append(
            f"`{spec}` looks like a GitHub repository, not an npm package. Install "
            "packages by name."
            if "/" in name and not name.startswith("@")
            else f"`{spec}` is not a valid npm package name."
        )
        return
    version = version.removeprefix("v")
    if not EXACT_SEMVER.fullmatch(version):
        plan.problems.append(pin_problem(spec, f"{name}@1.2.3"))
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


def check_config_change(tool: str, verb: str, tail: list[str], plan: Plan) -> None:
    """`npm config set registry ...` would point later installs at another registry."""
    if verb in ("config", "c") and tail[:1] == ["set"]:
        keys = tail[1:]
    elif verb == "set":
        keys = tail
    else:
        return
    for key in keys:
        name = key.partition("=")[0]
        if not key.startswith("-") and RISKY_SETTING.search(name):
            plan.problems.append(
                f"`{tool} {verb}` would change `{name}`, which decides where packages come "
                "from or whether certificates are checked. Leave it as it is."
            )


def inline_script_requests(path: str, plan: Plan, directory: str = ".") -> None:
    """`uv run script.py` installs the packages listed in the script's own header.

    The script is read before the command runs, so a script the check cannot read,
    including one the same command creates, blocks the command.
    """
    location = os.path.join(directory, path)
    plan.scripts.append(location)
    if URL_SCHEME.match(path):  # uv downloads the script, then runs it
        plan.problems.append(RUN_DOWNLOAD)
        return
    if from_stdin(path):  # stdin or a substitution: no file to read beforehand
        candidates = []
    elif os.path.isabs(location):
        candidates = [location]
    else:  # every folder the command could be in when uv runs
        candidates = sorted(os.path.join(d, location) for d in plan.cwds or ())
    texts: list[str] = []
    for candidate in candidates:
        try:
            with open(candidate, "rb") as handle:
                data = handle.read(MAX_SCRIPT_BYTES + 1)
        except (FileNotFoundError, NotADirectoryError):
            continue  # not in this folder
        except OSError:
            plan.problems.append(
                f"The check could not read {path}, so it cannot vet the dependencies "
                "the script lists."
            )
            return
        if len(data) > MAX_SCRIPT_BYTES:
            plan.problems.append(
                f"{path} is larger than the {MAX_SCRIPT_BYTES // (1024 * 1024)} MB the "
                "check reads, so it cannot see all of the script's dependency header."
            )
            return
        texts.append(data.decode("utf-8", "replace"))
    if not texts:
        plan.problems.append(
            f"The check could not read {path} before the command runs, so it cannot vet "
            "the dependencies the script lists. Create the script first, then run it "
            "with `uv run` in a separate command."
        )
        return
    for text in texts:
        script_header_requests(text, path, plan)


def script_header_requests(text: str, path: str, plan: Plan) -> None:
    """Check the dependencies a script lists in its PEP 723 header."""
    match = SCRIPT_METADATA.search(text)
    if match is None:
        return
    content = "".join(
        line[2:] if line.startswith("# ") else line[1:]
        for line in match.group("content").splitlines(keepends=True)
    )
    try:
        import tomllib  # imported here because it needs Python 3.11 or later

        metadata = tomllib.loads(content)
    except (ImportError, ValueError):
        plan.problems.append(
            f"The check could not read the dependencies listed in {path}, so it cannot "
            "vet them."
        )
        return
    tool = as_dict(metadata.get("tool"))
    sources = as_dict(tool.get("uv")).get("sources")  # git, path or URL sources
    if sources or RISKY_SETTING.search(json.dumps(tool)):
        plan.problems.append(
            f"{path} sets its own index or package source, so the check cannot vet its "
            "dependencies."
        )
    for spec in as_list(metadata.get("dependencies")):
        if isinstance(spec, str):
            parse_pypi_spec(spec, plan)


def uv_run_command(
    args: list[str], plan: Plan | None = None
) -> tuple[list[str], dict[str, list[str]], str | None]:
    """What `uv run` starts: the command, the options, and the script file if any.

    `uv run x.py` runs the script with Python and installs the dependencies its
    header lists; `uv run python x.py` runs Python and reads no header.
    """
    operands, options, _ = read_args(
        args,
        UV_RUN_VALUE_FLAGS,
        UV_RUN_BOOL_FLAGS,
        UV_FILE_FLAGS,
        plan or Plan(),
        "uv run",
        stop_at_operand=True,
    )
    if "-m" in options or "--module" in options:
        return ["python", "-m", *operands], options, None
    as_script = {"-s", "--script"} & set(options)
    first = operands[0] if operands else ""
    # uv runs a .py file, a URL or stdin ("-") as a script. Words from xargs may
    # name one too.
    if first and (
        first.endswith((".py", ".pyw"))
        or as_script
        or first in ("-", XARGS_INPUT)
        or URL_SCHEME.match(first)
    ):
        return ["python", *operands], options, first
    return operands, options, None


def inner_command(program: str, args: list[str]) -> list[str] | None:
    """The command that `uv run`, `pnpm exec` or corepack starts."""
    tool = program_name(args[0]).partition("@")[0] if args else ""
    if program == "corepack" and tool in COREPACK_TOOLS:
        return args  # `corepack pnpm@10.0.0 add x` runs pnpm 10.0.0
    if program == "uv":
        index = find_verb(args, UV_SUBCOMMANDS, UV_VALUE_FLAGS, UV_BOOL_FLAGS)
        if index is not None and args[index] == "run":
            return uv_run_command(args[index + 1 :])[0] or None
    if program == "pnpm":
        index = find_verb(args, PNPM_VERBS, PNPM_VALUE_FLAGS, PNPM_BOOL_FLAGS)
        shell_mode = any(a in ("-c", "--shell-mode") for a in args[: index or 0])
        while index is not None and args[index] in ("recursive", "multi", "m"):
            args = args[index + 1 :]
            index = find_verb(args, PNPM_VERBS, PNPM_VALUE_FLAGS, PNPM_BOOL_FLAGS)
        if index is not None and args[index] == "exec":
            operands, options, _ = read_args(
                args[index + 1 :],
                PNPM_VALUE_FLAGS,
                PNPM_BOOL_FLAGS,
                frozenset(),
                Plan(),
                "pnpm exec",
                stop_at_operand=True,
            )
            if shell_mode or "-c" in options or "--shell-mode" in options:
                return ["sh", "-c", operands[0]] if operands else None
            return operands or None
    return None


def program_of(argv: list[str]) -> tuple[str, list[str]]:
    """The program that really runs, past wrappers, `uv run` and `pnpm exec`."""
    stripped = strip_wrappers(argv)
    for _ in range(MAX_NESTING):
        if not stripped:
            return "", []
        program, args = program_name(stripped[0]), stripped[1:]
        inner = inner_command(program, args)
        if not inner:
            return program, args
        stripped = strip_wrappers(inner)
    return "", []


def plan_uv(args: list[str], plan: Plan) -> None:
    index = find_verb(args, UV_SUBCOMMANDS, UV_VALUE_FLAGS, UV_BOOL_FLAGS)
    head = args if index is None else args[:index]
    _, options, _ = read_args(
        head, UV_VALUE_FLAGS, UV_BOOL_FLAGS, UV_FILE_FLAGS, plan, "uv"
    )
    if index is None:
        return
    sub, tail = args[index], args[index + 1 :]
    if sub == "run":
        _, more, script = uv_run_command(tail, plan)
        for spec in more.get("--with", []):
            for item in spec.split(","):
                parse_pypi_spec(item, plan, at_version=True)
        if script:
            # `uv --directory api run tool.py` runs api/tool.py.
            directory = [*options.get("--directory", []), *more.get("--directory", [])]
            inline_script_requests(script, plan, (directory or ["."])[-1])
    elif sub == "tool" and tail[:1] in (["run"], ["install"]):
        more = plan_tool_run(tail[1:], plan, f"uv tool {tail[0]}")
    else:
        operands, more, maybes = read_args(
            tail, UV_VALUE_FLAGS, UV_BOOL_FLAGS, UV_FILE_FLAGS, plan, f"uv {sub}"
        )
        if sub == "add":
            for spec in operands + maybes:
                parse_pypi_spec(spec, plan)
        elif sub == "pip" and operands[:1] in (["install"], ["sync"], ["compile"]):
            plan.problems.append(
                f"`uv pip {operands[0]}` works outside pyproject.toml and uv.lock, so the "
                "check cannot vet it. Use `uv add <name>==<version>`, or `uv sync` to "
                "install the lockfile."
            )
        elif sub == "tool" and operands[:1] == ["upgrade"]:
            plan.problems.append(f"`uv tool upgrade` {BULK_UPGRADE}")
        elif sub == "self" and operands[:1] == ["update"]:
            plan.problems.append(
                "`uv self update` replaces uv without the check. Leave uv at the version "
                "the environment provides."
            )
        elif sub == "venv" and "--seed" in more:
            plan.problems.append(
                "`uv venv --seed` installs pip and setuptools without the check, and uv "
                "does not need them. Leave out --seed."
            )
    flags = [*options, *more]
    if any(
        f in UV_UPGRADE_FLAGS or (not f.startswith("--") and f[:2] in ("-U", "-P"))
        for f in flags
    ):
        plan.problems.append(f"`uv {sub} --upgrade` {BULK_UPGRADE}")


def plan_tool_run(args: list[str], plan: Plan, tool: str) -> dict[str, list[str]]:
    """uvx, uv tool run and uv tool install: the package is --from or the command."""
    operands, options, maybes = read_args(
        args,
        UV_VALUE_FLAGS,
        UV_BOOL_FLAGS,
        UV_FILE_FLAGS,
        plan,
        tool,
        stop_at_operand=True,
    )
    targets = options.get("--from", [])[-1:] or operands[:1] + maybes
    extras = [item for value in options.get("--with", []) for item in value.split(",")]
    for spec in targets + extras:
        parse_pypi_spec(spec, plan, at_version=True)
    return options


def plan_pnpm(args: list[str], plan: Plan, depth: int) -> None:
    index = find_verb(args, PNPM_VERBS, PNPM_VALUE_FLAGS, PNPM_BOOL_FLAGS)
    head = args if index is None else args[:index]
    _, options, _ = read_args(
        head, PNPM_VALUE_FLAGS, PNPM_BOOL_FLAGS, frozenset(), plan, "pnpm"
    )
    while index is not None and args[index] in ("recursive", "multi", "m"):
        args = args[index + 1 :]
        index = find_verb(args, PNPM_VERBS, PNPM_VALUE_FLAGS, PNPM_BOOL_FLAGS)
        # Options between `recursive` and the subcommand count too.
        head = args if index is None else args[:index]
        _, more, _ = read_args(
            head, PNPM_VALUE_FLAGS, PNPM_BOOL_FLAGS, frozenset(), plan, "pnpm"
        )
        for name, values in more.items():
            options.setdefault(name, []).extend(values)
    if index is None:
        return
    verb, tail = args[index], args[index + 1 :]
    check_config_change("pnpm", verb, tail, plan)
    if verb in ("update", "up", "upgrade", "self-update"):
        plan.problems.append(f"`pnpm {verb}` {BULK_UPGRADE}")
    elif verb == "dlx":
        plan_dlx(tail, plan, depth, options.get("--package", []))
    elif verb in ("add", "install", "i", "create"):
        operands, _, maybes = read_args(
            tail, PNPM_VALUE_FLAGS, PNPM_BOOL_FLAGS, frozenset(), plan, f"pnpm {verb}"
        )
        specs = operands + maybes
        if verb == "create":
            specs = [create_package(spec) for spec in specs[:1]]
        for spec in specs:
            parse_npm_spec(spec, plan)


def plan_dlx(args: list[str], plan: Plan, depth: int, packages: list[str]) -> None:
    """pnpm dlx: --package values are the packages, otherwise the command is."""
    operands, options, maybes = read_args(
        args,
        PNPM_VALUE_FLAGS,
        PNPM_BOOL_FLAGS,
        frozenset(),
        plan,
        "pnpm dlx",
        stop_at_operand=True,
    )
    found = packages + options.get("--package", [])
    shell_mode = "-c" in options or "--shell-mode" in options
    command = operands[0] if operands else None
    if shell_mode and command:
        plan_script(command, plan, depth + 1)  # pnpm dlx -c runs the text in a shell
    if not found:
        first = (split_words(command) if shell_mode else [command]) if command else []
        found = first[:1] + maybes
    for spec in found:
        parse_npm_spec(spec, plan)


def plan_npm(args: list[str], plan: Plan) -> None:
    index = find_verb(args, NPM_VERBS, NPM_VALUE_FLAGS, frozenset())
    if index is None:
        return
    verb, tail = args[index], args[index + 1 :]
    check_config_change("npm", verb, tail, plan)
    if verb in NPM_INSTALL_VERBS or (verb == "audit" and "fix" in tail):
        blocked_tool(plan, f"npm {verb}", JS_WAY)


def plan_corepack(args: list[str], plan: Plan) -> None:
    """corepack downloads the package manager version a command names."""
    verb = args[0] if args else ""
    tool, at_sign, _ = program_name(verb).partition("@")
    if tool in COREPACK_TOOLS and not at_sign:
        # Without a version, corepack downloads whichever version it picks.
        plan.problems.append(pin_problem(f"corepack {tool}", f"corepack {tool}@1.2.3"))
    if verb == "up":
        plan.problems.append(f"`corepack up` {BULK_UPGRADE}")
    elif verb in ("use", "install", "prepare", "pack", "hydrate"):
        for arg in args[1:]:
            if re.match(r"^(pnpm|yarn|npm)(@|$)", arg):
                parse_npm_spec(arg, plan)


def plan_xargs(args: list[str], plan: Plan, depth: int) -> None:
    """Check what xargs runs, with a stand-in for the words it reads from stdin."""
    i, replace = 0, None
    while i < len(args) and args[i].startswith("-"):
        arg = args[i]
        if arg in ("-I", "--replace"):
            replace = args[i + 1] if i + 1 < len(args) else "{}"
            i += 2
            continue
        if arg.startswith(("-I", "-i", "--replace=")):
            replace = arg.partition("=")[2] if "=" in arg else (arg[2:] or "{}")
        i += 2 if arg in XARGS_VALUE_FLAGS else 1
    command = args[i:]
    if not command:
        return
    if replace:
        probe = [word.replace(replace, XARGS_INPUT) for word in command]
    else:
        probe = [*command, XARGS_INPUT]
    folders = None if plan.cwds is None else set(plan.cwds)
    trial = Plan(downloads=set(plan.downloads), written=plan.written, cwds=folders)
    plan_simple_command(Command(probe), trial, depth + 1)
    from_stdin = any(XARGS_INPUT in r.name for r in trial.requests) or any(
        XARGS_INPUT in p for p in trial.problems
    )
    if from_stdin:
        plan.problems.append(
            "Packages passed through `xargs` cannot be checked. Name each package in "
            "the command."
        )
    plan.scripts += trial.scripts
    plan.requests += [r for r in trial.requests if XARGS_INPUT not in r.name]
    plan.problems += [p for p in trial.problems if XARGS_INPUT not in p]


def plan_git(args: list[str], plan: Plan, depth: int) -> None:
    """git runs commands for `bisect run`, `rebase --exec` and `submodule foreach`."""
    for i, arg in enumerate(args):
        following = args[i + 1 :]
        if arg in ("--exec", "-x") and following:
            plan_script(following[0], plan, depth + 1)
        elif arg.startswith("--exec="):
            plan_script(arg.partition("=")[2], plan, depth + 1)
        elif arg == "foreach" and following:
            plan_script(
                " ".join(f for f in following if not f.startswith("-")), plan, depth + 1
            )
        elif arg == "run" and "bisect" in args[:i] and following:
            plan_simple_command(Command(following), plan, depth + 1)


def plan_script(text: str, plan: Plan, depth: int) -> None:
    """Text that a shell runs as code.

    In `bash -c "$(cat <<'EOF' ... EOF)"` the script is a here-document inside a
    command substitution, so those here-documents are code too. A here-document at
    the top of the text is data for its command, as in a file written with cat.
    """
    plan_command(text, plan, depth)
    try:
        lexer = lex(text)
    except ParseError:
        return
    if len(lexer.tokens) == 1 and lexer.tokens[0].kind == "word":
        for tokens in lexer.nested:
            for token in tokens:
                if token.kind == "heredoc":
                    plan_command(token.value, plan, depth)


def plan_fed_code(
    operand: str | None, command: Command, plan: Plan, depth: int
) -> None:
    """Code that a shell or `source` reads from stdin or a descriptor: its
    here-documents and here-strings, and what a process substitution prints.
    `bash <(echo "uv add x")` runs like `echo "uv add x" | bash`."""
    for text in command.heredocs + command.here_strings():
        plan_script(text, plan, depth)
    for target in [operand or "", *command.inputs()]:
        if not (target.startswith("<(") and target.endswith(")")):
            continue
        try:
            tokens = lex(target[2:-1]).tokens
        except ParseError:
            continue  # quoted text that only looks like <(...); a real one read already
        for feeder in simple_commands(tokens):
            plan_fed_text(feeder, plan, depth)


def plan_program(
    program: str, args: list[str], command: Command, plan: Plan, depth: int
) -> None:
    """Apply the install rules to one program and its arguments."""
    base, at_sign, version = program.partition("@")
    if at_sign and base in COREPACK_TOOLS:
        # corepack downloads this version of the package manager first
        parse_npm_spec(f"{COREPACK_TOOLS[base]}@{version}", plan)
        program = base
    script = script_of(program, args)
    if program in plan.downloads or (
        script and os.path.basename(script) in plan.downloads
    ):
        plan.problems.append(
            "Running a file in the same command that downloads it is blocked, because "
            "nothing checks what it runs. Download the file, read it, then decide "
            "whether to run it."
        )
    if any(
        DOWNLOAD_SUBSTITUTION.search(text)
        for text in code_texts(program, args, command)
    ):
        plan.problems.append(RUN_DOWNLOAD)
    plan.written |= written_files(program, args, command)
    if program in DOWNLOADERS:
        plan.downloads |= downloaded_files(program, args, command)
    elif program in SHELLS:
        has_c, has_s, operand = shell_options(args)
        if has_c and operand is not None:
            plan_script(operand, plan, depth + 1)
        elif has_s or from_stdin(operand):  # bash <<'EOF' runs the here-document
            plan_fed_code(operand, command, plan, depth + 1)
    elif program in ("source", ".") and from_stdin(script):
        plan_fed_code(script, command, plan, depth + 1)
    elif program == "eval":
        plan_script(" ".join(args), plan, depth + 1)
    elif program in COMMAND_STRING_RUNNERS:
        command_text = command_string(args)
        if command_text:
            plan_script(command_text, plan, depth + 1)
    elif program == "watch":
        plan_command(" ".join(watch_command(args)), plan, depth + 1)
    elif program == "xargs":
        plan_xargs(args, plan, depth)
    elif program == "git":
        plan_git(args, plan, depth)
    elif PYTHON.match(program):
        call = read_python_args(args)
        module = top_module(call.module)
        if module == "venv" and "--upgrade-deps" in call.rest:
            plan.problems.append(
                "`python -m venv --upgrade-deps` installs the newest pip and setuptools "
                "without the check. Leave out --upgrade-deps."
            )
        elif module:
            plan_program(module, call.rest, Command(), plan, depth + 1)
    elif program == "uv":
        plan_uv(args, plan)
    elif program == "uvx":
        plan_tool_run(args, plan, "uvx")
    elif program == "pnpm":
        plan_pnpm(args, plan, depth)
    elif program == "npm":
        plan_npm(args, plan)
    elif program == "corepack":
        plan_corepack(args, plan)
    elif PIP.match(program):
        index = find_verb(args, PIP_VERBS, PIP_VALUE_FLAGS, frozenset())
        if index is not None and args[index] in (
            "install",
            "download",
            "wheel",
            "lock",
        ):
            blocked_tool(plan, "pip install", PYTHON_WAY)
    elif program in UNUSED_PYTHON_TOOLS:
        blocked_tool(plan, program, PYTHON_WAY)
    elif program in UNUSED_JS_TOOLS:
        blocked_tool(plan, program, JS_WAY)


def runs_other_commands(program: str) -> bool:
    """Programs not handled above whose arguments may hold a command to run, such as
    `docker exec web sh -c "..."` or `find . -exec ...`."""
    return not (
        program in NO_COMMAND_ARGS
        or program in PACKAGE_MANAGERS
        or program in SHELLS
        or program in INTERPRETERS
        or program in COMMAND_STRING_RUNNERS
        or program in ("eval", "source", ".", "watch", "xargs", "git")
        or PYTHON.match(program)
        or PIP.match(program)
    )


def plan_simple_command(command: Command, plan: Plan, depth: int) -> None:
    argv = command.argv
    for word in argv:
        name = word.partition("=")[0] if "=" in word else ""
        if name and risky_variable(name):
            plan.problems.append(
                f"`{name}` decides where packages come from or whether certificates are "
                "checked, so the check cannot vet installs that use it. Remove it."
            )
    stripped = strip_wrappers(argv)
    if not stripped:  # redirects alone still write, as in `{ ...; } > tool.py`
        plan.written |= written_files("", [], command)
        return
    if DOWNLOAD_SUBSTITUTION.search(stripped[0]):  # `$(curl ...)` runs what it prints
        plan.problems.append(RUN_DOWNLOAD)
    program, args = program_name(stripped[0]), stripped[1:]
    if program in ("cd", "pushd", "popd"):
        targets = [arg for arg in args if not arg.startswith("-") or arg == "-"]
        target = targets[0] if targets else "~"
        unknown = program == "popd" or target == "-" or "$" in target or "`" in target
        if unknown or (program == "pushd" and not targets) or plan.cwds is None:
            plan.cwds = None
        else:
            moved = {os.path.join(d, os.path.expanduser(target)) for d in plan.cwds}
            plan.cwds |= moved
            if len(plan.cwds) > MAX_FOLDERS:
                plan.cwds = None
        return
    plan_program(program, args, command, plan, depth)
    if depth >= MAX_NESTING:
        return
    base = program.partition("@")[0]  # corepack runs pnpm@10.0.0 as pnpm
    inner = inner_command(base, args)
    if inner:  # `uv run python x.py` and `pnpm exec node x.js` run another program
        plan_simple_command(
            Command(inner, command.heredocs, command.redirects, command.expanded),
            plan,
            depth + 1,
        )
    elif runs_other_commands(base):
        k = len(argv) - len(stripped)
        for j in range(1, len(argv)):  # from 1, in case a wrapper option was misread
            if j != k and starts_nested_command(argv, j):
                plan_simple_command(Command(argv[j:]), plan, depth + 1)
                break


def substitution_runs_stdin(text: str) -> bool:
    """True when text holds a substitution, such as $(sh), <(sh) or >(sh), whose
    commands run code from stdin."""
    if not any(mark in text for mark in ("$(", "`", "<(", ">(")):
        return False
    scanner = Lexer(text)
    try:
        scanner.run()
    except ParseError:  # here-document text, whose quotes need not pair up
        scanner = Lexer(text)
        try:
            scanner.scan_expansions(text)
        except ParseError:
            return True
    return any(
        runs_stdin_code(command)
        for tokens in scanner.nested
        for command in simple_commands(tokens)
    )


def substitutes_stdin_code(command: Command) -> bool:
    """True when a substitution in the command runs code from stdin.

    `$(sh)` and `<(sh)` read the stdin the command has, `>(sh)` reads what the
    command writes into it, and the shell fills in the substitutions of an unquoted
    here-document before the command reads it.
    """
    targets = [target for _, target in command.redirects]
    texts = [*command.argv, *targets, *command.expanded]
    return any(substitution_runs_stdin(text) for text in texts)


def plan_tokens(tokens: list[Token], plan: Plan, depth: int) -> None:
    for command, feeders in fed_commands(tokens):
        program, _ = program_of(command.argv)
        piped = bool(feeders) and runs_stdin_code(command)
        hidden = substitutes_stdin_code(command)
        downloaded = any(program_of(f.argv)[0] in DOWNLOADERS for f in feeders)
        if (downloaded and (piped or hidden)) or (hidden and program in DOWNLOADERS):
            plan.problems.append(PIPE_DOWNLOAD)
        if downloaded and not command.argv:  # `{ curl ...; } > i.sh` saves a download
            plan.downloads |= downloaded_files("", [], command)
        # `echo "uv add x" | sh` runs the text it reads as shell code, and so do
        # `| source /dev/stdin`, `| eval "$(cat)"` and `| tee >(sh)`.
        shell_code = program in SHELLS or program in ("source", ".", "eval")
        if (piped and shell_code) or (hidden and feeders):
            for feeder in feeders:
                plan_fed_text(feeder, plan, depth + 1)
        plan_simple_command(command, plan, depth)


def plan_fed_text(command: Command, plan: Plan, depth: int) -> None:
    for text in command.heredocs + command.here_strings():
        plan_script(text, plan, depth)
    program, args = program_of(command.argv)
    if program in ("echo", "printf"):
        text = " ".join(arg for arg in args if not arg.startswith("-"))
        if program == "printf" or "-e" in args:
            text = text.replace("\\n", "\n").replace("\\t", "\t")
        plan_command(text, plan, depth)


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
    if depth == 0 and plan.scripts:  # after the whole command, so order does not matter
        for script in sorted(set(plan.scripts)):
            parts = [p for p in script.split("/") if p not in ("", ".", "..")]
            *folders, name = parts or [script]
            if name in plan.written:
                plan.problems.append(
                    f"This command writes {name} and runs it with `uv run`, so the "
                    "check cannot read the dependencies the script will list. Write "
                    "the file in one command and run it in the next."
                )
            # `cp -R new/. app` or `mv new app` replaces app/tool.py too.
            for folder in sorted(set(folders) & plan.written):
                plan.problems.append(
                    f"This command writes {folder} and runs {script} from it with "
                    "`uv run`, so the check cannot be sure which dependencies the "
                    "script will list. Write the files in one command and run the "
                    "script in the next."
                )
        if "*" in plan.written:
            plan.problems.append(
                "This command changes files the check cannot name and runs a script with "
                "`uv run`, so the check cannot be sure which dependencies the script will "
                "list. Run the script in a separate command."
            )


# ---------------------------------------------------------------- registries and OSV


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


class Registry:
    """Reads PyPI, npm, OSV and the approvals file. Every request has a timeout and
    respects the deadline."""

    pypi_url = "https://pypi.org"
    npm_url = "https://registry.npmjs.org"
    osv_url = "https://api.osv.dev"
    approvals_url = APPROVALS_URL

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline  # a time.monotonic() value

    def get(
        self,
        url: str,
        body: dict[str, Any] | None = None,
        accept: str = "application/json",
    ) -> bytes | None:
        """Return the response body, or None for HTTP 404. Retries once after a
        transient error."""
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
    ) -> bytes:
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
            # read1 returns whatever has arrived, so the deadline is checked between
            # reads even when a server sends its answer very slowly.
            while chunk := response.read1(64 * 1024):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES or time.monotonic() > self.deadline:
                    raise CheckError(
                        f"{host} sent more data than the check can read in time"
                    )
                chunks.append(chunk)
            raw = b"".join(chunks)
            if (response.headers.get("Content-Encoding") or "").lower() == "gzip":
                raw = gunzip(raw, host)
        return raw

    def get_json(
        self,
        url: str,
        body: dict[str, Any] | None = None,
        accept: str = "application/json",
    ) -> Any:
        raw = self.get(url, body, accept)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError as error:
            host = urllib.parse.urlsplit(url).hostname
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
            answer = self.get_json(f"{self.osv_url}/v1/query", body=body)
            # OSV answers an object even when it knows of nothing, so a 404 or any
            # other body means the check could not finish.
            if not isinstance(answer, dict):
                raise CheckError("api.osv.dev sent no usable answer")
            vulns = answer.get("vulns", [])
            if not isinstance(vulns, list):
                raise CheckError("api.osv.dev sent no usable answer")
            for vuln in map(as_dict, vulns):
                # Only a real withdrawal time removes an advisory. A malformed value,
                # such as "false", must not hide a malware report.
                if parse_time(vuln.get("withdrawn")) is not None:
                    continue
                # An ID in an unexpected format still counts, as "", but is never
                # repeated to Claude, because whoever wrote it controls its text.
                primary = vuln.get("id")
                ids.append(primary if valid_osv_id(primary) else "")
                for alias in as_list(vuln.get("aliases")):
                    if valid_osv_id(alias) and alias.startswith("MAL-"):
                        ids.append(alias)
            token = answer.get("next_page_token")
            if not token:
                return ids
            body["page_token"] = token
        raise CheckError("api.osv.dev returned too many pages")

    def approvals(self) -> set[str]:
        """The approvals on main. If they cannot be read, there are none."""
        try:
            raw = self.get(self.approvals_url, accept="text/plain")
        except CheckError:
            return set()
        return parse_approvals(raw.decode("utf-8", "replace")) if raw else set()


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


def age_text(delta: timedelta) -> str:
    if delta.days < 1:
        return "less than a day ago"
    return f"{delta.days} day{'s' if delta.days != 1 else ''} ago"


def shown_version(value: Any) -> str | None:
    """A registry's version string, if it is short and plain enough to show Claude."""
    if isinstance(value, str) and len(value) <= 32 and SHOWN_VERSION.fullmatch(value):
        return value
    return None


def release_key(version: str) -> tuple[int, ...]:
    match = re.match(r"\d+(\.\d+)*", version)
    return tuple(int(part) for part in match.group().split(".")) if match else ()


def version_from_filename(filename: str) -> str | None:
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        return parts[1] if len(parts) >= 5 else None
    for suffix in (".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz"):
        if filename.endswith(suffix):
            return filename[: -len(suffix)].rpartition("-")[2] or None
    return None


def older_version(
    times: dict[str, datetime], now: datetime, pattern: re.Pattern[str], requested: str
) -> str | None:
    """The newest stable version below the requested one that is past the cooldown."""
    ceiling = release_key(requested)
    candidates = [
        version
        for version, when in times.items()
        if pattern.fullmatch(version)
        and release_key(version) < ceiling
        and now - when >= MIN_VERSION_AGE
    ]
    return max(candidates, key=release_key) if candidates else None


def approval_key(request: Request) -> str:
    if request.ecosystem == PYPI:
        return f"pypi/{request.name}=={request.version}".lower()
    return f"npm/{request.name}@{request.version}".lower()


def parse_approvals(text: str) -> set[str]:
    approved = set()
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if entry:
            approved.add(entry)
    return approved


def valid_osv_id(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and OSV_ID.fullmatch(value) is not None


def osv_problems(registry: Registry, request: Request) -> list[str]:
    found = registry.osv_ids(request.ecosystem, request.name, request.version)
    ids = sorted({i for i in found if i})
    malware = [i for i in ids if i.startswith("MAL-")]
    if malware:
        return [
            (
                f"OSV lists this package as malware ({', '.join(malware[:3])}). Never "
                f"install it. https://osv.dev/vulnerability/{malware[0]}"
            )
        ]
    problems = []
    if ids:
        links = " ".join(f"https://osv.dev/vulnerability/{i}" for i in ids[:5])
        more = f" and {len(ids) - 5} more" if len(ids) > 5 else ""
        problems.append(
            f"Version {request.version} has known vulnerabilities: {links}{more}. "
            "Pick another."
        )
    unreadable = found.count("")
    if unreadable:
        count = f"{unreadable} {'more ' if ids else ''}"
        noun = "advisory" if unreadable == 1 else "advisories"
        search = urllib.parse.urlencode(
            {"ecosystem": request.ecosystem, "q": request.name}
        )
        problems.append(
            f"OSV lists {count}{noun} for this version with an ID in an unexpected "
            "format, so the check does not repeat it. Look the version up at "
            f"https://osv.dev/list?{search}"
        )
    return problems


def age_problems(
    finding: Finding,
    first: datetime,
    newest: datetime,
    now: datetime,
    suggestion: Callable[[], str | None],
) -> None:
    if now - first < MIN_PACKAGE_AGE:
        finding.cooldown = True
        finding.problems.append(
            f"This package was first published {age_text(now - first)}. Packages younger "
            "than 30 days are blocked, because most malicious packages are brand new."
        )
    if now - newest < MIN_VERSION_AGE:
        finding.cooldown = True
        older = suggestion()
        hint = (
            f" {older} is older and past the cooldown; try it, and the check will vet it."
            if older
            else ""
        )
        finding.problems.append(
            f"A file of version {finding.request.version} was published "
            f"{age_text(now - newest)}. Versions with files younger than 7 days are "
            f"blocked while the community checks them.{hint}"
        )


def summarize(finding: Finding, newest: datetime, now: datetime, latest: Any) -> None:
    request = finding.request
    finding.summary = f"{request.label()}, last file published {age_text(now - newest)}: {request.url()}"
    shown = shown_version(latest)
    if shown and shown != request.version:
        finding.summary += f" (latest release: {shown})"


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
    release = project if request.version == latest else None
    release = release or registry.pypi_release(request.name, request.version)
    if release is None:
        finding.problems.append(f"Version {request.version} does not exist on PyPI.")
        return finding
    if as_dict(release.get("info")).get("yanked"):
        finding.problems.append(
            f"Version {request.version} was yanked by its maintainers."
        )
    uploads = [
        parse_time(as_dict(item).get("upload_time_iso_8601"))
        for item in as_list(release.get("urls"))
    ]
    times = [t for t in uploads if t is not None]
    if not times:
        finding.problems.append(f"PyPI lists no files for version {request.version}.")
        return finding
    newest = max(times)  # a file added to an old release is as new as its upload
    if approval_key(request) not in approved:
        files = [as_dict(item) for item in registry.pypi_files(request.name)]
        all_times = [t for t in (parse_time(f.get("upload-time")) for f in files) if t]
        first = min(all_times, default=min(times))

        def suggestion() -> str | None:
            per_version: dict[str, datetime] = {}
            yanked: set[str] = set()
            for item in files:
                found = version_from_filename(str(item.get("filename", "")))
                when = parse_time(item.get("upload-time"))
                if found and when:
                    per_version[found] = max(per_version.get(found, when), when)
                    if item.get("yanked"):
                        yanked.add(found)
            usable = {v: t for v, t in per_version.items() if v not in yanked}
            older = older_version(usable, now, PY_RELEASE, request.version)
            return f"{request.name}=={older}" if older else None

        age_problems(finding, first, newest, now, suggestion)
    finding.problems += osv_problems(registry, request)
    summarize(finding, newest, now, latest)
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
    manifest = versions.get(request.version)
    if not isinstance(manifest, dict):
        finding.problems.append(f"Version {request.version} does not exist on npm.")
        return finding
    if manifest.get("deprecated"):
        # The deprecation text is written by the package author, so it is not repeated.
        finding.problems.append(
            f"Version {request.version} is deprecated on npm. Read why on the package "
            "page, then pick another version or package."
        )
    times = as_dict(doc.get("time"))
    published = parse_time(times.get(request.version))
    if published is None:
        raise CheckError(
            f"npm gave no publish date for {request.name} {request.version}"
        )
    if approval_key(request) not in approved:
        per_version: dict[str, datetime] = {}
        for candidate in versions:
            when = parse_time(times.get(candidate))
            if when is not None:
                per_version[candidate] = when
        earliest = min(per_version.values(), default=published)
        first = parse_time(times.get("created")) or earliest

        def suggestion() -> str | None:
            usable = {
                v: t
                for v, t in per_version.items()
                if not as_dict(versions.get(v)).get("deprecated")
            }
            older = older_version(usable, now, NPM_RELEASE, request.version)
            return f"{request.name}@{older}" if older else None

        age_problems(finding, first, published, now, suggestion)
    finding.problems += osv_problems(registry, request)
    summarize(finding, published, now, as_dict(doc.get("dist-tags")).get("latest"))
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
    cwd: str = ".",
) -> Outcome:
    plan = Plan(cwds={cwd})
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
        approved = registry.approvals() if approvals is None else approvals

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
        request = finding.request
        where = f"{request.label()} ({request.url()})"
        lines += [f"- {where}: {problem}" for problem in finding.problems]
    lines.append(
        "Do not work around this check. Tell Aisha what was blocked and why, with the "
        "links above."
    )
    cooled = [approval_key(f.request) for f in blocked if f.cooldown]
    if cooled:
        lines.append(
            "If Aisha decides a version is safe to use before the cooldown ends, she adds "
            f"`{cooled[0]}` to .claude/approved-packages.txt in a pull request. The check "
            "reads approvals from main on GitHub, so an approval counts only after review "
            "and merge, and can take a few minutes to show."
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
        f"The package check ran out of time ({DEADLINE_SECONDS:.0f} seconds), so it "
        "blocked the command to be safe. A registry may be slow, or the command may be "
        "too long to read. Try again, or split the command into smaller ones.\n"
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
        if payload.get("tool_name") not in SHELL_TOOLS:
            return 0
        tool_input = as_dict(payload.get("tool_input"))
        command = tool_input.get("command")
        if (
            command is None
            and payload.get("tool_name") == "Monitor"
            and "ws" in tool_input
        ):
            return 0  # a WebSocket monitor runs no shell command
        if not isinstance(command, str):
            raise TypeError("the hook input has no command")
        given = payload.get("cwd")
        cwd = given if isinstance(given, str) else "."
        cloud = os.environ.get("CLAUDE_CODE_REMOTE") == "true"
        now = datetime.now(timezone.utc)
        outcome = evaluate(command, Registry(deadline), now, cloud=cloud, cwd=cwd)
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
