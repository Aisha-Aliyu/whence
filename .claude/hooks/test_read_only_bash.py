"""Tests for read_only_bash.py.

Run from the repository root:

    python3 -m unittest discover --start-directory .claude/hooks --verbose
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

import read_only_bash as ro

HOOKS = Path(__file__).resolve().parent
HOOK = HOOKS / "read_only_bash.py"
SETTINGS = HOOKS.parent / "settings.json"
AGENT = HOOKS.parent / "agents" / "reviewer.md"


class DecideTests(unittest.TestCase):
    def test_allows_reading_and_checking(self) -> None:
        cases = [
            "git diff main...HEAD",
            "git diff --stat origin/main",
            "git diff HEAD~1 -- '*.py'",
            "git log --oneline -20",
            'git log --grep "fix: " --format="%h %s"',
            "git log --no-ext-diff -p",
            "git show HEAD:CLAUDE.md",
            "git status --short",
            "git blame -L 10,20 CLAUDE.md",
            "git ls-files .claude",
            "git rev-parse --abbrev-ref HEAD",
            "git merge-base main HEAD",
            "git grep -n 'pip install' -- docs",
            "git grep --or -e alpha -e beta",
            "git branch --show-current",
            "python3 -m unittest discover --start-directory .claude/hooks --verbose",
            "uvx ruff@0.16.9 check .claude/hooks",
            "uvx ruff@0.16.9 check --no-fix .claude/hooks",
            "uvx ruff@0.16.9 format --check .claude/hooks",
            "uvx mypy@2.3.1 --strict .claude/hooks",
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertIsNone(ro.decide(command))

    def test_blocks_commands_outside_the_list(self) -> None:
        cases = [
            "",
            "rm -rf .claude",
            "touch x",
            "git commit -am x",
            "git push",
            "git checkout -- CLAUDE.md",
            "git restore CLAUDE.md",
            "git branch -D main",
            "git branch new-branch",
            "git config core.pager cat",
            "git -c core.pager=sh log",
            "git -C /tmp log",
            "sed -i s/a/b/ CLAUDE.md",
            'python3 -c \'open("x", "w")\'',
            "python3 script.py",
            "uvx ruff check .",
            "uvx ruff@latest check .",
            "uvx ruff@0.16.9 check --fix .",
            "uvx ruff@0.16.9 check --unsafe-fixes .",
            "uvx ruff@0.16.9 check --output-file=x .",
            "uvx ruff@0.16.9 format .",
            "uvx mypy@2.3.1 --strict --junit-xml x .claude/hooks",
            "uvx mypy@2.3.1 .claude/hooks",
            "uvx black@24.1.0 .",
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertIsNotNone(ro.decide(command))

    def test_blocks_shell_syntax_that_could_write_or_run_anything(self) -> None:
        cases = [
            "git diff > out.txt",
            "git diff >> out.txt",
            "git log < input",
            "git log | tee out.txt",
            "git status; rm -rf x",
            "git status && touch x",
            "git status || touch x",
            "git status & touch x",
            "git log $(touch x)",
            "git log `touch x`",
            'git log "$(touch x)"',
            'git log "`touch x`"',
            "git log $HOME",
            "git log ${HOME}",
            "git diff --{output,x}=/tmp/x",
            "git log\ntouch x",
            "git log \\\n--output=x",
            "git ls-files *.py",
            "git ls-files ?.py",
            "(git log)",
            "git log 'unbalanced",
            'git log "unbalanced',
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertIsNotNone(ro.decide(command))

    def test_blocks_git_options_that_write_files_or_start_programs(self) -> None:
        cases = [
            "git diff --output=/tmp/x",
            "git diff --output /tmp/x",
            "git diff '--output=/tmp/x'",
            "git diff\t--output=/tmp/x",
            'git diff "--ext-diff"',
            "git diff --ext",  # git accepts a shortened long option
            "git show --ext-diff",
            "git log -p --textconv",
            "git grep -O pattern",
            "git grep -Otouch pattern",
            "git grep -nO pattern",
            "git grep --open-files-in-pager=touch pattern",
            "git grep --op=touch pattern",
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertIsNotNone(ro.decide(command))


class EntryPointTests(unittest.TestCase):
    """Runs the script the way Claude Code does: JSON on stdin, exit code back."""

    def run_hook(self, payload: Any) -> subprocess.CompletedProcess[str]:
        data = payload if isinstance(payload, str) else json.dumps(payload)
        return subprocess.run(
            [sys.executable, "-I", str(HOOK)],
            input=data,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def payload(self, command: str, agent: str | None = ro.REVIEWER) -> dict[str, Any]:
        result: dict[str, Any] = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        if agent:
            result.update(agent_id="a1", agent_type=agent)
        return result

    def test_the_review_agent_may_read(self) -> None:
        result = self.run_hook(self.payload("git diff main...HEAD"))
        self.assertEqual((result.returncode, result.stderr), (0, ""))

    def test_the_review_agent_may_not_write(self) -> None:
        result = self.run_hook(self.payload("git commit -am x"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("The review agent is read-only", result.stderr)

    def test_other_callers_are_not_limited(self) -> None:
        self.assertEqual(
            self.run_hook(self.payload("touch x", agent=None)).returncode, 0
        )
        other = self.payload("touch x", agent="general-purpose")
        self.assertEqual(self.run_hook(other).returncode, 0)

    def test_the_review_agent_may_not_open_a_socket_with_monitor(self) -> None:
        payload = {
            "tool_name": "Monitor",
            "tool_input": {"ws": {"url": "wss://example.com"}},
            "agent_type": ro.REVIEWER,
        }
        self.assertEqual(self.run_hook(payload).returncode, 2)
        monitor = self.payload("git status")
        monitor["tool_name"] = "Monitor"
        self.assertEqual(self.run_hook(monitor).returncode, 0)

    def test_unreadable_input_blocks(self) -> None:
        self.assertEqual(self.run_hook("not json").returncode, 2)
        self.assertEqual(self.run_hook(["a", "list"]).returncode, 2)
        broken = {"tool_name": "Bash", "tool_input": "x", "agent_type": ro.REVIEWER}
        self.assertEqual(self.run_hook(broken).returncode, 2)


class WiringTests(unittest.TestCase):
    def test_settings_run_the_check_for_shell_commands(self) -> None:
        settings = json.loads(SETTINGS.read_text())
        entries = settings["hooks"]["PreToolUse"]
        hooks = [
            h for e in entries if e["matcher"] == "Bash|Monitor" for h in e["hooks"]
        ]
        commands = [h["command"] for h in hooks]
        expected = 'python3 -I "$CLAUDE_PROJECT_DIR/.claude/hooks/read_only_bash.py"'
        self.assertIn(f"{expected} || exit 2", commands)

    def test_the_agent_file_matches_the_name_and_has_no_edit_tools(self) -> None:
        text = AGENT.read_text()
        front = text.split("---")[1]
        fields = dict(
            line.split(":", 1) for line in front.strip().splitlines() if ":" in line
        )
        self.assertEqual(fields["name"].strip(), ro.REVIEWER)
        tools = {t.strip() for t in fields["tools"].split(",")}
        self.assertEqual(tools, {"Read", "Grep", "Glob", "Bash"})


if __name__ == "__main__":
    unittest.main()
