# How we work

These rules apply to every change, including changes written by AI. Claude Code reads the short version in [CLAUDE.md](../CLAUDE.md) at the start of every session.

## The loop for every change

1. Write down what the change must do and how we will know it works. Usually that is the day's entry in the [roadmap](roadmap.md).
2. Claude Code makes the change on its own branch and runs the checks for every part it touched.
3. Open a pull request. The template asks what changed, why, the trade-offs, how it was tested and how to roll it back.
4. Automated checks run: secret scan and dependency review from Day 1, then lint, type checks, tests, CodeQL and evaluations as each arrives.
5. CodeRabbit reviews the pull request. Small public repositories sometimes have to ask, so if no review appears within a few minutes, comment `@coderabbitai review`.
6. An independent review agent, with no memory of how the code was written, reviews it against the checklist below. See [the review agent](#the-review-agent).
7. Aisha reads the change. If she cannot explain a part of it, Claude explains it or simplifies it.
8. Resolve every review conversation, then squash and merge. GitHub deletes the branch.

## Branches and commits

- `main` is protected: no direct pushes, no force pushes, no deletion. Changes arrive only through pull requests with every conversation resolved and every required check green.
- Branch names start with `feat/`, `fix/`, `chore/`, `docs/`, `ci/`, `refactor/` or `test/`. Claude Code cloud sessions name their own branches (`claude/...`), which is fine.
- Pull request titles follow Conventional Commits, for example `feat(api): add upload route`. Squash merging turns the title into the commit message on `main`, and those messages later drive semantic versions and the changelog.

## Why approvals are set to zero

GitHub does not let anyone approve their own pull request, and Whence has one developer. Requiring an approval would block every merge. Instead, `main` requires a pull request, resolved conversations and passing checks, and CodeRabbit plus the review agent act as reviewers. When a second developer joins, we raise required approvals to one.

## Definition of done

A change is done when all of these are true:

- It does what the plan said, including the failure cases.
- Tests cover the new behavior, with at least one failure path.
- CI is green, and CodeRabbit and the review agent have no open findings.
- Docs reflect any changed behavior or decision.
- Code, logs and test fixtures contain no secrets, keys or personal data.
- UI changes work at 280, 390, 768, 1280 and 2560 px wide, with a keyboard alone, with a screen reader, and score at least 95 in Lighthouse.
- Aisha can explain why it works and what we traded off.

## Reviewing AI-written code

Ten checks for every pull request:

1. Requirement: restate what the change must do, then confirm it does that.
2. Edge cases: empty, invalid, huge, duplicate and concurrent inputs, and partial failures. Follow what happens when each one goes wrong.
3. Complexity: remove layers, options and dependencies the problem does not need.
4. Readability: the important logic reads end to end. No vague names, no dead code, no duplicated blocks, no comments that repeat the code.
5. Security and privacy: inputs validated, authorization checked on the server for every route, no way to reach another workspace's data, no secrets or personal data in code or logs.
6. Failure handling: timeouts on calls, retries that cannot repeat a side effect, and logs and metrics that explain a failure.
7. Scale: no queries inside loops, no loading everything into memory, indexes for the queries we run, sized for realistic production data.
8. APIs and dependencies: every method used exists in the installed version. Every new package is needed, maintained, licensed for our use and checked for vulnerabilities.
9. Tests: they check outputs, state changes and failure handling, and they fail when the behavior breaks.
10. Production readiness: one focused change, a safe deploy order for migrations, a rollback path, and logs good enough to debug it in production.

## Dependencies

- Before adding a package, confirm it exists on PyPI or npm and link to it. Check the latest version, release history, maintainers, license and known vulnerabilities, and whether we need it at all.
- Lockfiles pin every version (`uv.lock` for Python, `pnpm-lock.yaml` for the web app).
- Dependabot opens grouped update pull requests every week. New versions wait 7 days before Dependabot proposes them, which keeps us away from freshly published malicious releases. Security fixes skip that wait.
- A Claude Code hook checks every package before Claude installs it. See [the package check](#the-package-check).
- The dependency review check blocks pull requests that add packages with known vulnerabilities of moderate severity or worse.

## The package check

Claude Code runs [.claude/hooks/check_packages.py](../.claude/hooks/check_packages.py) before every shell command it starts with the Bash or Monitor tools, as a PreToolUse hook set in [.claude/settings.json](../.claude/settings.json). The hook reads the command the way bash would and finds every package it would install, including installs inside `bash -c`, `$(...)`, a here-document that a shell runs, `uv run`, `pnpm exec` and `corepack`. Each package must pass four checks:

1. It exists on PyPI or npm. Attackers register package names that AI tools tend to invent, so a misspelled or made-up name can pull in malware. This attack is called slopsquatting.
2. The package is at least 30 days old, and every file of the version is at least 7 days old, because malicious releases are usually found and removed within days. A file added later to an old release counts as new. In [one review of ten supply chain attacks](https://blog.yossarian.net/2025/11/21/We-should-all-be-using-dependency-cooldowns), eight were open for less than a week.
3. [OSV](https://osv.dev), the open vulnerability database, which also collects malware reports, lists nothing against that version.
4. The version is not yanked on PyPI or deprecated on npm.

The hook also enforces how we install. Every install names an exact version, so the check vets exactly what gets installed: `uv add httpx==0.28.1` and `pnpm add zod@4.1.12` for dependencies, `uvx ruff@0.16.9` and `pnpm dlx create-next-app@16.0.0` for one-off tools. Python packages come from PyPI through uv, and JavaScript packages come from npm through pnpm, so pip, npm, npx, yarn, Poetry and similar tools are blocked. Nothing installs from a URL, a git repository, a local path, a requirements file, or another index, registry or mirror, whether an option, an environment variable or `npm config set` points there. When `uv run` starts a script that lists its own dependencies at the top, the hook checks those too. Bulk upgrades such as `pnpm update` and `uv lock --upgrade` are blocked, because Dependabot proposes upgrades in reviewed pull requests. Running a downloaded script is blocked, whether it is piped into a shell or run later in the same command. Installs from the reviewed lockfiles (`uv sync`, `pnpm install`) run without checks.

When every package passes, Claude receives each package's link and the age of its newest file, plus the latest version when an older one was pinned. When anything fails, the command does not run, and Claude receives the reason, the links and, for a version that is too new, an older version past the cooldown, which the check vets again when Claude tries it. Text written by package authors, such as an npm deprecation message, is never passed on, because it could carry instructions aimed at Claude. If a check cannot finish, for example because a registry is down, the command is blocked. Claude Code lets a hook that times out pass, so the script stops itself after 60 seconds and blocks, and settings.json turns a crash or a missing Python into a block too.

### Approving a new release

Sometimes a version is needed before its 7 days are up, such as a security fix. Aisha decides, then adds the exact version to [.claude/approved-packages.txt](../.claude/approved-packages.txt) in a pull request, with the reason and the date. The hook reads that file from `main` on GitHub, not from the copy in the session, so nothing in a session can approve its own install. GitHub can take a few minutes to serve the new file after a merge. If the hook cannot read the file, no approvals apply. An approval lifts only the age rules: the package must still exist and have no known vulnerability.

### Network access

The hook needs `pypi.org`, `registry.npmjs.org` and `api.osv.dev`, and reads approvals from `raw.githubusercontent.com`. Codespaces reaches all four. A Claude Code cloud environment on the default Trusted network level reaches all but OSV, so it blocks every install until OSV is allowed:

1. In a Claude Code cloud session, tap the arrow after the session title at the top, then Edit cloud environment. On the new-session screen, the same dialog opens from the environment selector, the first control under the message box, through the settings icon on the environment's row.
2. Set Network access to Custom.
3. In Allowed domains, enter `api.osv.dev`.
4. Tick Also include default list of common package managers, so the registries stay reachable.
5. Save. Running sessions pick up the change within about a minute.

If approvals stop working in a cloud session after this change, add `raw.githubusercontent.com` to the allowed domains too. Until then, the cooldown simply stays in force.

### What it cannot do

- It reads commands, so it cannot see installs that a script, a Makefile or a program performs, or a command disguised on purpose.
- It checks commands, not file edits. A dependency typed into `package.json` or `pyproject.toml` by hand and then installed with `pnpm install` or `uv sync` skips it. Settings stored in files, such as `.npmrc`, `uv.toml` or the `[tool.uv]` table in `pyproject.toml`, can also point installs at another index. A second hook that checks edits to these files comes in its own pull request before Day 4, when the first of them appears. Until then, pull request review of the lockfile and settings diffs is the check.
- It checks the packages a command names, not their dependencies. The lockfile review in each pull request, the dependency review check, Dependabot's 7-day cooldown, and the package managers' own cooldowns (uv's `exclude-newer` from Day 4, pnpm's `minimumReleaseAge` from Day 14) cover those.
- Claude Code reloads its settings when the file changes, so a session that edits `.claude/` could switch the check off. CLAUDE.md forbids editing `.claude/` unless the task asks for it, and CodeRabbit flags every change there. The hook guards against mistakes; the hard limits are the cloud environment's network allowlist and branch protection.

Run its tests with `python3 -m unittest discover --start-directory .claude/hooks --verbose`. The lint and type commands are in CLAUDE.md.

## The review agent

[.claude/agents/reviewer.md](../.claude/agents/reviewer.md) defines a Claude Code subagent named `reviewer`. It starts with a fresh context, so it has not seen the conversation that wrote the code, and it judges only what is in the repository. It reads the diff against `main`, goes through the ten checks above, runs the tests, linters and type checks, and replies with a verdict and findings, most severe first.

To run it, ask Claude Code: "Use the reviewer agent to review this branch." Claude Code runs it after finishing a change, before the pull request goes to Aisha. Its findings go into the pull request description, under "How it was tested", with what was fixed.

It is read-only. Its tools are Read, Grep, Glob and Bash, with no file editing. Bash could still change files, so a second PreToolUse hook, [.claude/hooks/read_only_bash.py](../.claude/hooks/read_only_bash.py), checks every shell command the reviewer starts. It allows only read-only git commands (`git diff`, `log`, `show`, `status`, `blame`, `ls-files`, `rev-parse`, `merge-base`, `grep` and `git branch --show-current`), `python3 -m unittest`, and the ruff and mypy commands from CLAUDE.md. It blocks pipes, redirects, chained commands, variables, substitutions, wildcards, and the git options that write files or start other programs, including their shortened forms. Commands from anyone other than the reviewer pass this hook untouched.

The rule lives in `.claude/settings.json`, not in the agent file, because Claude Code skips hooks in an agent file when the folder is not marked as trusted. Running the tests runs the project's own code, so the hook limits what the reviewer chooses to run; it is not a sandbox. CodeRabbit stays the second reviewer, and Aisha the last one.

## Working with Claude Code

- CLAUDE.md holds the rules, so nobody has to repeat them in prompts.
- One task per session, sized so the result can be reviewed in one sitting.
- Use Plan mode for anything that touches authentication, data access or the database schema.
- Ask Claude Code to explain trade-offs in the pull request description, in words that work in an interview.
- Never merge code you cannot explain.

## Practices we follow

Alan Knox's [Engineering for Vibe Coders](https://alanknox.com/vibe-coding/) series shaped this process. The parts we apply on every change: write requirements before generating code, break work into tasks small enough for one prompt, agree on a definition of done, document decisions while we still remember them, limit how much one change can break (blast radius), explain the work out loud to find gaps (rubber ducking), and evaluate AI-generated code before accepting it. The reliability, security and operations topics from the series map to rows in [engineering-concepts.md](engineering-concepts.md).

## Releases

- Version numbers follow semantic versioning: `0.x` until launch, `1.0.0` at launch.
- Every release gets a tag, changelog entries and notes on any migration.
