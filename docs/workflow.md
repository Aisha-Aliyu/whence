# How we work

These rules apply to every change, including changes written by AI. Claude Code reads the short version in [CLAUDE.md](../CLAUDE.md) at the start of every session.

## The loop for every change

1. Write down what the change must do and how we will know it works. Usually that is the day's entry in the [roadmap](roadmap.md).
2. Claude Code makes the change on its own branch and runs the checks for every part it touched.
3. Open a pull request. The template asks what changed, why, the trade-offs, how it was tested and how to roll it back.
4. Automated checks run: secret scan and dependency review from Day 1, then lint, type checks, tests, CodeQL and evaluations as each arrives.
5. CodeRabbit reviews the pull request. Small public repositories sometimes have to ask, so if no review appears within a few minutes, comment `@coderabbitai review`.
6. An independent review agent, with no memory of how the code was written, reviews it against the checklist below.
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
- From Day 2, a Claude Code hook checks every install command before it runs.
- The dependency review check blocks pull requests that add packages with known vulnerabilities of moderate severity or worse.

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
